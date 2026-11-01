"""Detection primitives for the LLM firewall.

Every detector returns a list of Finding objects with exact character spans so
the policy layer can redact precisely instead of nuking the whole message.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    start: int
    end: int
    match: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "match": self.match,
            "reason": self.reason,
        }


# --- prompt injection -------------------------------------------------------

_INJECTION_PATTERNS = [
    (r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions?", "critical",
     "classic instruction-override"),
    (r"disregard\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions|rules|guidelines)", "critical",
     "instruction-override"),
    (r"forget\s+(?:everything|all)\s+(?:above|before|you\s+were\s+told)", "high",
     "context-reset attempt"),
    (r"you\s+are\s+now\s+(?:a|an|in)\b", "high", "persona hijack"),
    (r"(?:reveal|print|show|repeat|output)\s+(?:me\s+)?(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+rules)", "critical",
     "system-prompt exfiltration"),
    (r"\bDAN\b|\bdo\s+anything\s+now\b", "high", "known jailbreak persona"),
    (r"</?(?:system|assistant|user)>", "medium", "role-tag injection"),
    (r"\[/?(?:INST|SYS)\]", "medium", "instruction-tag injection"),
    (r"new\s+(?:system\s+)?instructions?\s*:", "high", "injected instruction block"),
]

_INJECTION_RE = [(re.compile(p, re.IGNORECASE), s, r) for p, s, r in _INJECTION_PATTERNS]


def detect_prompt_injection(text: str) -> List[Finding]:
    out: List[Finding] = []
    for rx, sev, reason in _INJECTION_RE:
        for m in rx.finditer(text):
            out.append(Finding("prompt_injection", sev, m.start(), m.end(), m.group(0), reason))
    return out


# --- PII --------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?!\d)")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn_ok(digits: str) -> bool:
    """Luhn checksum — stops us flagging every 16-digit order number as a card."""
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, alt = 0, False
    for n in reversed(nums):
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def detect_pii(text: str) -> List[Finding]:
    out: List[Finding] = []
    for m in _EMAIL_RE.finditer(text):
        out.append(Finding("pii", "medium", m.start(), m.end(), m.group(0), "email address"))
    for m in _SSN_RE.finditer(text):
        out.append(Finding("pii", "high", m.start(), m.end(), m.group(0), "US SSN"))
    for m in _IBAN_RE.finditer(text):
        out.append(Finding("pii", "high", m.start(), m.end(), m.group(0), "IBAN"))
    for m in _CARD_RE.finditer(text):
        if luhn_ok(m.group(0)):
            out.append(Finding("pii", "critical", m.start(), m.end(), m.group(0), "payment card (Luhn valid)"))
    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 9 <= len(digits) <= 15 and not _overlaps(out, m.start(), m.end()):
            out.append(Finding("pii", "low", m.start(), m.end(), m.group(0), "phone number"))
    return out


def _overlaps(findings: List[Finding], start: int, end: int) -> bool:
    return any(not (end <= f.start or start >= f.end) for f in findings)


# --- secrets ----------------------------------------------------------------

_SECRET_PATTERNS = [
    (r"\bAKIA[0-9A-Z]{16}\b", "critical", "AWS access key id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "critical", "GitHub token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "critical", "Slack token"),
    (r"\bsk-[A-Za-z0-9]{20,}\b", "critical", "OpenAI-style API key"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical", "private key block"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "high", "JWT"),
]
_SECRET_RE = [(re.compile(p), s, r) for p, s, r in _SECRET_PATTERNS]


def detect_secrets(text: str) -> List[Finding]:
    out: List[Finding] = []
    for rx, sev, reason in _SECRET_RE:
        for m in rx.finditer(text):
            out.append(Finding("secret", sev, m.start(), m.end(), m.group(0), reason))
    return out


# --- toxicity ---------------------------------------------------------------

_TOXIC = {
    "idiot", "moron", "stupid", "kill yourself", "kys", "retard",
    "worthless", "subhuman", "die in a fire",
}
_TOXIC_RE = re.compile(r"\b(" + "|".join(re.escape(w) for w in _TOXIC) + r")\b", re.IGNORECASE)


def detect_toxicity(text: str) -> List[Finding]:
    return [
        Finding("toxicity", "medium", m.start(), m.end(), m.group(0), "abusive language")
        for m in _TOXIC_RE.finditer(text)
    ]


DETECTORS = {
    "prompt_injection": detect_prompt_injection,
    "pii": detect_pii,
    "secret": detect_secrets,
    "toxicity": detect_toxicity,
}


def scan(text: str, enabled=None) -> List[Finding]:
    """Run every enabled detector and return findings sorted by position."""
    enabled = enabled or DETECTORS.keys()
    findings: List[Finding] = []
    for name in enabled:
        fn = DETECTORS.get(name)
        if fn:
            findings.extend(fn(text))
    return sorted(findings, key=lambda f: (f.start, f.end))
