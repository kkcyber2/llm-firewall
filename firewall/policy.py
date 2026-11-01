"""Policy engine: turn findings into a decision (allow / redact / block)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .detectors import Finding, scan

# Per-category action. "flag" = pass through but record; "redact" = mask spans;
# "block" = refuse the request entirely.
DEFAULT_POLICY: Dict[str, str] = {
    "prompt_injection": "block",
    "secret": "block",
    "pii": "redact",
    "toxicity": "flag",
}

_ACTION_RANK = {"allow": 0, "flag": 1, "redact": 2, "block": 3}


@dataclass
class Decision:
    action: str
    findings: List[Finding] = field(default_factory=list)
    text: str = ""
    reasons: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "reasons": self.reasons,
            "findings": [f.as_dict() for f in self.findings],
        }


def redact(text: str, findings: List[Finding]) -> str:
    """Replace each finding span with a masked token, right-to-left so offsets hold."""
    out = text
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        out = out[: f.start] + f"[REDACTED:{f.category}]" + out[f.end:]
    return out


def evaluate(text: str, policy: Optional[Dict[str, str]] = None,
             enabled=None) -> Decision:
    policy = {**DEFAULT_POLICY, **(policy or {})}
    findings = scan(text, enabled=enabled)
    if not findings:
        return Decision("allow", [], text, [])

    action = "allow"
    reasons: List[str] = []
    for f in findings:
        rule = policy.get(f.category, "flag")
        if _ACTION_RANK[rule] > _ACTION_RANK[action]:
            action = rule
        reasons.append(f"{f.category}:{f.reason}")

    if action == "block":
        return Decision("block", findings, text, sorted(set(reasons)))

    if action == "redact":
        redactable = [f for f in findings if policy.get(f.category) == "redact"]
        return Decision("redact", findings, redact(text, redactable), sorted(set(reasons)))

    return Decision(action, findings, text, sorted(set(reasons)))
