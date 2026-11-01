"""FastAPI guardrail proxy for OpenAI-compatible chat completions.

Sits between your app and any upstream (OpenAI, Groq, Ollama, vLLM) and applies
the policy to both directions: the prompt going out and the completion coming back.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .policy import DEFAULT_POLICY, evaluate

app = FastAPI(title="LLM Firewall", version="1.0.0")

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "https://api.openai.com/v1/chat/completions")
UPSTREAM_KEY = os.environ.get("UPSTREAM_KEY", "")
POLICY = {**DEFAULT_POLICY}

# Injected in tests so no network is required.
_upstream_call: Optional[Callable[[dict], dict]] = None


def set_upstream(fn: Callable[[dict], dict]) -> None:
    """Replace the upstream transport (used by tests and by custom deployments)."""
    global _upstream_call
    _upstream_call = fn


def _default_upstream(payload: dict) -> dict:
    import httpx

    headers = {"Content-Type": "application/json"}
    if UPSTREAM_KEY:
        headers["Authorization"] = f"Bearer {UPSTREAM_KEY}"
    with httpx.Client(timeout=60) as client:
        r = client.post(UPSTREAM_URL, json=payload, headers=headers)
        r.raise_for_status()
        return r.json()


def inspect_messages(messages: List[dict]) -> Dict[str, Any]:
    """Scan every message; return the worst decision plus a rewritten message list."""
    worst = "allow"
    rank = {"allow": 0, "flag": 1, "redact": 2, "block": 3}
    all_findings: List[dict] = []
    reasons: List[str] = []
    rewritten: List[dict] = []

    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            d = evaluate(content, POLICY)
            all_findings.extend(f.as_dict() for f in d.findings)
            reasons.extend(d.reasons)
            if rank[d.action] > rank[worst]:
                worst = d.action
            rewritten.append({**m, "content": d.text})
        else:
            rewritten.append(m)

    return {
        "action": worst,
        "findings": all_findings,
        "reasons": sorted(set(reasons)),
        "messages": rewritten,
    }


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "policy": POLICY}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=400, detail="messages[] required")

    inbound = inspect_messages(messages)
    if inbound["action"] == "block":
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "guardrail_blocked",
                    "message": "Request blocked by LLM firewall policy.",
                    "reasons": inbound["reasons"],
                    "findings": inbound["findings"],
                }
            },
        )

    safe_payload = {**payload, "messages": inbound["messages"]}
    call = _upstream_call or _default_upstream
    try:
        result = call(safe_payload)
    except Exception as exc:  # upstream failure must not look like a policy block
        raise HTTPException(status_code=502, detail=f"upstream error: {exc}")

    # Inspect the completion too — models can echo secrets or emit PII.
    for choice in result.get("choices", []):
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            d = evaluate(content, POLICY)
            if d.action in ("redact", "block"):
                msg["content"] = d.text if d.action == "redact" else "[BLOCKED BY FIREWALL]"
                choice["message"] = msg
                result.setdefault("guardrail", {})["outbound_action"] = d.action

    result.setdefault("guardrail", {})["inbound_action"] = inbound["action"]
    result["guardrail"]["findings"] = inbound["findings"]
    return result
