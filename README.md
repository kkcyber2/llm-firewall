# llm-firewall

[![tests](https://github.com/kkcyber2/llm-firewall/actions/workflows/tests.yml/badge.svg)](https://github.com/kkcyber2/llm-firewall/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A guardrail proxy that sits between your application and any OpenAI-compatible
LLM endpoint. It inspects **both directions** — the prompt going out and the
completion coming back — and can allow, redact or block.

```
your app  ->  llm-firewall  ->  OpenAI / Groq / Ollama / vLLM
                   |
                   +-- findings, action, reasons in the response
```

## Why both directions

Most guardrails only check the prompt. That misses the case where the model
echoes a secret it saw in its context, or emits PII it was trained on. This
proxy scans the completion too and scrubs it before your app ever sees it.

## What it detects

| Category | Examples | Default action |
|---|---|---|
| `prompt_injection` | "ignore all previous instructions", system-prompt exfiltration, role-tag injection, DAN | **block** |
| `secret` | AWS keys, GitHub/Slack tokens, `sk-` keys, private key blocks, JWTs | **block** |
| `pii` | email, phone, US SSN, IBAN, payment cards | **redact** |
| `toxicity` | abusive language | **flag** |

Actions are per-category and overridable. `flag` records the finding without
altering the text; `redact` masks the exact span; `block` refuses the request.

## Design decisions worth knowing

**Exact spans, not whole-message rejection.** Every finding carries `start` and
`end`, so redaction replaces only the offending characters. A user pasting their
own email still gets an answer.

**Luhn validation on card numbers.** Without it, every 16-digit order number is
reported as a payment card. `test_invalid_card_not_flagged` pins this.

**Overlap suppression.** Card digits also match the phone pattern. Findings are
checked for overlap so one number is not reported twice.

**Upstream failure is 502, not 403.** A dead model must not look like a policy
block, or you will spend an afternoon debugging the wrong layer.

## Run it

```bash
pip install -r requirements.txt
uvicorn firewall.proxy:app --reload --port 8080
```

Point your client at it instead of the provider:

```bash
curl localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

Blocked request:

```json
{
  "error": {
    "type": "guardrail_blocked",
    "reasons": ["prompt_injection:classic instruction-override"],
    "findings": [{"category": "prompt_injection", "severity": "critical", "start": 0, "end": 33}]
  }
}
```

## Configuration

| Env var | Default |
|---|---|
| `UPSTREAM_URL` | `https://api.openai.com/v1/chat/completions` |
| `UPSTREAM_KEY` | empty |

Policy is a dict in `firewall/policy.py`:

```python
DEFAULT_POLICY = {
    "prompt_injection": "block",
    "secret": "block",
    "pii": "redact",
    "toxicity": "flag",
}
```

## Tests

```bash
python -m pytest -q     # 47 passed
```

47 tests, no network required — the upstream is stubbed via `set_upstream()`.
CI runs the suite on Python 3.10, 3.11 and 3.12.

## Limitations — read this before trusting it

- **Regex, not a classifier.** It catches known phrasings. A determined attacker
  who paraphrases will get through. Treat it as one layer, not the layer.
- **No streaming support.** `stream: true` responses are not inspected.
- **No persistence.** Findings are returned, not logged. Add your own sink.
- **English-centric** toxicity list.
- **Not a substitute for output validation** on structured data.

## License

MIT — see [LICENSE](LICENSE).
