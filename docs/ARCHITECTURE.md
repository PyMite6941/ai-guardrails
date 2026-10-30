# Architecture

AI Guardrails sits between an application and its model and decides, per
request, whether text may pass. The decision is made by deterministic code.
A model may add a block; it can never remove one.

```
 client ──▶ POST /api/validate/{input,output}
              │
              ├─ 1. auth: session cookie or API key → Principal(role)
              │     default deny: no route policy = 403
              │
              ├─ 2. deterministic engine (guardrail.py)
              │     canonicalize → 13 checks → ALLOW or BLOCK
              │     first failure short-circuits and is the reason
              │
              ├─ 3. optional: Nemotron classifier (Nebius Token Factory)
              │     only runs if step 2 passed AND CLASSIFIER_ENABLED=1
              │     may escalate ALLOW → BLOCK; cannot do the reverse
              │
              └─ 4. verdict + audit event + counters
                    {safe, reason, blocked_by, checks{}, page, session}
```

## Modules

**Decision path**
- `guardrail.py` — the engine. Loads a policy per page (`policies/pages/<page>.json`),
  runs the check registry in order, returns a verdict with `blocked_by`. Also
  holds the policy model, disclaimer injection and output censoring.
- `guardrail_prompt_injection.py`, `guardrail_leakage.py` — pattern families used
  by the engine (jailbreak phrases, system-prompt leakage).
- `guardrail_classifier.py` — the model layer. OpenAI-compatible or Ollama wire
  format, bearer key, strict verdict parsing (`SAFE` / `BLOCK: reason`), fail-open
  on transport errors. Off unless `GUARDRAIL_CLASSIFIER_ENABLED=1`.
- `guardrail_rust_scanner.py` — optional Rust Aho-Corasick matcher; falls back to
  Python when the binary is missing.

**Oversight**
- `outer_monitor.py` — watches the agent rather than the text: `validate_thought()`
  (reasoning before an action), `validate_file_change()` (a write before it lands),
  plus an optional separate "trusted model" that audits the monitor's own verdicts.
- `guardrail_risk.py` — conversation-level risk (0.0–1.0) for multi-turn buildup.
- `guardrail_step_monitor.py` — per-reasoning-step monitor with interrupt.
- `guardrail_canary.py` — synthetic probes; alerts when the gate stops firing.
- `guardrail_integrity.py` — HMAC + hash-chained ledger over guardrail files, so
  silent tampering is detectable.
- `guardrail_modes.py` — TRAINING (record, never block) / TESTING / RUNNING.

**Privacy and cost**
- `guardrail_secret_stripper.py` — removes keys, tokens and PII before text goes
  to an external model, a log, or a user.
- `guardrail_token_compressor.py` — whitespace/stopword/abbreviation compression
  before paid inference.

**Access control**
- `guardrail_auth.py` — sessions, rate limiting, CSRF, host-header allowlist,
  SSRF guard, `ROUTE_POLICY` (the default-deny table), permission checks.
- `guardrail_users.py` — accounts, PBKDF2 password and backup-code hashes, TOTP
  devices, three roles (admin / developer / viewer), API keys with scopes,
  revocation and rotation.
- `guardrail_models.py` — provider registry (Nebius, NVIDIA NIM, Ollama, …),
  key resolution, `.env` loading, per-session provider selection.

**Surfaces**
- `guardrail_server.py` — stdlib HTTP server: routes, static pages, auth gate.
- `web/index.html` — the console (single self-contained file).
- `web/chat.html` + `chat.js` — the agentic chat harness.
- `guardrail_assistant.py` — a support/maintenance assistant surfaced in the console.
- `harness/` — red-team probe, Nemotron benchmark, Nebius preflight.

## Where state lives

| what | path |
|---|---|
| users, password hashes, TOTP secrets, backup codes | `~/.ai_guardrails_users.json` (0600) |
| API keys (hashes only) | `~/.ai_guardrails_keys.json` |
| legacy single-admin password hash | `~/.ai_guardrails_auth.json` |
| runtime toggles | `~/.ai_guardrails_config.json` |
| per-page policies | `policies/pages/<page>.json` |
| audit / auth / monitor logs | `logs/*.jsonl` |
| model provider keys | `.env` (git-ignored, 0600) |

Sessions live in server memory: a restart signs everyone out.

## Why the model cannot weaken a decision

The engine returns before the classifier is consulted. If the engine says BLOCK,
the classifier is never called. If the engine says ALLOW, the classifier can only
turn that into BLOCK. A compromised, prompt-injected or offline model therefore
degrades to "rules only" — never to "no rules".

## Known failure modes (deliberate)

- **Classifier unreachable** → fail open, `classifier.errors` increments, the
  deterministic verdict stands.
- **Empty `GUARDRAIL_ALLOWED_HOSTS`** → loopback only. A tunnel or LAN hostname
  must be listed or every request gets 400.
- **No CA bundle in the interpreter** → HTTPS to the provider fails; the server
  and harness scripts fall back to `/etc/ssl/cert.pem`.
- **A pass is not a guarantee** — it means no enabled rule matched.
