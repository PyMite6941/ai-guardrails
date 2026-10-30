---
layout: default
title: Architecture
permalink: /architecture.html
---

# Architecture

AI Guardrails sits between an application and its model and decides, per request, whether text may pass. The decision is made by **deterministic code**. A model may add a block; it can never remove one.

## Decision path

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

### Decision path

| Module | Purpose |
|--------|---------|
| `guardrail.py` | The engine. Loads per-page policies, runs checks in order, returns verdict |
| `guardrail_prompt_injection.py` | Jailbreak detection with obfuscation decoding |
| `guardrail_leakage.py` | Information leakage / data exfiltration prevention |
| `guardrail_classifier.py` | Optional LLM second opinion (fail-open on error) |
| `guardrail_rust_scanner.py` | Memory-safe Aho-Corasick pattern matcher |

### Oversight

| Module | Purpose |
|--------|---------|
| `outer_monitor.py` | Watches agent thoughts and actions before they execute |
| `guardrail_risk.py` | Conversation-level composite risk scoring (0.0–1.0) |
| `guardrail_step_monitor.py` | Per-reasoning-step monitor with interrupt |
| `guardrail_canary.py` | Synthetic probes; alerts when the gate stops firing |
| `guardrail_integrity.py` | HMAC + hash-chained ledger for tamper detection |
| `guardrail_modes.py` | TRAINING / TESTING / RUNNING modes |

### Privacy & cost

| Module | Purpose |
|--------|---------|
| `guardrail_secret_stripper.py` | Removes keys, tokens, PII before text goes to models/logs/users |
| `guardrail_token_compressor.py` | Compression before paid inference |

### Access control

| Module | Purpose |
|--------|---------|
| `guardrail_auth.py` | Sessions, rate limiting, CSRF, host allowlist, SSRF guard, route policy |
| `guardrail_users.py` | Accounts, PBKDF2 hashes, TOTP, API keys, roles |
| `guardrail_models.py` | Provider registry, key resolution, `.env` loading |

### Surfaces

| Module | Purpose |
|--------|---------|
| `guardrail_server.py` | stdlib HTTP server: routes, static pages, auth gate |
| `web/index.html` | Console (single self-contained file) |
| `web/chat.html` + `chat.js` | Agentic chat harness |
| `guardrail_assistant.py` | Support/maintenance assistant (restricted scope) |
| `harness/` | Red-team probe, Nemotron benchmark, Nebius preflight |

## Where state lives

| What | Path |
|------|------|
| Users, password hashes, TOTP secrets, backup codes | `~/.ai_guardrails_users.json` (0600) |
| API keys (hashes only) | `~/.ai_guardrails_keys.json` |
| Legacy single-admin password hash | `~/.ai_guardrails_auth.json` |
| Runtime toggles | `~/.ai_guardrails_config.json` |
| Per-page policies | `policies/pages/<page>.json` |
| Audit / auth / monitor logs | `logs/*.jsonl` |
| Model provider keys | `.env` (git-ignored, 0600) |

Sessions live in server memory; a restart signs everyone out.

## Why the model cannot weaken a decision

The engine returns before the classifier is consulted. If the engine says **BLOCK**, the classifier is never called. If the engine says **ALLOW**, the classifier can only turn that into **BLOCK**. A compromised, prompt-injected, or offline model therefore degrades to "rules only" — never to "no rules".

## Known failure modes (deliberate)

- **Classifier unreachable** → fail open, `classifier.errors` increments, deterministic verdict stands
- **Empty `GUARDRAIL_ALLOWED_HOSTS`** → loopback only; tunnel/LAN hostnames must be listed
- **No CA bundle in interpreter** → HTTPS to provider fails; server falls back to `/etc/ssl/cert.pem`
- **A pass is not a guarantee** — it means no enabled rule matched, not that the input is safe
