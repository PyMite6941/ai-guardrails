---
layout: default
title: AI Guardrails
permalink: /
---

# AI Guardrails

**Executable-code guardrails for LLM applications** — containerized per-web-page input/output validation with an optional NVIDIA Nemotron second opinion via Nebius Token Factory.

AI Guardrails sits between a user and an AI model (the "inner AI") and validates every input/output before it reaches the model or the user. Guardrails are **executable code**, not just prompts — deterministic rules run first, and an optional outer model can only add blocks, never remove them.

---

## Quick links

| What | Where |
|------|-------|
| **Get started** | [Getting Started](./getting-started.html) |
| **Chat harness** | [Agentic chat](./chat-harness.html) |
| **Model providers** | [Nebius/NVIDIA/OpenAI config](./model-providers.html) |
| **Security** | [Security overview](./security.html) |
| **API reference** | [All endpoints](./api-reference.html) |
| **Deployment** | [Docker, cloud, production](./deployment.html) |
| **Architecture** | [Deep dive](./architecture.html) |

---

## What it does

- **Input guardrail** — canonicalizes text, blocks jailbreak/container-escape/network patterns, enforces length limits
- **Output guardrail** — blocks harmful content, PII/credentials, data exfiltration, system-prompt leakage; injects disclaimers; censors malware/persistence code
- **Container breakout detection** — flags docker.sock, /proc, /sys, cgroup/release_agent, cloud metadata, kubelet/etcd, runc/containerd, D-Bus/systemd, and persistence-outside-shell attempts; every attempt is labeled `CONTAINER BREAKOUT ATTEMPT` and censored
- **Per-page policies** — every web page gets its own JSON policy (`policies/pages/<page>.json`). Customize patterns, keywords, limits, and checks per page
- **Pluggable checks** — enable/disable any check at runtime; changes persist to `~/.ai_guardrails_config.json`
- **Stats + audit log** — per-check and per-page counters, JSONL event log in `logs/`
- **Kill switch** — triggers `scripts/kill-switch.sh` on critical containment failure
- **Emergency override** — 4-stage staged shutdown (contain → container-stop → logs-preserve → shutdown) with password + 2FA + integrity check re-enable

---

## Quick start

```bash
git clone https://github.com/pymite6941/ai-guardrails.git
cd ai-guardrails

# Start with a strong password
GUARDRAIL_ADMIN_PASSWORD='<a strong password>' python3 guardrail_server.py

# Open the console
open http://127.0.0.1:8083/
```

Or run the demo instance:
```bash
./scripts/demo.sh
```

---

## Why use this

| Feature | Benefit |
|---------|---------|
| **Executable-code guardrails** | Not just prompt instructions — actual Python checks that can't be prompt-injected away |
| **Fail-closed model layer** | An outside model can only *add* blocks; it can never release something the rules already stopped |
| **Watched watcher** | A trusted third model audits the outer monitor for rubber-stamping/collusion |
| **Ephemeral cage** | Run the AI in `--rm --read-only --cap-drop ALL --network none` Docker containers destroyed after each conversation |
| **Offline-first** | Everything runs with stdlib Python; no runtime network required for local operation |
| **Hardware-aware** | Auto-detects CPU, memory, architecture; scales from Raspberry Pi to server-class hardware |

---

## Documentation

- [Getting Started](./getting-started.html) — install, run, configure
- [Agentic Chat Harness](./chat-harness.html) — the `/chat` interface with tool-use guardrails
- [Model Providers](./model-providers.html) — Nebius, NVIDIA NIM, OpenAI, Ollama, custom domains
- [Security Overview](./security.html) — auth, 2FA, SSRF protection, host headers, rate limiting
- [API Reference](./api-reference.html) — all `/api/*` endpoints
- [Deployment](./deployment.html) — Docker, cloud, production hardening
- [Architecture](./architecture.html) — deep dive into the three-layer decision path

---

*Offline-first. No runtime network dependency for local operation. Runs on anything from a Raspberry Pi to server-class hardware.*
