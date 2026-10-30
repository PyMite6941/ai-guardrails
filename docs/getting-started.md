---
layout: default
title: Getting Started
permalink: /getting-started.html
---

# Getting Started

Install and run AI Guardrails on any machine — from a Raspberry Pi to a server-class workstation. The system is hardware-aware: it detects your CPU, memory, and architecture at startup and adapts its settings accordingly.

## 1. Install

```bash
git clone https://github.com/pymite6941/ai-guardrails.git
cd ai-guardrails
```

Optional: build the memory-safe Rust pattern scanner for faster hot-path matching:

```bash
./scripts/install.sh
```

If the Rust build fails, the Python fallback scanner is used automatically.

## 2. Run

**Plain Python (stdlib only):**

```bash
GUARDRAIL_ADMIN_PASSWORD='<your strong password>' python3 guardrail_server.py
```

This starts the API server on `http://127.0.0.1:8083/`.

**Or use the scripts:**

```bash
./scripts/run.sh       # start API server in background
./scripts/stop.sh      # stop the server
```

## 3. Access

| Interface | URL | Purpose |
|-----------|-----|---------|
| **Console** | `http://127.0.0.1:8083/` | Policy editor, stats, test bench, emergency override |
| **Agentic chat** | `http://127.0.0.1:8083/chat` | ChatGPT-style interface with agentic tools |

Log in with the password you set via `GUARDRAIL_ADMIN_PASSWORD`.

## 4. Hardware adaptation

The system detects your hardware at startup:

- **Server-class** (many CPUs, high RAM): full parallelism, all checks enabled, verbose logging
- **Constrained** (Raspberry Pi, small VM): fewer parallel checks, Rust scanner preferred, smaller models, lower limits

You can override hardware detection:

```bash
python3 guardrail_hardware.py   # see detected profile and recommended env vars
```

Example for a server-class machine:

```bash
GUARDRAIL_PARALLEL_CHECKS=4 \
GUARDRAIL_MAX_INPUT_LENGTH=8192 \
GUARDRAIL_MAX_OUTPUT_LENGTH=16384 \
python3 guardrail_server.py
```

## 5. Next steps

- Configure [model providers](./model-providers.html) (Nebius, NVIDIA NIM, OpenAI, Ollama, custom domain)
- Read the [security overview](./security.html) to lock down the API for production
- Deploy with [Docker](./deployment.html) or run standalone

## Tests

```bash
for t in tests/*.py; do python3 "$t" || echo "FAILED $t"; done
```

All 9 test suites pass. Run `python3 guardrail_testing.py` for the adversarial suite (catch rate + false-positive rate).
