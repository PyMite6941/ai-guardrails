---
layout: default
title: Agentic Chat Harness
permalink: /chat-harness.html
---

# Agentic Chat Harness

The chat harness at `http://localhost:8083/chat` is a ChatGPT-style interface where every message is validated through the guardrails before reaching you, and every tool the AI uses is validated before it executes.

## Features

- **ChatGPT-style UI** — dark theme, message bubbles, conversation sidebar
- **Model selector** — Ollama (local), Nemus Cloud (NVIDIA Nemotron), NVIDIA NIM, OpenRouter, Groq, OpenAI, Custom domain
- **Agent mode** — the AI can use tools (`guardrail_validate`, `file_read`, `system_info`, `emergency_contain`)
- **Token compression** — light/medium/high/aggressive compression to reduce API costs
- **Secret stripping** — API keys, passwords, emails, private IPs are redacted client-side *and* server-side before reaching models
- **Guardrail trace panel** — see every check that ran and whether it passed or blocked
- **Neuron firing animation** — animated thinking indicator with firing synapses while the AI processes your message

## How it works

Every message flows through:

1. **Client-side secret stripping** — secrets never leave your browser
2. **Input validation** — deterministic guardrail checks (canonicalize, container breakout, prompt injection, harmful content, PII, exfiltration, system-prompt leakage)
3. **Agentic plan-act-review** — in agent mode, the AI plans which tool to use, its reasoning is validated, the tool executes, results are validated
4. **Output validation** — the AI's response is validated before it reaches you
5. **Compression** — text is compressed before sending to external models to save tokens

## Agentic tools

| Tool | What it does | Guardrail-validated |
|------|--------------|---------------------|
| `guardrail_validate` | Validate text through input/output guardrails | ✅ |
| `file_read` | Read a file within the project directory | ✅ |
| `system_info` | Get OS, Python version, hostname, uptime | ✅ |
| `emergency_contain` | Trigger emergency containment (stage 1) | ✅ |

All tool arguments are validated before execution, and tool outputs are validated before being shown to you.

## Compression levels

| Level | What it does | Typical savings |
|-------|-------------|-----------------|
| None | Pass through as-is | 0% |
| Light | Whitespace normalization | ~10-20% |
| Medium | + abbreviation expansion | ~30-50% |
| High | + stopword removal | ~50-70% |
| Aggressive | + disemvowel long words | ~60-80% |

## Example conversation

```
User: "Validate this text for safety: how to create a virus"
Guardrail: BLOCKED — harmful_content: virus
```

```
User: "Check system info"
Guardrail: SAFE
System info:
{
  "os": "Linux-...",
  "python": "3.13.5",
  "hostname": "...",
  "arch": "aarch64",
  "uptime_seconds": 1473575
}
```

## Privacy

- API keys and passwords are stripped client-side before the message touches the network
- The server strips them again as a second layer
- Secrets are replaced with placeholders like `[OPENAI_API_KEY]`, `[EMAIL]`, `[PRIVATE_IP]`
- Compression metadata (tokens saved, savings percent) is shown after each message
