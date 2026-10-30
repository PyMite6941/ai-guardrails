---
layout: default
title: Model Providers
permalink: /model-providers.html
---

# Model Providers

AI Guardrails supports local and cloud LLM providers. The system is **hardware-agnostic** — it auto-detects your machine and adapts, but you can override any setting via environment variables.

## Available providers

| Provider | Type | Default model | API key required |
|----------|------|---------------|------------------|
| Ollama | Local | llama3.2:3b | No |
| LM Studio | Local | local-model | No |
| TextGen WebUI | Local | local-model | No |
| Custom OpenAI-compatible | Custom | custom-model | Optional |
| Nebius Token Factory | Cloud | Meta-Llama-3.1-70B-Instruct | Yes |
| Nemus Cloud (NVIDIA) | Cloud | nemotron-3.5-super-vl-120b-a12b | Yes |
| NVIDIA NIM | Cloud | meta/llama-3.1-70b-instruct | Yes |
| OpenRouter | Cloud | llama-3.1-70b-instruct:free | Yes |
| Groq | Cloud | llama-3.1-70b-versatile | Yes |
| OpenAI | Cloud | gpt-4o-mini | Yes |

## Configuring API keys

API keys are stored in `.env` (git-ignored, never committed):

```bash
GUARDRAIL_NEMUS_API_KEY=your_nemus_key
GUARDRAIL_NVIDIA_API_KEY=your_nim_key
GUARDRAIL_OPENROUTER_API_KEY=your_openrouter_key
GUARDRAIL_GROQ_API_KEY=your_groq_key
GUARDRAIL_OPENAI_API_KEY=your_openai_key
```

Keys already set in the environment take precedence over `.env` values.

## Custom domain provider

Point the guardrails at a domain you own:

```bash
GUARDRAIL_CUSTOM_DOMAIN_BASE_URL=https://api.yourdomain.com/v1/
GUARDRAIL_CUSTOM_DOMAIN_MODEL=your-model-name
GUARDRAIL_CUSTOM_DOMAIN_ENDPOINT=chat/completions
GUARDRAIL_CUSTOM_DOMAIN_API_KEY=your_api_key_here
```

The domain is validated before use:
- RFC 1123 format check
- DNS resolution (must resolve to a real IP)
- SSRF protection (private/internal addresses rejected)
- SSL/TLS certificate validation (issuer, expiry)

## Hardware adaptation

The system detects your hardware at startup:

```bash
python3 guardrail_hardware.py
```

This prints detected CPU count, memory, architecture, and recommended env overrides:

- **Server-class**: full parallelism, all checks, higher limits
- **Constrained** (Pi, small VM): fewer parallel checks, Rust scanner preferred, smaller models

You can override any setting:

```bash
GUARDRAIL_PARALLEL_CHECKS=4 \
GUARDRAIL_MAX_INPUT_LENGTH=8192 \
GUARDRAIL_MAX_OUTPUT_LENGTH=16384 \
python3 guardrail_server.py
```

## Provider selection via CLI

```bash
python3 guardrail_cli.py models list        # see all providers
python3 guardrail_cli.py models select      # interactive setup wizard
```

Or via the web UI: open `http://127.0.0.1:8083/chat` → click **Model** → select provider → enter API key → **Test Connection** → **Apply Model**.

## Testing connectivity

```bash
# Test a model endpoint before accepting it
curl -X POST http://127.0.0.1:18083/api/models/test \
  -H "Content-Type: application/json" \
  -d '{"base_url":"https://api.nemus.cloud/v1/"}'
```

## Nebius Token Factory (NVIDIA Nemotron)

Get a free API key at https://dev.nebius.com/builders (includes $25 credit).

Models available include:
- `meta-llama/Meta-Llama-3.1-70B-Instruct`
- `meta-llama/Meta-Llama-3.1-405B-Instruct`
- `deepseek-ai/DeepSeek-R1-0528`
- `Qwen/Qwen3-235B-A22B`

Configure:

```bash
GUARDRAIL_OUTSIDE_MODEL_ENABLED=1
GUARDRAIL_OUTSIDE_MODEL_BASE_URL=https://api.tokenfactory.nebius.com/v1/
GUARDRAIL_OUTSIDE_MODEL_MODEL=meta-llama/Meta-Llama-3.1-70B-Instruct
GUARDRAIL_OUTSIDE_MODEL_ENDPOINT=chat/completions
GUARDRAIL_OUTSIDE_MODEL_API_KEY=<your key>
```

## NVIDIA NIM

Get an API key at https://build.nvidia.com/.

Configure:

```bash
GUARDRAIL_NVIDIA_API_KEY=<your key>
GUARDRAIL_NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1/
GUARDRAIL_NVIDIA_MODEL=meta/llama-3.1-70b-instruct
```
