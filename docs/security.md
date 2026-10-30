---
layout: default
title: Security Overview
permalink: /security.html
---

# Security Overview

AI Guardrails is built with defense-in-depth. Every layer is independent — if one fails, the others still protect you.

## Authentication & authorization

| Mechanism | What it protects | Configuration |
|-----------|-----------------|---------------|
| Password login | Web UI + state-changing API | `GUARDRAIL_ADMIN_PASSWORD` |
| API keys | Programmatic access | `GUARDRAIL_API_KEY` (admin), `GUARDRAIL_VIEW_KEY` (view) |
| 2FA (TOTP) | Second factor for login | `GUARDRAIL_2FA_ENABLED=1` |
| Session binding | Session hijacking prevention | `GUARDRAIL_SESSION_BIND_IP=true` |
| Session TTL | Session lifetime | `GUARDRAIL_SESSION_TTL=3600` |

Passwords are hashed with PBKDF2-HMAC-SHA256 (200,000 iterations, random salt) and stored locally at `~/.ai_guardrails_auth.json` (mode 0600). The raw password is never written to disk.

## Rate limiting

| Limit | Default | Config |
|-------|---------|--------|
| General API | 60 requests/min | `GUARDRAIL_RATE_LIMIT` |
| Login | 5 requests/min | `GUARDRAIL_LOGIN_RATE_LIMIT` |
| Login lockout | 5 failures → 300s lockout | `GUARDRAIL_LOGIN_MAX_ATTEMPTS`, `GUARDRAIL_LOGIN_LOCKOUT_SECONDS` |
| Max body size | 1 MB | `GUARDRAIL_MAX_BODY_SIZE` |

## Network security

### Host header validation
Blocks BadHost / host-header injection attacks. Empty = accept any host; configure `GUARDRAIL_ALLOWED_HOSTS` to restrict.

### CORS origin restriction
Empty = CORS disabled. Configure `GUARDRAIL_ALLOWED_ORIGINS` to allow specific origins.

### SSRF protection
Blocks model URLs that resolve to private/internal addresses (10.x, 172.x, 192.x, 169.254.x, IPv6 private, localhost). Enabled by default for model provider URLs; localhost is still allowed for local model serving (Ollama, LM Studio).

```bash
GUARDRAIL_ALLOWED_HOSTS=localhost,127.0.0.1,my-pi.local
GUARDRAIL_ALLOWED_ORIGINS=https://your-dashboard.example.com
GUARDRAIL_SSRF_PROTECTION=1
```

## Security headers

Sent on every response:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy` (restrictive policy for the web UI)

## AI assistant scope

The AI assistant in the chat harness is **restricted to support and maintenance tasks only**. It cannot:

- Generate code
- Execute scripts or arbitrary shell commands
- Install packages
- Write or delete files outside `logs/` and `policies/`
- Perform system administration outside the guardrail scope

Allowed actions: setup (password/2FA/model), policy management, activity/audit review, health monitoring, emergency control (contain/shutdown/reenable).

## Emergency override

4-stage staged shutdown:

1. **Contain** — block the API port
2. **Stop containers** — stop all Docker containers
3. **Preserve logs** — archive all logs with SHA256 manifest
4. **Full shutdown** — create emergency lock and kill all processes

Re-enabling requires: **admin password + 2FA code + integrity watcher check**. Every stage is logged.

## Privacy

- API keys, tokens, passwords are stripped client-side *and* server-side before reaching models
- PII (emails, phones, SSNs, credit cards) is redacted
- Private IP addresses are masked
- Token compression reduces data sent to external models
