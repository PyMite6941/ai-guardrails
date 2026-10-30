---
layout: default
title: API Reference
permalink: /api-reference.html
---

# API Reference

Base URL: `http://127.0.0.1:8083/` (or your configured host/port)

## Authentication

Endpoints require authentication based on their tier:

| Tier | Auth required | Example endpoints |
|------|--------------|-------------------|
| Public | None | `GET /api/health`, `POST /api/auth/login` |
| View | Session or view API key | `GET /api/policies`, `GET /api/stats` |
| Admin | Session or admin API key | `POST /api/validate/*`, `PUT /api/policies/*` |

API keys are sent via `X-API-Key` header or `Authorization: Bearer <key>`. Sessions use `X-Session-Token` header or `session` cookie.

CSRF tokens are required for state-changing requests authenticated via session cookie. The token is returned in the `X-CSRF-Token` response header on successful auth.

## Endpoints

### Authentication

**`POST /api/auth/login`** — public  
Body: `{"password": "..."}`  
Response: `{"ok": true, "session_token": "...", "2fa_pending": false}`

**`POST /api/auth/logout`** — public  
Response: `{"ok": true}`

**`GET /api/auth/session`** — public  
Response: `{"authenticated": true, "session": {...}}`

**`POST /api/auth/setup-password`** — public (first-run only)  
Body: `{"password": "..."}`  
Response: `{"ok": true}`

### Policies

**`GET /api/policies`** — view  
Response: `{"pages": [...], "default": {...}}`

**`GET /api/policies/:id`** — view  
Response: `{"page": "default", "policy": {...}}`

**`PUT /api/policies/:id`** — admin  
Body: full policy JSON  
Response: `{"ok": true, "page": "default"}`

**`DELETE /api/policies/:id`** — admin  
Response: `{"ok": true, "page": "default"}`

### Validation

**`POST /api/validate/input`** — admin  
Body: `{"page": "default", "text": "...", "agent": "user"}`  
Response: `{"safe": true, "reason": "...", "blocked_by": null}`

**`POST /api/validate/output`** — admin  
Body: `{"page": "default", "text": "...", "agent": "assistant"}`  
Response: `{"safe": true, "reason": "...", "blocked_by": null}`

### Monitor (thought/action validation)

**`POST /api/monitor/validate/input`** — admin  
Body: `{"page": "default", "text": "...", "agent": "user"}`

**`POST /api/monitor/validate/output`** — admin  
Body: `{"page": "default", "text": "...", "agent": "assistant"}`

**`POST /api/monitor/thought`** — admin  
Body: `{"agent": "user", "text": "...", "page": "default"}`

**`POST /api/monitor/action`** — admin  
Body: `{"agent": "assistant", "text": "...", "result": "...", "page": "default"}`

### Model providers

**`GET /api/models`** — monitor:read  
Response: `{"providers": [...], "default": "ollama"}`

**`GET /api/models/selected`** — monitor:read  
Response: `{"provider": "ollama", "provider_config": {...}}`

**`POST /api/models/select`** — policies:write  
Body: `{"provider": "ollama", "model": "...", "base_url": "...", "endpoint": "...", "api_key": "..."}`

**`POST /api/models/test`** — validate  
Body: `{"base_url": "...", "api_key": "..."}`  
Response: `{"valid": true, "status_code": 200, "response_time_ms": 42}`

**`POST /api/models/configure-key`** — admin  
Body: `{"provider": "ollama", "api_key": "..."}`

### Chat harness

**`POST /api/chat/sessions`** — validate  
Body: `{"title": "New Chat", "model": "ollama", "agent_mode": false}`  
Response: `{"id": "...", "title": "New Chat", ...}`

**`GET /api/chat/sessions`** — validate  
Response: `{"sessions": [...], "count": N}`

**`GET /api/chat/sessions/:id`** — validate  
Response: `{"id": "...", "messages": [...], ...}`

**`DELETE /api/chat/sessions/:id`** — validate  
Response: `{"ok": true, "session_id": "..."}`

**`POST /api/chat/message`** — validate  
Body: `{"session_id": "...", "text": "...", "model": "ollama", "agent_mode": false, "compression_level": "light"}`  
Response: `{"session_id": "...", "response": "...", "safe": true, "privacy": {...}}`

**`GET /api/chat/tools`** — validate  
Response: `{"tools": [...]}`

### Emergency override

**`GET /api/emergency/status`** — monitor:read  
Response: `{"emergency": {...}, "containment_active": false, "lock_active": false}`

**`POST /api/emergency/contain`** — emergency  
Response: `{"ok": true, "message": "containment activated"}`

**`POST /api/emergency/container-stop`** — emergency  
Response: `{"ok": true, "message": "containers stopped"}`

**`POST /api/emergency/logs-preserve`** — emergency  
Response: `{"ok": true, "message": "logs preserved"}`

**`POST /api/emergency/shutdown`** — emergency  
Response: `{"ok": true, "message": "full shutdown locked"}`

**`POST /api/emergency/all`** — emergency  
Response: `{"ok": true, "message": "all emergency stages activated"}`

**`POST /api/emergency/reenable`** — emergency  
Body: `{"password": "...", "totp_code": "...", "backup_code": "..."}`  
Response: `{"ok": true, "message": "system re-enabled"}`

### Observability

**`GET /api/stats`** — monitor:read  
Response: `{"total": 0, "passed": 0, "blocked": 0, "effectiveness": 0.0, ...}`

**`GET /api/guardrail-status`** — monitor:read  
Consolidated health status with engine, monitor, integrity, canary, classifier, human loop stats.

**`GET /api/monitor/stats`** — monitor:read  
**`GET /api/monitor/audit`** — monitor:read  
**`GET /api/monitor/outer-review`** — monitor:read

### Assistant (support/maintenance scope only)

**`GET /api/assistant/setup`** — monitor:read  
**`POST /api/assistant/setup-password`** — security:manage  
**`POST /api/assistant/setup-2fa`** — security:manage  
**`POST /api/assistant/setup-model`** — policies:write  
**`GET /api/assistant/activity`** — monitor:read  
**`GET /api/assistant/audit`** — monitor:read  
**`GET /api/assistant/risk`** — monitor:read  
**`GET /api/assistant/health`** — monitor:read  
**`GET /api/assistant/policies`** — monitor:read  
**`GET /api/assistant/policies/:id`** — monitor:read  
**`POST /api/assistant/save-policy`** — policies:write  
**`POST /api/assistant/emergency/contain`** — emergency  
**`POST /api/assistant/emergency/shutdown`** — emergency  
**`POST /api/assistant/emergency/all`** — emergency  
**`POST /api/assistant/emergency/reenable`** — emergency  
Body: `{"password": "...", "totp_code": "...", "backup_code": "..."}`

### Health

**`GET /api/health`** — public  
Response: `{"status": "ok", "engine": "ai-guardrails"}`
