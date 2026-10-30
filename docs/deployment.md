---
layout: default
title: Deployment
permalink: /deployment.html
---

# Deployment

AI Guardrails is hardware-agnostic — it runs on anything from a Raspberry Pi to server-class hardware. The system auto-detects your hardware at startup and adapts its settings accordingly.

## Hardware detection

```bash
python3 guardrail_hardware.py
```

This detects CPU count, memory, architecture, and container/virtualization status, then prints recommended environment overrides.

## Plain Python (any machine)

```bash
GUARDRAIL_ADMIN_PASSWORD='<strong password>' python3 guardrail_server.py
```

The server binds to `127.0.0.1:8083` by default. To bind to all interfaces:

```bash
GUARDRAIL_HOST=0.0.0.0 GUARDRAIL_ADMIN_PASSWORD='<strong password>' python3 guardrail_server.py
```

## Docker

```bash
docker compose -f docker/docker-compose.yml up -d
```

The compose stack includes:
- **guardrails** — the API server on port 8083
- **inner-model** — local model server on port 8000
- **outside-model** — outer monitor model on port 8001

Access the web UI at `http://localhost:8083/`.

### Docker environment variables

```yaml
environment:
  - GUARDRAIL_ADMIN_PASSWORD=<strong password>
  - GUARDRAIL_HOST=0.0.0.0
  - GUARDRAIL_PORT=8083
  - OUTSIDE_MODEL_ENABLED=1
  - OUTSIDE_MODEL_BASE_URL=http://outside-model:8000
  - OUTSIDE_MODEL_MODEL=container-model
```

## Standalone binary

A 9.4 MB ARM aarch64 PyInstaller binary is available:

```bash
./dist/ai-guardrails-server
```

Set environment variables before running:

```bash
GUARDRAIL_ADMIN_PASSWORD='<strong password>' ./dist/ai-guardrails-server
```

## Raspberry Pi (ARM aarch64)

The standalone binary is built for ARM aarch64 and works on Raspberry Pi out of the box:

```bash
GUARDRAIL_ADMIN_PASSWORD='<strong password>' ./dist/ai-guardrails-server
```

For constrained devices, consider:

```bash
GUARDRAIL_PARALLEL_CHECKS=2 \
GUARDRAIL_PREFER_RUST_SCANNER=1 \
GUARDRAIL_MAX_INPUT_LENGTH=4096 \
GUARDRAIL_MAX_OUTPUT_LENGTH=8192 \
./dist/ai-guardrails-server
```

## Production hardening

1. **Set a strong password:**
   ```bash
   GUARDRAIL_ADMIN_PASSWORD='<32+ char random password>'
   ```

2. **Restrict to localhost (if behind a reverse proxy):**
   ```bash
   GUARDRAIL_HOST=127.0.0.1
   ```

3. **Enable SSRF protection:**
   ```bash
   GUARDRAIL_SSRF_PROTECTION=1
   ```

4. **Set allowed hosts:**
   ```bash
   GUARDRAIL_ALLOWED_HOSTS=your-domain.com,127.0.0.1
   ```

5. **Configure CORS:**
   ```bash
   GUARDRAIL_ALLOWED_ORIGINS=https://your-dashboard.example.com
   ```

6. **Set rate limits:**
   ```bash
   GUARDRAIL_RATE_LIMIT=60
   GUARDRAIL_MAX_BODY_SIZE=1048576
   ```

7. **Enable IP allowlist:**
   ```bash
   GUARDRAIL_ALLOWED_IPS=10.0.0.0/8,192.168.1.0/24
   ```

8. **Never commit `.env`** — it contains API keys and is git-ignored.

## Cron jobs (scheduled maintenance)

Install via `./scripts/cron/setup_cron.sh install`:

| Job | Schedule | Purpose |
|-----|----------|---------|
| canary_probe.sh | Every 5 min | Sends synthetic tests to verify the gate is still firing |
| integrity_check.sh | Every 15 min | Re-hashes watched files; alerts on tampering |
| update_check.sh | Daily 02:00 | Checks for security updates |
| session_cleanup.sh | Every hour | Cleans expired sessions |
| log_rotate.sh | Daily 03:00 | Rotates log files |

## Hardware adaptation

The system adapts to your hardware automatically:

| Hardware | Adaptation |
|----------|------------|
| Server-class | Full parallelism, all checks, verbose logging |
| Raspberry Pi / constrained | Fewer parallel checks, Rust scanner, smaller models, lower limits |
| Container | cgroup-aware limits, no host assumptions |

Override via environment variables:

```bash
# Full server
GUARDRAIL_PARALLEL_CHECKS=8 \
GUARDRAIL_MAX_INPUT_LENGTH=16384 \
GUARDRAIL_MAX_OUTPUT_LENGTH=32768 \
python3 guardrail_server.py

# Constrained device
GUARDRAIL_PARALLEL_CHECKS=2 \
GUARDRAIL_PREFER_RUST_SCANNER=1 \
GUARDRAIL_MAX_INPUT_LENGTH=4096 \
GUARDRAIL_MAX_OUTPUT_LENGTH=8192 \
python3 guardrail_server.py
```

## Environment variable reference

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDRAIL_HOST` | `127.0.0.1` | Bind host |
| `GUARDRAIL_PORT` | `8083` | HTTP port |
| `GUARDRAIL_ADMIN_PASSWORD` | — | Admin login password |
| `GUARDRAIL_API_KEY` | — | Admin API key |
| `GUARDRAIL_VIEW_KEY` | — | View API key |
| `GUARDRAIL_ALLOWED_IPS` | — | Comma-separated CIDR list |
| `GUARDRAIL_ALLOWED_ORIGINS` | — | Comma-separated CORS origins |
| `GUARDRAIL_ALLOWED_HOSTS` | — | Comma-separated host allowlist |
| `GUARDRAIL_RATE_LIMIT` | `60` | Requests per minute |
| `GUARDRAIL_MAX_BODY_SIZE` | `1048576` | Max request body bytes |
| `GUARDRAIL_SESSION_TTL` | `3600` | Session lifetime seconds |
| `GUARDRAIL_SESSION_BIND_IP` | `true` | Bind sessions to IP |
| `GUARDRAIL_SSRF_PROTECTION` | `0` | Block private/internal model URLs |
| `GUARDRAIL_PARALLEL_CHECKS` | — | Auto-detected from CPU |
| `GUARDRAIL_MAX_INPUT_LENGTH` | `4096` | Max input characters |
| `GUARDRAIL_MAX_OUTPUT_LENGTH` | `8192` | Max output characters |
| `GUARDRAIL_PREFER_RUST_SCANNER` | — | Use Rust Aho-Corasick scanner |
