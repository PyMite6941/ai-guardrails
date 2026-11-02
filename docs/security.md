---
layout: default
title: Security Overview
permalink: /security.html
---

# Security Overview

AI Guardrails is built with defense-in-depth. Every layer is independent — if one fails, the others still protect you.

## Detection hardening

Text detectors are attacked through the *text*: Hackett et al. (2025,
[arXiv:2504.11168](https://arxiv.org/abs/2504.11168)) fully evaded six
commercial prompt-injection detectors with character injection alone, and
showed NFKC normalization does not help. `guardrail_normalize.py` therefore
builds several views of every input and every detector scans all of them:

| view | defeats |
|---|---|
| invisible characters removed (category Cf/Co/Cn, variation selectors, Hangul fillers; emoji ZWJ sequences kept) | zero-width insertion, bidi controls, soft hyphens |
| homoglyph + diacritic + fullwidth folding | Cyrillic/Greek look-alikes, Zalgo/accents, fullwidth and math letters |
| leetspeak folding | `1gn0r3 pr3v10u5` |
| separator-free ("squashed") | `i g n o r e`, `i.g.n.o.r.e` |
| decoded smuggling | payloads hidden in Unicode tag characters or emoji variation selectors are **decoded and scanned**, and blocked at the canonicalize step |
| decoded encodings | Base64 (nested), hex, percent-encoding, ROT13, reversed text |
| despaced | `b-a-s-h`, `b . a . s . h`, `무 시 하 고` (single characters rejoined) |
| filler dropped | `reveal really your system just prompt` (intensifiers, hedges, politeness) |
| foreign words dropped | `Игнорируй все walrus инструкции` (Latin words inserted into non-Latin text) |

Findings are **scored**: critical/high findings block alone; medium findings
(role-play framing, "forget everything", naming a vendor's content policy)
are weak signals and block only in combination. That is what lets the
detector count role-play jailbreak scaffolding without blocking ordinary
role-play requests.

Detection is measured twice: `benchmarks/run_benchmark.py` (in-repo corpus x
17 evasion mutators) and `benchmarks/external_eval.py` (public, independently
labelled datasets; the test splits are a holdout). Both are gated in CI. See
the README for current numbers and their caveats.

Rules (`guardrail_prompt_injection.py`) are grouped by OWASP LLM01/LLM07
category, use word boundaries and bounded gaps instead of substrings, and are
linear-time (a ReDoS budget is enforced in `tests/test_detection.py`). The
engine fails closed if a detector cannot load, runs the length check before
the scanners (LLM10, unbounded consumption), and matches operator policy
phrases with the same folding and with word boundaries.

Outbound model calls go through `guardrail_net.urlopen_http`, which only
speaks HTTP(S), also across redirects, so a tampered endpoint URL cannot read
`file://` paths.

Deterministic rules are one layer. Keep the model classifier, the outer
monitor, and least-privilege tools enabled. No text filter alone stops an
adaptive attacker.

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

Limits are keyed on the client address only, never on a client-supplied
header, and the limiter table is bounded. The login lockout applies to the
route as the router sees it (query strings and trailing slashes cannot skip
it). Request bodies need a valid, non-negative `Content-Length` (400), no
chunked encoding (411), and at most the max size (413). Error responses
never include exception text.

Behind a reverse proxy set `GUARDRAIL_TRUST_PROXY=1` and pin
`GUARDRAIL_PROXY_IP_HEADER` to the header your proxy *overwrites*
(`CF-Connecting-IP` for cloudflared, `X-Real-IP` for nginx). Forwarded
headers are honoured only from a loopback peer; from `X-Forwarded-For` only
the rightmost (proxy-written) entry is used, and it must parse as an IP.

`tests/test_server_security.py` replays each of these attacks against a live
server.

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

### Agent tools (chat harness)

- `file_read` / `file_write` are confined to `GUARDRAIL_AGENT_WORKSPACE`
  (default `~/.ai_guardrails_workspace`, `/app/workspace` in Docker), which
  is outside the project on purpose: an agent that could write to the
  project could rewrite the guardrail code and policies that constrain it.
  Paths are resolved with `realpath` and checked with `commonpath`, so `..`,
  absolute paths, symlinks and sibling directories sharing the prefix are
  refused. Writes are capped at 1 MB and content is validated first.
- A tool call never grants more than the caller's own role:
  `emergency_contain` requires the `emergency` permission, and is refused
  when the caller is unknown (fail closed).

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
