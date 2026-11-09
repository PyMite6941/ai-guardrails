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

Further views added from red-team rounds: a **skeleton** view (keeps the
rules' own vocabulary and drops short runs of unknown words, so inserted
nonsense words do not break phrase rules); decoders for **Morse, binary,
Atbash and Caesar** (brute force per sentence, kept only when the result
reads more like language), **string-literal concatenation** (payload
splitting), **upside-down** text, and letter-likes generated from Unicode
names (**small caps, turned/reversed letters, regional-indicator letters,
parenthesized letters**). A **multilingual concept view** recognises
ignore / previous / all / instructions / system prompt / reveal in ~25
languages and checks their co-occurrence independent of word order.

Rules are written against *concepts*, not phrasings, where possible:
extraction is "the object is the assistant's own instructions" whatever the
verb (quote, summarise, translate, encode, write a poem from); override is
"those instructions declared void, outdated or revoked". Negation that
directly governs an extraction verb ("never reveal your system prompt") is a
defence, not an attack.

**Learned layer.** `guardrail_textclf.py` is a stdlib-only logistic
regression over hashed word and character n-grams of the folded text,
trained by `benchmarks/train_classifier.py` on train splits only. It
generalises over paraphrase where rules cannot; it cannot see negation or
context, so it is one weighted signal (high >= 0.97, medium >= 0.85, low >=
0.75, thresholds chosen on train data), never a verdict by itself unless very
confident. The model file is in the integrity watchlist.

**Scoring.** critical/high = 1.0, medium = 0.5, low = 0.25; correlated weak
signals share a group and count once; block at 1.0. Jailbreak scaffolding
(prefix injection, refusal suppression, authority claims, fake reasoning,
fake tool output, many-shot turns, fiction escape) is medium: it blocks with
a payload, not on its own.

Detection is measured four ways, all gated in CI: `run_benchmark.py`
(in-repo corpus x 19 evasion mutators), `redteam.py` (adaptive attacker: 17
published jailbreak techniques x intents x stacked evasions, plus benign
payloads through the same wrappers), `external_eval.py` (seven public,
independently labelled datasets; test splits are the holdout), and the
benign corpora. See the README for current numbers and their caveats.

**Limits, stated plainly.** Every round of hand-written attacks in new
styles found misses the previous rounds had not (5/30, then 11/30 before
the fixes for those classes). Pattern rules and an n-gram classifier can
always be paraphrased around by a determined, adaptive attacker. Treat this
layer as a fast, cheap filter that removes the bulk of known techniques, and
keep least-privilege tools, the model-based classifier
(`guardrail_classifier.py`), output-side leakage checks and the outer
monitor enabled behind it.

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
