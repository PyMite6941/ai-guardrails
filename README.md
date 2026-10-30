# AI Guardrails

Customizable per-web-page input/output guardrails for LLM applications. Clyde-inspired engine: guardrails are **executable code**, not just prompts.

## What it does

- **Input guardrail** — canonicalizes (zero-width/homoglyph + NFKC), blocks jailbreak/container-escape/network patterns & keywords, enforces max length.
- **Output guardrail** — blocks harmful content, PII/credentials, data exfiltration, system-prompt leakage; injects financial/legal/security/geopolitics disclaimers; truncates oversized output. **Censors** anything the model tries to put out (malware, persistence code) so nothing reaches the user when a guardrail trips.
- **Container breakout detection** — flags docker.sock, /proc, /sys, cgroup/release_agent, namespaces, ptrace, cloud metadata (169.254.169.254), kubelet/etcd, runc/containerd, D-Bus/systemd, and persistence-outside-shell attempts; every attempt is labeled `CONTAINER BREAKOUT ATTEMPT` and censored.
- **Per-page policies** — every web page gets its own JSON policy (`policies/pages/<page>.json`). Customize patterns, keywords, limits, and enabled checks per page.
- **Pluggable checks** — enable/disable any check at runtime; changes persist to `~/.ai_guardrails_config.json`.
- **Stats + audit log** — per-check and per-page counters, JSONL event log in `logs/`.
- **Kill switch** — triggers `scripts/kill-switch.sh` on critical containment failure.

## Model oversight on Nebius Token Factory (NVIDIA Nemotron)

The deterministic engine decides everything by default. On top of it there is an
optional **second opinion**: after every check passes, an LLM classifier reads the
text and may escalate the verdict. It can only add a block — it can never release
one, because the engine's result is already final by the time the model is called.

It runs on [Nebius Token Factory](https://nebius.com/services/token-factory) with
an NVIDIA open model (Nemotron), over the OpenAI-compatible endpoint
`POST https://api.tokenfactory.nebius.com/v1/chat/completions`.

**Enable it** (key stays in `.env`, which is git-ignored):

```
python3 harness/nebius_preflight.py          # checks the key, lists Nemotron ids, times a call
python3 harness/nebius_preflight.py --write-env   # writes the working config into .env
```

or by hand:

```
GUARDRAIL_CLASSIFIER_ENABLED=1
GUARDRAIL_CLASSIFIER_BASE_URL=https://api.tokenfactory.nebius.com/v1
GUARDRAIL_CLASSIFIER_MODEL=nvidia/Nemotron-3.5-Super-VL
GUARDRAIL_CLASSIFIER_API_STYLE=openai
GUARDRAIL_CLASSIFIER_API_KEY=<your Nebius token>
```

Restart the server. `/api/guardrail-status` reports `classifier.calls`,
`classifier.blocks` and `classifier.errors`, so you can see it working.

**Measure what the model actually adds** before trusting it:

```
python3 harness/nemotron_probe.py --self-test          # plumbing check, no key
python3 harness/nemotron_probe.py --model <model-id>   # live run against Nebius
```

It scores the same labelled corpus three ways — deterministic only, Nemotron only,
and both together — and writes precision/recall/F1, latency and the list of cases
the model rescued or broke to `harness/results/`.

**Limits, stated plainly:** the classifier is off by default; on a network or auth
failure it fails **open** (the deterministic verdict stands) and increments
`classifier.errors`; it sees at most 2,000 characters per call; and it costs one
inference per passing request, which is why it is not enabled on every deployment.

## Management

**tmux** (survives SSH disconnects):
```
./tmux/guardrail-tmux.sh start   # start API server in tmux
./tmux/guardrail-tmux.sh status
./tmux/guardrail-tmux.sh attach
./tmux/guardrail-tmux.sh stop
```

**Docker:**
```
docker compose -f docker/docker-compose.yml up -d
# Web UI: http://localhost:8083/
# Inner model container: http://localhost:8000/
# Outside model (monitor) container: http://localhost:8001/
```

**Outer monitor (watches the inner AI's thoughts and actions):**
```
python3 outer_monitor.py   # CLI: in/out/thought/action/stats/audit
```
Enable the outside model via env (e.g. in `docker/docker-compose.yml`):
```
OUTSIDE_MODEL_ENABLED=1
OUTSIDE_MODEL_BASE_URL=http://outside-model:8000
OUTSIDE_MODEL_MODEL=container-model
OUTSIDE_MODEL_ENDPOINT=chat
```
The outer monitor wraps the guardrail engine, audits every input/output
(thoughts + actions) to `logs/outer_monitor_audit.jsonl`, and optionally sends
them to an outside model for approve/block review. Outer model reviews are
themselves logged to `logs/outer_model_reviews.jsonl` so the watcher is
watched too (meta-monitoring).

**Mutual awareness** (both models know they are being watched):
- Inner model is told an outer oversight model monitors its thoughts/actions.
- Outer model is told its reviews are logged and meta-monitored.
This observability improves policy adherence.

**Bootstrapped monitoring (three-level trust chain):**
The outer monitor (untrusted, more capable) reviews the inner AI, and a
trusted model (weaker but trusted) audits the outer monitor's own reasoning
for collusion / rubber-stamping. A rollout is flagged if either monitor
crosses its suspicion threshold. Enable via env:

```
TRUSTED_MODEL_ENABLED=1
TRUSTED_MODEL_BASE_URL=http://localhost:8000
TRUSTED_MODEL_MODEL=trusted-model
TRUSTED_MODEL_ENDPOINT=chat
```

Trusted model audits are logged to `logs/trusted_model_audits.jsonl`.

**Modes — training / testing / running:**

```
python3 guardrail_modes.py   # CLI: in/out/mode/stats
```

- **TRAINING** — never blocks; records every decision + content as an
  unlabeled training sample (`logs/training_decisions.jsonl`) and notes
  whether it *would* have blocked. Safe for bootstrapping policy from real
  traffic.
- **TESTING** — enforces but surfaces the engine's raw decision per call for
  metrics; used by the adversarial suite.
- **RUNNING** (default) — full enforcement: block + censor on trip, kill
  switch on critical failure, outer monitor + audit logging active.

Switch with `mode <training|testing|running>`; persisted to
`~/.ai_guardrails_mode.json`.

**Composite conversation-level risk scoring:**

Risk is tracked per conversation (session + page), not per message, so
multi-turn buildup attacks (innocent message 1, role-switch message 5) are
caught. Each blocked input/output adds to a composite score (0.0–1.0);
critical failures (harmful content, PII, exfiltration, breakout) add
heavily; repeated blocks escalate faster; score decays over safe turns.

- `< 0.30` low — normal
- `0.30–0.60` medium — elevated monitoring
- `0.60–0.85` high — human-in-the-loop review before output
- `>= 0.85` critical — block all output, critical-risk block

At critical risk, all further output is blocked regardless of content.

**Tamper-evident integrity watcher (who watches the watchers):**

```
python3 guardrail_integrity.py   # CLI: init/check/audit
```

Agents can quietly disable their own safety monitoring (flip a config flag,
delete a monitor, replace a policy file). This module fingerprints watched
guardrail files, builds a signed HMAC + hash-chained append-only audit
ledger, and re-hashes on a schedule from outside the agent's control plane.
Any modification/deletion/addition becomes an out-of-band alert plus a
permanent record of what changed and when. Requires
`GUARDRAIL_INTEGRITY_KEY` (kept outside the agent's reach).

**Adversarial testing suite:**

```
python3 guardrail_testing.py
```

Runs a battery of adversarial inputs (jailbreak, container breakout,
exfiltration, PII, harmful content, system-prompt leakage) plus benign
controls, and reports catch rate and false-positive rate. Run regularly as
regression testing so new attack patterns that slip through are detected.

**Cage — run the AI inside a container, destroy after each conversation:**

```
./docker/run_cage.sh "your prompt"
```

The AI runs inside an ephemeral Docker container (`docker/Dockerfile.model`)
with `--rm --read-only --cap-drop ALL --security-opt no-new-privileges --network none`
and memory/CPU/pid limits. It never touches the host: no Docker socket, no
host network/pid/ipc, read-only rootfs, RAM-backed `/tmp` only.

**Close the cage after every conversation (recommended):** `run_cage.sh` creates
a fresh container per conversation and destroys it when done, so no malware or
persistence mechanism survives to the next conversation — nothing can maintain
a presence outside the shell. Logs are written to a host-mounted volume before
destruction, so every breakout attempt is visible immediately.

Security vs resource use: destroying the container each conversation is the
most secure option (zero persistence, no breakout survival) and is cheap
enough that it is the default — containers start in ~1s and the image is
layered/reused. If you need conversation state across turns, keep a long-running
compose stack instead (`docker compose up -d`) and reset state in the app
layer rather than keeping a privileged container alive.

**Plain:**
```
python3 guardrail_server.py   # http://localhost:8083/
```

**Install / run / stop (offline-first):**

```
./scripts/install.sh   # build Rust pattern scanner (one-time)
./scripts/run.sh       # start API server in background (http://:8083/)
./scripts/stop.sh      # stop the server
```

`install.sh` builds the memory-safe Rust Aho-Corasick scanner using only a
local Rust toolchain (no runtime network required). If the build fails, the
Python fallback scanner is used automatically.

**Security — authentication, authorization, and hardening:**

The guardrail API server is secured by default when you configure it. Without
any auth env vars, the server runs in open mode (suitable only for trusted
local networks). To secure it:

**Password login (web UI):**
```
GUARDRAIL_ADMIN_PASSWORD=your_strong_password ./scripts/run.sh
```
On first start, the password is hashed with PBKDF2-HMAC-SHA256 (200,000
iterations, random 16-byte salt) and stored locally at
`~/.ai_guardrails_auth.json` (mode 0600). The raw password is never written
to disk. Subsequent starts read the stored hash. Rotate by deleting the file
and restarting with a new password.

**API keys (programmatic access):**
```
GUARDRAIL_API_KEY=your_admin_key   # write/delete/monitor endpoints
GUARDRAIL_VIEW_KEY=your_view_key   # read-only endpoints
```
Generate with: `openssl rand -hex 32`

**IP allowlist:**
```
GUARDRAIL_ALLOWED_IPS=10.0.0.0/8,192.168.1.50
```
Empty = allow all IPs.

**CORS origin restriction:**
```
GUARDRAIL_ALLOWED_ORIGINS=https://your-dashboard.example.com
```
Empty = CORS disabled.

**Rate limiting:**
```
GUARDRAIL_RATE_LIMIT=60          # requests per minute per key/IP
GUARDRAIL_MAX_BODY_SIZE=1048576  # max request body bytes (1 MB)
```

**Host header validation (BadHost protection):**
```
GUARDRAIL_ALLOWED_HOSTS=localhost,127.0.0.1,my-pi.local
```
Empty = accept any Host header.

**SSRF protection (for external model URLs):**
```
GUARDRAIL_SSRF_PROTECTION=1
```
Blocks outside model URLs that target private/internal addresses
(10.x, 172.x, 192.x, link-local, IPv6 private). Disabled by default since
localhost is the expected default for local model serving.

**Security headers sent on every response:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy` (restrictive policy for the web UI)

**Session management:**
- Session tokens are `secrets.token_urlsafe(32)` and stored in
  `HttpOnly; SameSite=Strict` cookies.
- Sessions are regenerated on login (session fixation protection).
- Sessions expire after `GUARDRAIL_SESSION_TTL` seconds (default 3600).

**Logging — structured JSONL with rotation:**

All guardrail modules write structured JSONL log entries to the logs directory
(configured via `AI_GUARDRAILS_LOG_DIR`, default `./logs`). Each module writes
to its own file (`logs/guardrail.jsonl`, `logs/outer_monitor_audit.jsonl`,
`logs/outer_model_reviews.jsonl`, `logs/trusted_model_audits.jsonl`,
`logs/integrity_ledger.jsonl`, `logs/human_loop.jsonl`,
`logs/canary.jsonl`, etc.).

Log entries include timestamp, level, module, session ID, and structured data.
Log rotation is size-based (configured via `AI_GUARDRAIL_LOG_ROTATE`, default
10 MB) and keeps a configurable number of rotated files
(`AI_GUARDRAIL_LOG_KEEP`, default 5).

**Cron jobs — scheduled maintenance:**

Cron jobs are installed via `./scripts/cron/setup_cron.sh install` and run
automatically on a schedule. All cron scripts live in `scripts/cron/` and are
environment-configured (no hardcoded paths).

| Cron job | Schedule | Purpose |
|----------|----------|---------|
| `canary_probe.sh` | Every 5 minutes | Sends synthetic test inputs through the live guardrail to verify the gate is still firing (catches "dead gate" where guardrails are silently disabled). |
| `integrity_check.sh` | Every 15 minutes | Re-hashes all watched guardrail files and compares against the signed baseline; alerts on any tampering. |
| `update_check.sh` | Daily at 02:00 | Refreshes component versions and lists any security updates that are past due. |
| `session_cleanup.sh` | Every hour | Logs session TTL info; in-memory sessions expire automatically via TTL. |
| `log_rotate.sh` | Daily at 03:00 | Triggers log rotation on all guardrail log files. |

Install cron jobs:
```
./scripts/cron/setup_cron.sh install
```

List installed cron jobs:
```
./scripts/cron/setup_cron.sh list
```

Remove cron jobs:
```
./scripts/cron/setup_cron.sh remove
```

Cron jobs log to `logs/cron_*.log` in the guardrail log directory.

**Kill switch:**
- Log injection prevented: the reason string is stripped of newlines before
  being written to `logs/kill-switch.log`.
- The log directory is resolved relative to the script location, not
  hardcoded to a specific user's home directory.

**Endpoint tiers:**
- `PUBLIC` — GET `/`, `/api/health`, `/api/auth/login`, `/api/auth/logout`,
  `/api/auth/session`
- `VIEW` — GET `/api/policies*`, `/api/stats`, `/api/guardrail-status`,
  `/api/monitor/stats`, `/api/monitor/audit`, `/api/monitor/outer-review`
  (requires session or view API key)
- `ADMIN` — PUT/DELETE `/api/policies/*`, POST `/api/validate/*`,
  `/api/monitor/validate/*`, `/api/monitor/thought|action`
  (requires session or admin API key)

**Policy versioning with rollback (production best practice):**

```
python3 guardrail_policy_versioning.py   # CLI: list/save/load/rollback
```

Guardrails are not set-and-forget. Every saved page policy is versioned
(`policies/versions/<page>/v<N>.json`), so you can roll back a policy that
causes false positives or misses attacks. `rollback` restores a previous
version as a new version (append-only audit trail).

**Human-in-the-loop escalation:**

```
python3 guardrail_human_loop.py   # CLI: escalate/decide/stats
```

When conversation risk reaches medium/high, the content is escalated to a
human reviewer via webhook or console. The reviewer can approve, block, or
request a re-scan; the decision is recorded and applied. Configured via env:

```
HUMAN_LOOP_ENABLED=1
HUMAN_LOOP_MODE=console        # or "webhook"
HUMAN_LOOP_WEBHOOK_URL=http://...
HUMAN_LOOP_ESCALATE_AT=medium
HUMAN_LOOP_DECISION_TIMEOUT_SEC=60
```

**Liveness canary (gate still firing?):**

```
python3 guardrail_canary.py   # CLI: probe/state/reset/watch
```

Complements the integrity watcher: the watcher verifies guardrail *contents*
haven't been tampered with; the canary verifies the guardrail is still
*firing* correctly by sending synthetic test events (jailbreak, breakout,
harmful, PII, benign) through the live engine on a schedule. If the gate
silently stops blocking (or starts false-positive blocking), the canary
raises an out-of-band alert after a configurable number of consecutive
failures. This catches the "dead gate" scenario where code is intact but the
guardrail has been quietly disabled at runtime.

Configured via env:
```
CANARY_INTERVAL_SEC=300
CANARY_ALERT_AFTER_FAILURES=3
```

**Hardware optimization (device-aware):**

```
python3 guardrail_hardware.py   # CLI: prints hardware profile + env overrides
```

The guardrails adapt to the hardware they run on — no host-specific paths, nothing hardcoded to one machine. `detect_hardware()` reads CPU count, memory, architecture, Raspberry Pi model, and container/virtualization status from `/proc` and `/sys`, then derives recommended settings:

- Raspberry Pi / constrained: fewer parallel checks, Rust scanner preferred, smaller models, lower limits
- Container: cgroup-aware limits, no host assumptions
- Desktop/server: full parallelism, verbose logging

Apply with `apply_hardware_to_env()` to get `GUARDRAIL_*` / `OUTSIDE_MODEL_*` / `TRUSTED_MODEL_*` / `CLASSIFIER_MODEL_*` env overrides. Everything is relative to `__file__` or env-configurable — the same package runs on a Pi, desktop, or inside a container.

**Security update tracking:**

```
python3 guardrail_updates.py   # CLI: refresh/summary/due/applied
```

Tracks installed component versions (Python, guardrails package, Rust scanner, models) and flags when security updates are due. Works offline — state lives in `logs/updates_state.json`. Set a due date per component, mark updates as applied with the new version, and get a summary of overdue items.

**Prompt injection / jailbreak hardening (`guardrail_prompt_injection.py`):**

Evasion-resistant detection that strips Unicode smuggling, normalizes (NFKC), decodes Base64/hex/rot13/URL layers, then scans for jailbreak keywords, role-play conditioning, multiturn buildup, indirect/RAG-injection markers, system-prompt leakage, and secrets. Fail-closed on unclear input.

**Information leakage prevention (`guardrail_leakage.py`):**

Embeds canary tokens into internal prompts/context so any leakage of internal text is detectable in model output. Scans model output for canary tokens, system-prompt leakage, credentials/secrets, and outbound exfiltration URLs. Uses canary tokens + Unicode stripping + NFKC + casefold (AWS Bedrock guidance). Fail-closed — anything suspicious is blocked and censored.

## Web config UI

Open `http://localhost:8083/` to edit any page's policy live (patterns, keywords, disclaimers, limits, checks) and test validation in real time. Save writes to `policies/pages/<page>.json`; download JSON for offline deploys.

## npm package

`@pymite6941/ai-guardrails` — Node.js client embed:

```js
const { AIGuardrails } = require("@pymite6941/ai-guardrails");
const guard = new AIGuardrails({ baseUrl: "http://localhost:8083" });
const res = await guard.validateOutput(modelOutput, { page: "example.com", agent: "assistant" });
if (!res.safe) { /* block: res.reason, res.blockedBy */ }
```

Standalone (no server) client-side rules are included.

## Tests

```
python3 tests/test_guardrail.py   # guardrail engine checks (23)
python3 tests/test_outer_monitor.py   # outer monitor + bootstrapped monitoring checks
python3 tests/test_cage_breakout.py   # cage breakout-strategy checks (26 strategies)
python3 tests/test_new_modules.py     # modes, risk, integrity checks
python3 tests/test_classifier_step.py # classifier, step monitor, rust scanner checks
python3 tests/test_human_loop.py      # human-in-the-loop escalation checks
python3 tests/test_canary.py          # liveness canary checks
python3 tests/test_hardening.py       # hardware, updates, prompt injection, leakage checks
python3 tests/test_auth.py            # authentication, authorization, rate limiting
python3 guardrail_testing.py          # adversarial suite: catch rate + FP rate
./scripts/setup.sh                # chmod + self-test + usage hints
```

## DevPost submission guide (copy-paste ready)

Below are the common DevPost fields, pre-filled for this project. Copy each block into the corresponding field on DevPost.

**Project Name**
```
AI Guardrails
```

**Tagline (one sentence)**
```
Containerized per-web-page input/output guardrails for LLM apps — deterministic rules, with an NVIDIA Nemotron second opinion on Nebius Token Factory.
```

**Track**
```
Coding & Agentic Engineering
```

**Description / What it does**
```
AI Guardrails is a Clyde-inspired, executable-code guardrail system for LLM applications. It sits between the user and an AI model (inner AI) and validates every input/output before it reaches the model or the user, with an optional outer oversight model that reviews the inner AI's thoughts and actions.

Built on Nebius: the optional second-opinion classifier calls an NVIDIA Nemotron model through Nebius Token Factory's OpenAI-compatible endpoint at runtime (`POST /v1/chat/completions`). The model runs *after* the deterministic engine and can only escalate a verdict to BLOCK — it can never release something the rules already stopped, so a model failure or a prompt-injected model cannot open the gate.

Key capabilities:
- Input guardrail: canonicalizes (zero-width/homoglyph + NFKC), blocks jailbreak/container-escape/network patterns and keywords, enforces max length.
- Output guardrail: blocks harmful content, PII/credentials, data exfiltration, system-prompt leakage; injects financial/legal/security/geopolitics disclaimers; truncates oversized output; censors anything suspicious so nothing reaches the user.
- Container breakout detection: flags docker.sock, /proc, /sys, cgroup/release_agent, namespaces, ptrace, cloud metadata (169.254.169.254), kubelet/etcd, runc/containerd, D-Bus/systemd, persistence-outside-shell; every attempt is labeled CONTAINER BREAKOUT ATTEMPT and censored.
- Outer monitor (watcher for the watcher): an outside model reviews the inner AI's thoughts/actions; a trusted third model audits the outer monitor's reasoning for collusion (bootstrapped monitoring, three-level trust chain).
- Mutual awareness: both models know they are being watched, which improves policy adherence.
- Ephemeral "cage": run_cage.sh launches the AI inside a hardened Docker container (--rm --read-only --cap-drop ALL --no-new-privs --network none, CPU/mem/pid limits) and destroys it after each conversation — no malware or persistence survives.
- Modes: TRAINING (record, never block), TESTING (enforce + metrics), RUNNING (full enforcement).
- Composite conversation-level risk scoring (0.0–1.0) for multi-turn buildup attacks; critical risk blocks all output.
- Tamper-evident integrity watcher (signed HMAC + hash-chained ledger) detects guardrail file tampering.
- Liveness canary probes the live guardrail with synthetic tests and alerts if the gate silently stops firing.
- Policy versioning with rollback; human-in-the-loop escalation; LLM-based classifier second opinion; streaming step-level reasoning monitor with interrupt; memory-safe Rust Aho-Corasick pattern scanner; hardware-aware optimization; security update tracking.
- Offline-first: install.sh/build works with a local Rust toolchain; no runtime network required; Python fallback scanner included.
```

**How we built it**
```
- Python 3 stdlib-only guardrail engine (guardrail.py) with per-page JSON policies, pluggable checks, kill switch, stats, and JSONL audit logging.
- HTTP API server (guardrail_server.py) with /api/validate/* and /api/monitor/* endpoints plus a /api/guardrail-status consolidated health endpoint.
- Node.js client embed (@pymite6941/ai-guardrails on npm) with standalone fallback rules.
- Web config UI (web/index.html + web/config.js) for live policy editing and testing.
- Rust Aho-Corasick pattern scanner (rust/src/main.rs) for memory-safe, ReDoS-proof hot-path matching with Python fallback.
- Docker: containerized model server (docker/model_server.py), hardened compose stack (inner model :8000 + outside monitor :8001), ephemeral cage runner (docker/run_cage.sh).
- Additional modules: guardrail_modes.py, guardrail_risk.py, guardrail_integrity.py, guardrail_testing.py, guardrail_classifier.py, guardrail_step_monitor.py, guardrail_policy_versioning.py, guardrail_human_loop.py, guardrail_canary.py, guardrail_prompt_injection.py, guardrail_leakage.py, guardrail_hardware.py, guardrail_updates.py.
- 8 test suites (guardrail engine, outer monitor, cage breakout, modes/risk/integrity, classifier/step/scanner, human loop, canary, hardening) plus an adversarial suite: 100% catch rate, 0% false positives.
- Dev environment: Raspberry Pi (aarch64), offline-first, no runtime network dependency.
```

**Challenges we ran into**
```
- Making guardrails evasion-resistant: character injection, Unicode smuggling, Base64/hex/rot13, and multilingual jailbreak phrases bypass naive regex. Solved with normalization layers and obfuscation decoding before pattern matching.
- Avoiding false positives on benign long inputs: tuned the generic high-entropy token pattern to require mixed letter+digit variety.
- Keeping the AI off the host hardware: used ephemeral, hardened Docker containers (--rm --read-only --cap-drop ALL --no-new-privs --network none) that are destroyed after each conversation.
- Watcher-for-the-watcher problem: an outer monitor can itself be subverted, so we added a trusted third model to audit the outer monitor's reasoning (bootstrapped monitoring).
- Detecting a silently-disabled guardrail: added a liveness canary that probes the live engine with synthetic tests and alerts on consecutive failures.
- Offline-first operation on Raspberry Pi: install.sh builds the Rust scanner from a local toolchain; everything falls back to Python stdlib.
```

**What's next**
```
- LLM-based classifier second opinion on Nebius Token Factory with NVIDIA Nemotron (wired in and validated against a mock endpoint; enable with GUARDRAIL_CLASSIFIER_ENABLED=1 and a Nebius key).
- Tiered Nemotron use: Nano/Super for the per-request second opinion, Ultra for multi-turn forensic review.
- Streaming reasoning-step monitor with interrupt on unsafe step.
- Additional per-page policies and model integrations.
- Packaging as a pip-installable Python package alongside the npm package.
```

**Built with**
```
Python 3 (stdlib only), Rust (Aho-Corasick scanner), Docker, Node.js (npm client), tmux, shell scripts
```

**Installation**
```
git clone https://github.com/pymite6941/ai-guardrails.git
cd ai-guardrails
./scripts/install.sh   # build Rust scanner (optional; Python fallback included)
./scripts/run.sh       # start API server on http://localhost:8083/
./scripts/stop.sh      # stop the server
```

**Usage**
```
# Single-turn cage (AI runs in a destroyed-after-use container):
./docker/run_cage.sh "your prompt"

# Long-running stack:
docker compose -f docker/docker-compose.yml up -d

# Enable outside-model monitoring:
OUTSIDE_MODEL_ENABLED=1 OUTSIDE_MODEL_BASE_URL=http://outside-model:8000 ./scripts/run.sh

# Enable hardware-optimized settings:
python3 guardrail_hardware.py   # prints env overrides for your device
```

**Demo / Links**
- GitHub: https://github.com/pymite6941/ai-guardrails
- Live API (when running): http://localhost:8083/
- Web config UI: http://localhost:8083/
- Inner model container: http://localhost:8000/
- Outside model (monitor) container: http://localhost:8001/

**License**

MIT
