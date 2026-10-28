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
python3 guardrail_testing.py          # adversarial suite: catch rate + FP rate
./scripts/setup.sh                # chmod + self-test + usage hints
```

## Publish

Git tag `v*` → GitHub Actions (`.github/workflows/publish.yml`) publishes to npm.

```
git tag v1.0.0 && git push origin v1.0.0
```

## License

MIT
