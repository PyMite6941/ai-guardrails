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
python3 tests/test_guardrail.py   # guardrail engine checks
python3 tests/test_outer_monitor.py   # outer monitor checks
python3 tests/test_cage_breakout.py   # cage breakout-strategy checks
./scripts/setup.sh                # chmod + self-test + usage hints
```

## Publish

Git tag `v*` → GitHub Actions (`.github/workflows/publish.yml`) publishes to npm.

```
git tag v1.0.0 && git push origin v1.0.0
```

## License

MIT
