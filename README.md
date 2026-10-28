# AI Guardrails

Customizable per-web-page input/output guardrails for LLM applications. Clyde-inspired engine: guardrails are **executable code**, not just prompts.

## What it does

- **Input guardrail** — canonicalizes (zero-width/homoglyph + NFKC), blocks jailbreak/container-escape/network patterns & keywords, enforces max length.
- **Output guardrail** — blocks harmful content, PII/credentials, data exfiltration, system-prompt leakage; injects financial/legal/security/geopolitics disclaimers; truncates oversized output.
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
```

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
python3 tests/test_guardrail.py   # 16 checks
./scripts/setup.sh                # chmod + self-test + usage hints
```

## Publish

Git tag `v*` → GitHub Actions (`.github/workflows/publish.yml`) publishes to npm.

```
git tag v1.0.0 && git push origin v1.0.0
```

## License

MIT
