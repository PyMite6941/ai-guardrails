# Demo runbook

You need a URL a judge can open. Two ways to get one, both safe because the demo
account cannot reconfigure anything.

## 1. Run the demo instance

```
./scripts/demo.sh                 # 127.0.0.1:8083, throwaway state
./scripts/demo.sh --port 8099
```

What it does: starts the server with users/keys/logs in `/tmp/ag-demo` (your real
config is untouched), creates a **developer** account, and writes the credentials
to `~/.ai_guardrails_demo_credentials.txt` (mode 600).

A developer can: read the console, run the test bench, open the chat page.
It cannot: change policies, manage users or keys, or trigger emergency containment.

## 2. Expose it

A domain name alone does not make the app reachable — something has to carry the
traffic. Two workable shapes:

**A. Own domain through a Cloudflare Tunnel (recommended)**

No port forwarding, no exposed home IP, TLS handled for you:

```
cloudflared tunnel login
cloudflared tunnel create ai-guardrails-demo
cloudflared tunnel route dns ai-guardrails-demo demo.yourdomain.com
cloudflared tunnel run --url http://127.0.0.1:8099 ai-guardrails-demo
```

**B. DNS A record + port forward + a terminating proxy**

Point `demo.yourdomain.com` at your public IP, forward 443, and run Caddy or
nginx in front of `127.0.0.1:8099`:

```
demo.yourdomain.com {
    reverse_proxy 127.0.0.1:8099
}
```

**Then start the app so it accepts that hostname and trusts the proxy:**

```
DEMO_HOST=demo.yourdomain.com \
GUARDRAIL_TRUST_PROXY=1 \
GUARDRAIL_RATE_LIMIT=240 \
./scripts/demo.sh --port 8099
```

- `DEMO_HOST` adds the hostname to `GUARDRAIL_ALLOWED_HOSTS`. Without it every
  request returns 400 "invalid host header" — the Host-injection guard, working
  as designed.
- `GUARDRAIL_TRUST_PROXY=1` makes rate limiting and audit logs use the real
  client IP (`CF-Connecting-IP` / `X-Forwarded-For`) instead of the proxy's
  127.0.0.1. **Without it, every visitor shares one 60-request/minute bucket and
  one 5-failure login lockout — one person mistyping a password locks out the
  judge.** Forwarded headers are only honoured from a loopback peer, so a remote
  client cannot spoof its own IP.
- `GUARDRAIL_RATE_LIMIT=240` is for demos only; the default 60/min is right for
  a single operator.

TLS: the app speaks plain HTTP and must never be exposed directly. Terminate TLS
at the tunnel/proxy and make sure the browser sees `https://`.

Keep the tunnel up while judging. A dead demo link reads worse than a recorded
video, so if the tunnel is flaky, host it on a VM for the judging window.

## 3. What to show (150 seconds)

1. **0:00–0:20 — problem.** An agent that can run tools needs an enforced boundary,
   not a polite prompt.
2. **0:20–0:50 — a real block.** Test bench → jailbreak preset → Validate. Say the
   rule name out loud (`prompt_injection`), then the container-escape preset.
3. **0:50–1:10 — rules are data.** Policies → edit a pattern → Save → re-run the
   same text, now blocked. Show that the change persists.
4. **1:10–1:40 — the model (Nebius + Nemotron).** Models panel, then the terminal:
   `harness/nebius_preflight.py` output and `nemotron_probe.py` numbers. Say the
   measured lift, not a guess.
5. **1:40–2:10 — oversight.** `/chat` → an agent turn, then the thought/file-change
   validation in Monitoring. Show a blocked file write.
6. **2:10–2:30 — limits.** Regex-only rules, short credential list, classifier
   fail-open. Candour scores better than overclaiming.

## 4. Checklist before you paste the URL into Devpost

- [ ] Console loads over the tunnel hostname (not 400)
- [ ] Demo login works from a different network (phone on cellular)
- [ ] Test bench returns a verdict (needs the `X-CSRF-Token` path the UI handles)
- [ ] `/chat` loads with styling
- [ ] No real data in the instance: it is `/tmp/ag-demo`, so nothing real is there
- [ ] Kill the tunnel when judging ends
