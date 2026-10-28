#!/usr/bin/env python3
#=============================================================================
# AI Guardrails HTTP API server (stdlib only — no external deps)
#=============================================================================
# Serves:
#   GET    /                 -> web config UI (login required if password set)
#   GET    /login            -> login page
#   GET    /api/policies     -> list page policies (VIEW)
#   GET    /api/policies/:id -> get a page policy (VIEW)
#   PUT    /api/policies/:id -> save a page policy (ADMIN)
#   DELETE /api/policies/:id -> delete a page policy (ADMIN)
#   POST   /api/validate/input   -> {page, text, agent} (ADMIN)
#   POST   /api/validate/output  -> {page, text, agent} (ADMIN)
#   GET    /api/stats            -> engine stats (VIEW)
#   GET    /api/guardrail-status -> consolidated health (VIEW)
#   GET    /api/health           -> health check (PUBLIC)
#   POST   /api/auth/login       -> {password} -> session token (PUBLIC)
#   POST   /api/auth/logout      -> destroy session (PUBLIC)
#   GET    /api/auth/session     -> check session validity (PUBLIC)
#   POST   /api/monitor/validate/input   -> {page, text, agent} (ADMIN)
#   POST   /api/monitor/validate/output  -> {page, text, agent} (ADMIN)
#   POST   /api/monitor/thought          -> {agent, text, page} (ADMIN)
#   POST   /api/monitor/action           -> {agent, text, result, page} (ADMIN)
#   GET    /api/monitor/stats            -> monitor stats (VIEW)
#   GET    /api/monitor/audit            -> audit log (VIEW)
#   GET    /api/monitor/outer-review     -> outer review log (VIEW)
#=============================================================================

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Allow running both as `python guardrail_server.py` and from a package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrail import GuardrailEngine, GuardrailPolicy, DEFAULT_POLICY, DEFAULT_POLICIES_DIR, DEFAULT_PAGES_DIR
from outer_monitor import OuterMonitor, OutsideModelConfig
from guardrail_risk import get_tracker
from guardrail_integrity import get_watcher
from guardrail_canary import GuardrailCanary
from guardrail_classifier import GuardrailClassifier, ClassifierConfig
from guardrail_human_loop import HumanLoopConfig, HumanLoopEscalator
from guardrail_modes import load_mode
from guardrail_auth import (
    authenticate, path_tier, send_json, send_auth_error,
    read_body_limited, create_session, validate_session, destroy_session,
    verify_password, has_password, set_password, is_auth_configured,
    ADMIN_API_KEY, VIEW_API_KEY, ALLOWED_IPS, ALLOWED_ORIGINS,
    RATE_LIMIT, MAX_BODY_SIZE, BIND_HOST,
)

HOST = os.environ.get("GUARDRAIL_HOST", BIND_HOST)
PORT = int(os.environ.get("GUARDRAIL_PORT", "8083"))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# Auto-set admin password from env on first start (offline-first setup).
_admin_password = os.environ.get("GUARDRAIL_ADMIN_PASSWORD", "")
if _admin_password and not has_password():
    set_password(_admin_password)

engine = GuardrailEngine(policies_dir=DEFAULT_POLICIES_DIR,
                         pages_dir=DEFAULT_PAGES_DIR)

# Outer monitor: watches the inner AI's thoughts and actions, optionally via
# an outside model. Configure with env:
#   OUTSIDE_MODEL_ENABLED=1
#   OUTSIDE_MODEL_BASE_URL=http://localhost:11434
#   OUTSIDE_MODEL_MODEL=qwen2.5:1.5b
#   OUTSIDE_MODEL_ENDPOINT=generate   (or "chat")
_outside = OutsideModelConfig({
    "enabled": os.environ.get("OUTSIDE_MODEL_ENABLED", "0") == "1",
    "base_url": os.environ.get("OUTSIDE_MODEL_BASE_URL", "http://localhost:11434"),
    "model": os.environ.get("OUTSIDE_MODEL_MODEL", "qwen2.5:1.5b"),
    "endpoint": os.environ.get("OUTSIDE_MODEL_ENDPOINT", "generate"),
    "timeout": int(os.environ.get("OUTSIDE_MODEL_TIMEOUT", "30")),
})
monitor = OuterMonitor(engine=engine,
                       outside_model_config=_outside,
                       watch_inner=True,
                       monitor_outer=True)

# Aggregated status subsystem instances (observability endpoint).
classifier = GuardrailClassifier(ClassifierConfig({
    "enabled": os.environ.get("CLASSIFIER_ENABLED", "0") == "1",
    "base_url": os.environ.get("CLASSIFIER_BASE_URL",
                               "http://localhost:8000").rstrip("/"),
    "model": os.environ.get("CLASSIFIER_MODEL", "classifier-model"),
    "endpoint": os.environ.get("CLASSIFIER_ENDPOINT", "chat"),
    "timeout": int(os.environ.get("CLASSIFIER_TIMEOUT", "20")),
}))
human_loop = HumanLoopEscalator(HumanLoopConfig({
    "enabled": os.environ.get("HUMAN_LOOP_ENABLED", "0") == "1",
    "mode": os.environ.get("HUMAN_LOOP_MODE", "console"),
    "webhook_url": os.environ.get("HUMAN_LOOP_WEBHOOK_URL", ""),
    "webhook_api_key": os.environ.get("HUMAN_LOOP_WEBHOOK_API_KEY", ""),
    "timeout": int(os.environ.get("HUMAN_LOOP_TIMEOUT", "30")),
    "escalate_at": os.environ.get("HUMAN_LOOP_ESCALATE_AT", "medium"),
    "decision_timeout_sec": int(
        os.environ.get("HUMAN_LOOP_DECISION_TIMEOUT_SEC", "60")),
}))
canary = GuardrailCanary(engine=engine)
risk_tracker = get_tracker()
integrity_watcher = get_watcher()
current_mode = load_mode()


def _json_response(handler, status, payload,
                   extra_headers: Optional[dict] = None,
                   session_token: Optional[str] = None) -> None:
    import typing  # noqa: F401  (typing already imported via guardrail_auth)
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    if extra_headers:
        headers.update(extra_headers)
    if session_token:
        headers["Set-Cookie"] = (
            f"session={session_token}; HttpOnly; SameSite=Strict; "
            f"Path=/; Max-Age={3600}"
        )
    handler.send_response(status)
    for k, v in headers.items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "AI-Guardrails/1.0"

    def log_message(self, format, *args):  # noqa: ARG002
        return  # silence default stderr logging

    def _route(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        method = self.command
        return path, method

    def _auth_and_preflight(self, tier: str):
        """Run auth middleware. Returns (AuthResult, cors_headers).

        If not ok, the handler should send the error and stop.
        """
        result = authenticate(self, tier)
        return result, result.headers

    def _read_body(self):
        return read_body_limited(self)

    def do_OPTIONS(self):  # noqa: N802
        """CORS preflight."""
        path, _ = self._route()
        result = authenticate(self, path_tier(path))
        headers = result.headers
        if not result.ok:
            self.send_response(result.status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            return
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path))
        if not result.ok:
            send_auth_error(self, result)
            return

        # Serve login page for / or /login when not authenticated.
        if path == "/":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            if validate_session(session_token):
                self._serve_file(os.path.join(WEB_DIR, "index.html"),
                                 "text/html", extra_headers=cors_headers)
            else:
                self._serve_login_page(cors_headers)
            return
        if path == "/login":
            self._serve_login_page(cors_headers)
            return
        if path.startswith("/api/policies"):
            segments = [s for s in path.split("/") if s]
            if len(segments) == 2:
                _json_response(self, 200, {
                    "pages": engine.list_pages(),
                    "default": engine.get_policy("default").to_dict(),
                }, cors_headers)
                return
            if len(segments) == 3:
                page_id = segments[2]
                policy = engine.get_policy(page_id)
                _json_response(self, 200, {"page": page_id,
                                           "policy": policy.to_dict()},
                               cors_headers)
                return
        if path == "/api/stats":
            _json_response(self, 200, engine.get_stats(), cors_headers)
            return
        if path == "/api/health":
            _json_response(self, 200, {"status": "ok",
                                       "engine": "ai-guardrails"},
                           cors_headers)
            return
        if path == "/api/guardrail-status":
            risk_states = risk_tracker.all_states()
            status = {
                "status": "ok",
                "engine": "ai-guardrails",
                "mode": (current_mode.value
                         if hasattr(current_mode, "value")
                         else str(current_mode)),
                "engine_stats": engine.get_stats(),
                "monitor_stats": monitor.get_stats(),
                "risk": {
                    "conversations": len(risk_states),
                    "conversations_at_risk": [
                        r for r in risk_states
                        if r["level"] in ("high", "critical")
                    ],
                    "all": risk_states,
                },
                "integrity": integrity_watcher.check(),
                "canary": canary.get_state(),
                "classifier": classifier.get_stats(),
                "human_loop": human_loop.get_stats(),
            }
            degraded = (
                len(status["risk"]["conversations_at_risk"]) > 0
                or (isinstance(status["integrity"].get("findings"), list)
                    and len(status["integrity"]["findings"]) > 0)
                or status["canary"].get("consecutive_failures", 0) > 0
            )
            status["health"] = "degraded" if degraded else "ok"
            _json_response(self, 200, status, cors_headers)
            return
        # ── Outer monitor endpoints (GET) ─────────────────────────
        if path == "/api/monitor/stats":
            _json_response(self, 200, monitor.get_stats(), cors_headers)
            return
        if path == "/api/monitor/audit":
            limit = int(self.headers.get("X-Audit-Limit", "50"))
            _json_response(self, 200, {"audit": monitor.get_audit_log(limit)},
                           cors_headers)
            return
        if path == "/api/monitor/outer-review":
            limit = int(self.headers.get("X-Review-Limit", "50"))
            _json_response(self, 200,
                           {"outer_review": monitor.get_outer_review_log(limit)},
                           cors_headers)
            return
        # ── Auth endpoints (GET) ──────────────────────────────────
        if path == "/api/auth/session":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            _json_response(self, 200, {
                "authenticated": session is not None,
                "session": session,
            }, cors_headers)
            return
        _json_response(self, 404, {"error": "not found"}, cors_headers)

    def do_PUT(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path))
        if not result.ok:
            send_auth_error(self, result)
            return
        segments = [s for s in path.split("/") if s]
        if len(segments) == 3 and segments[1] == "policies":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            page_id = segments[2]
            policy = GuardrailPolicy.__new__(GuardrailPolicy)
            policy.data = dict(DEFAULT_POLICY)
            if isinstance(body, dict):
                policy._merge(body)
            saved_path = engine.save_page_policy(page_id, policy)
            _json_response(self, 200, {"ok": True, "page": page_id,
                                       "saved_to": saved_path},
                           cors_headers,
                           session_token=result.session_token)
            return
        _json_response(self, 404, {"error": "not found"}, cors_headers)

    def do_DELETE(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path))
        if not result.ok:
            send_auth_error(self, result)
            return
        segments = [s for s in path.split("/") if s]
        if len(segments) == 3 and segments[1] == "policies":
            page_id = segments[2]
            path_file = engine.page_policy_path(page_id)
            removed = False
            if os.path.exists(path_file):
                os.remove(path_file)
                removed = True
            engine._page_policies.pop(page_id, None)
            _json_response(self, 200, {"ok": True, "page": page_id,
                                       "removed": removed},
                           cors_headers,
                           session_token=result.session_token)
            return
        _json_response(self, 404, {"error": "not found"}, cors_headers)

    def do_POST(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path))
        if not result.ok:
            send_auth_error(self, result)
            return

        # ── Auth endpoints ────────────────────────────────────────
        if path == "/api/auth/login":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            password = body.get("password", "")
            if not has_password():
                _json_response(self, 403, {
                    "error": "no password configured. Set "
                             "GUARDRAIL_ADMIN_PASSWORD env var."},
                               cors_headers)
                return
            if verify_password(password):
                # Session regeneration: destroy any existing session first
                # to prevent session fixation attacks.
                old_token = self.headers.get("X-Session-Token", "") or \
                    self.headers.get("Cookie", "").replace("session=", "", 1)
                if old_token:
                    destroy_session(old_token)
                session_token = create_session(
                    self.client_address[0] if self.client_address else "unknown",
                    self.headers.get("User-Agent", ""))
                _json_response(self, 200, {
                    "ok": True,
                    "message": "login successful",
                    "session_token": session_token,
                }, cors_headers, session_token=session_token)
            else:
                _json_response(self, 401, {"error": "invalid password"},
                               cors_headers)
            return

        if path == "/api/auth/logout":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            destroy_session(session_token)
            _json_response(self, 200, {"ok": True,
                                       "message": "logged out"},
                           cors_headers)
            return

        # ── Validate endpoints (ADMIN) ────────────────────────────
        if path == "/api/validate/input":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "user")
            _json_response(self, 200,
                           engine.validate_input(text, page, agent),
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/validate/output":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "assistant")
            _json_response(self, 200,
                           engine.validate_output(text, page, agent),
                           cors_headers,
                           session_token=result.session_token)
            return
        # ── Outer monitor endpoints (POST) ────────────────────────
        if path == "/api/monitor/validate/input":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "user")
            _json_response(self, 200,
                           monitor.validate_input(text, page, agent),
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/monitor/validate/output":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "assistant")
            _json_response(self, 200,
                           monitor.validate_output(text, page, agent),
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/monitor/thought":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            agent = body.get("agent", "user")
            text = body.get("text", "")
            page = body.get("page", "default")
            _json_response(self, 200,
                           monitor.record_thought(agent, text, page),
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/monitor/action":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            agent = body.get("agent", "assistant")
            text = body.get("text", "")
            result_summary = body.get("result", "")
            page = body.get("page", "default")
            _json_response(self, 200,
                           monitor.record_action(agent, text, result_summary,
                                                 page),
                           cors_headers,
                           session_token=result.session_token)
            return
        _json_response(self, 404, {"error": "not found"}, cors_headers)

    def _serve_file(self, fs_path, content_type,
                    extra_headers: Optional[dict] = None) -> None:
        try:
            with open(fs_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            _json_response(self, 404, {"error": "file not found"},
                           extra_headers or {})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _serve_login_page(self, extra_headers: Optional[dict] = None) -> None:
        """Serve an inline login page (no external file needed)."""
        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Guardrails — Login</title>
<style>
  :root { --bg:#0b0f19; --card:#131b26; --text:#e8eaed; --muted:#8b93a5;
          --accent:#38bdf8; --danger:#f87171; --border:#25303f; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:'Inter',system-ui,sans-serif;
         background:var(--bg); color:var(--text); display:flex;
         height:100vh; align-items:center; justify-content:center; }
  .card { background:var(--card); border:1px solid var(--border);
          border-radius:12px; padding:32px; width:100%; max-width:380px; }
  .card h1 { margin:0 0 8px 0; font-size:18px; letter-spacing:-0.4px; }
  .card h1 span { color:var(--accent); font-weight:700; }
  .card p { margin:0 0 20px 0; font-size:13px; color:var(--muted); }
  .field { margin-bottom:16px; }
  .field label { display:block; font-size:12px; color:var(--muted);
                 margin-bottom:6px; font-weight:600; }
  .field input { width:100%; background:#0b0f19; border:1px solid var(--border);
                 border-radius:8px; color:var(--text); font-size:13px;
                 padding:10px; box-sizing:border-box; }
  .field input:focus { outline:none; border-color:var(--accent); }
  .btn { border:none; border-radius:8px; padding:10px 16px;
         font-size:13px; font-weight:600; cursor:pointer;
         background:var(--accent); color:#00141f; width:100%; }
  .btn:hover { opacity:0.9; }
  .btn:disabled { opacity:0.5; cursor:not-allowed; }
  .error { margin-top:12px; font-size:12px; color:var(--danger); height:16px; }
  .hint { margin-top:16px; font-size:11px; color:var(--muted); }
</style>
</head>
<body>
  <div class="card">
    <h1><span>AI</span> Guardrails</h1>
    <p>Enter the admin password to access the guardrail configuration.</p>
    <div class="field">
      <label>Password</label>
      <input type="password" id="password" placeholder="Password">
    </div>
    <div class="error" id="error"></div>
    <button class="btn" id="loginBtn">Sign in</button>
    <div class="hint">Set the password with the GUARDRAIL_ADMIN_PASSWORD
      environment variable on first start.</div>
  </div>
<script>
  const btn = document.getElementById('loginBtn');
  const error = document.getElementById('error');
  const input = document.getElementById('password');
  btn.onclick = async () => {
    error.textContent = '';
    btn.disabled = true;
    btn.textContent = 'Signing in…';
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ password: input.value }),
      });
      if (res.ok) {
        const data = await res.json();
        const token = data.session_token;
        if (token) {
          document.cookie = `session=${token}; HttpOnly; SameSite=Strict; Path=/; max-age=3600`;
          sessionStorage.setItem('x-session-token', token);
          window.location.href = '/';
        } else {
          error.textContent = 'Login failed: no token returned';
        }
      } else {
        const txt = await res.text();
        error.textContent = 'Invalid password';
      }
    } catch (e) {
      error.textContent = 'Login request failed';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  };
  input.addEventListener('keypress', (e) => { if (e.key === 'Enter') btn.click(); });
</script>
</body>
</html>"""
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"AI Guardrails API server on http://{HOST}:{PORT}")
    print(f"  Web UI:      http://{HOST}:{PORT}/  (login required if password set)")
    print(f"  Policies:    http://{HOST}:{PORT}/api/policies")
    print(f"  Validate:    POST http://{HOST}:{PORT}/api/validate/input|output")
    print(f"  Auth:        POST http://{HOST}:{PORT}/api/auth/login")
    if is_auth_configured():
        print("  Auth:        ENABLED (API key / session / IP allowlist)")
    else:
        print("  Auth:        DISABLED — set GUARDRAIL_ADMIN_PASSWORD or "
              "GUARDRAIL_API_KEY to protect the API")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
