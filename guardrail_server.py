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
import subprocess
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
from guardrail_models import (
    get_providers, get_provider, resolve_provider_config,
    load_api_keys_into_env, get_session_provider, set_session_provider,
    clear_session_provider, DEFAULT_PROVIDER_KEY,
    PROVIDERS, PROVIDER_API_KEY_ENV,
)
from guardrail_assistant import get_assistant
from guardrail_auth import (
    authenticate, path_tier, send_json, send_auth_error,
    read_body_limited, create_session, validate_session, destroy_session,
    verify_password, has_password, set_password, is_auth_configured,
    is_2fa_configured, enable_2fa, disable_2fa, verify_2fa_code,
    verify_backup_code, session_2fa_verified, session_2fa_pending,
    has_2fa, _clear_login_attempts, SESSION_TTL_SECONDS,
    set_csrf_token,
    ADMIN_API_KEY, VIEW_API_KEY, ALLOWED_IPS, ALLOWED_ORIGINS,
    RATE_LIMIT, MAX_BODY_SIZE, BIND_HOST,
    _log_auth_event,
)

HOST = os.environ.get("GUARDRAIL_HOST", BIND_HOST)
PORT = int(os.environ.get("GUARDRAIL_PORT", "8083"))

# Load provider API keys from .env into the environment (for cloud models).
# Keys already set in the environment take precedence over .env values.
_loaded_keys = load_api_keys_into_env()
if _loaded_keys:
    for _pk, _kv in _loaded_keys.items():
        pass  # Keys loaded silently; visible via /api/models endpoint

# Resolve the web UI directory. When running as a PyInstaller binary,
# bundled files live under sys._MEIPASS; when running from source, use
# the directory next to this script.
if getattr(sys, "_MEIPASS", None):
    _base_dir = sys._MEIPASS
else:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(_base_dir, "web")

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
    "api_key": os.environ.get("OUTSIDE_MODEL_API_KEY", ""),
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
    "api_key": os.environ.get("CLASSIFIER_API_KEY", ""),
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
            f"Path=/; Max-Age={SESSION_TTL_SECONDS}"
        )
    handler.send_response(status)
    for k, v in headers.items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


def _require_json_content_type(handler) -> bool:
    """Reject requests without application/json Content-Type on JSON endpoints.

    Prevents content-type confusion attacks (e.g. form-encoded or text/plain
    bodies being interpreted as JSON).
    """
    ct = handler.headers.get("Content-Type", "")
    if not ct.startswith("application/json"):
        _json_response(handler, 400, {"error": "Content-Type must be application/json"})
        return False
    return True


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
        try:
            self._do_options_impl()
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "internal server error: " + str(e)}).encode("utf-8"))
            except Exception:
                pass

    def _do_options_impl(self):  # noqa: N802
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
        try:
            self._do_get_impl()
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "internal server error: " + str(e)}).encode("utf-8"))
            except Exception:
                pass

    def _do_get_impl(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path))
        if not result.ok:
            send_auth_error(self, result)
            return

        # Serve the unified app page for / or /login.
        # The page embeds a login card when not authenticated,
        # and a setup wizard when no password is configured yet.
        if path == "/" or path == "/login":
            self._serve_file(os.path.join(WEB_DIR, "index.html"),
                             "text/html", extra_headers=cors_headers)
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
                "2fa_configured": is_2fa_configured(),
                "2fa_verified": session_2fa_verified(session),
            }, cors_headers)
            return
        if path == "/api/auth/2fa/status":
            _json_response(self, 200, {
                "2fa_configured": is_2fa_configured(),
                "2fa_enabled": has_2fa(),
            }, cors_headers)
            return
        if path == "/api/auth/2fa/setup":
            if not is_auth_configured():
                _json_response(self, 503, {"error": "auth not configured"},
                               cors_headers)
                return
            result = enable_2fa()
            _json_response(self, 200, result, cors_headers)
            return
        if path == "/api/emergency/status":
            # Read emergency state file
            import json as _json
            state_path = os.path.join(
                os.environ.get("GUARDRAIL_LOG_DIR", "logs"),
                "emergency_state.json")
            state = {}
            if os.path.exists(state_path):
                try:
                    with open(state_path, "r") as f:
                        state = _json.load(f)
                except Exception:
                    state = {}
            _json_response(self, 200, {
                "emergency": state,
                "containment_active": os.path.exists(
                    os.path.join(os.environ.get("GUARDRAIL_LOG_DIR", "logs"),
                                 "containment.active")),
                "lock_active": os.path.exists(
                    os.path.join(os.environ.get("GUARDRAIL_LOG_DIR", "logs"),
                                 "emergency.lock")),
            }, cors_headers)
            return
        # ── Model provider endpoints (GET) ─────────────────────────
        if path == "/api/models":
            _json_response(self, 200, {
                "providers": get_providers(),
                "default": DEFAULT_PROVIDER_KEY,
            }, cors_headers)
            return
        if path == "/api/models/selected":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            provider_key = get_session_provider(session)
            provider = None
            if provider_key:
                provider = resolve_provider_config(provider_key)
            _json_response(self, 200, {
                "provider": provider_key,
                "provider_config": provider,
            }, cors_headers)
            return
        # ── Assistant endpoints (GET) ─────────────────────────────
        if path == "/api/assistant/setup":
            assistant = get_assistant()
            _json_response(self, 200, assistant.setup_status(), cors_headers)
            return
        if path == "/api/assistant/activity":
            assistant = get_assistant()
            limit = int(self.headers.get("X-Activity-Limit", "50"))
            _json_response(self, 200, assistant.get_activity(limit=limit), cors_headers)
            return
        if path == "/api/assistant/audit":
            assistant = get_assistant()
            limit = int(self.headers.get("X-Audit-Limit", "100"))
            _json_response(self, 200, assistant.get_audit_detail(limit=limit), cors_headers)
            return
        if path == "/api/assistant/risk":
            assistant = get_assistant()
            _json_response(self, 200, assistant.get_risk_summary(), cors_headers)
            return
        if path == "/api/assistant/health":
            assistant = get_assistant()
            _json_response(self, 200, assistant.get_health(), cors_headers)
            return
        if path == "/api/assistant/policies":
            assistant = get_assistant()
            _json_response(self, 200, assistant.list_policies(), cors_headers)
            return
        if path.startswith("/api/assistant/policies/"):
            page_id = path.split("/")[-1]
            assistant = get_assistant()
            _json_response(self, 200, assistant.get_policy(page_id), cors_headers)
            return
        _json_response(self, 404, {"error": "not found"}, cors_headers)

    def do_PUT(self):  # noqa: N802
        try:
            self._do_put_impl()
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "internal server error: " + str(e)}).encode("utf-8"))
            except Exception:
                pass

    def _do_put_impl(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path))
        if not result.ok:
            send_auth_error(self, result)
            return
        # Content-Type validation on JSON body endpoints
        if not _require_json_content_type(self):
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
        try:
            self._do_delete_impl()
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "internal server error: " + str(e)}).encode("utf-8"))
            except Exception:
                pass

    def _do_delete_impl(self):  # noqa: N802
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
        try:
            self._do_post_impl()
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "internal server error: " + str(e)}).encode("utf-8"))
            except Exception:
                pass

    def _do_post_impl(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path))
        if not result.ok:
            send_auth_error(self, result)
            return
        # Content-Type validation on JSON body endpoints
        if not _require_json_content_type(self):
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
            totp_code = body.get("totp_code", "")
            backup_code = body.get("backup_code", "")
            if not has_password():
                _json_response(self, 403, {
                    "error": "no password configured. Set "
                             "GUARDRAIL_ADMIN_PASSWORD env var."},
                               cors_headers)
                return
            if verify_password(password):
                # Clear login attempts on successful password
                login_ident = f"login:{self.client_address[0] if self.client_address else 'unknown'}"
                _clear_login_attempts(login_ident)
                # Log successful password step
                _log_auth_event("login_password_ok", self.client_address[0] if self.client_address else "unknown",
                               self.headers.get("User-Agent", ""))
                # ── 2FA step ──
                if is_2fa_configured():
                    # Issue a temporary 2fa-pending session token
                    tmp_token = create_session(
                        self.client_address[0] if self.client_address else "unknown",
                        self.headers.get("User-Agent", ""))
                    # Mark session as 2fa-pending
                    sess = validate_session(tmp_token)
                    if sess:
                        sess["2fa_pending"] = True
                    # Verify TOTP or backup code if provided
                    totp_ok = verify_2fa_code(totp_code) if totp_code else False
                    backup_ok = verify_backup_code(backup_code) if backup_code else False
                    if totp_ok or backup_ok:
                        # 2FA satisfied — mark session fully authenticated
                        sess["2fa_verified"] = True
                        sess["2fa_pending"] = False
                        _log_auth_event("login_2fa_ok", self.client_address[0] if self.client_address else "unknown",
                                       self.headers.get("User-Agent", ""))
                        csrf = set_csrf_token(tmp_token)
                        _h = dict(cors_headers)
                        _h["X-CSRF-Token"] = csrf
                        _json_response(self, 200, {
                            "ok": True,
                            "message": "login successful",
                            "session_token": tmp_token,
                            "2fa_verified": True,
                        }, _h, session_token=tmp_token)
                    else:
                        # 2FA required but not yet provided
                        _json_response(self, 200, {
                            "ok": False,
                            "message": "2fa_required",
                            "session_token": tmp_token,
                            "2fa_pending": True,
                            "requires_2fa": True,
                        }, cors_headers, session_token=tmp_token)
                    return
                else:
                    # No 2FA — full login
                    _log_auth_event("login_success", self.client_address[0] if self.client_address else "unknown",
                                   self.headers.get("User-Agent", ""))
                    session_token = create_session(
                        self.client_address[0] if self.client_address else "unknown",
                        self.headers.get("User-Agent", ""))
                    csrf = set_csrf_token(session_token)
                    _h = dict(cors_headers)
                    _h["X-CSRF-Token"] = csrf
                    _json_response(self, 200, {
                        "ok": True,
                        "message": "login successful",
                        "session_token": session_token,
                    }, _h, session_token=session_token)
            else:
                # Record failed login attempt
                login_ident = f"login:{self.client_address[0] if self.client_address else 'unknown'}"
                _record_login_attempt(login_ident, success=False)
                # Log failed login
                _log_auth_event("login_failure", self.client_address[0] if self.client_address else "unknown",
                               self.headers.get("User-Agent", ""), "invalid password")
                _json_response(self, 401, {"error": "invalid password"},
                               cors_headers)
            return

        if path == "/api/auth/logout":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            destroy_session(session_token)
            _log_auth_event("logout", self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, {"ok": True,
                                       "message": "logged out"},
                           cors_headers)
            return

        # ── 2FA endpoints (POST) ──────────────────────────────────
        if path == "/api/auth/2fa/verify":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            totp_code = body.get("totp_code", "")
            backup_code = body.get("backup_code", "")
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            if not session or not session.get("2fa_pending"):
                _json_response(self, 400, {"error": "no 2FA-pending session"},
                               cors_headers)
                return
            totp_ok = verify_2fa_code(totp_code) if totp_code else False
            backup_ok = verify_backup_code(backup_code) if backup_code else False
            if totp_ok or backup_ok:
                session["2fa_verified"] = True
                session["2fa_pending"] = False
                _log_auth_event("login_2fa_ok",
                               self.client_address[0] if self.client_address else "unknown",
                               self.headers.get("User-Agent", ""))
                csrf = set_csrf_token(session_token)
                _h = dict(cors_headers)
                _h["X-CSRF-Token"] = csrf
                _json_response(self, 200, {
                    "ok": True,
                    "message": "2FA verified",
                    "2fa_verified": True,
                }, _h, session_token=session_token)
            else:
                _json_response(self, 401, {"error": "invalid 2FA code"},
                               cors_headers)
            return

        if path == "/api/auth/2fa/disable":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            if not session_2fa_verified(session):
                _json_response(self, 403, {"error": "2FA verification required"},
                               cors_headers)
                return
            result = disable_2fa()
            _log_auth_event("2fa_disabled",
                           self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, result, cors_headers)
            return

        # ── Emergency override endpoints (POST) ───────────────────
        if path == "/api/emergency/contain":
            subprocess.run(["bash", os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "scripts", "emergency-override.sh"), "contain"],
                           capture_output=True, text=True, timeout=30)
            _log_auth_event("emergency_contain",
                           self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, {"ok": True,
                                       "message": "containment activated"},
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/emergency/container-stop":
            subprocess.run(["bash", os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "scripts", "emergency-override.sh"), "container-stop"],
                           capture_output=True, text=True, timeout=30)
            _log_auth_event("emergency_container_stop",
                           self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, {"ok": True,
                                       "message": "containers stopped"},
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/emergency/logs-preserve":
            subprocess.run(["bash", os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "scripts", "emergency-override.sh"), "logs-preserve"],
                           capture_output=True, text=True, timeout=30)
            _log_auth_event("emergency_logs_preserve",
                           self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, {"ok": True,
                                       "message": "logs preserved"},
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/emergency/shutdown":
            subprocess.run(["bash", os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "scripts", "emergency-override.sh"), "shutdown"],
                           capture_output=True, text=True, timeout=30)
            _log_auth_event("emergency_shutdown",
                           self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, {"ok": True,
                                       "message": "full shutdown locked"},
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/emergency/all":
            subprocess.run(["bash", os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "scripts", "emergency-override.sh"), "all"],
                           capture_output=True, text=True, timeout=30)
            _log_auth_event("emergency_all_stages",
                           self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, {"ok": True,
                                       "message": "all emergency stages activated"},
                           cors_headers,
                           session_token=result.session_token)
            return
        if path == "/api/emergency/reenable":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            password = body.get("password", "")
            totp_code = body.get("totp_code", "")
            backup_code = body.get("backup_code", "")
            # Build args for the shell script
            script_args = ["reenable"]
            if password:
                script_args += ["--password", password]
            if totp_code:
                script_args += ["--totp", totp_code]
            if backup_code:
                script_args += ["--backup", backup_code]
            proc = subprocess.run(["bash", os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "scripts", "emergency-override.sh")] + script_args,
                           capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                _log_auth_event("emergency_reenable_ok",
                               self.client_address[0] if self.client_address else "unknown",
                               self.headers.get("User-Agent", ""))
                _json_response(self, 200, {"ok": True,
                                           "message": "system re-enabled"},
                               cors_headers,
                               session_token=result.session_token)
            else:
                _log_auth_event("emergency_reenable_denied",
                               self.client_address[0] if self.client_address else "unknown",
                               self.headers.get("User-Agent", ""),
                               detail=proc.stderr[:200])
                _json_response(self, 403, {"ok": False,
                                           "error": "re-enable denied: " + proc.stderr.strip()[:200]},
                               cors_headers)
            return
        # ── Model provider selection (POST) ─────────────────────────
        if path == "/api/models/select":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            provider_key = body.get("provider", "")
            base_url = body.get("base_url", "")
            model = body.get("model", "")
            endpoint = body.get("endpoint", "")
            api_key = body.get("api_key", "")

            if not provider_key:
                _json_response(self, 400, {"error": "provider is required"},
                               cors_headers)
                return
            if provider_key not in PROVIDERS:
                _json_response(self, 400, {"error": f"unknown provider: {provider_key}"},
                               cors_headers)
                return

            provider = get_provider(provider_key)
            if provider and provider["api_key_required"] and not api_key:
                env_name = PROVIDER_API_KEY_ENV.get(provider_key, "")
                if not os.environ.get(env_name, ""):
                    _json_response(self, 400, {
                        "error": f"API key required for {provider['name']}. "
                                 f"Set {env_name} in .env or provide it.",
                    }, cors_headers)
                    return

            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            if not session:
                _json_response(self, 401, {"error": "authentication required"},
                               cors_headers)
                return

            # Store provider selection in session
            set_session_provider(session, provider_key)

            # Resolve full config
            config = resolve_provider_config(
                provider_key, base_url=base_url or None,
                model=model or None, endpoint=endpoint or None,
                api_key=api_key or None,
            )
            provider_name = provider["name"] if provider else provider_key
            _log_auth_event("model_selected",
                           self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""),
                           detail=f"provider={provider_key}")
            _json_response(self, 200, {
                "ok": True,
                "provider": provider_key,
                "provider_config": config,
                "message": f"Model provider set to {provider_name}",
            }, cors_headers, session_token=session_token)
            return

        # ── Assistant endpoints (POST) ─────────────────────────────
        if path == "/api/assistant/setup-password":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            password = body.get("password", "")
            assistant = get_assistant()
            result = assistant.setup_password(password)
            if result["ok"]:
                _log_auth_event("assistant_setup_password", "assistant")
            _json_response(self, 200 if result["ok"] else 400, result,
                           cors_headers)
            return
        if path == "/api/assistant/setup-2fa":
            assistant = get_assistant()
            result = assistant.setup_2fa()
            if result["ok"]:
                _log_auth_event("assistant_setup_2fa", "assistant")
            _json_response(self, 200 if result["ok"] else 400, result,
                           cors_headers)
            return
        if path == "/api/assistant/setup-model":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            provider_key = body.get("provider", "")
            base_url = body.get("base_url", "")
            model = body.get("model", "")
            endpoint = body.get("endpoint", "")
            api_key = body.get("api_key", "")
            assistant = get_assistant()
            result = assistant.setup_model_provider(
                provider_key, base_url=base_url or None,
                model=model or None, endpoint=endpoint or None,
                api_key=api_key or None,
            )
            if result["ok"]:
                _log_auth_event("assistant_setup_model", "assistant",
                               detail=provider_key)
            _json_response(self, 200 if result["ok"] else 400, result,
                           cors_headers)
            return
        if path == "/api/assistant/save-policy":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            page_id = body.get("page", "default")
            policy_data = body.get("policy", {})
            note = body.get("note", "")
            assistant = get_assistant()
            result = assistant.save_policy(
                page_id, policy_data,
                changed_by="assistant", note=note,
            )
            if result["ok"]:
                _log_auth_event("assistant_save_policy", "assistant",
                               detail=page_id)
            _json_response(self, 200 if result["ok"] else 400, result,
                           cors_headers)
            return
        if path == "/api/assistant/emergency/contain":
            assistant = get_assistant()
            result = assistant.emergency_contain()
            _json_response(self, 200 if result["ok"] else 400, result,
                           cors_headers)
            return
        if path == "/api/assistant/emergency/shutdown":
            assistant = get_assistant()
            result = assistant.emergency_shutdown()
            _json_response(self, 200 if result["ok"] else 400, result,
                           cors_headers)
            return
        if path == "/api/assistant/emergency/all":
            assistant = get_assistant()
            result = assistant.emergency_all()
            _json_response(self, 200 if result["ok"] else 400, result,
                           cors_headers)
            return
        if path == "/api/assistant/emergency/reenable":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            password = body.get("password", "")
            totp_code = body.get("totp_code", "")
            backup_code = body.get("backup_code", "")
            assistant = get_assistant()
            result = assistant.emergency_reenable(
                password, totp_code=totp_code or None,
                backup_code=backup_code or None,
            )
            _json_response(self, 200 if result["ok"] else 403, result,
                           cors_headers)
            return

        # ── Setup password (initial configuration, no auth needed) ──
        if path == "/api/auth/setup-password":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            password = body.get("password", "")
            if has_password():
                _json_response(self, 403, {
                    "error": "password already configured. Use /api/auth/login instead."
                }, cors_headers)
                return
            try:
                set_password(password)
            except ValueError as e:
                _json_response(self, 400, {"error": str(e)}, cors_headers)
                return
            _log_auth_event("password_setup", self.client_address[0] if self.client_address else "unknown",
                           self.headers.get("User-Agent", ""))
            _json_response(self, 200, {"ok": True,
                                       "message": "password set successfully"},
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
