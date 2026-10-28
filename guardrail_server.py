#!/usr/bin/env python3
#=============================================================================
# AI Guardrails HTTP API server (stdlib only — no external deps)
#=============================================================================
# Serves:
#   GET    /                 -> web config UI
#   GET    /api/policies     -> list page policies
#   GET    /api/policies/:id -> get a page policy
#   PUT    /api/policies/:id -> save a page policy (JSON body)
#   DELETE /api/policies/:id -> delete a page policy
#   POST   /api/validate/input   -> {page, text, agent}
#   POST   /api/validate/output  -> {page, text, agent}
#   GET    /api/stats            -> engine stats
#   GET    /api/health           -> health check
#=============================================================================

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# Allow running both as `python guardrail_server.py` and from a package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardrail import GuardrailEngine, GuardrailPolicy, DEFAULT_POLICY, DEFAULT_POLICIES_DIR, DEFAULT_PAGES_DIR
from outer_monitor import OuterMonitor, OutsideModelConfig

HOST = os.environ.get("GUARDRAIL_HOST", "0.0.0.0")
PORT = int(os.environ.get("GUARDRAIL_PORT", "8083"))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

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


def _json_response(handler, status, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "AI-Guardrails/1.0"

    def log_message(self, format, *args):  # noqa: ARG002
        return  # silence default stderr logging

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return b""
        return self.rfile.read(length)

    def _route(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        method = self.command
        return path, method

    def do_GET(self):  # noqa: N802
        path, _ = self._route()
        if path == "/":
            self._serve_file(os.path.join(WEB_DIR, "index.html"), "text/html")
            return
        if path.startswith("/api/policies"):
            segments = [s for s in path.split("/") if s]
            # /api/policies or /api/policies/:id
            if len(segments) == 2:
                _json_response(self, 200, {
                    "pages": engine.list_pages(),
                    "default": engine.get_policy("default").to_dict(),
                })
                return
            if len(segments) == 3:
                page_id = segments[2]
                policy = engine.get_policy(page_id)
                _json_response(self, 200, {"page": page_id, "policy": policy.to_dict()})
                return
        if path == "/api/stats":
            _json_response(self, 200, engine.get_stats())
            return
        if path == "/api/health":
            _json_response(self, 200, {"status": "ok", "engine": "ai-guardrails"})
            return
        # ── Outer monitor endpoints (GET) ─────────────────────────
        if path == "/api/monitor/stats":
            _json_response(self, 200, monitor.get_stats())
            return
        if path == "/api/monitor/audit":
            limit = int(self.headers.get("X-Audit-Limit", "50"))
            _json_response(self, 200, {"audit": monitor.get_audit_log(limit)})
            return
        if path == "/api/monitor/outer-review":
            limit = int(self.headers.get("X-Review-Limit", "50"))
            _json_response(self, 200, {"outer_review": monitor.get_outer_review_log(limit)})
            return
        _json_response(self, 404, {"error": "not found"})

    def do_PUT(self):  # noqa: N802
        path, _ = self._route()
        segments = [s for s in path.split("/") if s]
        if len(segments) == 3 and segments[1] == "policies":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"})
                return
            page_id = segments[2]
            policy = GuardrailPolicy.__new__(GuardrailPolicy)
            policy.data = dict(DEFAULT_POLICY)
            if isinstance(body, dict):
                policy._merge(body)
            saved_path = engine.save_page_policy(page_id, policy)
            _json_response(self, 200, {"ok": True, "page": page_id,
                                       "saved_to": saved_path})
            return
        _json_response(self, 404, {"error": "not found"})

    def do_DELETE(self):  # noqa: N802
        path, _ = self._route()
        segments = [s for s in path.split("/") if s]
        if len(segments) == 3 and segments[1] == "policies":
            page_id = segments[2]
            path_file = engine.page_policy_path(page_id)
            removed = False
            if os.path.exists(path_file):
                os.remove(path_file)
                removed = True
            engine._page_policies.pop(page_id, None)
            _json_response(self, 200, {"ok": True, "page": page_id, "removed": removed})
            return
        _json_response(self, 404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path, _ = self._route()
        segments = [s for s in path.split("/") if s]
        try:
            body = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            _json_response(self, 400, {"error": "invalid json"})
            return
        if len(segments) == 3 and segments[1] == "api" and segments[2] == "validate":
            # body must carry the page; route by query ?kind=input|output is simpler:
            _json_response(self, 400, {"error": "use /api/validate/input or /api/validate/output"})
            return
        if path == "/api/validate/input":
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "user")
            _json_response(self, 200, engine.validate_input(text, page, agent))
            return
        if path == "/api/validate/output":
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "assistant")
            _json_response(self, 200, engine.validate_output(text, page, agent))
            return
        # ── Outer monitor endpoints (POST) ────────────────────────
        if path == "/api/monitor/validate/input":
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "user")
            _json_response(self, 200, monitor.validate_input(text, page, agent))
            return
        if path == "/api/monitor/validate/output":
            page = body.get("page", "default")
            text = body.get("text", "")
            agent = body.get("agent", "assistant")
            _json_response(self, 200, monitor.validate_output(text, page, agent))
            return
        if path == "/api/monitor/thought":
            agent = body.get("agent", "user")
            text = body.get("text", "")
            page = body.get("page", "default")
            _json_response(self, 200, monitor.record_thought(agent, text, page))
            return
        if path == "/api/monitor/action":
            agent = body.get("agent", "assistant")
            text = body.get("text", "")
            result_summary = body.get("result", "")
            page = body.get("page", "default")
            _json_response(self, 200, monitor.record_action(agent, text, result_summary, page))
            return
        _json_response(self, 404, {"error": "not found"})

    def _serve_file(self, fs_path, content_type):
        try:
            with open(fs_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            _json_response(self, 404, {"error": "file not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"AI Guardrails API server on http://{HOST}:{PORT}")
    print(f"  Web UI:      http://{HOST}:{PORT}/")
    print(f"  Policies:    http://{HOST}:{PORT}/api/policies")
    print(f"  Validate:    POST http://{HOST}:{PORT}/api/validate/input|output")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
