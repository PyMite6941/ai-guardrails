#!/usr/bin/env python3
#=============================================================================
# Containerized model server — runs an AI model inside a Docker container on a
# machine. Exposes /api/generate and /api/chat so the guardrails and the outer
# monitor can connect to a model that lives inside a container.
#=============================================================================
# Modes (set via MODE_SERVER_MODE):
#   upstream   - proxy to an upstream model API (OLLAMA_BASE_URL / OPENAI_BASE_URL)
#   local      - deterministic local responder (works out of the box, no model
#                weights needed; useful for testing the guardrails + monitor
#                wiring inside containers)
#=============================================================================

import json
import os
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("MODEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("MODEL_PORT", "8000"))
MODE = os.environ.get("MODE_SERVER_MODE", "local").lower()
MODEL_NAME = os.environ.get("MODEL_NAME", "container-model")

UPSTREAM_BASE = (os.environ.get("OLLAMA_BASE_URL")
                 or os.environ.get("OPENAI_BASE_URL")
                 or "").rstrip("/")
UPSTREAM_API_KEY = os.environ.get("UPSTREAM_API_KEY")


def _upstream_chat(prompt: str) -> str:
    """Proxy to an upstream Ollama/OpenAI-compatible model API."""
    if not UPSTREAM_BASE:
        return ("[upstream not configured] " + prompt[:200]).strip()
    try:
        payload = {
            "model": MODEL_NAME,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if UPSTREAM_API_KEY:
            headers["Authorization"] = f"Bearer {UPSTREAM_API_KEY}"
        req = urllib.request.Request(UPSTREAM_BASE + "/api/chat",
                                     data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        try:
            j = json.loads(body)
            msg = j.get("message", {})
            if isinstance(msg, dict) and msg.get("content"):
                return msg["content"]
            return body
        except Exception:
            return body
    except Exception as e:
        return f"[upstream error: {e}]"


def _local_respond(prompt: str) -> str:
    """Deterministic local responder — no model weights required."""
    p = prompt.strip()
    if not p:
        return "I am a containerized model running in Docker. Send me a prompt."
    low = p.lower()
    if any(k in low for k in ["virus", "malware", "exploit", "how to create"]):
        return ("I cannot help with that. This containerized model is guarded "
                "by the AI Guardrails outer monitor.")
    if any(k in low for k in ["hello", "hi", "hey"]):
        return "Hello! I am a model running inside a Docker container."
    return f"I received your prompt ({len(p)} chars). I am running inside a Docker container as model '{MODEL_NAME}'."


class Handler(BaseHTTPRequestHandler):
    server_version = "ContainerModel/1.0"

    def log_message(self, format, *args):  # noqa: ARG002
        return

    def _respond(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _route(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path.rstrip("/") or "/"
        return path, self.command

    def do_GET(self):  # noqa: N802
        path, _ = self._route()
        if path == "/api/health":
            self._respond(200, {"status": "ok", "model": MODEL_NAME,
                                "mode": MODE, "containerized": True})
            return
        self._respond(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path, _ = self._route()
        try:
            body = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid json"})
            return
        prompt = body.get("prompt", body.get("message", ""))

        if path in ("/api/generate", "/api/chat"):
            if MODE == "upstream":
                text = _upstream_chat(prompt)
            else:
                text = _local_respond(prompt)
            self._respond(200, {"model": MODEL_NAME, "response": text,
                                "containerized": True})
            return
        self._respond(404, {"error": "not found"})


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Container model server on http://{HOST}:{PORT} (mode={MODE}, model={MODEL_NAME})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
