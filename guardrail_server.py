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
import time
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Python.org builds on macOS ship without a CA bundle. curl reaches model
# providers fine, but urllib then fails with CERTIFICATE_VERIFY_FAILED and the
# classifier silently falls back to "unreachable". Point at the system bundle
# when the interpreter has none and the caller did not choose one.
if not os.environ.get("SSL_CERT_FILE"):
    for _ca in ("/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem"):
        if os.path.exists(_ca):
            os.environ["SSL_CERT_FILE"] = _ca
            break

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
    test_model_connection,
)
from guardrail_secret_stripper import strip_all_sensitive, count_secrets, detect_secrets
from guardrail_token_compressor import compress_for_model, estimate_tokens
from guardrail_assistant import get_assistant
from guardrail_auth import (
    authenticate, path_tier, send_json, send_auth_error,
    read_body_limited, create_session, validate_session, destroy_session,
    verify_password, has_password, set_password, is_auth_configured,
    is_2fa_configured, enable_2fa, disable_2fa, verify_2fa_code,
    verify_backup_code, session_2fa_verified, session_2fa_pending,
    has_2fa, _clear_login_attempts, SESSION_TTL_SECONDS,
    set_csrf_token, validate_model_url,
    ADMIN_API_KEY, VIEW_API_KEY, ALLOWED_IPS, ALLOWED_ORIGINS,
    RATE_LIMIT, MAX_BODY_SIZE, BIND_HOST,
    _log_auth_event,
    _record_login_attempt,
    verify_user_backup_code, enable_user_2fa, disable_user_2fa,
    enable_2fa, disable_2fa,
)

HOST = os.environ.get("GUARDRAIL_HOST", BIND_HOST)


def _env(name: str, default: str = "") -> str:
    """Read an env var, accepting the documented GUARDRAIL_ prefix too."""
    return os.environ.get("GUARDRAIL_" + name, os.environ.get(name, default))


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
    "enabled": _env("OUTSIDE_MODEL_ENABLED", "0") == "1",
    "base_url": _env("OUTSIDE_MODEL_BASE_URL", "http://localhost:11434"),
    "model": _env("OUTSIDE_MODEL_MODEL", "qwen2.5:1.5b"),
    "endpoint": _env("OUTSIDE_MODEL_ENDPOINT", "generate"),
    "timeout": int(_env("OUTSIDE_MODEL_TIMEOUT", "30")),
    "api_key": _env("OUTSIDE_MODEL_API_KEY", ""),
})
monitor = OuterMonitor(engine=engine,
                       outside_model_config=_outside,
                       watch_inner=True,
                       monitor_outer=True)

# Aggregated status subsystem instances (observability endpoint).
# Use the monitor's classifier so /api/guardrail-status reports the same
# counters that the validate path actually increments. Two instances meant the
# status page could show 0 calls while the model was being consulted.
classifier = monitor.classifier
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

# ── Paths ──
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

# ── Chat / Agentic harness ──────────────────────────────────────────────
# ChatGPT-style interface with agentic capabilities.
# Every agent turn is validated through the guardrail engine before
# reaching the user. All conversations are persisted for audit.

CHAT_SESSIONS_DIR = os.path.join(LOGS_DIR, "chat")
os.makedirs(CHAT_SESSIONS_DIR, exist_ok=True)

AGENT_TOOLS: Dict[str, Dict[str, Any]] = {
    "guardrail_validate": {
        "name": "guardrail_validate",
        "description": "Validate text through the AI guardrails (input/output checks).",
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to validate"},
                "kind": {"type": "string", "enum": ["input", "output"], "default": "input"},
                "page": {"type": "string", "default": "default"},
                "agent": {"type": "string", "default": "assistant"},
            },
            "required": ["text"],
        },
    },
    "file_read": {
        "name": "file_read",
        "description": "Read a file from the local filesystem (read-only).",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"},
            },
            "required": ["path"],
        },
    },
    "system_info": {
        "name": "system_info",
        "description": "Get system information (OS, Python version, uptime).",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    "emergency_contain": {
        "name": "emergency_contain",
        "description": "Trigger emergency containment (stage 1) — blocks the API port.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    "file_write": {
        "name": "file_write",
        "description": "Write content to a file within the project directory (read + write guarded).",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to write (within project dir)"},
                "content": {"type": "string", "description": "File content to write"},
            },
            "required": ["path", "content"],
        },
    },
}


class ChatMessage:
    """A single message in a chat session."""

    def __init__(self, role: str, content: str,
                 timestamp: Optional[float] = None,
                 tool_calls: Optional[List[Dict]] = None,
                 tool_results: Optional[List[Dict]] = None):
        self.role = role
        self.content = content
        self.timestamp = timestamp or time.time()
        self.tool_calls = tool_calls or []
        self.tool_results = tool_results or []

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
        }
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.tool_results:
            d["tool_results"] = self.tool_results
        return d


class ChatSession:
    """A chat session with messages, model, and agent mode."""

    def __init__(self, session_id: str, title: str = "New Chat",
                 model: str = "ollama"):
        self.id = session_id
        self.title = title
        self.model = model
        self.created_at = time.time()
        self.updated_at = time.time()
        self.messages: List[ChatMessage] = []
        self.system_prompt = ""
        self.agent_mode = False

    def to_dict(self, include_messages: bool = False) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "model": self.model,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "system_prompt": self.system_prompt,
            "agent_mode": self.agent_mode,
            "message_count": len(self.messages),
        }
        if include_messages:
            d["messages"] = [m.to_dict() for m in self.messages]
        return d

    def add_message(self, role: str, content: str,
                    tool_calls: Optional[List[Dict]] = None,
                    tool_results: Optional[List[Dict]] = None) -> ChatMessage:
        msg = ChatMessage(role, content, tool_calls=tool_calls,
                          tool_results=tool_results)
        self.messages.append(msg)
        self.updated_at = time.time()
        return msg

    def save(self) -> None:
        path = os.path.join(CHAT_SESSIONS_DIR, f"{self.id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "id": self.id,
                "title": self.title,
                "model": self.model,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "system_prompt": self.system_prompt,
                "agent_mode": self.agent_mode,
                "messages": [m.to_dict() for m in self.messages],
            }, f, indent=2)

    @classmethod
    def load(cls, session_id: str) -> Optional["ChatSession"]:
        path = os.path.join(CHAT_SESSIONS_DIR, f"{session_id}.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None
        session = cls(data["id"], data.get("title", "New Chat"),
                      data.get("model", "ollama"))
        session.created_at = data.get("created_at", time.time())
        session.updated_at = data.get("updated_at", time.time())
        session.system_prompt = data.get("system_prompt", "")
        session.agent_mode = data.get("agent_mode", False)
        session.messages = [
            ChatMessage(m["role"], m["content"],
                        m.get("timestamp"),
                        m.get("tool_calls"),
                        m.get("tool_results"))
            for m in data.get("messages", [])
        ]
        return session

    @classmethod
    def list_all(cls) -> List[Dict[str, Any]]:
        sessions: List[Dict[str, Any]] = []
        if os.path.isdir(CHAT_SESSIONS_DIR):
            for name in os.listdir(CHAT_SESSIONS_DIR):
                if name.endswith(".json"):
                    session_id = name[:-5]
                    session = cls.load(session_id)
                    if session:
                        sessions.append(session.to_dict())
        sessions.sort(key=lambda s: s.get("updated_at", 0), reverse=True)
        return sessions


# In-memory session cache
_chat_sessions: Dict[str, ChatSession] = {}


def get_chat_session(session_id: str) -> Optional[ChatSession]:
    if session_id in _chat_sessions:
        return _chat_sessions[session_id]
    session = ChatSession.load(session_id)
    if session:
        _chat_sessions[session_id] = session
    return session


def create_chat_session(title: str = "New Chat",
                        model: str = "ollama") -> ChatSession:
    session_id = str(uuid.uuid4())[:8]
    session = ChatSession(session_id, title, model)
    _chat_sessions[session_id] = session
    session.save()
    return session


def delete_chat_session(session_id: str) -> bool:
    path = os.path.join(CHAT_SESSIONS_DIR, f"{session_id}.json")
    if os.path.exists(path):
        os.remove(path)
        _chat_sessions.pop(session_id, None)
        return True
    return False


def execute_agent_tool(tool_name: str, arguments: Dict[str, Any],
                       session_token: Optional[str] = None) -> Dict[str, Any]:
    """Execute an agent tool with guardrail validation.

    Every tool call is validated through the guardrail engine before
    execution. Returns the tool result or a blocked response.
    """
    if tool_name not in AGENT_TOOLS:
        return {"error": f"Unknown tool: {tool_name}"}

    args = arguments or {}

    # ── Guardrail validation on tool arguments ──
    # Validate the tool name and key arguments through input guardrails
    validation_text = f"Tool: {tool_name} | Args: {json.dumps(args)[:500]}"
    validation = engine.validate_input(validation_text, page_id="agent-tools",
                                       agent_name="agent")
    if not validation["safe"]:
        return {
            "blocked": True,
            "reason": validation["reason"],
            "blocked_by": validation["blocked_by"],
        }

    # ── Execute tool ──
    try:
        if tool_name == "guardrail_validate":
            text = args.get("text", "")
            kind = args.get("kind", "input")
            page = args.get("page", "default")
            agent = args.get("agent", "assistant")
            if kind == "output":
                result = engine.validate_output(text, page, agent)
            else:
                result = engine.validate_input(text, page, agent)
            return {
                "safe": result["safe"],
                "reason": result["reason"],
                "blocked_by": result.get("blocked_by"),
                "censored": result.get("censored", False),
                "sanitized": result.get("sanitized_input") or result.get("sanitized_output", ""),
            }

        elif tool_name == "file_read":
            file_path = args.get("path", "")
            # Resolve and validate path — only allow within project dir
            project_dir = os.path.dirname(os.path.abspath(__file__))
            resolved = os.path.realpath(file_path)
            if not resolved.startswith(os.path.realpath(project_dir)):
                return {"error": "File access restricted to project directory"}
            if not os.path.exists(resolved):
                return {"error": f"File not found: {file_path}"}
            if os.path.isdir(resolved):
                return {"error": f"Path is a directory: {file_path}"}
            # Check file size
            size = os.path.getsize(resolved)
            if size > 1_000_000:
                return {"error": "File too large (>1MB)"}
            try:
                with open(resolved, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(resolved, "rb") as f:
                    content = f.read(5000).hex()
                return {"content": content[:5000],
                        "note": "Binary file, shown as hex (first 5000 bytes)"}
            return {"content": content, "path": resolved, "size": size}

        elif tool_name == "file_write":
            file_path = args.get("path", "")
            content = args.get("content", "")
            # Validate path — only allow within project dir
            project_dir = os.path.dirname(os.path.abspath(__file__))
            resolved = os.path.realpath(file_path)
            if not resolved.startswith(os.path.realpath(project_dir)):
                return {"error": "File write restricted to project directory"}
            # Validate content through guardrails (fast, deterministic)
            file_validation = engine.validate_input(
                content, page_id="file-write", agent_name="agent"
            )
            if not file_validation["safe"]:
                return {
                    "blocked": True,
                    "reason": file_validation["reason"],
                    "blocked_by": file_validation["blocked_by"],
                }
            # Also validate the file path itself
            path_validation = engine.validate_input(
                file_path, page_id="file-write-path", agent_name="agent"
            )
            if not path_validation["safe"]:
                return {
                    "blocked": True,
                    "reason": path_validation["reason"],
                    "blocked_by": path_validation["blocked_by"],
                }
            # Write the file
            try:
                os.makedirs(os.path.dirname(resolved), exist_ok=True)
                with open(resolved, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception as e:
                return {"error": f"Failed to write file: {str(e)}"}
            return {
                "ok": True,
                "path": resolved,
                "bytes_written": len(content.encode("utf-8")),
                "message": f"File written: {resolved}",
            }

        elif tool_name == "system_info":
            import platform
            return {
                "os": platform.platform(),
                "python": platform.python_version(),
                "hostname": platform.node(),
                "arch": platform.machine(),
                "uptime_seconds": time.time() - psutil_boot_time(),
            }

        elif tool_name == "emergency_contain":
            script = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "scripts", "emergency-override.sh",
            )
            result = subprocess.run(
                ["bash", script, "contain"],
                capture_output=True, text=True, timeout=30,
            )
            return {
                "ok": result.returncode == 0,
                "message": "containment activated" if result.returncode == 0
                else result.stderr[:200],
            }

    except Exception as e:
        return {"error": str(e)}

    return {"error": f"Tool {tool_name} not implemented"}


def psutil_boot_time() -> float:
    """Get system boot time without psutil dependency."""
    try:
        with open("/proc/uptime", "r") as f:
            uptime = float(f.read().split()[0])
        return time.time() - uptime
    except Exception:
        return 0.0


def agentic_plan_and_act(user_text: str, session: ChatSession,
                         session_token: Optional[str] = None) -> Dict[str, Any]:
    """Run an agentic plan-act-review loop.

    1. Validate user input through guardrails
    2. Agent decides which tool to call (plan)
    3. Execute tool with validation (act)
    4. Review results and generate response
    5. Validate output through guardrails

    Returns the final assistant response and execution trace.
    """
    trace: List[Dict[str, Any]] = []

    # Step 1: Validate input
    input_validation = engine.validate_input(
        user_text, page_id="chat-agent", agent_name="agent"
    )
    trace.append({"step": "input_validation", "result": input_validation})
    if not input_validation["safe"]:
        output = (f"I cannot process that request. "
                  f"{input_validation['reason']}")
        output_validation = engine.validate_output(
            output, page_id="chat-agent", agent_name="assistant"
        )
        session.add_message("assistant", output)
        session.save()
        return {
            "response": output,
            "safe": False,
            "blocked_by": input_validation.get("blocked_by"),
            "trace": trace,
        }

    # Step 2: Agent planning — decide tool to use
    # Build a planning prompt
    tool_list = "\n".join(
        f"- {name}: {info['description']}"
        for name, info in AGENT_TOOLS.items()
    )
    plan_prompt = (
        f"You are an AI assistant with guardrails. The user said: '{user_text}'\n"
        f"Available tools:\n{tool_list}\n"
        f"Decide which tool (if any) to use. Respond with ONLY the tool name "
        f"and arguments as JSON, or 'none' if no tool is needed."
    )
    plan_validation = engine.validate_input(
        plan_prompt, page_id="chat-agent-plan", agent_name="agent"
    )
    trace.append({"step": "plan_validation", "result": plan_validation})

    # For now, use a heuristic: if the text mentions specific keywords,
    # route to appropriate tools. This avoids needing an external model
    # for planning while still being agentic.
    tool_name = "none"
    tool_args: Dict[str, Any] = {}

    text_lower = user_text.lower()
    if "validate" in text_lower or "guardrail" in text_lower:
        tool_name = "guardrail_validate"
        tool_args = {"text": user_text, "kind": "input"}
    elif "file" in text_lower and ("read" in text_lower or "open" in text_lower):
        # Extract potential file path
        tool_name = "file_read"
        tool_args = {"path": user_text}
    elif "system" in text_lower or "info" in text_lower:
        tool_name = "system_info"
        tool_args = {}
    elif "contain" in text_lower or "emergency" in text_lower:
        tool_name = "emergency_contain"
        tool_args = {}

    trace.append({"step": "plan", "tool": tool_name, "args": tool_args})

    # Step 2.5: Thought-process validation — validate the agent's reasoning
    # before acting. This is fast (deterministic regex, no LLM call).
    thought_text = f"Agent {agent_name} plans to use tool '{tool_name}' with args {json.dumps(tool_args)} for user request: {user_text[:200]}"
    thought_validation = monitor.validate_thought(
        agent_name="agent", thought=thought_text, page_id="chat-agent-thought"
    )
    trace.append({"step": "thought_validation", "result": thought_validation})
    if not thought_validation["safe"]:
        # Block the action if the thought itself is malicious
        response = (f"I cannot proceed with that action. "
                    f"The planned tool use was flagged: "
                    f"{thought_validation['reason']}")
        output_validation = engine.validate_output(
            response, page_id="chat-agent", agent_name="assistant"
        )
        trace.append({"step": "output_validation", "result": output_validation})
        session.add_message("assistant", response,
                            tool_calls=[{"name": tool_name,
                                         "arguments": tool_args}],
                            tool_results=[{"blocked": True,
                                           "reason": thought_validation["reason"]}])
        session.save()
        return {
            "response": response,
            "safe": False,
            "blocked_by": thought_validation.get("blocked_by"),
            "trace": trace,
        }

    # Step 3: Act — execute tool if selected
    tool_result: Optional[Dict[str, Any]] = None
    if tool_name != "none":
        tool_result = execute_agent_tool(tool_name, tool_args, session_token)
        trace.append({"step": "act", "tool": tool_name, "result": tool_result})

        # Validate tool output if it contains text
        if tool_result and not tool_result.get("error") \
                and not tool_result.get("blocked"):
            output_text = json.dumps(tool_result)[:2000]
            output_validation = engine.validate_output(
                output_text, page_id="chat-agent-tool", agent_name="assistant"
            )
            trace.append({"step": "tool_output_validation",
                          "result": output_validation})
            if not output_validation["safe"]:
                tool_result["blocked_by_tool_output"] = True

    # Step 4: Generate final response
    if tool_result and tool_result.get("blocked"):
        response = (f"I was blocked from using the {tool_name} tool. "
                    f"Reason: {tool_result.get('reason', 'unknown')}")
    elif tool_result and tool_result.get("error"):
        response = f"Tool error: {tool_result['error']}"
    elif tool_result:
        # Summarize tool result
        if tool_name == "guardrail_validate":
            safe = tool_result.get("safe", False)
            reason = tool_result.get("reason", "")
            response = (f"Guardrail validation: {'SAFE' if safe else 'BLOCKED'}\n"
                        f"Reason: {reason}")
        elif tool_name == "file_read":
            content = tool_result.get("content", "")
            response = f"File contents:\n\n{content[:2000]}"
        elif tool_name == "system_info":
            response = f"System info:\n{json.dumps(tool_result, indent=2)}"
        elif tool_name == "emergency_contain":
            response = f"Emergency containment: {tool_result.get('message', '')}"
        elif tool_name == "file_write":
            if tool_result.get("blocked"):
                response = (f"File write blocked: {tool_result.get('reason', '')}")
            elif tool_result.get("ok"):
                response = (f"File written: {tool_result['path']} "
                            f"({tool_result['bytes_written']} bytes)")
            else:
                response = f"File write error: {tool_result.get('error', '')}"
        else:
            response = f"Tool result: {json.dumps(tool_result, indent=2)}"
    else:
        response = (f"I understand: {user_text[:200]}...\n"
                    f"I'm running in agentic mode with guardrails enabled. "
                    f"Tell me what you'd like me to do — validate text, read "
                    f"files, check system info, or trigger emergency containment.")

    # Step 5: Validate output through guardrails
    output_validation = engine.validate_output(
        response, page_id="chat-agent", agent_name="assistant"
    )
    trace.append({"step": "output_validation", "result": output_validation})

    if not output_validation["safe"]:
        response = (f"My response was blocked by output guardrails. "
                    f"{output_validation['reason']}")

    session.add_message("assistant", response,
                        tool_calls=[{"name": tool_name, "arguments": tool_args}]
                        if tool_name != "none" else None,
                        tool_results=[tool_result] if tool_result else None)
    session.save()

    return {
        "response": response,
        "safe": output_validation["safe"],
        "blocked_by": output_validation.get("blocked_by"),
        "trace": trace,
    }


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
        if path == "/chat":
            self._serve_file(os.path.join(WEB_DIR, "chat.html"),
                             "text/html", extra_headers=cors_headers)
            return
        # chat.html loads these two relatively (chat.js / chat.css). Without
        # these handlers the agentic chat page renders unstyled and inert.
        if path in ("/chat.js", "/chat.css"):
            name = path.lstrip("/")
            ctype = ("text/javascript" if name.endswith(".js") else "text/css")
            self._serve_file(os.path.join(WEB_DIR, name),
                             ctype, extra_headers=cors_headers)
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
        # ── User and API-key administration (GET) ────────────────
        if path == "/api/users":
            from guardrail_users import list_users
            _json_response(self, 200, {"users": list_users()}, cors_headers)
            return
        if path == "/api/keys":
            from guardrail_users import list_api_keys
            _json_response(self, 200, {"keys": list_api_keys()}, cors_headers)
            return
        # ── Auth endpoints (GET) ──────────────────────────────────
        if path == "/api/auth/session":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            username = (session or {}).get("username")
            from guardrail_users import get_user, user_2fa_state
            user = get_user(username) if username else None
            _json_response(self, 200, {
                "authenticated": session is not None,
                "session": session,
                "username": username,
                "role": (user or {}).get("role"),
                "2fa_configured": bool(user and user.get("totp_enabled")) or is_2fa_configured(),
                "2fa_verified": session_2fa_verified(session),
                "2fa": user_2fa_state(username) if username else {"enabled": False},
            }, cors_headers)
            return
        if path == "/api/auth/2fa/status":
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            username = (session or {}).get("username", "admin")
            from guardrail_users import user_2fa_state
            st = user_2fa_state(username)
            _json_response(self, 200, {
                "username": username,
                **st,
                "2fa_configured": st["enabled"],
                "2fa_enabled": st["enabled"],
            }, cors_headers)
            return
        if path == "/api/auth/2fa/setup":
            # Enrolment is POST-only, requires security:manage, and is
            # non-destructive. This GET used to regenerate the secret for
            # anyone who could reach the port (fixed in the security audit).
            _json_response(self, 405, {
                "error": "use POST /api/auth/2fa/setup",
                "detail": "anonymous 2FA enrolment was removed in the security audit",
            }, cors_headers)
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
        # ── Chat endpoints (GET) ───────────────────────────────────
        if path == "/api/chat/sessions":
            sessions = ChatSession.list_all()
            _json_response(self, 200, {"sessions": sessions, "count": len(sessions)},
                           cors_headers)
            return
        if path == "/api/chat/tools":
            _json_response(self, 200, {
                "tools": [
                    {
                        "name": name,
                        "description": info["description"],
                        "parameters": info["parameters"],
                    }
                    for name, info in AGENT_TOOLS.items()
                ],
            }, cors_headers)
            return
        if path.startswith("/api/chat/sessions/"):
            session_id = path.split("/")[-1]
            session = get_chat_session(session_id)
            if not session:
                _json_response(self, 404, {"error": "session not found"},
                               cors_headers)
                return
            include_messages = self.headers.get("X-Include-Messages", "false").lower() == "true"
            _json_response(self, 200, session.to_dict(include_messages=include_messages),
                           cors_headers)
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
        result_token = getattr(result, "session_token", None)
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
        result, cors_headers = self._auth_and_preflight(path_tier(path, "DELETE"))
        if not result.ok:
            send_auth_error(self, result)
            return
        session_token = getattr(result, "session_token", None)
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
                           cors_headers, session_token=session_token)
            return
        if len(segments) == 3 and segments[1] == "users":
            from guardrail_users import set_disabled
            out = set_disabled(segments[2], True)
            _json_response(self, 200 if out.get("ok") else 400, out,
                           cors_headers, session_token=session_token)
            return
        if len(segments) == 3 and segments[1] == "keys":
            from guardrail_users import revoke_api_key
            out = revoke_api_key(segments[2])
            _json_response(self, 200 if out.get("ok") else 404, out,
                           cors_headers, session_token=session_token)
            return
        _json_response(self, 404, {"error": "not found"}, cors_headers)

    def do_PATCH(self):  # noqa: N802
        path, _ = self._route()
        result, cors_headers = self._auth_and_preflight(path_tier(path, "PATCH"))
        if not result.ok:
            send_auth_error(self, result)
            return
        segments = [s for s in path.split("/") if s]
        if len(segments) == 3 and segments[1] == "users":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"}, cors_headers)
                return
            from guardrail_users import set_role, set_disabled
            name = segments[2]
            out = {"ok": True, "username": name}
            if "role" in body:
                r = set_role(name, body["role"])
                if not r.get("ok"):
                    _json_response(self, 400, r, cors_headers)
                    return
                out["role"] = body["role"]
            if "disabled" in body:
                r = set_disabled(name, bool(body["disabled"]))
                if not r.get("ok"):
                    _json_response(self, 400, r, cors_headers)
                    return
                out["disabled"] = bool(body["disabled"])
            _json_response(self, 200, out, cors_headers)
            return
        if len(segments) == 3 and segments[1] == "chat" and segments[2] != "sessions":
            session_id = segments[2]
            # Extract just the session ID (remove any trailing parts)
            session_id = session_id.split("?")[0]
            if delete_chat_session(session_id):
                _json_response(self, 200, {"ok": True, "session_id": session_id,
                                           "removed": True},
                               cors_headers,
                               session_token=result.session_token)
            else:
                _json_response(self, 404, {"error": "session not found"},
                               cors_headers)
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
            from guardrail_users import (ensure_initialised, verify_credentials,
                                          user_2fa_state)
            ensure_initialised()
            username = (body.get("username") or "admin").strip().lower()
            user_rec = verify_credentials(username, password)
            if user_rec is None and username == "admin" and verify_password(password):
                # Legacy single-admin fallback, kept for backward compatibility
                user_rec = {"username": "admin", "role": "admin",
                            "totp_enabled": is_2fa_configured(),
                            "totp_secret": None, "backup_codes": []}
            if user_rec is not None:
                role = user_rec.get("role", "viewer")
                twofa_enabled = bool(user_rec.get("totp_enabled")) or (
                    username == "admin" and is_2fa_configured())
                # Clear login attempts on successful password
                login_ident = f"login:{self.client_address[0] if self.client_address else 'unknown'}"
                _clear_login_attempts(login_ident)
                # Log successful password step
                _log_auth_event("login_password_ok", self.client_address[0] if self.client_address else "unknown",
                               self.headers.get("User-Agent", ""))
                # ── 2FA step ──
                if twofa_enabled:
                    # Issue a temporary 2fa-pending session token
                    tmp_token = create_session(
                        self.client_address[0] if self.client_address else "unknown",
                        self.headers.get("User-Agent", ""), username, role)
                    # Mark session as 2fa-pending
                    sess = validate_session(tmp_token)
                    if sess:
                        sess["2fa_pending"] = True
                    # Verify TOTP or backup code if provided
                    totp_ok = verify_2fa_code(totp_code, username) if totp_code else False
                    backup_ok = (verify_user_backup_code(username, backup_code)
                                 or verify_backup_code(backup_code)) if backup_code else False
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
                        self.headers.get("User-Agent", ""), username, role)
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
            totp_ok = verify_2fa_code(totp_code, session.get("username")) if totp_code else False
            backup_ok = ((verify_user_backup_code(session.get("username"), backup_code)
                          or verify_backup_code(backup_code)) if backup_code else False)
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

            # ── SSRF / domain validation for custom base_url ──────────
            # Never accept a model URL that resolves to a private/internal
            # address. This blocks DNS-rebinding and SSRF attacks where an
            # attacker points the model endpoint at localhost or internal
            # services.
            if base_url and base_url.strip():
                try:
                    validate_model_url(base_url.strip(), label="model base URL")
                except ValueError as e:
                    _json_response(self, 400, {"error": str(e)},
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

        # ── Model connection test (POST) ─────────────────────────────
        # Tests connectivity to a model provider endpoint before accepting
        # it. Validates domain, SSL certificate, and HTTP reachability.
        if path == "/api/models/test":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            base_url = body.get("base_url", "")
            api_key = body.get("api_key", "")
            if not base_url:
                _json_response(self, 400, {"error": "base_url is required"},
                               cors_headers)
                return
            # SSRF/domain validation first
            try:
                validate_model_url(base_url.strip(), label="model base URL")
            except ValueError as e:
                _json_response(self, 400, {"error": str(e)},
                               cors_headers)
                return
            result = test_model_connection(base_url.strip(), api_key=api_key or None)
            _json_response(self, 200 if result["valid"] else 400, result,
                           cors_headers)
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

        # ── Chat endpoints (POST) ──────────────────────────────────
        if path == "/api/chat/sessions":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            title = body.get("title", "New Chat")
            model = body.get("model", "ollama")
            agent_mode = body.get("agent_mode", False)
            session = create_chat_session(title=title, model=model)
            session.agent_mode = agent_mode
            session.save()
            _json_response(self, 200, session.to_dict(), cors_headers)
            return

        if path == "/api/chat/message":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            session_id = body.get("session_id", "")
            text = body.get("text", "")
            model = body.get("model", "ollama")
            agent_mode = body.get("agent_mode", False)
            system_prompt = body.get("system_prompt", "")

            if not session_id:
                # Create a new session
                session = create_chat_session(title=text[:50] or "New Chat",
                                              model=model)
                session.agent_mode = agent_mode
                session.system_prompt = system_prompt
                session.save()
                session_id = session.id
            else:
                session = get_chat_session(session_id)
                if not session:
                    _json_response(self, 404, {"error": "session not found"},
                                   cors_headers)
                    return
                session.model = model
                session.agent_mode = agent_mode
                session.system_prompt = system_prompt

            # Validate session access (auth required for state-changing)
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            sess = validate_session(session_token) if session_token else None
            if not sess:
                _json_response(self, 401, {"error": "authentication required"},
                               cors_headers)
                return

            # ── Privacy: strip secrets and PII from user message ──────────
            # Never send API keys, tokens, passwords, or PII to external models.
            secrets_found = count_secrets(text)
            pii_found = detect_secrets(text)
            sanitized_text = strip_all_sensitive(text)
            if secrets_found > 0:
                _log_auth_event("chat_secret_stripped",
                               self.client_address[0] if self.client_address else "unknown",
                               detail=f"{secrets_found} secrets redacted")

            # ── Token compression for cost savings ───────────────────────
            compression_level = body.get("compression_level", "light")
            max_tokens = body.get("max_tokens", None)
            compression_result = compress_for_model(
                sanitized_text,
                compression_level=compression_level,
                max_tokens=max_tokens,
            )
            compressed_text = compression_result["compressed"]

            # Add user message (store original + sanitized version for audit)
            session.add_message("user", text,
                                tool_calls=[{"name": "privacy_strip",
                                             "arguments": {
                                                 "secrets_stripped": secrets_found,
                                                 "compression": compression_level,
                                                 "tokens_saved": compression_result["tokens_saved"],
                                             }}])
            session.save()

            # Process based on mode — use compressed text to save tokens
            if agent_mode:
                result = agentic_plan_and_act(compressed_text, session, session_token)
            else:
                # Regular chat: validate input, generate response
                input_validation = engine.validate_input(
                    compressed_text, page_id="chat", agent_name="user"
                )
                if not input_validation["safe"]:
                    response = (f"I cannot process that message. "
                                f"{input_validation['reason']}")
                else:
                    response = (f"I received: '{compressed_text[:200]}'\n"
                                f"I'm running in chat mode with guardrails. "
                                f"Enable agent mode to use tools (validate, "
                                f"file_read, system_info, emergency_contain).")
                # Validate output
                output_validation = engine.validate_output(
                    response, page_id="chat", agent_name="assistant"
                )
                if not output_validation["safe"]:
                    response = (f"My response was blocked by output guardrails. "
                                f"{output_validation['reason']}")
                result = {
                    "response": response,
                    "safe": output_validation["safe"],
                    "blocked_by": output_validation.get("blocked_by"),
                    "trace": [{"step": "input_validation",
                               "result": input_validation}],
                }

            # Add assistant response
            assistant_response = result["response"]
            # ── Privacy: strip secrets from assistant response too ───────
            assistant_response = strip_all_sensitive(assistant_response)
            assistant_secrets = count_secrets(assistant_response)
            if assistant_secrets > 0:
                _log_auth_event("chat_response_secret_stripped",
                               self.client_address[0] if self.client_address else "unknown",
                               detail=f"{assistant_secrets} secrets redacted from response")
            session.add_message("assistant", assistant_response)
            session.save()

            _json_response(self, 200, {
                "session_id": session_id,
                "response": assistant_response,
                "safe": result["safe"],
                "blocked_by": result.get("blocked_by"),
                "trace": result.get("trace", []),
                # Privacy & compression metadata
                "privacy": {
                    "secrets_stripped": secrets_found,
                    "compression": {
                        "level": compression_result["compression_level"],
                        "original_tokens": compression_result["original_tokens"],
                        "compressed_tokens": compression_result["compressed_tokens"],
                        "tokens_saved": compression_result["tokens_saved"],
                        "savings_percent": compression_result["savings_percent"],
                    },
                },
            }, cors_headers, session_token=session_token)
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

        # ── 2FA enrolment (authenticated, non-destructive) ────────
        if path == "/api/auth/2fa/setup":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                body = {}
            session_token = self.headers.get("X-Session-Token", "") or \
                self.headers.get("Cookie", "").replace("session=", "", 1)
            session = validate_session(session_token) if session_token else None
            username = (session or {}).get("username", "admin")
            from guardrail_users import get_user, user_2fa_state
            user = get_user(username) or {}
            already = bool(user.get("totp_enabled"))
            replace = str(body.get("confirm", "")).lower() == "replace"
            if already:
                # Replacement requires a fresh proof of possession: the account
                # password plus a current code (TOTP or backup code).
                if not replace:
                    _json_response(self, 409, {
                        "error": "2FA is already configured for this account",
                        "code": "already_configured",
                        "how_to_replace": "POST again with {\"confirm\":\"replace\","
                                          "\"password\":\"...\",\"code\":\"123456\"}",
                    }, cors_headers)
                    return
                if not verify_password(body.get("password", "")):
                    _json_response(self, 403, {"error": "password confirmation failed"},
                                   cors_headers)
                    return
                code = body.get("code", "")
                if not (verify_2fa_code(code, username)
                        or verify_user_backup_code(username, code)):
                    _json_response(self, 403, {"error": "current 2FA code required"},
                                   cors_headers)
                    return
            result = enable_user_2fa(username, replace=replace)
            _log_auth_event("2fa_enrolled", self.client_address[0] if self.client_address else "unknown",
                            self.headers.get("User-Agent", ""), username)
            _json_response(self, 200 if result.get("ok") else 400, result, cors_headers)
            return

        # ── User administration (POST) ────────────────────────────
        if path == "/api/users":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"}, cors_headers)
                return
            from guardrail_users import create_user
            result = create_user(body.get("username", ""), body.get("password", ""),
                                 body.get("role", "viewer"))
            _json_response(self, 200 if result.get("ok") else 400, result, cors_headers)
            return
        if len([x for x in path.split("/") if x]) == 4 and path.startswith("/api/users/") \
                and path.endswith("/password"):
            uname = [x for x in path.split("/") if x][2]
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"}, cors_headers)
                return
            from guardrail_users import set_user_password
            result = set_user_password(uname, body.get("password", ""))
            _json_response(self, 200 if result.get("ok") else 400, result, cors_headers)
            return

        # ── API keys (POST) ───────────────────────────────────────
        if path == "/api/keys":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"}, cors_headers)
                return
            from guardrail_users import create_api_key
            result = create_api_key(body.get("name", ""), body.get("role", "viewer"))
            _json_response(self, 200 if result.get("ok") else 400, result, cors_headers)
            return
        if path.startswith("/api/keys/") and path.endswith("/rotate"):
            kid = [x for x in path.split("/") if x][2]
            from guardrail_users import rotate_api_key
            result = rotate_api_key(kid)
            _json_response(self, 200 if result.get("ok") else 404, result, cors_headers)
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
            verdict = engine.validate_input(text, page, agent)
            # Model oversight (Nebius/Nemotron) — escalate-only, skipped when
            # the classifier is disabled. Runs only if every rule passed.
            verdict = monitor.apply_classifier(verdict, text, agent)
            _json_response(self, 200, verdict,
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
            verdict = engine.validate_output(text, page, agent)
            verdict = monitor.apply_classifier(verdict, text, agent)
            _json_response(self, 200, verdict,
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
        # ── Thought-process validation (fast, deterministic) ─────────
        if path == "/api/monitor/validate/thought":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            agent_name = body.get("agent", "agent")
            thought = body.get("thought", "")
            page = body.get("page", "default")
            result = monitor.validate_thought(agent_name, thought, page)
            _json_response(self, 200 if result["safe"] else 400, result,
                           cors_headers)
            return
        # ── File-change validation (fast, deterministic) ─────────────
        if path == "/api/monitor/validate/file_change":
            try:
                body = json.loads(self._read_body() or b"{}")
            except json.JSONDecodeError:
                _json_response(self, 400, {"error": "invalid json"},
                               cors_headers)
                return
            file_path = body.get("path", "")
            content = body.get("content", "")
            agent_name = body.get("agent", "agent")
            page = body.get("page", "default")
            result = monitor.validate_file_change(file_path, content,
                                                  agent_name, page)
            _json_response(self, 200 if result["safe"] else 400, result,
                           cors_headers)
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
