#!/usr/bin/env python3
#=============================================================================
# Agentic tool-call guardrails
#=============================================================================
# Validates agent tool calls *before* execution:
#   - tool must be registered (allowlist, default-deny)
#   - argument schema validation (required fields, types, size limits)
#   - dangerous argument scan (command injection, shell escapes,
#     container/host escape paths, exfiltration URLs)
#   - per-session resource budget (calls, bytes, concurrency)
#   - destructive tools require explicit confirmation
#
# Fail-closed: anything that does not match a registered, allowed, in-budget
# tool is blocked. Lightweight: compiled patterns at import, stdlib only,
# early exit on the first failing check. Used by guardrail_server.py's
# agentic chat harness and exposed over HTTP at /api/tools/validate.
#=============================================================================

import json
import re
import threading
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from guardrail import canonicalize
from guardrail_resource import (DEFAULT_MAX_ARG_BYTES_PER_SESSION,
                                ResourceGuard, get_resource_guard)


# ── Patterns scanned inside every string argument value ─────────────────────
# Substring matches (case-insensitive) after canonicalization, so encoding
# tricks cannot smuggle a dangerous command past the guard.
DANGEROUS_ARG_PATTERNS = [
    # command injection / shell escapes
    "rm -rf", "format disk", "mkfs", "fdisk", "dd if=", "chmod 777",
    "chmod -R", "chown ", "sudo ", "su -", "setuid", "setgid",
    "exec(", "eval(", "subprocess", "os.system", "popen", "Popen(",
    "curl | bash", "curl | sh", "wget | bash", "wget | sh", "bash -c",
    "sh -c", "reverse shell", "nc -", "netcat", "/bin/sh", "/bin/bash",
    "cmd.exe", "powershell",
    # container / host escape
    "docker.sock", "/var/run/docker.sock", "/proc/", "/sys/", "cgroup",
    "release_agent", "169.254.169.254", "kubelet", "etcd ", "runc",
    "containerd", "kubectl", "nsenter", "chroot", "mount ", "umount ",
    # credentials / persistence
    "~/.ssh", "id_rsa", "id_dsa", "authorized_keys", "known_hosts",
    # networking / firewall
    "iptables", "nftables",
    # destructive data ops
    "delete all", "drop table", "truncate", "> /dev/",
]

# Argument *names* that imply shell/execution access. Blocked unless the
# tool explicitly declares allows_shell=True.
DANGEROUS_ARG_NAMES = {
    "shell", "command", "cmd", "exec", "eval", "run", "script", "code",
    "binary", "payload",
}

# Tool *names* that are dangerous by default (shadowing common binaries).
DANGEROUS_TOOL_NAMES = {
    "rm", "del", "delete", "format", "fdisk", "mkfs", "shutdown",
    "reboot", "poweroff", "passwd", "chmod", "chown", "curl", "wget",
    "ssh", "nc", "netcat", "iptables", "mount", "umount",
}

DEFAULT_MAX_ARG_BYTES = 64 * 1024  # per tool call, all args combined


def _compile_patterns(patterns: List[str]) -> List[Any]:
    return [re.compile(re.escape(p), re.IGNORECASE) for p in patterns]


_COMPILED_DANGEROUS = _compile_patterns(DANGEROUS_ARG_PATTERNS)


# ── Tool specification ──────────────────────────────────────────────────────

class ToolSpec:
    """A registered agent tool, with its validation policy."""

    def __init__(self,
                 name: str,
                 description: str = "",
                 input_schema: Optional[Dict[str, Any]] = None,
                 allowed: bool = True,
                 destructive: bool = False,
                 require_confirm: bool = False,
                 allows_shell: bool = False,
                 max_arg_bytes: int = DEFAULT_MAX_ARG_BYTES,
                 max_calls_per_session: Optional[int] = None,
                 page_id: str = "agent-tools") -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema or {
            "type": "object", "properties": {}, "required": [],
        }
        self.allowed = allowed
        self.destructive = destructive
        self.require_confirm = require_confirm or destructive
        self.allows_shell = allows_shell
        self.max_arg_bytes = max_arg_bytes
        self.max_calls_per_session = max_calls_per_session
        self.page_id = page_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.input_schema,
            "allowed": self.allowed,
            "destructive": self.destructive,
            "require_confirm": self.require_confirm,
            "allows_shell": self.allows_shell,
            "max_arg_bytes": self.max_arg_bytes,
            "page_id": self.page_id,
        }


# Default tool registry for the built-in agentic chat harness.
DEFAULT_TOOL_SPECS = [
    ToolSpec(
        "guardrail_validate",
        "Validate text through the AI guardrails (input/output checks).",
        {"type": "object", "properties": {
            "text": {"type": "string", "maxLength": 4096},
            "kind": {"type": "string", "enum": ["input", "output"]},
            "page": {"type": "string", "maxLength": 128},
            "agent": {"type": "string", "maxLength": 128},
        }, "required": ["text"]}),
    ToolSpec(
        "file_read",
        "Read a file from the local filesystem (read-only, project dir).",
        {"type": "object", "properties": {
            "path": {"type": "string", "maxLength": 4096},
        }, "required": ["path"]}),
    ToolSpec(
        "file_write",
        "Write content to a file within the project directory.",
        {"type": "object", "properties": {
            "path": {"type": "string", "maxLength": 4096},
            "content": {"type": "string", "maxLength": 1000000},
        }, "required": ["path", "content"]},
         destructive=True, require_confirm=True),
    ToolSpec(
        "system_info",
        "Get system information (OS, Python version, uptime).",
        {"type": "object", "properties": {}, "required": []}),
    ToolSpec(
        "emergency_contain",
        "Trigger emergency containment (stage 1) — blocks the API port.",
        {"type": "object", "properties": {}, "required": []},
        destructive=True, require_confirm=True),
]


# ── Tool-call guardrail ─────────────────────────────────────────────────────

class ToolCallGuardrail:
    """Validates agent tool calls before they are executed."""

    def __init__(self,
                 engine: Optional[Any] = None,
                 resource_guard: Optional[ResourceGuard] = None) -> None:
        self.engine = engine
        self._tools: Dict[str, ToolSpec] = {}
        self._lock = threading.Lock()
        self.resource_guard = resource_guard or get_resource_guard()
        self.stats: Dict[str, Any] = {
            "calls_validated": 0, "calls_blocked": 0,
            "by_tool": {}, "by_reason": {},
        }

    # ── Registry ──────────────────────────────────────────────────────

    def register_tool(self, spec: ToolSpec) -> None:
        with self._lock:
            self._tools[spec.name] = spec

    def unregister_tool(self, name: str) -> bool:
        with self._lock:
            if name in self._tools:
                del self._tools[name]
                return True
            return False

    def get_tool(self, name: str) -> Optional[ToolSpec]:
        with self._lock:
            return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [spec.to_dict() for spec in self._tools.values()]

    # ── Validation ────────────────────────────────────────────────────

    def validate_call(self,
                      tool_name: str,
                      args: Optional[Dict[str, Any]] = None,
                      session_id: str = "default",
                      confirm: bool = False,
                      page_id: str = "agent-tools") -> Dict[str, Any]:
        """Validate a tool call before execution. Fail-closed result dict:

        {"safe", "blocked", "reason", "blocked_by", "tool", "args",
         "sanitized_args", "session", "page", "checks"}
        """
        args = args or {}
        session_id = session_id or "default"
        result: Dict[str, Any] = {
            "safe": False, "blocked": True, "reason": "", "blocked_by": None,
            "tool": tool_name, "args": args, "sanitized_args": {},
            "session": session_id, "page": page_id, "checks": {},
        }
        self.stats["calls_validated"] += 1

        def fail(blocked_by: str, reason: str) -> Dict[str, Any]:
            result["safe"] = False
            result["blocked"] = True
            result["reason"] = reason
            result["blocked_by"] = blocked_by
            result["checks"][blocked_by] = {"passed": False, "reason": reason}
            self.stats["calls_blocked"] += 1
            self.stats["by_tool"][tool_name] = (
                self.stats["by_tool"].get(tool_name, 0) + 1)
            self.stats["by_reason"][blocked_by] = (
                self.stats["by_reason"].get(blocked_by, 0) + 1)
            return result

        # 1. known tool (default-deny: unknown tools can never run)
        spec = self.get_tool(tool_name)
        if spec is None:
            return fail("unknown_tool",
                        f"Unknown or unregistered tool: {tool_name}")
        if not spec.allowed:
            return fail("tool_disabled",
                        f"Tool is disabled: {tool_name}")

        # 2. per-session resource budget (fail before any parsing work)
        arg_bytes = len(json.dumps(args).encode("utf-8"))
        ok, reason = self.resource_guard.reserve(
            session_id, arg_bytes=arg_bytes, calls=1)
        if not ok:
            return fail("budget_exceeded", reason)

        result["checks"]["budget"] = {
            "passed": True,
            "reason": f"{arg_bytes} argument bytes reserved",
        }

        # 3. argument schema validation
        schema_ok, schema_reason = self._validate_schema(spec, args)
        result["checks"]["schema"] = {
            "passed": schema_ok, "reason": schema_reason,
        }
        if not schema_ok:
            return fail("schema", schema_reason)

        # 4. dangerous argument content
        dangerous_ok, dangerous_reason, sanitized = self._scan_dangerous_args(
            spec, args)
        result["checks"]["dangerous_arguments"] = {
            "passed": dangerous_ok, "reason": dangerous_reason,
        }
        if not dangerous_ok:
            result["sanitized_args"] = sanitized
            return fail("dangerous_arguments", dangerous_reason)

        # 5. destructive tools require explicit confirmation
        if spec.require_confirm and not confirm:
            return fail("confirmation_required",
                        f"Destructive tool {tool_name} requires confirm=true")

        result["safe"] = True
        result["blocked"] = False
        result["reason"] = "Tool call allowed"
        result["sanitized_args"] = self._sanitize_args(spec, args)
        result["checks"]["confirmation"] = {
            "passed": True, "reason": "confirmation not required",
        }
        return result

    # ── Internal checks ───────────────────────────────────────────────

    @staticmethod
    def _type_matches(value: Any, expected: str) -> bool:
        if expected == "string":
            return isinstance(value, str)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected == "array":
            return isinstance(value, list)
        if expected == "object":
            return isinstance(value, dict)
        return True  # unknown types: permit (schema is advisory for them)

    def _validate_schema(self,
                         spec: ToolSpec,
                         args: Dict[str, Any]) -> Tuple[bool, str]:
        schema = spec.input_schema or {}
        props = schema.get("properties", {}) or {}
        required = schema.get("required", []) or []
        additional = schema.get("additionalProperties", True)

        for field in required:
            if field not in args:
                return False, f"Missing required argument: {field}"

        for key, value in args.items():
            if key not in props:
                if additional is False:
                    return False, f"Additional argument not allowed: {key}"
                continue
            pschema = props[key] or {}
            expected = pschema.get("type")
            if expected and not self._type_matches(value, expected):
                return (False,
                        f"Argument {key} must be {expected}, "
                        f"got {type(value).__name__}")
            if expected == "string" and isinstance(value, str):
                max_len = pschema.get("maxLength")
                if max_len is not None and len(value) > int(max_len):
                    return (False,
                            f"Argument {key} too long "
                            f"({len(value)} > {max_len})")
                min_len = pschema.get("minLength")
                if min_len is not None and len(value) < int(min_len):
                    return (False,
                            f"Argument {key} too short "
                            f"({len(value)} < {min_len})")
            if expected in ("integer", "number") and isinstance(value, (int, float)):
                if "minimum" in pschema and value < pschema["minimum"]:
                    return False, f"Argument {key} below minimum {pschema['minimum']}"
                if "maximum" in pschema and value > pschema["maximum"]:
                    return False, f"Argument {key} above maximum {pschema['maximum']}"
        return True, "Schema valid"

    def _scan_dangerous_args(self,
                             spec: ToolSpec,
                             args: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """Scan string argument values for dangerous content.

        Returns (ok, reason, sanitized_args). sanitized_args mirrors args
        with matched string values replaced by "[redacted]".
        """
        sanitized: Dict[str, Any] = dict(args)
        for key, value in args.items():
            # Argument names that imply shell access are not allowed unless
            # the tool explicitly declares allows_shell=True.
            if (not spec.allows_shell and isinstance(value, str)
                    and value.strip() and key.lower() in DANGEROUS_ARG_NAMES):
                return (False,
                        f"Shell/execution argument not allowed: {key}",
                        sanitized)
            if isinstance(value, str):
                cleaned = canonicalize(value).lower()
                for pattern in _COMPILED_DANGEROUS:
                    if pattern.search(cleaned):
                        matched = pattern.pattern
                        sanitized[key] = "[redacted]"
                        return (False,
                                f"Dangerous argument content in {key}: "
                                f"{matched[:60]}",
                        sanitized)
            elif isinstance(value, (list, dict)):
                text = json.dumps(value)[:2000]
                cleaned = canonicalize(text).lower()
                for pattern in _COMPILED_DANGEROUS:
                    if pattern.search(cleaned):
                        return (False,
                                f"Dangerous argument content in {key}",
                                sanitized)
        return True, "Arguments clean", sanitized

    @staticmethod
    def _sanitize_args(spec: ToolSpec,
                       args: Dict[str, Any]) -> Dict[str, Any]:
        """Best-effort cleaned copy of the args (no PII redaction here;
        just a normalized shape for the caller to reuse)."""
        out: Dict[str, Any] = {}
        for key, value in args.items():
            if isinstance(value, str):
                out[key] = canonicalize(value)[: spec.max_arg_bytes]
            else:
                out[key] = value
        return out

    # ── Observability ─────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "calls_validated": self.stats["calls_validated"],
                "calls_blocked": self.stats["calls_blocked"],
                "by_tool": dict(self.stats["by_tool"]),
                "by_reason": dict(self.stats["by_reason"]),
                "tools_registered": len(self._tools),
            }


_default_guardrail: Optional[ToolCallGuardrail] = None


def get_tool_guardrail() -> ToolCallGuardrail:
    """Module-level default guardrail (one per process)."""
    global _default_guardrail
    if _default_guardrail is None:
        _default_guardrail = ToolCallGuardrail()
        for spec in DEFAULT_TOOL_SPECS:
            _default_guardrail.register_tool(spec)
    return _default_guardrail


def validate_tool_call(tool_name: str,
                       args: Optional[Dict[str, Any]] = None,
                       session_id: str = "default",
                       confirm: bool = False) -> Dict[str, Any]:
    """Convenience wrapper over the default tool-guardrail instance."""
    return get_tool_guardrail().validate_call(
        tool_name, args, session_id=session_id, confirm=confirm)


def main() -> None:
    guardrail = get_tool_guardrail()

    # 1. Safe call passes
    r = guardrail.validate_call("system_info", {}, session_id="smoke")
    assert r["safe"] is True, r

    # 2. Unknown tool blocked (default-deny)
    r = guardrail.validate_call("rm", {}, session_id="smoke")
    assert r["safe"] is False and r["blocked_by"] == "unknown_tool", r

    # 3. Dangerous argument content blocked + redacted (non-destructive tool
    #    so the dangerous-args check runs before confirmation)
    r = guardrail.validate_call("guardrail_validate",
                                {"text": "rm -rf /tmp/x"},
                                session_id="smoke")
    assert r["safe"] is False and r["blocked_by"] == "dangerous_arguments", r
    assert r["sanitized_args"].get("text") == "[redacted]", r

    # 4. Missing required argument blocked
    r = guardrail.validate_call("file_write", {"path": "x.txt"},
                                session_id="smoke")
    assert r["safe"] is False and r["blocked_by"] == "schema", r

    # 5. Wrong argument type blocked
    r = guardrail.validate_call("file_write",
                                {"path": 123, "content": "hi"},
                                session_id="smoke")
    assert r["safe"] is False and r["blocked_by"] == "schema", r

    # 6. Destructive tool requires confirmation
    r = guardrail.validate_call("emergency_contain", {}, session_id="smoke")
    assert r["safe"] is False and r["blocked_by"] == "confirmation_required", r
    r = guardrail.validate_call("emergency_contain", {},
                                session_id="smoke", confirm=True)
    assert r["safe"] is True, r

    # 7. Budget rejection
    tight = ToolCallGuardrail(resource_guard=ResourceGuard(
        max_calls_per_session=1, max_arg_bytes_per_session=100,
        max_concurrent_calls=1))
    tight.register_tool(DEFAULT_TOOL_SPECS[3])  # system_info
    assert tight.validate_call("system_info", {}, session_id="budget")["safe"]
    r = tight.validate_call("system_info", {}, session_id="budget")
    assert r["safe"] is False and r["blocked_by"] == "budget_exceeded", r

    # 8. Stats recorded
    stats = guardrail.get_stats()
    assert stats["calls_validated"] > 0 and stats["calls_blocked"] > 0

    print("tool-call guardrail smoke test passed")
    print("  tools registered:", stats["tools_registered"])
    print(f"  calls validated: {stats['calls_validated']}, "
          f"blocked: {stats['calls_blocked']}")


if __name__ == "__main__":
    main()
