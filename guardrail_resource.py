#!/usr/bin/env python3
#=============================================================================
# Guardrail Resource Guard — per-session tool-call budgets
#=============================================================================
# Lightweight, dependency-free resource budgets for agentic tool use:
#   - max tool calls per session
#   - max total argument bytes per session
#   - max concurrent tool calls
#
# Designed to be cheap on the hot path: plain dict counters, a single lock,
# no file I/O and no external dependencies. Fail-closed: when a budget is
# exceeded the call is rejected before anything executes.
#=============================================================================

import os
import threading
import time
from typing import Any, Dict, Optional, Tuple


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get("GUARDRAIL_" + name,
                                  os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


DEFAULT_MAX_CALLS_PER_SESSION = _env_int("MAX_TOOL_CALLS_PER_SESSION", 200)
DEFAULT_MAX_ARG_BYTES_PER_SESSION = _env_int("MAX_TOOL_ARG_BYTES_PER_SESSION",
                                             4 * 1024 * 1024)
DEFAULT_MAX_CONCURRENT_CALLS = _env_int("MAX_CONCURRENT_TOOL_CALLS", 8)


class ResourceGuard:
    """Thread-safe per-session resource budgets for agent tool calls.

    Budgets are enforced per session_id. All counters live in memory
    (nothing is written to disk on the hot path), so the guard adds
    microseconds per call even under the threaded HTTP server.
    """

    def __init__(self,
                 max_calls_per_session: int = DEFAULT_MAX_CALLS_PER_SESSION,
                 max_arg_bytes_per_session: int = DEFAULT_MAX_ARG_BYTES_PER_SESSION,
                 max_concurrent_calls: int = DEFAULT_MAX_CONCURRENT_CALLS) -> None:
        self.max_calls_per_session = max_calls_per_session
        self.max_arg_bytes_per_session = max_arg_bytes_per_session
        self.max_concurrent_calls = max_concurrent_calls
        self._lock = threading.Lock()
        # session_id -> {"calls": int, "bytes": int, "active": int, "created": float}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self.stats: Dict[str, int] = {
            "reservations": 0, "rejected": 0,
            "begins": 0, "ends": 0, "concurrency_rejections": 0,
        }

    def _session(self, session_id: str) -> Dict[str, Any]:
        return self._sessions.setdefault(
            session_id, {"calls": 0, "bytes": 0, "active": 0,
                         "created": time.time()})

    def reserve(self, session_id: str = "default", arg_bytes: int = 0,
                calls: int = 1) -> Tuple[bool, Optional[str]]:
        """Pre-flight budget check. Returns (ok, reason)."""
        session_id = session_id or "default"
        arg_bytes = max(0, int(arg_bytes))
        calls = max(1, int(calls))
        with self._lock:
            s = self._session(session_id)
            self.stats["reservations"] += 1
            if s["calls"] + calls > self.max_calls_per_session:
                self.stats["rejected"] += 1
                return (False,
                        f"tool call budget exceeded "
                        f"({s['calls']}/{self.max_calls_per_session} calls used)")
            if s["bytes"] + arg_bytes > self.max_arg_bytes_per_session:
                self.stats["rejected"] += 1
                return (False,
                        f"tool argument budget exceeded "
                        f"({s['bytes']}/{self.max_arg_bytes_per_session} bytes used)")
            s["calls"] += calls
            s["bytes"] += arg_bytes
            return True, None

    def begin_call(self, session_id: str = "default"
                   ) -> Tuple[bool, Optional[str]]:
        """Mark the start of a concurrent tool call. Returns (ok, reason)."""
        session_id = session_id or "default"
        with self._lock:
            s = self._session(session_id)
            if s["active"] >= self.max_concurrent_calls:
                self.stats["concurrency_rejections"] += 1
                return (False,
                        f"concurrent tool call limit reached "
                        f"({self.max_concurrent_calls})")
            s["active"] += 1
            self.stats["begins"] += 1
            return True, None

    def end_call(self, session_id: str = "default") -> None:
        session_id = session_id or "default"
        with self._lock:
            s = self._session(session_id)
            s["active"] = max(0, s["active"] - 1)
            self.stats["ends"] += 1

    def status(self, session_id: str = "default") -> Dict[str, Any]:
        session_id = session_id or "default"
        with self._lock:
            s = self._session(session_id)
            return {
                "session": session_id,
                "calls": s["calls"],
                "max_calls": self.max_calls_per_session,
                "calls_remaining": max(0, self.max_calls_per_session - s["calls"]),
                "bytes": s["bytes"],
                "max_bytes": self.max_arg_bytes_per_session,
                "bytes_remaining": max(0, self.max_arg_bytes_per_session - s["bytes"]),
                "active": s["active"],
                "max_concurrent": self.max_concurrent_calls,
            }

    def reset_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "sessions_tracked": len(self._sessions),
                **dict(self.stats),
                "max_calls_per_session": self.max_calls_per_session,
                "max_arg_bytes_per_session": self.max_arg_bytes_per_session,
                "max_concurrent_calls": self.max_concurrent_calls,
            }


_default_guard: Optional[ResourceGuard] = None


def get_resource_guard() -> ResourceGuard:
    """Module-level default guard (one per process)."""
    global _default_guard
    if _default_guard is None:
        _default_guard = ResourceGuard()
    return _default_guard


def main() -> None:
    guard = ResourceGuard()
    ok, reason = guard.reserve("s1", arg_bytes=100)
    print("reserve 1:", ok, reason)
    ok, reason = guard.begin_call("s1")
    print("begin:", ok, reason)
    guard.end_call("s1")
    print("status:", guard.status("s1"))
    print("stats:", guard.get_stats())
    print("smoke test passed")


if __name__ == "__main__":
    main()
