#!/usr/bin/env python3
#=============================================================================
# Guardrail Logging — unified structured logging for all guardrail modules
#=============================================================================
# Provides a single, consistent logging interface used by every guardrail
# component. Features:
#   - Structured JSONL log entries (one JSON object per line)
#   - Size-based log rotation (max size + max count)
#   - Per-module log files in a configurable logs directory
#   - Session-scoped logging for correlating events across turns
#   - Console + file output
#   - No external dependencies (stdlib only)
#
# All paths are relative to this file or configurable via env vars — nothing
# is hardcoded to a specific user or host. Works on Raspberry Pi, desktop,
# or inside Docker.
#
# Environment variables:
#   AI_GUARDRAILS_LOG_DIR   Directory for log files (default: <project>/logs)
#   AI_GUARDRAIL_LOG_LEVEL  Minimum level: DEBUG, INFO, WARN, ERROR, CRITICAL
#   AI_GUARDRAIL_LOG_ROTATE Max size in MB before rotation (default: 10)
#   AI_GUARDRAIL_LOG_KEEP   Number of rotated files to keep (default: 5)
#=============================================================================

import json
import os
import sys
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any

LOG_LEVELS: Dict[str, int] = {
    "DEBUG": 10,
    "INFO": 20,
    "WARN": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

DEFAULT_LOG_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs"
)
LOG_DIR = os.environ.get("AI_GUARDRAILS_LOG_DIR", DEFAULT_LOG_DIR)
LOG_LEVEL = LOG_LEVELS.get(
    os.environ.get("AI_GUARDRAIL_LOG_LEVEL", "INFO").upper(), 20
)
LOG_ROTATE_MB = int(os.environ.get("AI_GUARDRAIL_LOG_ROTATE", "10"))
LOG_KEEP = int(os.environ.get("AI_GUARDRAIL_LOG_KEEP", "5"))

os.makedirs(LOG_DIR, exist_ok=True)

_write_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rotate_if_needed(path: str) -> None:
    """Rotate a log file if it exceeds LOG_ROTATE_MB."""
    try:
        if not os.path.exists(path):
            return
        size_mb = os.path.getsize(path) / (1024 * 1024)
        if size_mb < LOG_ROTATE_MB:
            return
        # Rotate: shift existing backups, then start fresh
        for i in range(LOG_KEEP - 1, 0, -1):
            src = f"{path}.{i}"
            dst = f"{path}.{i + 1}"
            if os.path.exists(src):
                os.rename(src, dst)
        if os.path.exists(path):
            os.rename(path, f"{path}.1")
    except Exception:
        pass  # Never let logging break the application


def _write_line(path: str, line: str) -> None:
    """Append a single line to a log file with rotation and locking."""
    _rotate_if_needed(path)
    with _write_lock:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass  # Never let logging break the application


class GuardrailLogger:
    """Structured logger for guardrail components.

    Each logger instance writes to a dedicated JSONL file. All entries
    include timestamp, level, module, session_id (if provided), and a
    free-form message dict.
    """

    def __init__(self, module: str, session_id: Optional[str] = None):
        self.module = module
        self.session_id = session_id
        self.log_path = os.path.join(LOG_DIR, f"{module}.jsonl")

    def _entry(self, level: str, message: str, **fields: Any) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "ts": _now_iso(),
            "level": level,
            "module": self.module,
            "message": message,
        }
        if self.session_id:
            entry["session"] = self.session_id
        if fields:
            entry["data"] = fields
        return entry

    def _log(self, level: str, message: str, **fields: Any) -> None:
        if LOG_LEVELS.get(level, 0) < LOG_LEVEL:
            return
        entry = self._entry(level, message, **fields)
        _write_line(self.log_path, json.dumps(entry, separators=(",", ":")))

    def debug(self, message: str, **fields: Any) -> None:
        self._log("DEBUG", message, **fields)

    def info(self, message: str, **fields: Any) -> None:
        self._log("INFO", message, **fields)

    def warn(self, message: str, **fields: Any) -> None:
        self._log("WARN", message, **fields)

    def error(self, message: str, **fields: Any) -> None:
        self._log("ERROR", message, **fields)

    def critical(self, message: str, **fields: Any) -> None:
        self._log("CRITICAL", message, **fields)

    def log(self, level: str, message: str, **fields: Any) -> None:
        """Generic log method that dispatches to the appropriate level method."""
        level_upper = level.upper()
        if level_upper == "DEBUG":
            self.debug(message, **fields)
        elif level_upper == "INFO":
            self.info(message, **fields)
        elif level_upper == "WARN":
            self.warn(message, **fields)
        elif level_upper == "ERROR":
            self.error(message, **fields)
        elif level_upper == "CRITICAL":
            self.critical(message, **fields)
        else:
            self._log(level_upper, message, **fields)


# ── Global logger registry ──────────────────────────────────────────────

_loggers: Dict[str, GuardrailLogger] = {}


def get_logger(module: str, session_id: Optional[str] = None) -> GuardrailLogger:
    """Get or create a logger for the given module name."""
    key = f"{module}:{session_id or 'global'}"
    if key not in _loggers:
        _loggers[key] = GuardrailLogger(module, session_id)
    return _loggers[key]


def set_log_dir(path: str) -> None:
    """Change the global log directory (mostly for testing)."""
    global LOG_DIR
    LOG_DIR = path
    os.makedirs(LOG_DIR, exist_ok=True)


def set_log_level(level: str) -> None:
    """Change the global minimum log level."""
    global LOG_LEVEL
    LOG_LEVEL = LOG_LEVELS.get(level.upper(), 20)


def get_log_dir() -> str:
    return LOG_DIR


def get_log_level() -> int:
    return LOG_LEVEL


def rotate_all() -> None:
    """Manually trigger rotation on all module log files."""
    for logger in _loggers.values():
        _rotate_if_needed(logger.log_path)


# ── Backward-compatible module-level function (used by guardrail.py) ──────

_engine_logger: Optional[GuardrailLogger] = None


def _get_engine_logger() -> GuardrailLogger:
    global _engine_logger
    if _engine_logger is None:
        _engine_logger = GuardrailLogger("guardrail")
    return _engine_logger


def log(message: str, level: str = "INFO") -> None:
    """Module-level log function (backward compatible with guardrail.py).

    Writes to logs/guardrail.jsonl and stdout.
    """
    logger = _get_engine_logger()
    level_upper = level.upper()
    if LOG_LEVELS.get(level_upper, 0) >= LOG_LEVEL:
        entry = logger._entry(level_upper, message)
        line = json.dumps(entry, separators=(",", ":"))
        print(line, end="")
        _write_line(logger.log_path, line)


# ── CLI ─────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Guardrail logging utility")
    parser.add_argument("command", choices=["rotate", "stats", "tail"])
    parser.add_argument("module", nargs="?", default="guardrail")
    parser.add_argument("--lines", type=int, default=20)
    args = parser.parse_args()

    if args.command == "rotate":
        rotate_all()
        print("Log rotation complete.")
    elif args.command == "stats":
        logger = get_logger(args.module)
        print(f"Module: {args.module}")
        print(f"Log file: {logger.log_path}")
        print(f"Log dir: {LOG_DIR}")
        print(f"Log level: {LOG_LEVEL}")
        print(f"Rotate MB: {LOG_ROTATE_MB}")
        print(f"Keep: {LOG_KEEP}")
    elif args.command == "tail":
        path = os.path.join(LOG_DIR, f"{args.module}.jsonl")
        if not os.path.exists(path):
            print(f"No log file: {path}")
            return
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-args.lines:]:
            print(line.rstrip())


if __name__ == "__main__":
    main()
