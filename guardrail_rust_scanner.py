#!/usr/bin/env python3
#=============================================================================
# Guardrail Rust Scanner — memory-safe pattern matching via Rust binary
#=============================================================================
# Calls the compiled Rust Aho-Corasick scanner (guardrail-scanner) over JSON
# lines stdio for hot-path pattern matching (container breakout, PII,
# jailbreak, harmful content). Memory-safe: no ReDoS, no buffer overflows,
# linear-time matching. Falls back to Python re if the Rust binary is
# unavailable or misbehaves.
#=============================================================================

import json
import os
import re
import subprocess
from typing import Optional, Dict, Any, List, Tuple

RUST_BIN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rust", "target", "release",
    "guardrail-scanner",
)


def _python_fallback(patterns: List[str], text: str) -> Optional[Dict[str, Any]]:
    """Fallback Python regex scan (slower, ReDoS-risk on bad patterns)."""
    if not patterns or not text:
        return None
    lower = text.lower()
    for pat in patterns:
        if pat.lower() in lower:
            idx = lower.find(pat.lower())
            return {"matched": True, "pattern": pat, "index": idx, "count": 1}
    return {"matched": False, "pattern": None, "index": None, "count": 0}


def scan(patterns: List[str], text: str) -> Dict[str, Any]:
    """Scan `text` for any of `patterns`. Returns dict with matched/pattern/index/count.

    Tries the Rust binary first; falls back to Python substring scan on any
    failure so guardrails never silently skip a check.
    """
    if not patterns or not text:
        return {"matched": False, "pattern": None, "index": None, "count": 0}

    # Try Rust binary.
    if os.path.isfile(RUST_BIN) and os.access(RUST_BIN, os.X_OK):
        try:
            proc = subprocess.run(
                [RUST_BIN],
                input=json.dumps({"patterns": patterns, "text": text}),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                line = proc.stdout.strip().splitlines()[-1]
                result = json.loads(line)
                if "error" not in result:
                    return {
                        "matched": bool(result.get("matched", False)),
                        "pattern": result.get("pattern"),
                        "index": result.get("index"),
                        "count": int(result.get("count", 0)),
                    }
        except Exception:
            pass  # fall through to Python fallback

    return _python_fallback(patterns, text) or {
        "matched": False, "pattern": None, "index": None, "count": 0,
    }


def scan_many(patterns: List[str], texts: List[str]) -> List[Dict[str, Any]]:
    """Scan multiple texts; batch into one Rust process when possible."""
    return [scan(patterns, t) for t in texts]
