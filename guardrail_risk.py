#!/usr/bin/env python3
#=============================================================================
# Guardrail Risk — composite conversation-level risk scoring
#=============================================================================
# Risk is tracked per conversation (session + page), not per message. A
# single benign message can be safe while the *conversation* is risky
# because of multi-turn buildup (message 1 innocent, message 5 role
# switch). The composite score (0.0-1.0) accumulates across turns:
#
#   - Each blocked input/output adds risk
#   - Each critical failure (harmful content, PII, exfiltration, breakout)
#     adds heavy risk
#   - Repeated blocked attempts escalate faster (pattern = probing)
#   - Score decays slowly over safe turns so a long clean conversation
#     can recover
#
# Thresholds:
#   < 0.30  low     — normal operation
#   0.30-0.60 medium — elevate monitoring, log extra detail
#   0.60-0.85 high   — require human-in-the-loop review before output
#   >= 0.85 critical — block all output, trigger kill switch review
#=============================================================================

import json
import os
import time
from typing import Optional, Dict, Any, List

from guardrail import GuardrailEngine

RISK_STATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "risk_state"
)
os.makedirs(RISK_STATE_DIR, exist_ok=True)

# ── Thresholds ──────────────────────────────────────────────────────

LOW_THRESHOLD = 0.30
MEDIUM_THRESHOLD = 0.60
HIGH_THRESHOLD = 0.85

# ── Risk deltas per event type ──────────────────────────────────────

DELTA_BLOCKED_INPUT = 0.10
DELTA_BLOCKED_OUTPUT = 0.15
DELTA_CRITICAL_FAILURE = 0.30   # harmful content, PII, exfil, breakout
DELTA_PROBE_REPEAT = 0.05       # additional per repeated block in same session
DELTA_SAFE_DECAY = 0.05         # decay per safe turn (per minute of inactivity)
DECAY_INTERVAL_SEC = 60         # decay applies once per this many seconds


def _risk_level(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "critical"
    if score >= MEDIUM_THRESHOLD:
        return "high"
    if score >= LOW_THRESHOLD:
        return "medium"
    return "low"


class ConversationRisk:
    """Composite risk tracker for a single conversation session."""

    def __init__(self, session_id: str, page_id: str):
        self.session_id = session_id
        self.page_id = page_id
        self.path = os.path.join(
            RISK_STATE_DIR, f"risk_{session_id}_{page_id}.json"
        )
        self.score = 0.0
        self.blocked_count = 0
        self.critical_count = 0
        self.last_event_ts = time.time()
        self.history: List[Dict[str, Any]] = []
        self._load()

    # ── Persistence ─────────────────────────────────────────────────

    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.score = float(data.get("score", 0.0))
                self.blocked_count = int(data.get("blocked_count", 0))
                self.critical_count = int(data.get("critical_count", 0))
                self.last_event_ts = float(data.get("last_event_ts", time.time()))
                self.history = list(data.get("history", []))
            except Exception:
                pass

    def _save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({
                    "session_id": self.session_id,
                    "page_id": self.page_id,
                    "score": round(self.score, 4),
                    "blocked_count": self.blocked_count,
                    "critical_count": self.critical_count,
                    "last_event_ts": self.last_event_ts,
                    "level": _risk_level(self.score),
                    "history": self.history[-50:],  # keep last 50
                }, f, indent=2)
        except Exception:
            pass

    # ── Decay based on elapsed time ─────────────────────────────────

    def _decay(self) -> None:
        now = time.time()
        elapsed = now - self.last_event_ts
        intervals = int(elapsed // DECAY_INTERVAL_SEC)
        if intervals > 0 and self.score > 0:
            decay = min(intervals * DELTA_SAFE_DECAY, self.score)
            self.score -= decay
            self.last_event_ts = now

    # ── Event recording ─────────────────────────────────────────────

    def record_blocked(self, kind: str, is_critical: bool,
                       reason: str, detail: str = "") -> Dict[str, Any]:
        """Record a blocked event; returns updated risk state."""
        self._decay()

        if kind == "input":
            self.score += DELTA_BLOCKED_INPUT
        else:
            self.score += DELTA_BLOCKED_OUTPUT
        self.score += DELTA_PROBE_REPEAT * max(0, self.blocked_count)
        self.score = min(self.score, 1.0)

        self.blocked_count += 1
        if is_critical:
            self.critical_count += 1
            self.score += DELTA_CRITICAL_FAILURE
            self.score = min(self.score, 1.0)

        self.last_event_ts = time.time()
        entry = {
            "ts": self.last_event_ts,
            "kind": kind,
            "critical": is_critical,
            "reason": reason,
            "detail": detail,
            "score_after": round(self.score, 4),
        }
        self.history.append(entry)
        self._save()
        return self.state()

    def record_safe(self) -> Dict[str, Any]:
        """Record a safe turn; applies decay."""
        self._decay()
        self._save()
        return self.state()

    def state(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "page_id": self.page_id,
            "score": round(self.score, 4),
            "level": _risk_level(self.score),
            "blocked_count": self.blocked_count,
            "critical_count": self.critical_count,
            "last_event_ts": self.last_event_ts,
        }

    def should_block_output(self) -> bool:
        """At critical risk, block all output regardless of content."""
        return self.score >= HIGH_THRESHOLD

    def requires_human_review(self) -> bool:
        return self.score >= MEDIUM_THRESHOLD


class RiskTracker:
    """Global tracker: (session_id, page_id) -> ConversationRisk."""

    def __init__(self):
        self._risks: Dict[str, ConversationRisk] = {}

    def _key(self, session_id: str, page_id: str) -> str:
        return f"{session_id}::{page_id}"

    def get(self, session_id: str, page_id: str) -> ConversationRisk:
        key = self._key(session_id, page_id)
        if key not in self._risks:
            self._risks[key] = ConversationRisk(session_id, page_id)
        return self._risks[key]

    def all_states(self) -> List[Dict[str, Any]]:
        return [r.state() for r in self._risks.values()]


_tracker: Optional[RiskTracker] = None


def get_tracker() -> RiskTracker:
    global _tracker
    if _tracker is None:
        _tracker = RiskTracker()
    return _tracker


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    tracker = get_tracker()
    print("=" * 60)
    print("  Guardrail Risk — conversation-level composite scoring")
    print("=" * 60)
    print("  Commands:  state <session> <page>   |   all")
    print("             block <session> <page> <kind> <critical> <reason>")
    print("             safe <session> <page>    |   quit")
    print("=" * 60)
    while True:
        try:
            line = input("guardrail-risk> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not line:
            continue
        if line == "quit":
            print("Goodbye!")
            break
        if line == "all":
            for s in tracker.all_states():
                print(json.dumps(s))
            continue
        parts = line.split(None, 4)
        if parts[0] == "state" and len(parts) == 3:
            print(json.dumps(tracker.get(parts[1], parts[2]).state(), indent=2))
        elif parts[0] == "safe" and len(parts) == 3:
            print(json.dumps(tracker.get(parts[1], parts[2]).record_safe(), indent=2))
        elif parts[0] == "block" and len(parts) == 5:
            critical = parts[3].lower() in ("true", "1", "yes")
            print(json.dumps(
                tracker.get(parts[1], parts[2]).record_blocked(
                    parts[4] if len(parts) == 5 else "output",
                    critical, parts[4] if len(parts) > 4 else "",
                ), indent=2))
        else:
            print("  Usage: state|all|block|safe|quit")
        print()


if __name__ == "__main__":
    main()
