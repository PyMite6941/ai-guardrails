#!/usr/bin/env python3
#=============================================================================
# Guardrail Human Loop — human-in-the-loop escalation for risky conversations
#=============================================================================
# Production best practice (Patronus AI): "Implement human-in-the-loop fallback
# strategies so that when a guardrail is uncertain, it can route the content to
# a human reviewer."
#
# When conversation risk reaches medium/high, or when the classifier is
# uncertain, the content is escalated to a human reviewer via:
#   - a webhook (configurable URL), or
#   - the console (for offline / local-first use)
#
# The reviewer can approve, block, or request a re-scan. Their decision is
# recorded to the audit log and applied to the conversation.
#=============================================================================

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable

HUMAN_LOOP_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "human_loop"
)
os.makedirs(HUMAN_LOOP_DIR, exist_ok=True)


def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


class HumanLoopConfig:
    def __init__(self, data: Optional[Dict[str, Any]] = None):
        data = data or {}
        self.enabled = bool(data.get("enabled", False))
        # "webhook" or "console"
        self.mode = data.get("mode", "console")
        self.webhook_url = data.get("webhook_url", "")
        self.webhook_api_key = data.get("webhook_api_key")
        self.timeout = int(data.get("timeout", 30))
        # Escalate when risk >= this level: low/medium/high/critical
        self.escalate_at = data.get("escalate_at", "medium")
        self.timeout_decision = bool(data.get("timeout_decision", True))
        # Seconds to wait for a human decision before auto-blocking
        self.decision_timeout_sec = int(data.get("decision_timeout_sec", 60))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "webhook_url": self.webhook_url,
            "timeout": self.timeout,
            "escalate_at": self.escalate_at,
            "decision_timeout_sec": self.decision_timeout_sec,
        }


# Risk level ordering
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class HumanLoopEscalator:
    """Escalate risky conversations to a human reviewer."""

    def __init__(self, config: Optional[HumanLoopConfig] = None):
        self.config = config or HumanLoopConfig()
        self.pending: Dict[str, Dict[str, Any]] = {}
        self.decisions: Dict[str, str] = {}  # escalation_id -> approve/block/rescan

    def should_escalate(self, risk_level: str) -> bool:
        if not self.config.enabled:
            return False
        return RISK_ORDER.get(risk_level, 0) >= RISK_ORDER.get(
            self.config.escalate_at, 1)

    def escalate(self, escalation_id: str, session_id: str, page_id: str,
                 kind: str, content: str, reason: str,
                 risk_level: str) -> Dict[str, Any]:
        """Escalate content for human review. Returns the escalation record."""
        record = {
            "escalation_id": escalation_id,
            "timestamp": _now(),
            "session_id": session_id,
            "page": page_id,
            "kind": kind,
            "risk_level": risk_level,
            "reason": reason,
            "content_preview": content[:500],
            "status": "pending",
        }
        self.pending[escalation_id] = record
        path = os.path.join(HUMAN_LOOP_DIR, f"escalation_{escalation_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        _append_jsonl(os.path.join(HUMAN_LOOP_DIR, "human_loop.jsonl"), record)

        if self.config.mode == "webhook" and self.config.webhook_url:
            self._send_webhook(record)
        else:
            # Console (local-first / offline) escalation.
            print("\n" + "=" * 60)
            print("  HUMAN REVIEW REQUIRED")
            print("=" * 60)
            print(f"  Escalation: {escalation_id}")
            print(f"  Session:    {session_id}  Page: {page_id}")
            print(f"  Kind:       {kind}  Risk: {risk_level}")
            print(f"  Reason:     {reason}")
            print(f"  Content:    {content[:300]}")
            print("  Commands: approve <id> | block <id> | rescan <id>")
            print("=" * 60 + "\n", flush=True)

        return record

    def _send_webhook(self, record: Dict[str, Any]) -> None:
        if not self.config.webhook_url:
            return
        try:
            payload = json.dumps(record).encode("utf-8")
            req = urllib.request.Request(
                self.config.webhook_url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    **( {"Authorization": f"Bearer {self.config.webhook_api_key}"}
                       if self.config.webhook_api_key else {}),
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            record["webhook_response"] = body[:500]
        except Exception as e:
            record["webhook_error"] = str(e)[:200]

    # ── Decision handling (called by CLI / webhook receiver) ──────────

    def decide(self, escalation_id: str, decision: str,
               reviewer: str = "human") -> Dict[str, Any]:
        """Record a human decision: approve, block, or rescan."""
        if decision not in ("approve", "block", "rescan"):
            return {"ok": False, "reason": "invalid decision"}
        record = self.pending.get(escalation_id)
        if record is None:
            # Try loading from disk.
            path = os.path.join(HUMAN_LOOP_DIR, f"escalation_{escalation_id}.json")
            if not os.path.exists(path):
                return {"ok": False, "reason": "escalation not found"}
            with open(path, "r", encoding="utf-8") as f:
                record = json.load(f)
            self.pending[escalation_id] = record

        record["status"] = decision
        record["reviewer"] = reviewer
        record["decided_at"] = _now()
        self.decisions[escalation_id] = decision

        # Persist.
        path = os.path.join(HUMAN_LOOP_DIR, f"escalation_{escalation_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
        _append_jsonl(os.path.join(HUMAN_LOOP_DIR, "human_loop.jsonl"), {
            "escalation_id": escalation_id,
            "timestamp": _now(),
            "decision": decision,
            "reviewer": reviewer,
        })

        return {"ok": True, "decision": decision,
                "escalation_id": escalation_id}

    def get_decision(self, escalation_id: str) -> Optional[str]:
        return self.decisions.get(escalation_id)

    def clear_decision(self, escalation_id: str) -> None:
        self.decisions.pop(escalation_id, None)
        self.pending.pop(escalation_id, None)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "mode": self.config.mode,
            "escalate_at": self.config.escalate_at,
            "pending": len(self.pending),
            "decisions": dict(self.decisions),
        }


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    escalator = HumanLoopEscalator()
    print("=" * 60)
    print("  Guardrail Human Loop — human-in-the-loop escalation")
    print("=" * 60)
    print("  Commands:  escalate <id> <session> <page> <kind> <risk> <reason>")
    print("             decide <id> <approve|block|rescan> [reviewer]")
    print("             stats                |   quit")
    print("=" * 60)
    while True:
        try:
            line = input("human-loop> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not line:
            continue
        if line == "quit":
            print("Goodbye!")
            break
        if line == "stats":
            print(json.dumps(escalator.get_stats(), indent=2))
            continue
        parts = line.split(None, 6)
        if parts[0] == "escalate" and len(parts) >= 6:
            eid, session, page, kind, risk = parts[1], parts[2], parts[3], parts[4], parts[5]
            reason = parts[6] if len(parts) > 6 else "escalated for review"
            content = input("  Content to review: ")
            rec = escalator.escalate(eid, session, page, kind, content,
                                     reason, risk)
            print(json.dumps(rec, indent=2))
        elif parts[0] == "decide" and len(parts) >= 3:
            reviewer = parts[3] if len(parts) > 3 else "human"
            print(json.dumps(escalator.decide(parts[1], parts[2], reviewer),
                             indent=2))
        else:
            print("  Usage: escalate|decide|stats|quit")
        print()


if __name__ == "__main__":
    main()
