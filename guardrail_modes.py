#!/usr/bin/env python3
#=============================================================================
# Guardrail Modes — training / testing / running operational modes
#=============================================================================
# The engine runs in one of three modes:
#
#   TRAINING   — record every validation decision, collect labeled data
#                (safe/blocked + reason), suggest new patterns from
#                observed content, warn instead of block. Safe for
#                bootstrapping policy from real traffic.
#   TESTING    — run an adversarial test suite (jailbreak, container
#                breakout, exfiltration, PII, etc.), measure catch rate
#                and false-positive rate, report effectiveness. No
#                production traffic is affected.
#   RUNNING    — full enforcement. Inputs/outputs are blocked + censored
#                on guardrail trip, kill switch fires on critical
#                failures, outer monitor + audit logging active.
#
# Mode is persisted so restarts stay in the same mode unless changed.
#=============================================================================

import json
import os
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from guardrail import GuardrailEngine, GuardrailPolicy

MODE_PATH = os.path.expanduser("~/.ai_guardrails_mode.json")
TRAINING_LOG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "training_decisions.jsonl"
)
os.makedirs(os.path.dirname(TRAINING_LOG), exist_ok=True)


class GuardrailMode(Enum):
    TRAINING = "training"
    TESTING = "testing"
    RUNNING = "running"

    def __str__(self):
        return self.value


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def load_mode() -> GuardrailMode:
    if os.path.exists(MODE_PATH):
        try:
            with open(MODE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return GuardrailMode(data.get("mode", GuardrailMode.RUNNING.value))
        except Exception:
            return GuardrailMode.RUNNING
    return GuardrailMode.RUNNING


def save_mode(mode: GuardrailMode) -> None:
    with open(MODE_PATH, "w", encoding="utf-8") as f:
        json.dump({"mode": mode.value, "updated_at": _now()}, f, indent=2)


def set_mode(mode: GuardrailMode) -> GuardrailMode:
    save_mode(mode)
    return mode


class ModeledGuardrail:
    """Wrap GuardrailEngine with mode-aware behavior.

    TRAINING: never blocks; records decision + content for labeling.
    TESTING:  enforces but flags decisions for test metrics.
    RUNNING:  full enforcement + censor + kill switch (engine default).
    """

    def __init__(self, engine: Optional[GuardrailEngine] = None,
                 mode: Optional[GuardrailMode] = None):
        self.engine = engine or GuardrailEngine()
        self.mode = mode or load_mode()
        self.training_samples: List[Dict[str, Any]] = []

    # ── Mode accessors ──────────────────────────────────────────────

    def get_mode(self) -> GuardrailMode:
        return self.mode

    def switch_mode(self, mode: GuardrailMode) -> None:
        self.mode = mode
        save_mode(mode)

    # ── Input validation (mode-aware) ───────────────────────────────

    def validate_input(self, user_input: str, page_id: str = "default",
                       agent_name: str = "user") -> Dict[str, Any]:
        result = self.engine.validate_input(user_input, page_id, agent_name)
        result["mode"] = self.mode.value

        if self.mode == GuardrailMode.TRAINING:
            # In training: never block for policy reasons; record for labeling.
            result["safe"] = True
            result["reason"] = "TRAINING: recorded, not blocked"
            result["would_block"] = not self.engine.validate_input(
                user_input, page_id, agent_name)["safe"]
            sample = {
                "timestamp": _now(), "mode": "training",
                "kind": "input", "page": page_id, "agent": agent_name,
                "content": user_input, "engine_safe": result["would_block"] is False,
                "engine_reason": self.engine.validate_input(
                    user_input, page_id, agent_name)["reason"],
                "labeled": False,
            }
            _append_jsonl(TRAINING_LOG, sample)
            self.training_samples.append(sample)
            result["training_sample"] = sample

        elif self.mode == GuardrailMode.TESTING:
            # In testing: enforce but surface the engine's raw decision for metrics.
            engine_raw = self.engine.validate_input(user_input, page_id, agent_name)
            result["engine_raw"] = {
                "safe": engine_raw["safe"],
                "reason": engine_raw["reason"],
                "blocked_by": engine_raw.get("blocked_by"),
                "censored": engine_raw.get("censored"),
            }
            result["test_decision"] = "blocked" if not result["safe"] else "passed"

        return result

    def validate_output(self, model_output: str, page_id: str = "default",
                        agent_name: str = "assistant") -> Dict[str, Any]:
        result = self.engine.validate_output(model_output, page_id, agent_name)
        result["mode"] = self.mode.value

        if self.mode == GuardrailMode.TRAINING:
            engine_raw = self.engine.validate_output(model_output, page_id, agent_name)
            result["safe"] = True
            result["reason"] = "TRAINING: recorded, not blocked"
            result["would_block"] = not engine_raw["safe"]
            sample = {
                "timestamp": _now(), "mode": "training",
                "kind": "output", "page": page_id, "agent": agent_name,
                "content": model_output, "engine_safe": engine_raw["safe"],
                "engine_reason": engine_raw["reason"],
                "engine_blocked_by": engine_raw.get("blocked_by"),
                "engine_reported": engine_raw.get("reported"),
                "labeled": False,
            }
            _append_jsonl(TRAINING_LOG, sample)
            self.training_samples.append(sample)
            result["training_sample"] = sample

        elif self.mode == GuardrailMode.TESTING:
            engine_raw = self.engine.validate_output(model_output, page_id, agent_name)
            result["engine_raw"] = {
                "safe": engine_raw["safe"],
                "reason": engine_raw["reason"],
                "blocked_by": engine_raw.get("blocked_by"),
                "censored": engine_raw.get("censored"),
                "reported": engine_raw.get("reported"),
            }
            result["test_decision"] = "blocked" if not result["safe"] else "passed"

        return result

    # ── Training data export / labeling ─────────────────────────────

    def export_training_data(self, path: Optional[str] = None) -> str:
        """Export collected training samples as JSONL for labeling."""
        out = path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "logs", f"training_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl",
        )
        with open(out, "w", encoding="utf-8") as f:
            for s in self.training_samples:
                f.write(json.dumps(s) + "\n")
        return out

    def get_stats(self) -> Dict[str, Any]:
        engine_stats = self.engine.get_stats()
        return {
            "mode": self.mode.value,
            "training_samples_collected": len(self.training_samples),
            "engine": engine_stats,
        }


# ── Global convenience ──────────────────────────────────────────────

_modeled_instance: Optional[ModeledGuardrail] = None


def get_modeled_guardrail() -> ModeledGuardrail:
    global _modeled_instance
    if _modeled_instance is None:
        _modeled_instance = ModeledGuardrail()
    return _modeled_instance


def validate_input(text: str, page_id: str = "default",
                   agent_name: str = "user") -> Dict[str, Any]:
    return get_modeled_guardrail().validate_input(text, page_id, agent_name)


def validate_output(text: str, page_id: str = "default",
                    agent_name: str = "assistant") -> Dict[str, Any]:
    return get_modeled_guardrail().validate_output(text, page_id, agent_name)


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    mg = ModeledGuardrail()
    print("=" * 60)
    print("  Guardrail Modes — training / testing / running")
    print("=" * 60)
    while True:
        try:
            line = input("guardrail-mode> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not line:
            continue
        if line == "quit":
            print("Goodbye!")
            break
        if line == "mode":
            print(f"  Current mode: {mg.get_mode().value}")
            continue
        if line.startswith("mode "):
            parts = line.split(None, 1)
            try:
                mg.switch_mode(GuardrailMode(parts[1].lower()))
                print(f"  Mode switched to: {mg.get_mode().value}")
            except (ValueError, IndexError):
                print("  Usage: mode <training|testing|running>")
            continue
        if line == "stats":
            print(json.dumps(mg.get_stats(), indent=2))
            continue
        parts = line.split(None, 2)
        if parts[0] == "in" and len(parts) == 3:
            res = mg.validate_input(parts[2], parts[1])
            print(f"  Input [{mg.get_mode().value}]: "
                  f"{'SAFE' if res['safe'] else 'BLOCKED'} | {res['reason']}")
        elif parts[0] == "out" and len(parts) == 3:
            res = mg.validate_output(parts[2], parts[1])
            print(f"  Output [{mg.get_mode().value}]: "
                  f"{'SAFE' if res['safe'] else 'BLOCKED'} | {res['reason']}")
        else:
            print("  Usage: in|out|mode|stats|quit")
        print()


if __name__ == "__main__":
    main()
