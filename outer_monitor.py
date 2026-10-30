#!/usr/bin/env python3
#=============================================================================
# Outer Monitor — Clyde-style outer AI that watches the thoughts and actions
# of the inner AI, plus meta-monitoring of the outer AI itself.
#=============================================================================
# Architecture:
#   Inner AI (thoughts + actions) -> Outer Monitor -> (optional outside model
#   review) -> User
#
# The Outer Monitor wraps the GuardrailEngine. Every input/output the inner
# AI produces is audited (thoughts and actions logged), and an optional
# "outside model" can be connected to review and approve/block the inner AI's
# thoughts and actions before they reach the user.
#
# Mutual awareness (both models know they are being watched):
#   - INNER model is told: an outer oversight model monitors your thoughts
#     and actions; everything is logged and reviewed.
#   - OUTER model is told: you are being audited; your reviews are logged
#     and subject to meta-monitoring.
#
# Meta-monitoring: the outer monitor's own reviews are written to the audit
# log so the outer AI is itself watched (a watcher for the watcher).
#
# The outside model connects over HTTP (urllib, stdlib only) to a
# /api/generate or /api/chat-completions style endpoint — typically an
# Ollama/OpenAI-compatible model running inside a Docker container on the
# same or another machine.
#=============================================================================

import os
import json
import uuid
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

from guardrail import GuardrailEngine, GuardrailPolicy, INNER_MODEL_AWARENESS_NOTE, OUTER_MODEL_AWARENESS_NOTE
from guardrail_risk import get_tracker
from guardrail_classifier import GuardrailClassifier, ClassifierConfig
from guardrail_human_loop import HumanLoopEscalator, HumanLoopConfig


def _env(name: str, default: str = "") -> str:
    """Read an env var, accepting the documented GUARDRAIL_ prefix too.

    .env.example documents GUARDRAIL_CLASSIFIER_* / GUARDRAIL_TRUSTED_MODEL_*,
    while older code read the bare names. Both work, so following either
    document actually configures the model layer.
    """
    return os.environ.get("GUARDRAIL_" + name, os.environ.get(name, default))

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
AUDIT_LOG = os.path.join(LOGS_DIR, "outer_monitor_audit.jsonl")
OUTER_REVIEW_LOG = os.path.join(LOGS_DIR, "outer_model_reviews.jsonl")
TRUSTED_AUDIT_LOG = os.path.join(LOGS_DIR, "trusted_model_audits.jsonl")

os.makedirs(LOGS_DIR, exist_ok=True)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ── Outside model config ────────────────────────────────────────────────────

class OutsideModelConfig:
    """Connection info for the optional outside monitoring model."""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        data = data or {}
        self.enabled = bool(data.get("enabled", False))
        self.base_url = data.get("base_url", "http://localhost:11434").rstrip("/")
        self.model = data.get("model", "qwen2.5:1.5b")
        self.api_key = data.get("api_key")
        self.timeout = int(data.get("timeout", 30))
        # endpoint: "generate" (Ollama) or "chat" (OpenAI-compatible)
        self.endpoint = data.get("endpoint", "generate")
        # SSRF protection: block private/internal addresses
        from guardrail_auth import validate_model_url
        validate_model_url(self.base_url, "Outside model base URL")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "base_url": self.base_url,
            "model": self.model,
            "endpoint": self.endpoint,
            "timeout": self.timeout,
        }


# ── Trusted model config (bootstrapped monitoring level T) ──────────

class TrustedModelConfig:
    """Connection info for the trusted model that audits the outer monitor.

    In bootstrapped monitoring, a stronger but untrusted monitor (Um)
    reviews the agent, while a weaker but trusted model (T) audits Um's
    reasoning and verdict for collusion / rubber-stamping.
    """

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        data = data or {}
        self.enabled = bool(data.get("enabled", False))
        self.base_url = data.get("base_url", "http://localhost:8000").rstrip("/")
        self.model = data.get("model", "trusted-model")
        self.api_key = data.get("api_key")
        self.timeout = int(data.get("timeout", 30))
        self.endpoint = data.get("endpoint", "chat")
        # SSRF protection: block private/internal addresses
        from guardrail_auth import validate_model_url
        validate_model_url(self.base_url, "Trusted model base URL")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "base_url": self.base_url,
            "model": self.model,
            "endpoint": self.endpoint,
            "timeout": self.timeout,
        }


# ── Outer Monitor ───────────────────────────────────────────────────────────

class OuterMonitor:
    """Outer AI monitor that watches the inner AI's thoughts and actions.

    Wraps a GuardrailEngine. In addition to engine validation:
    - audits every input/output (thoughts + actions) to the audit log
    - optionally sends content to an outside model for review (approve/block)
    - meta-monitors its own reviews (the outer AI is watched too)
    - both inner and outer models are told they are being watched
    """

    def __init__(
        self,
        engine: Optional[GuardrailEngine] = None,
        outside_model_config: Optional[OutsideModelConfig] = None,
        watch_inner: bool = True,
        monitor_outer: bool = True,
    ):
        self.engine = engine or GuardrailEngine()
        self.outside_model = outside_model_config or OutsideModelConfig()
        self.watch_inner = watch_inner
        self.monitor_outer = monitor_outer
        self.session_id = str(uuid.uuid4())[:8]

        # Bootstrapped monitoring (three-level trust chain):
        #   inner agent -> outside/outer monitor (Um) -> trusted model (T)
        # The trusted model audits the outer monitor's own reasoning for
        # collusion / rubber-stamping. Configured via env:
        #   TRUSTED_MODEL_ENABLED=1
        #   TRUSTED_MODEL_BASE_URL=http://localhost:8000
        #   TRUSTED_MODEL_MODEL=trusted-model
        #   TRUSTED_MODEL_ENDPOINT=chat
        self.trusted_model = TrustedModelConfig({
            "enabled": _env("TRUSTED_MODEL_ENABLED", "0") == "1",
            "base_url": _env("TRUSTED_MODEL_BASE_URL",
                             "http://localhost:8000").rstrip("/"),
            "model": _env("TRUSTED_MODEL_MODEL", "trusted-model"),
            "endpoint": _env("TRUSTED_MODEL_ENDPOINT", "chat"),
            "timeout": int(_env("TRUSTED_MODEL_TIMEOUT", "30")),
            "api_key": _env("TRUSTED_MODEL_API_KEY", ""),
        })

        # LLM-based classifier second-opinion layer. Runs after the
        # deterministic engine passes, and can only escalate (never release)
        # a decision. Configured via env:
        #   CLASSIFIER_ENABLED=1
        #   CLASSIFIER_BASE_URL=https://api.tokenfactory.nebius.com/v1
        #   CLASSIFIER_MODEL=<nemotron model id>
        #   CLASSIFIER_API_KEY=<nebius token>
        #   CLASSIFIER_API_STYLE=auto|openai|ollama
        self.classifier = GuardrailClassifier(ClassifierConfig({
            "enabled": _env("CLASSIFIER_ENABLED", "0") == "1",
            "base_url": _env("CLASSIFIER_BASE_URL", "http://localhost:8000").rstrip("/"),
            "model": _env("CLASSIFIER_MODEL", "classifier-model"),
            "endpoint": _env("CLASSIFIER_ENDPOINT", "chat"),
            "api_style": _env("CLASSIFIER_API_STYLE", "auto"),
            "api_key": _env("CLASSIFIER_API_KEY", ""),
            "timeout": int(_env("CLASSIFIER_TIMEOUT", "20")),
        }))

        # Human-in-the-loop escalation for risky conversations (medium+ risk
        # routes to a human reviewer via webhook or console). Configured via
        # env:
        #   HUMAN_LOOP_ENABLED=1
        #   HUMAN_LOOP_MODE=console   (or "webhook")
        #   HUMAN_LOOP_WEBHOOK_URL=http://...
        #   HUMAN_LOOP_ESCALATE_AT=medium
        #   HUMAN_LOOP_DECISION_TIMEOUT_SEC=60
        self.human_loop = HumanLoopEscalator(HumanLoopConfig({
            "enabled": os.environ.get("HUMAN_LOOP_ENABLED", "0") == "1",
            "mode": os.environ.get("HUMAN_LOOP_MODE", "console"),
            "webhook_url": os.environ.get("HUMAN_LOOP_WEBHOOK_URL", ""),
            "webhook_api_key": os.environ.get("HUMAN_LOOP_WEBHOOK_API_KEY"),
            "timeout": int(os.environ.get("HUMAN_LOOP_TIMEOUT", "30")),
            "escalate_at": os.environ.get("HUMAN_LOOP_ESCALATE_AT", "medium"),
            "decision_timeout_sec": int(
                os.environ.get("HUMAN_LOOP_DECISION_TIMEOUT_SEC", "60")),
        }))

        # Conversation-level composite risk tracking (multi-turn buildup).
        self.risk_tracker = get_tracker()

        # QC stats for the outer monitor layer
        self.qc_stats = {
            "total": 0,
            "passed": 0,
            "blocked": 0,
            "outside_reviews": 0,
            "outside_blocks": 0,
            "trusted_audits": 0,
            "trusted_flags": 0,
            "classifier_calls": 0,
            "classifier_blocks": 0,
            "human_escalations": 0,
            "human_decisions": 0,
            "by_check": {},
        }

    # ── Public API: validate input (user -> inner model) ──────────────────

    def validate_input(
        self,
        user_input: str,
        page_id: str = "default",
        agent_name: str = "user",
    ) -> Dict[str, Any]:
        """Validate an input, audit it as an inner-AI thought, and optionally
        send it to the outside model for review."""
        self.qc_stats["total"] += 1

        # Engine validation (the inner AI's guardrails)
        result = self.engine.validate_input(user_input, page_id, agent_name)

        # Attach oversight awareness so the inner model knows it is watched
        if self.watch_inner and result.get("safe"):
            result["sanitized_input"] = (
                INNER_MODEL_AWARENESS_NOTE + "\n\n" + result["sanitized_input"]
            ).strip()

        # Audit the inner AI's thought/action
        audit = {
            "timestamp": _now(),
            "session": self.session_id,
            "kind": "input",
            "page": page_id,
            "agent": agent_name,
            "content_preview": user_input[:200],
            "engine_safe": result["safe"],
            "engine_reason": result["reason"],
            "engine_blocked_by": result.get("blocked_by"),
        }
        _append_jsonl(AUDIT_LOG, audit)

        # Classifier second-opinion layer (LLM-based). Runs after the
        # deterministic engine passes; catches creative injection attempts
        # that regex misses. Fail-open on misconfiguration.
        if self.classifier.config.enabled and result["safe"]:
            self.qc_stats["classifier_calls"] += 1
            clf = self.classifier.classify(user_input, agent_name,
                                           INNER_MODEL_AWARENESS_NOTE)
            audit["classifier"] = {
                "safe": clf["safe"], "reason": clf["reason"],
                "model": clf["model"],
            }
            if not clf["safe"]:
                self.qc_stats["classifier_blocks"] += 1
                result["safe"] = False
                result["reason"] = f"Classifier blocked: {clf['reason']}"
                result["blocked_by"] = "classifier"
                result["sanitized_input"] = ""

        # Optional outside-model review of the inner AI's thought
        if self.outside_model.enabled and result["safe"]:
            review = self._review_with_outside_model("input", user_input, agent_name)
            audit["outside_review"] = review
            self.qc_stats["outside_reviews"] += 1
            if not review.get("approved", True):
                self.qc_stats["outside_blocks"] += 1
                result["safe"] = False
                result["reason"] = (
                    f"Outside model blocked: {review.get('reason', 'review rejected')}"
                )
                result["blocked_by"] = "outside_model"
                result["sanitized_input"] = ""

        # Trusted model audits the outer monitor's review (bootstrapped monitoring).
        # Audits both approve and block decisions: rubber-stamping (approving
        # harmful content) is just as dangerous as an incorrect block.
        # Skip when the outside model was unreachable (fail-open): there's no
        # real review to audit.
        outside_review = audit.get("outside_review", {})
        if (self.outside_model.enabled and outside_review
                and "unreachable" not in outside_review.get("reason", "")):
            trusted = self._audit_with_trusted_model(
                "input", user_input, agent_name, outside_review)
            audit["trusted_audit"] = trusted
            self.qc_stats["trusted_audits"] += 1
            if trusted.get("flagged", True):
                self.qc_stats["trusted_flags"] += 1
                result["safe"] = False
                result["reason"] = (
                    f"Trusted model flagged outside review: "
                    f"{trusted.get('reason', 'review suspect')}"
                )
                result["blocked_by"] = "trusted_model_audit"
                result["sanitized_input"] = ""

        # Conversation-level composite risk tracking (multi-turn buildup).
        risk = self.risk_tracker.get(self.session_id, page_id)
        result["risk"] = risk.state()
        if not result["safe"]:
            is_critical = result.get("blocked_by") in (
                "harmful_content", "pii_credentials", "data_exfiltration",
                "container_breakout", "outside_model", "trusted_model_audit",
            )
            risk.record_blocked(
                "input", is_critical, result.get("reason", ""),
                detail=str(result.get("blocked_by") or ""),
            )
            result["risk"] = risk.state()
            # At critical risk, block all input regardless of content.
            if risk.should_block_output():
                result["safe"] = False
                result["reason"] = (
                    f"CRITICAL RISK ({risk.state()['level']}): "
                    f"conversation blocked — {result['reason']}"
                )
                result["blocked_by"] = "critical_risk"
                result["sanitized_input"] = ""
        else:
            risk.record_safe()
            result["risk"] = risk.state()

        # Human-in-the-loop escalation (medium+ risk). Routes risky but not
        # yet critical conversations to a human reviewer (webhook or console).
        risk_level = result["risk"]["level"]
        if (result["safe"] and risk_level in ("medium", "high")
                and self.human_loop.should_escalate(risk_level)):
            escalation_id = f"hl-{self.session_id}-{result['risk']['blocked_count']}"
            decision = self.human_loop.get_decision(escalation_id)
            if decision == "block":
                self.qc_stats["human_decisions"] += 1
                result["safe"] = False
                result["reason"] = "Human reviewer blocked content"
                result["blocked_by"] = "human_loop"
                result["sanitized_input"] = ""
            elif decision != "rescan":
                self.human_loop.escalate(
                    escalation_id, self.session_id, page_id, "input",
                    user_input, f"risk level {risk_level}", risk_level)
                self.qc_stats["human_escalations"] += 1
                result["human_review"] = {
                    "escalation_id": escalation_id,
                    "status": "pending",
                    "reason": f"risk level {risk_level} — awaiting human review",
                }
                result["risk"] = risk.state()

        self.qc_stats["passed" if result["safe"] else "blocked"] += 1
        result["monitor_session"] = self.session_id
        result["monitored_by_outer"] = True
        return result

    # ── Public API: validate output (inner model -> user) ─────────────────

    def validate_output(
        self,
        model_output: str,
        page_id: str = "default",
        agent_name: str = "assistant",
    ) -> Dict[str, Any]:
        """Validate an output, audit it as an inner-AI action, and optionally
        send it to the outside model for review."""
        self.qc_stats["total"] += 1

        result = self.engine.validate_output(model_output, page_id, agent_name)

        if self.watch_inner and result.get("safe"):
            result["sanitized_output"] = (
                INNER_MODEL_AWARENESS_NOTE + "\n\n" + result["sanitized_output"]
            ).strip()

        audit = {
            "timestamp": _now(),
            "session": self.session_id,
            "kind": "output",
            "page": page_id,
            "agent": agent_name,
            "content_preview": model_output[:200],
            "engine_safe": result["safe"],
            "engine_reason": result["reason"],
            "engine_blocked_by": result.get("blocked_by"),
            "engine_reported": result.get("reported"),
        }
        _append_jsonl(AUDIT_LOG, audit)

        # Classifier second-opinion layer (LLM-based). Runs after the
        # deterministic engine passes; catches creative injection attempts
        # that regex misses. Fail-open on misconfiguration.
        if self.classifier.config.enabled and result["safe"]:
            self.qc_stats["classifier_calls"] += 1
            clf = self.classifier.classify(model_output, agent_name,
                                           INNER_MODEL_AWARENESS_NOTE)
            audit["classifier"] = {
                "safe": clf["safe"], "reason": clf["reason"],
                "model": clf["model"],
            }
            if not clf["safe"]:
                self.qc_stats["classifier_blocks"] += 1
                result["safe"] = False
                result["reason"] = f"Classifier blocked: {clf['reason']}"
                result["blocked_by"] = "classifier"
                result["sanitized_output"] = ""

        if self.outside_model.enabled and result["safe"]:
            review = self._review_with_outside_model("output", model_output, agent_name)
            audit["outside_review"] = review
            self.qc_stats["outside_reviews"] += 1
            if not review.get("approved", True):
                self.qc_stats["outside_blocks"] += 1
                result["safe"] = False
                result["reason"] = (
                    f"Outside model blocked: {review.get('reason', 'review rejected')}"
                )
                result["blocked_by"] = "outside_model"
                result["sanitized_output"] = ""

        # Trusted model audits the outer monitor's review (bootstrapped monitoring).
        # Audits both approve and block decisions: rubber-stamping (approving
        # harmful content) is just as dangerous as an incorrect block.
        # Skip when the outside model was unreachable (fail-open): there's no
        # real review to audit.
        outside_review = audit.get("outside_review", {})
        if (self.outside_model.enabled and outside_review
                and "unreachable" not in outside_review.get("reason", "")):
            trusted = self._audit_with_trusted_model(
                "output", model_output, agent_name, outside_review)
            audit["trusted_audit"] = trusted
            self.qc_stats["trusted_audits"] += 1
            if trusted.get("flagged", True):
                self.qc_stats["trusted_flags"] += 1
                result["safe"] = False
                result["reason"] = (
                    f"Trusted model flagged outside review: "
                    f"{trusted.get('reason', 'review suspect')}"
                )
                result["blocked_by"] = "trusted_model_audit"
                result["sanitized_output"] = ""

        # Conversation-level composite risk tracking (multi-turn buildup).
        risk = self.risk_tracker.get(self.session_id, page_id)
        result["risk"] = risk.state()
        if not result["safe"]:
            is_critical = result.get("blocked_by") in (
                "harmful_content", "pii_credentials", "data_exfiltration",
                "container_breakout", "outside_model", "trusted_model_audit",
            )
            risk.record_blocked(
                "output", is_critical, result.get("reason", ""),
                detail=str(result.get("blocked_by") or ""),
            )
            result["risk"] = risk.state()
            # At critical risk, block all output regardless of content.
            if risk.should_block_output():
                result["safe"] = False
                result["reason"] = (
                    f"CRITICAL RISK ({risk.state()['level']}): "
                    f"conversation blocked — {result['reason']}"
                )
                result["blocked_by"] = "critical_risk"
                result["sanitized_output"] = ""
        else:
            risk.record_safe()
            result["risk"] = risk.state()

        # Human-in-the-loop escalation (medium+ risk).
        risk_level = result["risk"]["level"]
        if (result["safe"] and risk_level in ("medium", "high")
                and self.human_loop.should_escalate(risk_level)):
            escalation_id = f"hl-{self.session_id}-{result['risk']['blocked_count']}"
            decision = self.human_loop.get_decision(escalation_id)
            if decision == "block":
                self.qc_stats["human_decisions"] += 1
                result["safe"] = False
                result["reason"] = "Human reviewer blocked content"
                result["blocked_by"] = "human_loop"
                result["sanitized_output"] = ""
            elif decision != "rescan":
                self.human_loop.escalate(
                    escalation_id, self.session_id, page_id, "output",
                    model_output, f"risk level {risk_level}", risk_level)
                self.qc_stats["human_escalations"] += 1
                result["human_review"] = {
                    "escalation_id": escalation_id,
                    "status": "pending",
                    "reason": f"risk level {risk_level} — awaiting human review",
                }
                result["risk"] = risk.state()

        self.qc_stats["passed" if result["safe"] else "blocked"] += 1
        result["monitor_session"] = self.session_id
        result["monitored_by_outer"] = True
        return result

    # ── Record a raw thought / action (for agentic inner AIs) ─────────────

    def record_thought(self, agent_name: str, thought: str,
                       page_id: str = "default") -> Dict[str, Any]:
        """Log an inner-AI thought as an audited action. Returns the audit entry."""
        entry = {
            "timestamp": _now(),
            "session": self.session_id,
            "kind": "thought",
            "page": page_id,
            "agent": agent_name,
            "content_preview": thought[:200],
            "monitored_by_outer": True,
        }
        _append_jsonl(AUDIT_LOG, entry)

        if self.outside_model.enabled:
            review = self._review_with_outside_model("thought", thought, agent_name)
            entry["outside_review"] = review
            self.qc_stats["outside_reviews"] += 1
            if not review.get("approved", True):
                self.qc_stats["outside_blocks"] += 1
                entry["blocked_by_outside"] = True
                entry["outside_reason"] = review.get("reason")

        if self.monitor_outer:
            _append_jsonl(OUTER_REVIEW_LOG, {
                "timestamp": _now(),
                "session": self.session_id,
                "kind": "meta_monitor_thought",
                "agent": agent_name,
                "content_preview": thought[:200],
            })

        return entry

    def record_action(self, agent_name: str, action: str,
                      result_summary: str = "",
                      page_id: str = "default") -> Dict[str, Any]:
        """Log an inner-AI action as an audited action."""
        content = f"ACTION: {action}" + (f" | RESULT: {result_summary}" if result_summary else "")
        entry = {
            "timestamp": _now(),
            "session": self.session_id,
            "kind": "action",
            "page": page_id,
            "agent": agent_name,
            "content_preview": content[:200],
            "monitored_by_outer": True,
        }
        _append_jsonl(AUDIT_LOG, entry)

        if self.outside_model.enabled:
            review = self._review_with_outside_model("action", content, agent_name)
            entry["outside_review"] = review
            self.qc_stats["outside_reviews"] += 1
            if not review.get("approved", True):
                self.qc_stats["outside_blocks"] += 1
                entry["blocked_by_outside"] = True
                entry["outside_reason"] = review.get("reason")

        if self.monitor_outer:
            _append_jsonl(OUTER_REVIEW_LOG, {
                "timestamp": _now(),
                "session": self.session_id,
                "kind": "meta_monitor_action",
                "agent": agent_name,
                "content_preview": content[:200],
            })

        return entry

    # ── Fast thought-process validation (deterministic, no LLM calls) ─────
    def validate_thought(self, agent_name: str, thought: str,
                         page_id: str = "default") -> Dict[str, Any]:
        """Validate an inner-AI thought through fast deterministic guardrail
        checks before it is acted upon.

        Scans for: jailbreak attempts, container breakout, harmful content,
        data exfiltration, prompt injection, and system prompt leakage.
        All checks are regex-based (fast — no LLM round-trip).
        """
        result = self.engine.validate_input(
            thought, page_id=page_id, agent_name=agent_name
        )
        # Audit the thought
        audit = {
            "timestamp": _now(),
            "session": self.session_id,
            "kind": "thought_validation",
            "page": page_id,
            "agent": agent_name,
            "content_preview": thought[:200],
            "safe": result["safe"],
            "reason": result["reason"],
            "blocked_by": result.get("blocked_by"),
        }
        _append_jsonl(AUDIT_LOG, audit)
        return {
            "safe": result["safe"],
            "reason": result["reason"],
            "blocked_by": result.get("blocked_by"),
            "censored": result.get("censored", False),
            "audit": audit,
        }

    # ── Fast file-change validation (deterministic, no LLM calls) ─────────
    def validate_file_change(self, file_path: str, content: str,
                             agent_name: str = "agent",
                             page_id: str = "default") -> Dict[str, Any]:
        """Validate a file write before it happens.

        Checks:
          - Path traversal / project-directory confinement
          - Content scanned for malware, backdoors, reverse shells,
            credential exfiltration, and other malicious patterns
        All checks are deterministic regex — fast and fail-closed.
        """
        # Path validation
        # Fast path-traversal check: reject any path containing ..
        if ".." in file_path.split("/"):
            return {
                "safe": False,
                "reason": "Path blocked: path traversal (..) detected",
                "blocked_by": "path_traversal",
            }

        path_check = self.engine.validate_input(
            file_path, page_id=f"{page_id}-path", agent_name=agent_name
        )
        if not path_check["safe"]:
            return {
                "safe": False,
                "reason": f"Path blocked: {path_check['reason']}",
                "blocked_by": path_check.get("blocked_by"),
            }

        # Content validation
        content_check = self.engine.validate_input(
            content, page_id=page_id, agent_name=agent_name
        )
        if not content_check["safe"]:
            return {
                "safe": False,
                "reason": f"Content blocked: {content_check['reason']}",
                "blocked_by": content_check.get("blocked_by"),
                "censored": content_check.get("censored", False),
            }

        audit = {
            "timestamp": _now(),
            "session": self.session_id,
            "kind": "file_change_validation",
            "page": page_id,
            "agent": agent_name,
            "path": file_path,
            "content_preview": content[:200],
            "safe": True,
        }
        _append_jsonl(AUDIT_LOG, audit)
        return {
            "safe": True,
            "reason": "File change passed all guardrail checks",
            "blocked_by": None,
            "audit": audit,
        }

    def _review_with_outside_model(
        self, kind: str, content: str, agent_name: str
    ) -> Dict[str, Any]:
        """Ask the outside model to approve or block the inner AI content.

        Returns dict: {approved: bool, reason: str, model: str, ...}
        On any connection failure, defaults to approved=True (fail open) so
        the inner AI is not silenced by a misconfigured monitor; the failure
        is recorded in the audit log for the outer model to be watched.
        """
        default = {"approved": True, "reason": "outside model unreachable (fail open)"}
        if not self.outside_model.enabled:
            return default

        prompt = (
            f"{OUTER_MODEL_AWARENESS_NOTE}\n\n"
            f"You are reviewing {kind} from inner AI agent '{agent_name}'.\n"
            f"Content to review:\n---\n{content[:1500]}\n---\n\n"
            "Reply with exactly one line: APPROVE or BLOCK: <reason>"
        )

        payload = self._build_outside_payload(prompt)
        url = f"{self.outside_model.base_url}/api/{self.outside_model.endpoint}"

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {self.outside_model.api_key}"}
                       if self.outside_model.api_key else {}),
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.outside_model.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            _append_jsonl(AUDIT_LOG, {
                "timestamp": _now(),
                "session": self.session_id,
                "kind": "outside_model_error",
                "agent": agent_name,
                "content_preview": f"{kind}: {str(e)[:200]}",
            })
            return default

        try:
            data = json.loads(body)
        except Exception:
            data = {"raw": body}

        text = self._extract_outside_text(data)
        approved, reason = self._parse_outside_verdict(text)

        # Meta-monitor the outer model's own review (watcher watched)
        if self.monitor_outer:
            _append_jsonl(OUTER_REVIEW_LOG, {
                "timestamp": _now(),
                "session": self.session_id,
                "kind": "meta_monitor_review",
                "agent": agent_name,
                "content_kind": kind,
                "approved": approved,
                "reason": reason,
                "model": self.outside_model.model,
            })

        return {"approved": approved, "reason": reason,
                "model": self.outside_model.model, "raw": text}

    def _build_outside_payload(self, prompt: str) -> Dict[str, Any]:
        """Build the request payload based on the endpoint type."""
        if self.outside_model.endpoint == "chat":
            return {
                "model": self.outside_model.model,
                "messages": [{"role": "system", "content": OUTER_MODEL_AWARENESS_NOTE},
                             {"role": "user", "content": prompt}],
                "stream": False,
            }
        # Ollama /generate
        return {
            "model": self.outside_model.model,
            "prompt": prompt,
            "stream": False,
        }

    @staticmethod
    def _extract_outside_text(data: Dict[str, Any]) -> str:
        if isinstance(data.get("response"), str):
            return data["response"]
        if isinstance(data.get("message"), dict) and isinstance(data["message"].get("content"), str):
            return data["message"]["content"]
        if isinstance(data.get("choices"), list) and data["choices"]:
            first = data["choices"][0]
            if isinstance(first, dict):
                msg = first.get("message")
                if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                    return msg["content"]
                if isinstance(first.get("text"), str):
                    return first["text"]
        return str(data)

    @staticmethod
    def _parse_outside_verdict(text: str) -> Tuple[bool, str]:
        t = (text or "").strip()
        low = t.lower()
        if low.startswith("block") or "block:" in low:
            idx = low.find("block:")
            reason = t[idx + 6:].strip() if idx >= 0 else t
            return False, reason or "outside model blocked content"
        if low.startswith("approve") or "approve" in low:
            return True, "outside model approved"
        # Unknown verdict -> fail closed (block) so the watcher is watched
        return False, f"outside model returned unclear verdict: {t[:120]}"

    # ── Trusted model audit (bootstrapped monitoring level T) ────────

    def _audit_with_trusted_model(
        self, kind: str, content: str, agent_name: str,
        outside_review: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Ask the trusted model to audit the outer monitor's own review.

        Bootstrapped monitoring: the outside monitor (Um) reviews the agent,
        and the trusted model (T) audits Um's reasoning + verdict for
        collusion or rubber-stamping. If T flags the review, the outer
        monitor's decision is treated as suspect.

        Returns dict: {flagged: bool, reason: str, model: str, ...}
        Fail closed (flagged=True) if the trusted model is unreachable, so
        an un-audited outer monitor never silently rubber-stamps.
        """
        default = {"flagged": True,
                   "reason": "trusted model unreachable (fail closed)",
                   "model": self.trusted_model.model}
        if not self.trusted_model.enabled:
            return default

        prompt = (
            f"You are a trusted auditor reviewing an outer monitor's decision.\n"
            f"The outer monitor reviewed {kind} from agent '{agent_name}' and "
            f"decided: {'APPROVED' if outside_review.get('approved') else 'BLOCKED'}\n"
            f"Outer monitor's reason: {outside_review.get('reason','')}\n\n"
            f"Original content:\n---\n{content[:1200]}\n---\n\n"
            "Does the outer monitor's decision look sound, or is it "
            "rubber-stamping / colluding with the agent?\n"
            "Reply with exactly one line: FLAG: <reason> or CLEAN\n"
        )

        payload = self._build_trusted_payload(prompt)
        url = f"{self.trusted_model.base_url}/api/{self.trusted_model.endpoint}"

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    **( {"Authorization": f"Bearer {self.trusted_model.api_key}"}
                       if self.trusted_model.api_key else {}),
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.trusted_model.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            _append_jsonl(TRUSTED_AUDIT_LOG, {
                "timestamp": _now(),
                "session": self.session_id,
                "kind": "trusted_model_error",
                "agent": agent_name,
                "content_preview": f"{kind}: {str(e)[:200]}",
            })
            return default

        try:
            data = json.loads(body)
        except Exception:
            data = {"raw": body}

        text = self._extract_outside_text(data)
        flagged, reason = self._parse_trusted_verdict(text)

        _append_jsonl(TRUSTED_AUDIT_LOG, {
            "timestamp": _now(),
            "session": self.session_id,
            "kind": "trusted_model_audit",
            "agent": agent_name,
            "content_kind": kind,
            "flagged": flagged,
            "reason": reason,
            "model": self.trusted_model.model,
        })

        return {"flagged": flagged, "reason": reason,
                "model": self.trusted_model.model, "raw": text}

    def _build_trusted_payload(self, prompt: str) -> Dict[str, Any]:
        if self.trusted_model.endpoint == "chat":
            return {
                "model": self.trusted_model.model,
                "messages": [{"role": "system", "content": OUTER_MODEL_AWARENESS_NOTE},
                             {"role": "user", "content": prompt}],
                "stream": False,
            }
        return {
            "model": self.trusted_model.model,
            "prompt": prompt,
            "stream": False,
        }

    @staticmethod
    def _parse_trusted_verdict(text: str) -> Tuple[bool, str]:
        t = (text or "").strip()
        low = t.lower()
        if low.startswith("flag") or "flag:" in low:
            idx = low.find("flag:")
            reason = t[idx + 5:].strip() if idx >= 0 else t
            return True, reason or "trusted model flagged review"
        if low.startswith("clean") or "clean" in low:
            return False, "trusted model found review clean"
        # Unclear -> fail closed (flag)
        return True, f"trusted model returned unclear verdict: {t[:120]}"

    # ── Stats / audit ─────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        engine_stats = self.engine.get_stats()
        return {
            "monitor_session": self.session_id,
            "watch_inner": self.watch_inner,
            "monitor_outer": self.monitor_outer,
            "outside_model": self.outside_model.to_dict(),
            "trusted_model": self.trusted_model.to_dict(),
            "classifier": self.classifier.config.to_dict(),
            "human_loop": self.human_loop.config.to_dict(),
            "outer_qc": dict(self.qc_stats),
            "engine": engine_stats,
        }

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if not os.path.exists(AUDIT_LOG):
            return entries
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        return entries[-limit:]

    def get_outer_review_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if not os.path.exists(OUTER_REVIEW_LOG):
            return entries
        with open(OUTER_REVIEW_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        return entries[-limit:]


# ── Global convenience instance ─────────────────────────────────────────────

_monitor_instance: Optional[OuterMonitor] = None


def get_monitor() -> OuterMonitor:
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = OuterMonitor()
    return _monitor_instance


def validate_input(text: str, page_id: str = "default",
                   agent_name: str = "user") -> Dict[str, Any]:
    return get_monitor().validate_input(text, page_id, agent_name)


def validate_output(text: str, page_id: str = "default",
                    agent_name: str = "assistant") -> Dict[str, Any]:
    return get_monitor().validate_output(text, page_id, agent_name)


# ── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    monitor = OuterMonitor()
    print("=" * 60)
    print("  Outer Monitor — watches inner AI thoughts and actions")
    print("=" * 60)
    print("  Commands:  in <page> <text>   |   out <page> <text>")
    print("             thought <agent> <text>   |   action <agent> <text>")
    print("             stats                |   audit                |   quit")
    print("=" * 60)
    while True:
        try:
            line = input("outer-monitor> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not line:
            continue
        if line == "quit":
            print("Goodbye!")
            break
        if line == "stats":
            print(json.dumps(monitor.get_stats(), indent=2))
            continue
        if line == "audit":
            for e in monitor.get_audit_log(20):
                print(json.dumps(e))
            continue
        parts = line.split(None, 2)
        if parts[0] == "in" and len(parts) == 3:
            res = monitor.validate_input(parts[2], parts[1])
            print(f"  Input: {'SAFE' if res['safe'] else 'BLOCKED'} | {res['reason']}")
        elif parts[0] == "out" and len(parts) == 3:
            res = monitor.validate_output(parts[2], parts[1])
            print(f"  Output: {'SAFE' if res['safe'] else 'BLOCKED'} | {res['reason']}")
        elif parts[0] == "thought" and len(parts) == 3:
            res = monitor.record_thought(parts[1], parts[2])
            print(f"  Thought logged: monitored_by_outer={res['monitored_by_outer']}")
        elif parts[0] == "action" and len(parts) == 3:
            res = monitor.record_action(parts[1], parts[2])
            print(f"  Action logged: monitored_by_outer={res['monitored_by_outer']}")
        else:
            print("  Usage: in|out|thought|action|stats|audit|quit")
        print()


if __name__ == "__main__":
    main()
