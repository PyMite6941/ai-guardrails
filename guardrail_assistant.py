#!/usr/bin/env python3
#=============================================================================
# guardrail_assistant.py — AI Assistant management layer
#=============================================================================
# Provides an AI assistant-facing interface for setting up, managing, and
# reviewing the AI Guardrails system. Designed for use by an AI assistant
# (e.g. running on Nemus/NVIDIA cloud) that helps operators configure and
# monitor their guardrails.
#
# Features:
#   - Assistant setup: guided configuration of password, 2FA, model provider
#   - Policy management: read/write guardrail policies per page
#   - Activity review: audit log, risk states, canary status, integrity
#   - System health: engine stats, mode, emergency state
#   - Emergency control: contain, shutdown, reenable
#=============================================================================

import json
import os
from datetime import datetime
from typing import Optional, Dict, Any, List

from guardrail import GuardrailEngine, GuardrailPolicy, DEFAULT_POLICIES_DIR, DEFAULT_PAGES_DIR
from guardrail_auth import (
    set_password, verify_password, has_password, is_auth_configured,
    is_2fa_configured, enable_2fa, disable_2fa, verify_2fa_code,
    verify_backup_code, _log_auth_event,
)
from guardrail_models import (
    get_providers, get_provider, resolve_provider_config,
    load_api_keys_into_env, DEFAULT_PROVIDER_KEY,
)
from guardrail_logging import get_logger
from guardrail_risk import get_tracker
from guardrail_integrity import get_watcher
from guardrail_canary import GuardrailCanary
from guardrail_modes import load_mode, GuardrailMode
from outer_monitor import get_monitor

logger = get_logger("assistant")

ASSISTANT_STATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "assistant"
)
os.makedirs(ASSISTANT_STATE_DIR, exist_ok=True)

ASSISTANT_LOG = os.path.join(ASSISTANT_STATE_DIR, "assistant.jsonl")


def _append_assistant_log(entry: Dict[str, Any]) -> None:
    """Append an assistant action to the audit log."""
    try:
        entry["ts"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        with open(ASSISTANT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


class AssistantManager:
    """AI Assistant management interface for guardrails.

    Provides methods an AI assistant can call to help an operator set up,
    manage, and review the guardrail system. All actions are logged for
    auditability.
    """

    def __init__(self):
        self.engine = GuardrailEngine()
        self.monitor = get_monitor()
        self.tracker = get_tracker()
        self.canary = GuardrailCanary(engine=self.engine)
        self.watcher = get_watcher()

    # ── Setup ──────────────────────────────────────────────────────────

    def setup_status(self) -> Dict[str, Any]:
        """Return the current setup status for the assistant to guide the user."""
        return {
            "password_configured": has_password(),
            "auth_configured": is_auth_configured(),
            "2fa_configured": is_2fa_configured(),
            "default_provider": DEFAULT_PROVIDER_KEY,
            "providers_available": len(get_providers()),
            "emergency_locked": os.path.exists(
                os.path.join(
                    os.environ.get("GUARDRAIL_LOG_DIR", "logs"),
                    "emergency.lock",
                )
            ),
            "mode": load_mode().value,
        }

    def setup_password(self, password: str) -> Dict[str, Any]:
        """Set the admin password (initial setup)."""
        if has_password():
            return {"ok": False, "error": "password already configured"}
        try:
            set_password(password)
            _log_auth_event("assistant_password_setup", "assistant")
            _append_assistant_log({"action": "setup_password", "ok": True})
            return {"ok": True, "message": "password set successfully"}
        except ValueError as e:
            _append_assistant_log({"action": "setup_password", "ok": False, "error": str(e)})
            return {"ok": False, "error": str(e)}

    def setup_2fa(self) -> Dict[str, Any]:
        """Enable 2FA. Returns secret URI and backup codes."""
        if not has_password():
            return {"ok": False, "error": "password must be set before 2FA"}
        result = enable_2fa()
        _append_assistant_log({"action": "setup_2fa", "ok": result["ok"]})
        return result

    def setup_model_provider(
        self,
        provider_key: str,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Configure the model provider for the assistant to use."""
        try:
            config = resolve_provider_config(
                provider_key, base_url=base_url, model=model,
                endpoint=endpoint, api_key=api_key,
            )
            _append_assistant_log({
                "action": "setup_model_provider",
                "provider": provider_key,
                "ok": True,
            })
            return {"ok": True, "provider": config}
        except ValueError as e:
            _append_assistant_log({"action": "setup_model_provider", "ok": False, "error": str(e)})
            return {"ok": False, "error": str(e)}

    # ── Policy Management ──────────────────────────────────────────────

    def list_policies(self) -> Dict[str, Any]:
        """List all page policies."""
        pages = self.engine.list_pages()
        return {"ok": True, "pages": pages, "count": len(pages)}

    def get_policy(self, page_id: str) -> Dict[str, Any]:
        """Get a specific page policy."""
        policy = self.engine.get_policy(page_id)
        return {"ok": True, "page": page_id, "policy": policy.to_dict()}

    def save_policy(
        self,
        page_id: str,
        policy_data: Dict[str, Any],
        changed_by: str = "assistant",
        note: str = "",
    ) -> Dict[str, Any]:
        """Save/update a page policy."""
        try:
            policy = GuardrailPolicy(policy_data)
            path = self.engine.save_page_policy(page_id, policy)
            _log_auth_event("assistant_policy_save", "assistant", detail=page_id)
            _append_assistant_log({
                "action": "save_policy", "page": page_id,
                "changed_by": changed_by, "note": note, "ok": True,
            })
            return {"ok": True, "page": page_id, "saved_to": path}
        except Exception as e:
            _append_assistant_log({
                "action": "save_policy", "page": page_id,
                "changed_by": changed_by, "ok": False, "error": str(e),
            })
            return {"ok": False, "error": str(e)}

    # ── Activity Review ────────────────────────────────────────────────

    def get_activity(self, limit: int = 50) -> Dict[str, Any]:
        """Get recent guardrail activity (audit log + risk states)."""
        audit = self.monitor.get_audit_log(limit=limit)
        risk_states = self.tracker.all_states()
        canary_state = self.canary.get_state()
        integrity = self.watcher.check()
        engine_stats = self.engine.get_stats()
        monitor_stats = self.monitor.get_stats()

        return {
            "ok": True,
            "audit": audit,
            "audit_count": len(audit),
            "risk_states": risk_states,
            "risk_count": len(risk_states),
            "risk_at_risk": [
                r for r in risk_states
                if r["level"] in ("high", "critical")
            ],
            "canary": canary_state,
            "integrity": integrity,
            "engine_stats": engine_stats,
            "monitor_stats": monitor_stats,
        }

    def get_audit_detail(self, limit: int = 100) -> Dict[str, Any]:
        """Get detailed audit log entries."""
        audit = self.monitor.get_audit_log(limit=limit)
        return {"ok": True, "audit": audit, "count": len(audit)}

    def get_risk_summary(self) -> Dict[str, Any]:
        """Get conversation-level risk summary."""
        risk_states = self.tracker.all_states()
        return {
            "ok": True,
            "conversations": len(risk_states),
            "at_risk": [
                r for r in risk_states
                if r["level"] in ("high", "critical")
            ],
            "by_level": {
                "low": len([r for r in risk_states if r["level"] == "low"]),
                "medium": len([r for r in risk_states if r["level"] == "medium"]),
                "high": len([r for r in risk_states if r["level"] == "high"]),
                "critical": len([r for r in risk_states if r["level"] == "critical"]),
            },
        }

    # ── System Health ──────────────────────────────────────────────────

    def get_health(self) -> Dict[str, Any]:
        """Get overall system health."""
        engine_stats = self.engine.get_stats()
        mode = load_mode()
        integrity = self.watcher.check()
        canary = self.canary.get_state()
        risk_states = self.tracker.all_states()
        at_risk = [r for r in risk_states if r["level"] in ("high", "critical")]

        degraded = (
            len(at_risk) > 0
            or (isinstance(integrity.get("findings"), list)
                and len(integrity["findings"]) > 0)
            or canary.get("consecutive_failures", 0) > 0
            or os.path.exists(
                os.path.join(
                    os.environ.get("GUARDRAIL_LOG_DIR", "logs"),
                    "emergency.lock",
                )
            )
        )

        return {
            "ok": True,
            "status": "degraded" if degraded else "ok",
            "mode": mode.value,
            "engine_stats": engine_stats,
            "integrity": integrity,
            "canary": canary,
            "risk_at_risk_count": len(at_risk),
            "emergency_locked": os.path.exists(
                os.path.join(
                    os.environ.get("GUARDRAIL_LOG_DIR", "logs"),
                    "emergency.lock",
                )
            ),
            "2fa_configured": is_2fa_configured(),
            "auth_configured": is_auth_configured(),
        }

    # ── Emergency Control ──────────────────────────────────────────────

    def emergency_contain(self) -> Dict[str, Any]:
        """Trigger containment (stage 1)."""
        import subprocess
        script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "scripts", "emergency-override.sh",
        )
        result = subprocess.run(
            ["bash", script, "contain"],
            capture_output=True, text=True, timeout=30,
        )
        _log_auth_event("assistant_emergency_contain", "assistant")
        _append_assistant_log({
            "action": "emergency_contain", "ok": result.returncode == 0,
            "output": result.stdout[:500],
        })
        return {
            "ok": result.returncode == 0,
            "message": "containment activated" if result.returncode == 0
            else result.stderr[:200],
        }

    def emergency_shutdown(self) -> Dict[str, Any]:
        """Trigger full shutdown (stage 4)."""
        import subprocess
        script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "scripts", "emergency-override.sh",
        )
        result = subprocess.run(
            ["bash", script, "shutdown"],
            capture_output=True, text=True, timeout=30,
        )
        _log_auth_event("assistant_emergency_shutdown", "assistant")
        _append_assistant_log({
            "action": "emergency_shutdown", "ok": result.returncode == 0,
            "output": result.stdout[:500],
        })
        return {
            "ok": result.returncode == 0,
            "message": "full shutdown locked" if result.returncode == 0
            else result.stderr[:200],
        }

    def emergency_all(self) -> Dict[str, Any]:
        """Run all emergency stages."""
        import subprocess
        script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "scripts", "emergency-override.sh",
        )
        result = subprocess.run(
            ["bash", script, "all"],
            capture_output=True, text=True, timeout=30,
        )
        _log_auth_event("assistant_emergency_all", "assistant")
        _append_assistant_log({
            "action": "emergency_all", "ok": result.returncode == 0,
            "output": result.stdout[:500],
        })
        return {
            "ok": result.returncode == 0,
            "message": "all stages activated" if result.returncode == 0
            else result.stderr[:200],
        }

    def emergency_reenable(
        self, password: str, totp_code: Optional[str] = None,
        backup_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Re-enable the system after emergency shutdown."""
        import subprocess
        script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "scripts", "emergency-override.sh",
        )
        cmd = ["bash", script, "reenable"]
        if password:
            cmd += ["--password", password]
        if totp_code:
            cmd += ["--totp", totp_code]
        if backup_code:
            cmd += ["--backup", backup_code]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        ok = result.returncode == 0
        _log_auth_event(
            "assistant_emergency_reenable", "assistant",
            detail=("ok" if ok else "denied: " + result.stderr[:200]),
        )
        _append_assistant_log({
            "action": "emergency_reenable", "ok": ok,
            "output": result.stderr[:500] if not ok else "",
        })
        return {
            "ok": ok,
            "message": "system re-enabled" if ok else result.stderr[:200],
        }


# ── Global instance ──────────────────────────────────────────────────

_assistant: Optional[AssistantManager] = None


def get_assistant() -> AssistantManager:
    global _assistant
    if _assistant is None:
        _assistant = AssistantManager()
    return _assistant
