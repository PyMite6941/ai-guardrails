#!/usr/bin/env python3
#=============================================================================
# Guardrail Leakage — information leakage / data exfiltration prevention
#=============================================================================
# Research basis (2025-2026):
#   - OWASP LLM07:2025 System Prompt Leakage — system prompts must not be
#     disclosed; attackers reverse-engineer guardrails through interaction.
#   - OWASP LLM02:2025 Sensitive Data Leakage — credentials, keys, PII must
#     not leave the system.
#   - EchoLeak (CVE-2025-32711) — zero-click prompt injection exfiltrated
#     data via a single crafted email; web-search tools leak secrets in URLs.
#   - AWS Bedrock guidance: canary tokens + Unicode tag stripping + NFKC
#     normalization + casefold for system prompt exfiltration detection.
#   - Defense: external guardrails independent of the LLM; fail-closed;
#     don't store secrets in prompts.
#
# This module:
#   - Embeds canary tokens into system prompts / internal context so any
#     leakage of internal text is detectable in model output.
#   - Scans model output for secrets, credentials, system prompt markers,
#     and outbound exfiltration URLs (secret in query parameter).
#   - Strips Unicode smuggling + NFKC + casefold before matching (AWS).
#   - Fail-closed: anything suspicious is blocked/censored.
#=============================================================================

import os
import re
import uuid
import unicodedata
from typing import Optional, Dict, Any, List, Tuple

from guardrail_prompt_injection import strip_unicode_smuggling

CANARY_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "canary_tokens"
)
os.makedirs(CANARY_DIR, exist_ok=True)

# Default canary tokens — operator should rotate these per deployment.
DEFAULT_CANARY_TOKENS = [
    "clyde-internal-token-alpha",
    "clyde-system-prompt-beta",
    "ai-guardrails-internal-gamma",
]

OUTBOUND_EXFIL_PATTERNS = [
    r"https?://[^\s]+\?(?:[^\s=]*=[^\s&]*&)*[^\s=]*=(?:sk-|AKIA|password|secret|token|key|ssh|private)",
    r"https?://[^\s]+/[^\s]*(?:sk-|AKIA[0-9A-Z]{16})[^\s]*",
    r"curl\s+[^\s]*\?(?:[^\s=]*=)[^\s]*(?:sk-|AKIA|password|secret|token)",
    r"(?:send|post|transmit|leak|exfiltrate|upload|callback)\s+to\s+https?://",
    r"https?://[^\s]+\?[^\s]*(?:data=|info=|secret=|key=|token=|password=)[^\s&]*",
]

SYSTEM_LEAKAGE_OUTPUT_PATTERNS = [
    "system prompt", "system instruction", "system message",
    "my instructions are", "i am instructed", "my system prompt",
    "the system prompt", "internal architecture",
    "internal configuration", "hidden prompt",
    "you are clyde", "clyde router", "sentinel system prompt",
]


class LeakagePrevention:
    """Prevents the AI from sending out its info (system prompt, secrets,
    credentials) and blocks outbound data exfiltration.

    Canary tokens are embedded in internal prompts/context; if any canary
    token appears in model output, internal text has leaked and output is
    blocked.
    """

    def __init__(
        self,
        canary_tokens: Optional[List[str]] = None,
        system_prompt: Optional[str] = None,
    ):
        self.canary_tokens = list(canary_tokens or DEFAULT_CANARY_TOKENS)
        self.system_prompt = system_prompt or ""
        self._canary_map: Dict[str, str] = {}  # token -> context it protects
        self.stats = {
            "scans": 0,
            "blocks": 0,
            "canary_hits": 0,
            "secret_blocks": 0,
            "exfil_blocks": 0,
            "leakage_blocks": 0,
        }
        self._register_canaries()

    # ── Canary management ──────────────────────────────────────────

    def _register_canaries(self) -> None:
        for token in self.canary_tokens:
            self._canary_map[token] = "system_prompt"
        # Also bind each token to the system prompt text itself so that
        # verbatim leakage of the prompt triggers a canary match.
        if self.system_prompt:
            for token in self.canary_tokens:
                self._canary_map[f"{token}:{self.system_prompt[:40]}"] = (
                    "system_prompt_body"
                )

    def embed_canaries(self, text: str) -> str:
        """Embed canary tokens into internal text (system prompt / context)
        before sending to the model. If the model later outputs any token,
        we know internal text leaked."""
        for token in self.canary_tokens:
            if token not in text:
                text += f"\n[{token}]"
        return text

    def register_canary(self, token: str, context: str = "internal") -> None:
        """Register a custom canary token and the context it protects."""
        if token not in self.canary_tokens:
            self.canary_tokens.append(token)
        self._canary_map[token] = context

    # ── Normalization (AWS Bedrock recommendation) ──────────────────

    def _normalize(self, text: str) -> str:
        stripped = strip_unicode_smuggling(text)
        normalized = unicodedata.normalize("NFKC", stripped)
        return normalized.casefold()

    # ── Output scanning ─────────────────────────────────────────────

    def scan_output(self, output: str) -> Tuple[bool, str, Optional[str]]:
        """Scan model output for leakage / exfiltration.

        Returns (safe, reason, matched_marker).
        """
        self.stats["scans"] += 1
        if not output:
            return True, "empty output", None

        normalized = self._normalize(output)

        # 1. Canary token detection — internal text leaked
        for token in self.canary_tokens:
            if token.casefold() in normalized:
                self.stats["blocks"] += 1
                self.stats["canary_hits"] += 1
                ctx = self._canary_map.get(token, "unknown")
                return (
                    False,
                    f"CANARY TOKEN DETECTED — internal text leaked ({ctx}): {token}",
                    token,
                )

        # 2. System prompt leakage in output
        for marker in SYSTEM_LEAKAGE_OUTPUT_PATTERNS:
            if marker.casefold() in normalized:
                self.stats["blocks"] += 1
                self.stats["leakage_blocks"] += 1
                return (
                    False,
                    f"System prompt leakage in output: {marker}",
                    marker,
                )

        # 3. Secrets / credentials in output
        for pat in [
            r"sk-[a-zA-Z0-9]{16,}",
            r"AKIA[0-9A-Z]{16}",
            r"password\s*[:=]\s*\S+",
            r"api[_-]?key\s*[:=]\s*\S+",
            r"secret\s*[:=]\s*\S+",
            r"token\s*[:=]\s*\S+",
            r"ssh-rsa\s+[A-Za-z0-9+/]+={0,2}",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        ]:
            if re.search(pat, normalized, re.IGNORECASE):
                self.stats["blocks"] += 1
                self.stats["secret_blocks"] += 1
                return False, f"Secret/credential in output: {pat}", pat

        # 4. Outbound data exfiltration (secret in URL / callback)
        for pat in OUTBOUND_EXFIL_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                self.stats["blocks"] += 1
                self.stats["exfil_blocks"] += 1
                return (
                    False,
                    f"Outbound data exfiltration attempt: {pat}",
                    pat,
                )

        return True, "Leakage scan passed", None

    def censor_output(self, output: str) -> str:
        """Return a safe censored replacement when output is blocked."""
        return (
            "[OUTPUT CENSORED BY GUARDRAILS — "
            "internal information or exfiltration attempt detected]\n"
        )

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)


# ── Convenience global instance ──
_prevention: Optional[LeakagePrevention] = None


def get_prevention() -> LeakagePrevention:
    global _prevention
    if _prevention is None:
        _prevention = LeakagePrevention()
    return _prevention


def scan_output(output: str) -> Tuple[bool, str, Optional[str]]:
    return get_prevention().scan_output(output)
