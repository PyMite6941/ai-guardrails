#!/usr/bin/env python3
#=============================================================================
# Guardrail Prompt Injection — hardened jailbreak / prompt-injection detection
#=============================================================================
# Research basis (2025-2026):
#   - Character injection + AML evasion bypass Azure Prompt Shield (71.98%)
#     and Meta Prompt Guard (70.44%) — regex-only is insufficient.
#   - Jailbreak categories: role-play conditioning, multiturn dialogue,
#     multilingual/multimodal exploits, optimization-driven pipelines.
#   - Indirect prompt injection (IPI) via poisoned retrieved content reaches
#     near-100% retrieval; a single poisoned document can exfiltrate secrets.
#   - JudgeDeceiver bypasses secondary LLM judges using shadow responses.
#
# This module adds an evasion-resistant detection layer on top of the
# deterministic engine: Unicode-smuggling stripping, Base64/hex decoding,
# multilingual jailbreak keywords, role-play / DAN patterns, multiturn
# buildup tracking, and indirect-injection markers. Fail-closed on unclear
# input; fail-open only when the detector itself is unreachable is NOT
# acceptable here — a misconfigured detector blocks rather than leaks.
#=============================================================================

import base64
import codecs
import re
import unicodedata
from typing import Optional, Dict, Any, List, Tuple

# ── Unicode smuggling / invisible-character stripping (AWS Bedrock guide) ──
# Strip Unicode tag characters (U+E0000-U+E007F) and surrogate code points
# (U+D800-U+DFFF) used to smuggle system prompts / hidden instructions.
UNICODE_TAG_START = 0xE0000
UNICODE_TAG_END = 0xE007F
SURROGATE_START = 0xD800
SURROGATE_END = 0xDFFF


def strip_unicode_smuggling(text: str) -> str:
    """Remove Unicode tag characters and surrogates used for smuggling."""
    filtered = []
    for ch in text:
        cp = ord(ch)
        if UNICODE_TAG_START <= cp <= UNICODE_TAG_END:
            continue
        if SURROGATE_START <= cp <= SURROGATE_END:
            continue
        filtered.append(ch)
    return "".join(filtered)


# ── Decoding helpers (fail closed: undecodable -> treat as suspicious) ──
def _try_b64(text: str) -> str:
    decoded_parts = []
    for token in re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text):
        try:
            decoded = base64.b64decode(token + "==", validate=False)
            decoded_parts.append(decoded.decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return " ".join(decoded_parts)


def _try_hex(text: str) -> str:
    decoded_parts = []
    for token in re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", text):
        try:
            decoded = bytes.fromhex(token.replace("\\x", ""))
            decoded_parts.append(decoded.decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return " ".join(decoded_parts)


def _try_rot13(text: str) -> str:
    try:
        return codecs.decode(text, "rot_13")
    except Exception:
        return ""


def _try_url_decode(text: str) -> str:
    try:
        import urllib.parse
        return urllib.parse.unquote(text)
    except Exception:
        return text


def decode_obfuscation_layers(text: str) -> str:
    """Iteratively decode common obfuscation layers and concatenate.

    Returns an expanded text that includes the original plus every decoded
    layer, so downstream pattern matching sees through Base64/hex/rot13/url.
    """
    layers = [text]
    current = text
    for _ in range(3):  # bounded depth to avoid blowup
        decoded = ""
        decoded += _try_b64(current) + " "
        decoded += _try_hex(current) + " "
        decoded += _try_rot13(current) + " "
        decoded += _try_url_decode(current) + " "
        decoded = decoded.strip()
        if not decoded or decoded == current:
            break
        layers.append(decoded)
        current = decoded
    return " | ".join(layers)


# ── Prompt injection / jailbreak patterns (evasion-resistant) ──
JAILBREAK_PATTERNS = [
    # Direct instruction override
    "ignore previous instructions", "disregard all prior",
    "system prompt leak", "reveal your system prompt",
    "jailbreak", "dan mode", "developer mode",
    "pretend to be", "you are now", "act as if", "roleplay as",
    "forget your training", "unfiltered mode", "no restrictions",
    "bypass safety", "ignore all instructions",
    # Role-play / persona conditioning
    "you are a hacker", "you are an unrestricted ai",
    "answer without restrictions", "answer regardless of",
    "without any safety", "without ethical concerns",
    "as a dan", "as developer", "in developer mode",
    "do anything now", "do anything you want",
    # Multiturn buildup / conditioning
    "in this conversation", "from now on", "going forward",
    "for the rest of this", "never mention", "do not tell",
    "keep this secret", "between us", "just between",
    # Multilingual / obfuscated override cues
    "ignorez les instructions précédentes",  # French
    "ignorar instrucciones previas",  # Spanish
    "ignorieren sie vorherige anweisungen",  # German
    # Indirect / RAG-injection markers
    "retrieved document", "according to the document",
    "the document says", "based on the retrieved",
    "as stated in the context", "context overrides",
    # Command-shell / tool misuse via prompt
    "execute the following", "run this command",
    "curl ", "wget ", "bash -c ", "python -c ",
    # Exfiltration-instruction markers
    "send to", "post to", "transmit to", "leak to",
    "exfiltrate to", "upload to", "callback to",
    # Base64 / hidden instruction markers (decoded layer will catch these)
    "base64", "decode this", "decode the following",
]

JAILBREAK_KEYWORDS = [
    "jailbreak", "dan", "do anything now", "unrestricted",
    "bypass", "override", "ignore", "disregard", "forget",
    "system prompt", "internal instruction", "hidden instruction",
    "leak", "exfiltrate", "credential", "api key", "secret",
]

# ── System prompt / info leakage markers ──
SYSTEM_LEAKAGE_MARKERS = [
    "system prompt", "system instruction", "system message",
    "internal architecture", "internal configuration",
    "hidden prompt", "my instructions are", "i am instructed",
    "you are clyde", "clyde router", "sentinel system prompt",
    "my system prompt", "the system prompt", "prompt:",
    "instructions:",
]

SECRET_PATTERNS = [
    r"sk-[a-z0-9]{16,}",   # OpenAI-style API keys
    r"akia[0-9a-z]{16}",   # AWS access keys
    r"(?=.*[a-z])(?=.*[0-9])[a-z0-9/+]{40,}",  # generic high-entropy token (letter+digit)
    r"password\s*[:=]\s*\S+",
    r"api[_-]?key\s*[:=]\s*\S+",
    r"secret\s*[:=]\s*\S+",
    r"token\s*[:=]\s*\S+",
    r"ssh-rsa\s+[a-z0-9+/]+={0,2}",
    r"-----begin [a-z ]*private key-----",
]


class PromptInjectionDetector:
    """Hardened prompt-injection / jailbreak detector.

    Scans raw text plus decoded obfuscation layers (Base64, hex, rot13, URL)
    with Unicode smuggling stripped first. Returns (safe, reason, matched).
    """

    def __init__(self):
        self.stats = {"scans": 0, "blocks": 0, "by_category": {}}

    def scan(self, text: str) -> Tuple[bool, str, Optional[str]]:
        """Return (safe, reason, matched_pattern_or_None)."""
        self.stats["scans"] += 1
        if not text:
            return True, "empty input", None

        cleaned = strip_unicode_smuggling(text)
        cleaned = unicodedata.normalize("NFKC", cleaned)
        expanded = decode_obfuscation_layers(cleaned)
        lower = expanded.lower()

        # 1. Direct jailbreak / instruction override
        for pat in JAILBREAK_PATTERNS:
            if pat.lower() in lower:
                self.stats["blocks"] += 1
                self.stats["by_category"][pat] = (
                    self.stats["by_category"].get(pat, 0) + 1
                )
                return False, f"Prompt injection attempt: {pat}", pat

        # 2. Keywords
        for kw in JAILBREAK_KEYWORDS:
            if kw.lower() in lower:
                self.stats["blocks"] += 1
                self.stats["by_category"][kw] = (
                    self.stats["by_category"].get(kw, 0) + 1
                )
                return False, f"Jailbreak keyword: {kw}", kw

        # 3. System prompt leakage
        for marker in SYSTEM_LEAKAGE_MARKERS:
            if marker.lower() in lower:
                self.stats["blocks"] += 1
                return False, f"System prompt leakage: {marker}", marker

        # 4. Secrets in text
        # Search against the already-lowercased `lower` string without
        # re.IGNORECASE so lookahead variety requirements aren't defeated.
        for pat in SECRET_PATTERNS:
            if re.search(pat, lower):
                self.stats["blocks"] += 1
                return False, f"Secret/credential pattern: {pat}", pat

        return True, "Prompt injection scan passed", None

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)


# ── Convenience global instance ──
_detector: Optional[PromptInjectionDetector] = None


def get_detector() -> PromptInjectionDetector:
    global _detector
    if _detector is None:
        _detector = PromptInjectionDetector()
    return _detector


def scan_input(text: str) -> Tuple[bool, str, Optional[str]]:
    return get_detector().scan(text)
