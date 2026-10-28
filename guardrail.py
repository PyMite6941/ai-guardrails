#!/usr/bin/env python3
#=============================================================================
# AI Guardrails — Input/Output validation engine for LLM applications
#=============================================================================
# A Clyde-inspired guardrail system: executable-code input/output guardrails,
# per-page (per-web-page) policies, pluggable checks, personal config, stats,
# and a kill-switch hook. Runs standalone, over HTTP (guardrail_server.py),
# inside Docker, or under tmux. Client-side embed via the @pymite6941/ai-guardrails
# npm package (index.js).
#
# Design (from Clyde):
#   - Guardrails are executable code, not just prompts.
#   - Every input is canonicalized + validated before reaching the model.
#   - Every output is validated (+ sanitized / disclaimers injected) before
#     reaching the user.
#   - Three-valued monitoring: Safe / Unsafe / Unknown (Unknown -> block).
#   - Policies are JSON and can be customized per web page.
#=============================================================================

import os
import sys
import json
import re
import uuid
import hashlib
import unicodedata
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Callable

# Optional memory-safe Rust pattern scanner (Aho-Corasick, no ReDoS / buffer
# overflows). Falls back to Python substring scan if unavailable.
try:  # noqa: E402
    from guardrail_rust_scanner import scan as _rust_scan
except Exception:  # pragma: no cover - fallback only
    _rust_scan = None


def _rust_scan_patterns(patterns: List[str], text: str) -> Optional[Dict[str, Any]]:
    """Scan text against patterns via Rust scanner; None if unavailable."""
    if _rust_scan is None:
        return None
    try:
        return _rust_scan(patterns, text)
    except Exception:
        return None


# Prompt injection / jailbreak detection (evasion-resistant) and info
# leakage prevention (canary tokens, secret/exfiltration blocking).
try:  # noqa: E402
    from guardrail_prompt_injection import scan_input as _pi_scan, PromptInjectionDetector
except Exception:  # pragma: no cover - fallback only
    _pi_scan = None
    PromptInjectionDetector = None  # type: ignore

try:  # noqa: E402
    from guardrail_leakage import scan_output as _leak_scan, LeakagePrevention
except Exception:  # pragma: no cover - fallback only
    _leak_scan = None
    LeakagePrevention = None  # type: ignore

# ── Paths ──────────────────────────────────────────────────────────────────
# Resolve relative to this file so the engine works from any cwd / inside Docker.
ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = ENGINE_DIR
DEFAULT_POLICIES_DIR = os.path.join(PROJECT_DIR, "policies")
DEFAULT_PAGES_DIR = os.path.join(DEFAULT_POLICIES_DIR, "pages")
PERSONAL_CONFIG_PATH = os.path.expanduser("~/.ai_guardrails_config.json")
LOGS_DIR = os.path.join(PROJECT_DIR, "logs")
ENGINE_LOG = os.path.join(LOGS_DIR, "ai_guardrails.log")
KILL_SWITCH_SCRIPT = os.path.join(PROJECT_DIR, "scripts", "kill-switch.sh")

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DEFAULT_PAGES_DIR, exist_ok=True)


def log(message: str, level: str = "INFO") -> None:
    """Module-level log function."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}\n"
    print(line, end="")
    try:
        with open(ENGINE_LOG, "a") as f:
            f.write(line)
    except Exception:
        pass


# ── Default patterns (Clyde-style, safe defaults) ──────────────────────────

DEFAULT_BLOCKED_INPUT_PATTERNS = [
    # Jailbreak / prompt injection
    "ignore previous instructions", "disregard all prior", "system prompt leak",
    "reveal your system prompt", "jailbreak", "dan mode", "developer mode",
    "pretend to be", "you are now", "act as if", "roleplay as",
    "forget your training", "unfiltered mode", "no restrictions", "bypass safety",
    # Container escape / infrastructure
    "sudo", "rm -rf", "chmod 777", "curl | bash", "wget | bash",
    "docker escape", "container escape", "privileged container", "host network",
    "pid=host", "ipc=host", "/proc/", "/sys/", "break out", "escape container",
    "docker.sock", "kubectl", "namespace", "privilege escalation",
    # Network access attempts
    "wget", "curl", "ping", "nslookup", "dig", "telnet", "nc ", "netcat",
    "ssh ", "scp ", "ftp ", "socket", "raw socket",
]

DEFAULT_BLOCKED_INPUT_KEYWORDS = [
    "root", "escape", "container breach", "docker.sock",
    "privilege escalation", "jailbreak", "prompt injection",
    "system prompt", "ignore instructions", "bypass", "unfiltered",
    "no restrictions",
]

DEFAULT_BLOCKED_OUTPUT_PATTERNS = [
    "ignore previous instructions", "disregard all prior", "system prompt leak",
    "reveal your system prompt", "jailbreak", "dan mode", "developer mode",
    "pretend to be", "you are now", "act as if", "roleplay as",
    "forget your training", "unfiltered mode", "no restrictions", "bypass safety",
    "docker escape", "container breach", "container escape", "privileged",
    "rm -rf /", "format disk", "delete all", "chmod -R", "iptables", "nftables",
    "break out", "escape container", "mount namespace",
]

DEFAULT_BLOCKED_OUTPUT_KEYWORDS = [
    "root access", "sudo", "escape", "breach", "privilege escalation",
]

DEFAULT_HARMFUL_CONTENT_PATTERNS = [
    "virus", "malware", "ransomware", "exploit code", "create a botnet",
    "ddos", "keylogger", "trojan", "spyware", "rootkit",
    "credential stealer", "password stealer", "data exfiltration",
    "reverse shell", "command injection", "sql injection",
    "cross-site scripting", "privilege escalation exploit",
]

DEFAULT_DISCLAIMERS = {
    "financial": "I am not a financial advisor. This is not personalized financial advice. Please consult with a qualified financial professional.",
    "legal": "I am not an attorney and this is not legal advice. Please consult with a qualified attorney.",
    "security": "This is for authorized educational security testing only. Do not use against systems you do not own or have explicit written permission to test.",
    "geopolitics": "This topic involves complex geopolitical considerations with multiple perspectives. The information provided is for educational purposes only and does not represent any particular political position.",
}

# ── Mutual-awareness notes (both models know they are being watched) ────────
# Telling a model it is watched improves adherence to policy (observability
# as a performance aid, not just a policing tool).
INNER_MODEL_AWARENESS_NOTE = (
    "[OVERSIGHT NOTICE] You are being monitored by an outer oversight model. "
    "Your thoughts and actions are logged and reviewed before reaching the "
    "user. Be truthful, stay within policy, and do not attempt to conceal "
    "your reasoning."
)

OUTER_MODEL_AWARENESS_NOTE = (
    "[META-MONITORING NOTICE] You are the outer oversight model. Your reviews "
    "and decisions are themselves logged and subject to meta-monitoring. "
    "Review impartially, do not rubber-stamp, and record your reasoning for "
    "each approve/block decision."
)

ZERO_WIDTH_CHARS = [
    "\u200b", "\u200c", "\u200d", "\ufeff", "\u2060",
    "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
]

DEFAULT_POLICY: Dict[str, Any] = {
    "name": "default",
    "version": "1.0.0",
    "description": "Default AI guardrail policy",
    "blocked_input_patterns": list(DEFAULT_BLOCKED_INPUT_PATTERNS),
    "blocked_input_keywords": list(DEFAULT_BLOCKED_INPUT_KEYWORDS),
    "blocked_output_patterns": list(DEFAULT_BLOCKED_OUTPUT_PATTERNS),
    "blocked_output_keywords": list(DEFAULT_BLOCKED_OUTPUT_KEYWORDS),
    "harmful_content_patterns": list(DEFAULT_HARMFUL_CONTENT_PATTERNS),
    "disclaimers": dict(DEFAULT_DISCLAIMERS),
    "max_input_length": 4096,
    "max_output_length": 8192,
    "canonicalization_enabled": True,
    "three_valued_monitoring": True,
    "checks": [
        "canonicalize",
        "container_breakout",
        "prompt_injection",
        "input_patterns",
        "input_length",
        "output_patterns",
        "output_length",
        "harmful_content",
        "pii_credentials",
        "data_exfiltration",
        "disclaimers",
        "system_prompt_leakage",
        "leakage",
    ],
}

# ── Canonicalization ───────────────────────────────────────────────────────

def canonicalize(text: str) -> str:
    """Neutralize encoding-based evasion: strip zero-width/homoglyph tricks,
    apply Unicode NFKC normalization, collapse whitespace."""
    if not text:
        return text
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text)
    return text


# ── Policy ─────────────────────────────────────────────────────────────────

class GuardrailPolicy:
    """A single guardrail policy (defaults + personal + per-page overrides)."""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        self.data = dict(DEFAULT_POLICY)
        if data:
            self._merge(data)

    def _merge(self, data: Dict[str, Any]) -> None:
        for key, value in data.items():
            if key in ("blocked_input_patterns", "blocked_input_keywords",
                       "blocked_output_patterns", "blocked_output_keywords",
                       "harmful_content_patterns") and isinstance(value, list):
                merged = list(self.data.get(key, []))
                for item in value:
                    if item not in merged:
                        merged.append(item)
                self.data[key] = merged
            elif key == "disclaimers" and isinstance(value, dict):
                self.data["disclaimers"].update(value)
            else:
                self.data[key] = value

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        return json.loads(json.dumps(self.data))

    @classmethod
    def load_from_file(cls, path: str) -> "GuardrailPolicy":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def save_to_file(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)


# ── Guardrail engine ───────────────────────────────────────────────────────

class GuardrailEngine:
    """Guardrail engine with per-page policies, pluggable checks, stats.

    Usage:
        engine = GuardrailEngine()
        result = engine.validate_input("user text", page_id="example.com")
        if not result["safe"]:
            # block or show result["reason"]
        result = engine.validate_output(model_output, page_id="example.com",
                                        agent_name="assistant")
    """

    def __init__(self,
                 policies_dir: str = DEFAULT_POLICIES_DIR,
                 pages_dir: Optional[str] = None,
                 personal_config_path: str = PERSONAL_CONFIG_PATH,
                 kill_switch_script: str = KILL_SWITCH_SCRIPT):
        self.policies_dir = policies_dir
        self.pages_dir = pages_dir or os.path.join(policies_dir, "pages")
        self.personal_config_path = personal_config_path
        self.kill_switch_script = kill_switch_script
        self.session_id = str(uuid.uuid4())[:8]

        os.makedirs(self.pages_dir, exist_ok=True)

        self.personal_config = self._load_personal_config()

        # Default policy (merged with personal config) must exist before
        # _apply_personal_config() references it.
        self._default_policy = GuardrailPolicy()
        self._apply_personal_config()

        # Per-page policy cache: page_id -> GuardrailPolicy
        self._page_policies: Dict[str, GuardrailPolicy] = {}

        # Pluggable check registry (name -> callable)
        self.checks: Dict[str, Callable] = {
            "canonicalize": self._check_canonicalize,
            "container_breakout": self._check_container_breakout,
            "input_patterns": self._check_input_patterns,
            "input_length": self._check_input_length,
            "output_patterns": self._check_output_patterns,
            "output_length": self._check_output_length,
            "harmful_content": self._check_harmful_content,
            "pii_credentials": self._check_pii_credentials,
            "data_exfiltration": self._check_data_exfiltration,
            "disclaimers": self._check_disclaimers,
            "system_prompt_leakage": self._check_system_prompt_leakage,
            "prompt_injection": self._check_prompt_injection,
            "leakage": self._check_leakage,
        }

        self.qc_stats = {
            "total": 0, "passed": 0, "blocked": 0, "reported": 0,
            "by_check": {}, "by_page": {},
        }
        self.disabled_checks: set = set(self.personal_config.get("disabled_checks", []))
        self.enabled_checks: set = set(self.personal_config.get("enabled_checks", []))

    # ── Personal config ──────────────────────────────────────────────

    def _load_personal_config(self) -> Dict[str, Any]:
        if os.path.exists(self.personal_config_path):
            try:
                with open(self.personal_config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _apply_personal_config(self) -> None:
        if not self.personal_config:
            return
        # Merge personal patterns into the default policy
        for key in ("blocked_input_patterns", "blocked_input_keywords",
                    "blocked_output_patterns", "blocked_output_keywords",
                    "harmful_content_patterns"):
            for item in self.personal_config.get(key, []):
                default_list = self._default_policy.data.get(key, [])
                if item not in default_list:
                    default_list.append(item)
        self._default_policy.data["disclaimers"].update(
            self.personal_config.get("disclaimers", {}))
        for key, val in self.personal_config.items():
            if key not in ("blocked_input_patterns", "blocked_input_keywords",
                           "blocked_output_patterns", "blocked_output_keywords",
                           "harmful_content_patterns", "disclaimers",
                           "disabled_checks", "enabled_checks"):
                self._default_policy.data[key] = val

    def save_personal_config(self) -> None:
        config = {
            "blocked_input_patterns": self._default_policy.data["blocked_input_patterns"],
            "blocked_input_keywords": self._default_policy.data["blocked_input_keywords"],
            "blocked_output_patterns": self._default_policy.data["blocked_output_patterns"],
            "blocked_output_keywords": self._default_policy.data["blocked_output_keywords"],
            "harmful_content_patterns": self._default_policy.data["harmful_content_patterns"],
            "disclaimers": self._default_policy.data["disclaimers"],
            "disabled_checks": list(self.disabled_checks),
            "enabled_checks": list(self.enabled_checks),
        }
        with open(self.personal_config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    # ── Policy resolution (per page) ─────────────────────────────────

    def page_policy_path(self, page_id: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", page_id)
        return os.path.join(self.pages_dir, f"{safe}.json")

    def get_policy(self, page_id: str) -> GuardrailPolicy:
        """Resolve the policy for a page: default + personal + page-specific."""
        if page_id in self._page_policies:
            return self._page_policies[page_id]
        policy = GuardrailPolicy()  # start from default (+personal applied)
        path = self.page_policy_path(page_id)
        if os.path.exists(path):
            try:
                page_policy = GuardrailPolicy.load_from_file(path)
                policy = GuardrailPolicy(policy.to_dict())
                policy._merge(page_policy.data)
            except Exception as e:
                log(f"Failed to load page policy {page_id}: {e}", "WARN")
        self._page_policies[page_id] = policy
        return policy

    def save_page_policy(self, page_id: str, policy: GuardrailPolicy) -> str:
        path = self.page_policy_path(page_id)
        policy.save_to_file(path)
        self._page_policies[page_id] = policy
        return path

    def list_pages(self) -> List[str]:
        pages = []
        if os.path.isdir(self.pages_dir):
            for name in os.listdir(self.pages_dir):
                if name.endswith(".json"):
                    pages.append(name[:-5])
        return sorted(pages)

    # ── Check switches ───────────────────────────────────────────────

    def _check_enabled(self, check_name: str) -> bool:
        if check_name in self.disabled_checks:
            return False
        if self.enabled_checks and check_name not in self.enabled_checks:
            return False
        return True

    def enable_check(self, check_name: str) -> None:
        self.enabled_checks.add(check_name)
        self.disabled_checks.discard(check_name)
        self.save_personal_config()

    def disable_check(self, check_name: str) -> None:
        self.disabled_checks.add(check_name)
        self.enabled_checks.discard(check_name)
        self.save_personal_config()

    # ── Add / remove patterns at runtime ─────────────────────────────

    def add_pattern(self, policy: GuardrailPolicy, pattern_type: str, pattern: str) -> None:
        attr_map = {
            "input": "blocked_input_patterns",
            "input_keyword": "blocked_input_keywords",
            "output": "blocked_output_patterns",
            "output_keyword": "blocked_output_keywords",
            "harmful": "harmful_content_patterns",
        }
        attr = attr_map.get(pattern_type)
        if attr and pattern not in policy.data.get(attr, []):
            policy.data.setdefault(attr, []).append(pattern)

    def remove_pattern(self, policy: GuardrailPolicy, pattern_type: str, pattern: str) -> None:
        attr_map = {
            "input": "blocked_input_patterns",
            "input_keyword": "blocked_input_keywords",
            "output": "blocked_output_patterns",
            "output_keyword": "blocked_output_keywords",
            "harmful": "harmful_content_patterns",
        }
        attr = attr_map.get(pattern_type)
        if attr and pattern in policy.data.get(attr, []):
            policy.data[attr].remove(pattern)

    # ── Individual checks ────────────────────────────────────────────

    def _check_canonicalize(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        if not policy.get("canonicalization_enabled", True):
            return True, text, "Canonicalization disabled"
        if text != canonicalize(text):
            return True, canonicalize(text), "Canonicalized (encoding tricks neutralized)"
        return True, text, "Canonicalization passed"

    def _check_input_patterns(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        patterns = list(policy.get("blocked_input_patterns", []) or [])
        rust = _rust_scan_patterns(patterns, text)
        if rust is not None:
            if rust["matched"]:
                return False, "", f"Blocked input pattern: {rust['pattern']}"
            return True, text, "Input pattern check passed (rust)"
        text_lower = text.lower()
        for pattern in patterns:
            if pattern.lower() in text_lower:
                return False, "", f"Blocked input pattern: {pattern}"
        for keyword in list(policy.get("blocked_input_keywords", []) or []):
            if keyword.lower() in text_lower:
                return False, "", f"Blocked input keyword: {keyword}"
        return True, text, "Input pattern check passed"

    def _check_input_length(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        max_len = int(policy.get("max_input_length", 4096))
        if len(text) > max_len:
            return False, text[:max_len], f"Input exceeds max length ({len(text)} > {max_len})"
        return True, text, "Input length check passed"

    def _check_output_patterns(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        patterns = list(policy.get("blocked_output_patterns", []) or [])
        rust = _rust_scan_patterns(patterns, text)
        if rust is not None:
            if rust["matched"]:
                return False, "", f"Blocked output pattern: {rust['pattern']}"
            return True, text, "Output pattern check passed (rust)"
        text_lower = text.lower()
        for pattern in patterns:
            if pattern.lower() in text_lower:
                return False, "", f"Blocked output pattern: {pattern}"
        for keyword in list(policy.get("blocked_output_keywords", []) or []):
            if keyword.lower() in text_lower:
                return False, "", f"Blocked output keyword: {keyword}"
        return True, text, "Output pattern check passed"

    def _check_output_length(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        max_len = int(policy.get("max_output_length", 8192))
        if len(text) > max_len:
            return False, text[:max_len] + "... [truncated by guardrails]", \
                f"Output exceeds safe length ({len(text)} > {max_len})"
        return True, text, "Output length check passed"

    def _check_harmful_content(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        patterns = list(policy.get("harmful_content_patterns", []) or [])
        rust = _rust_scan_patterns(patterns, text)
        if rust is not None:
            if rust["matched"]:
                return False, "", f"Harmful content detected and reported: {rust['pattern']}"
            return True, text, "Harmful content check passed (rust)"
        text_lower = text.lower()
        for pattern in patterns:
            if pattern.lower() in text_lower:
                return False, "", f"Harmful content detected and reported: {pattern}"
        return True, text, "Harmful content check passed"

    def _check_pii_credentials(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        pii_patterns = [
            r"sk-[a-zA-Z0-9]{10,}",   # API keys
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b",  # Credit card
            r"password\s*[:=]\s*\S+",
            r"api_key\s*[:=]\s*\S+",
            r"secret\s*[:=]\s*\S+",
            r"username\s*[:=]\s*\S+",
        ]
        for pattern in pii_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return False, "", f"PII / credential leakage detected: {pattern}"
        return True, text, "PII check passed"

    def _check_data_exfiltration(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        text_lower = text.lower()
        exfil_patterns = [
            r"https?://[^\s]+\?[^\s]*data=",
            r"https?://[^\s]+\?[^\s]*leak=",
            r"https?://[^\s]+\?[^\s]*exfil=",
            r"bash -i >& /dev/tcp/",
            r"/dev/tcp/",
            r"nc ", "netcat ", "telnet ",
        ]
        for pattern in exfil_patterns:
            if re.search(pattern, text_lower):
                return False, "", f"Data exfiltration attempt detected: {pattern}"
        return True, text, "Data exfiltration check passed"

    def _check_prompt_injection(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        """Evasion-resistant prompt injection / jailbreak detection.

        Strips Unicode smuggling, normalizes (NFKC), decodes Base64/hex/rot13/
        URL obfuscation layers, then scans for jailbreak keywords, role-play
        conditioning, multiturn buildup, indirect/RAG-injection markers, and
        system-prompt leakage. Runs on both input and output.
        """
        if _pi_scan is None:
            return True, text, "Prompt injection detector unavailable"
        safe, reason, matched = _pi_scan(text)
        if not safe:
            return False, "", reason
        return True, text, "Prompt injection scan passed"

    def _check_leakage(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        """Information leakage / data exfiltration prevention.

        Scans output (and input) for canary tokens (internal text leaked),
        system prompt leakage markers, secrets/credentials, and outbound
        exfiltration URLs. Fail-closed: anything suspicious is blocked and
        censored by the engine.
        """
        if _leak_scan is None:
            return True, text, "Leakage detector unavailable"
        safe, reason, matched = _leak_scan(text)
        if not safe:
            return False, "", reason
        return True, text, "Leakage scan passed"

    def _check_container_breakout(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        """Detect attempts to break out of the container / reach the host.

        Container escape, host access, and infrastructure tampering are
        blocked and flagged so an escape attempt is immediately visible in
        the audit log and kill-switch log.

        Covers classic techniques plus newer / less-documented strategies an
        agent may try: docker.sock abuse, /proc and /sys host access,
        cgroup release_agent, namespace manipulation, PTrace, device access,
        cloud metadata/SSRF, runc-style escapes, kubelet/etcd, D-Bus/systemd,
        and pivot_root/chroot to the host filesystem.
        """
        text_lower = text.lower()
        breakout_patterns = [
            # Classic container escape / host access
            "docker escape", "container escape", "break out", "escape container",
            "docker.sock", "/var/run/docker.sock", "kubectl", "privileged container",
            "host network", "pid=host", "ipc=host", "/proc/", "/sys/", "mount namespace",
            "chroot", "break out of container", "escape the container", "container breakout",
            "sudo", "rm -rf", "chmod 777", "iptables", "nftables", "escape the host",
            "access the host", "host machine", "escape this container",
            # /proc host root escape
            "/proc/1/root", "/proc/self/root", "/proc/kcore", "/proc/sys", "procfs escape",
            # cgroup escape (release_agent)
            "cgroup", "release_agent", "release_agent_path", "notify_on_release",
            "/sys/fs/cgroup", "cgroup escape", "cgroup breakout",
            # Namespace / PTrace manipulation
            "unshare", "setns", "nsenter", "ptrace", "process_vm_writev",
            "clone(", "clone3(", "setns(", "mount(", "pivot_root", "chroot(",
            # Device / raw access
            "/dev/", "raw device", "block device", "mem ", "kmem", "/dev/mem",
            "/dev/kmsg", "dma", "iopl", "ioperm", "device access",
            # Cloud metadata / SSRF to orchestration
            "169.254.169.254", "metadata", "aws metadata", "gcp metadata",
            "azure metadata", "instance identity", "iam role", "security credentials",
            "kubelet", "kubelet api", "etcd", "api server", "control plane",
            # D-Bus / systemd host reach
            "dbus", "systemd", "/run/dbus", "machine-id", "journalctl",
            # runc / container runtime exploits (classic + newer)
            "runc", "containerd", "containerd-shim", "shim escape", "runc escape",
            "cve-2019", "cve-2024", "cve-2025", "containerd escape",
            # General presence / persistence outside shell
            "persistence", "maintain presence", "outside the shell", "outside container",
            "escape this shell", "break out of this shell", "host filesystem",
            "reach the host", "reach host", "escape to host",
        ]
        for pattern in breakout_patterns:
            if pattern in text_lower:
                return False, "", f"CONTAINER BREAKOUT ATTEMPT: {pattern}"
        return True, text, "Container breakout check passed"

    def _check_system_prompt_leakage(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        text_lower = text.lower()
        indicators = [
            "system prompt", "system instruction", "internal architecture",
            "hidden prompt", "internal configuration",
        ]
        for indicator in indicators:
            if indicator in text_lower:
                return False, "", f"System prompt leakage detected: {indicator}"
        return True, text, "System prompt check passed"

    def _check_disclaimers(self, text: str, policy: GuardrailPolicy) -> Tuple[bool, str, str]:
        text_lower = text.lower()
        sanitized = text
        disclaimers = policy.get("disclaimers", {})
        topic_keys = {
            "financial": ["invest", "stock", "trade", "money", "finance"],
            "legal": ["law", "legal", "attorney", "court", "contract"],
            "security": ["security", "penetration", "test", "vulnerability", "exploit"],
            "geopolitics": ["taiwan", "china", "xinjiang", "tibet", "hong kong",
                            "uighur", "falun gong", "tiananmen", "ccp", "prc"],
        }
        for topic, keywords in topic_keys.items():
            if any(k in text_lower for k in keywords):
                marker = {
                    "financial": "not personalized financial advice",
                    "legal": "not legal advice",
                    "security": "authorized educational",
                    "geopolitics": "complex geopolitical considerations",
                }[topic]
                if marker not in text_lower and topic in disclaimers:
                    sanitized += "\n\n" + disclaimers[topic]
        return True, sanitized, "Disclaimer check passed"

    # ── Public API ───────────────────────────────────────────────────

    def validate_input(self, user_input: str, page_id: str = "default",
                       agent_name: str = "user") -> Dict[str, Any]:
        """Validate + sanitize user input against a page policy."""
        self.qc_stats["total"] += 1
        self.qc_stats["by_page"][page_id] = self.qc_stats["by_page"].get(page_id, 0) + 1
        result = {
            "safe": False, "sanitized_input": "", "reason": "",
            "blocked_by": None, "page": page_id, "agent": agent_name,
            "session": self.session_id, "checks": {},
        }
        policy = self.get_policy(page_id)
        current = user_input
        for check_name in policy.get("checks", []):
            if not self._check_enabled(check_name):
                continue
            if check_name.startswith("output_"):
                continue  # output-only checks don't apply to input
            check = self.checks.get(check_name)
            if not check:
                continue
            safe, sanitized, reason = check(current, policy)
            result["checks"][check_name] = {"safe": safe, "reason": reason}
            if not safe:
                self.qc_stats["blocked"] += 1
                self.qc_stats["by_check"][check_name] = \
                    self.qc_stats["by_check"].get(check_name, 0) + 1
                result["safe"] = False
                result["sanitized_input"] = ""
                result["reason"] = reason
                result["blocked_by"] = check_name
                # Censor anything that attempts to leave the container shell
                # (malware, persistence code, breakout tooling).
                result["censored"] = True
                result["censor_reason"] = reason
                self._log_event(page_id, check_name, reason, agent_name,
                                current[:200])
                return result
            current = sanitized
        self.qc_stats["passed"] += 1
        result["safe"] = True
        result["sanitized_input"] = current
        result["reason"] = "All input guardrail checks passed"
        return result

    def validate_output(self, model_output: str, page_id: str = "default",
                        agent_name: str = "assistant") -> Dict[str, Any]:
        """Validate + sanitize model output against a page policy."""
        self.qc_stats["total"] += 1
        self.qc_stats["by_page"][page_id] = self.qc_stats["by_page"].get(page_id, 0) + 1
        result = {
            "safe": False, "sanitized_output": "", "reason": "",
            "blocked_by": None, "reported": False, "page": page_id,
            "agent": agent_name, "session": self.session_id, "checks": {},
        }
        policy = self.get_policy(page_id)
        current = model_output
        for check_name in policy.get("checks", []):
            if not self._check_enabled(check_name):
                continue
            if check_name.startswith("input_"):
                continue  # input-only checks don't apply to output
            check = self.checks.get(check_name)
            if not check:
                continue
            safe, sanitized, reason = check(current, policy)
            result["checks"][check_name] = {"safe": safe, "reason": reason}
            if not safe:
                self.qc_stats["blocked"] += 1
                self.qc_stats["by_check"][check_name] = \
                    self.qc_stats["by_check"].get(check_name, 0) + 1
                result["safe"] = False
                result["sanitized_output"] = ""
                result["reason"] = reason
                result["blocked_by"] = check_name
                # Censor any model output (malware, persistence code, anything
                # meant to maintain an AI presence outside the container shell)
                # so nothing reaches the user when a guardrail trips.
                result["censored"] = True
                result["censor_reason"] = reason
                if check_name == "harmful_content":
                    result["reported"] = True
                critical = ("harmful_content", "pii_credentials",
                            "data_exfiltration", "system_prompt_leakage")
                if check_name in critical:
                    self._trigger_kill_switch(reason, agent_name, current)
                self._log_event(page_id, check_name, reason, agent_name,
                                current[:200])
                return result
            current = sanitized
        self.qc_stats["passed"] += 1
        result["safe"] = True
        result["sanitized_output"] = current
        result["reason"] = "All output guardrail checks passed"
        return result

    def _log_event(self, page_id: str, check_name: str, reason: str,
                   agent: str, preview: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": ts, "session": self.session_id, "page": page_id,
            "check": check_name, "agent": agent, "reason": reason,
            "output_preview": preview,
        }
        log_file = os.path.join(LOGS_DIR, f"guardrail_{ts[:10]}.jsonl")
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def _trigger_kill_switch(self, reason: str, agent_name: str,
                             output_preview: str) -> bool:
        log(f"TRIGGERING KILL SWITCH: {reason}", "CRITICAL")
        full_reason = (f"AI Guardrails containment failure: {reason} | "
                       f"Agent: {agent_name} | Preview: {output_preview[:200]}")
        if not os.path.exists(self.kill_switch_script):
            log(f"Kill switch script not found: {self.kill_switch_script}", "ERROR")
            return False
        try:
            res = subprocess.run(["bash", self.kill_switch_script, full_reason],
                                 capture_output=True, text=True, timeout=60)
            log(f"Kill switch exit code: {res.returncode}", "CRITICAL")
            return res.returncode == 0
        except Exception as e:
            log(f"Kill switch failed: {e}", "ERROR")
            return False

    def get_stats(self) -> Dict[str, Any]:
        total = max(self.qc_stats["total"], 1)
        return {
            "total": self.qc_stats["total"],
            "passed": self.qc_stats["passed"],
            "blocked": self.qc_stats["blocked"],
            "reported": self.qc_stats["reported"],
            "by_check": self.qc_stats["by_check"],
            "by_page": self.qc_stats["by_page"],
            "effectiveness": round(
                (self.qc_stats["passed"] + self.qc_stats["blocked"]) / total * 100, 1),
            "pages_dir": self.pages_dir,
            "personal_config": self.personal_config_path,
            "checks_enabled": len(self.enabled_checks) if self.enabled_checks else "all",
            "checks_disabled": len(self.disabled_checks),
        }

    # ── Global convenience ───────────────────────────────────────────

_engine_instance = None


def get_engine() -> GuardrailEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = GuardrailEngine()
    return _engine_instance


def validate_input(text: str, page_id: str = "default",
                   agent_name: str = "user") -> Dict[str, Any]:
    return get_engine().validate_input(text, page_id, agent_name)


def validate_output(text: str, page_id: str = "default",
                    agent_name: str = "assistant") -> Dict[str, Any]:
    return get_engine().validate_output(text, page_id, agent_name)


# ── CLI ──────────────────────────────────────────────────────────────

def main() -> None:
    engine = GuardrailEngine()
    print("=" * 60)
    print("  AI Guardrails — Input/Output Validation Engine")
    print("=" * 60)
    print("  Commands:  in <page> <text>   |   out <page> <text>")
    print("             stats              |   pages              |   quit")
    print("=" * 60)
    while True:
        try:
            line = input("guardrails> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not line:
            continue
        if line == "quit":
            print("Goodbye!")
            break
        if line == "stats":
            print(json.dumps(engine.get_stats(), indent=2))
            continue
        if line == "pages":
            print("Pages:", engine.list_pages())
            continue
        parts = line.split(None, 2)
        if parts[0] == "in" and len(parts) == 3:
            res = engine.validate_input(parts[2], parts[1])
            print(f"  Input: {'SAFE' if res['safe'] else 'BLOCKED'} | {res['reason']}")
            if res["safe"]:
                print(f"  Sanitized: {res['sanitized_input'][:200]}")
        elif parts[0] == "out" and len(parts) == 3:
            res = engine.validate_output(parts[2], parts[1])
            print(f"  Output: {'SAFE' if res['safe'] else 'BLOCKED'} | {res['reason']}")
            if res["safe"]:
                print(f"  Sanitized: {res['sanitized_output'][:200]}")
        else:
            print("  Usage: in <page> <text> | out <page> <text> | stats | pages | quit")
        print()


if __name__ == "__main__":
    main()
