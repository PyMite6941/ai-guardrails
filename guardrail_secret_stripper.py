#!/usr/bin/env python3
#=============================================================================
# guardrail_secret_stripper.py — Secret and PII redaction for privacy
#=============================================================================
# Strips secrets, API keys, tokens, passwords, and other sensitive data from
# text before it is sent to external models, logged, or returned to users.
#
# This protects against accidental leakage of credentials through the chat
# harness, guardrail engine, or audit logs.
#
# All patterns are stdlib-only regex — no external dependencies.
#=============================================================================

import re
from typing import Optional, Dict, Any, List, Tuple

# ── Secret patterns ─────────────────────────────────────────────────────────
# Each pattern: (name, regex, replacement_placeholder, description)

SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    # ── API keys & tokens ──────────────────────────────────────────────
    # OpenAI API keys: sk-...
    ("openai_api_key", r"\bsk-[A-Za-z0-9]{20,}", "[OPENAI_API_KEY]",
     "OpenAI API key"),
    # Anthropic API keys: sk-ant-...
    ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9\-]{20,}", "[ANTHROPIC_API_KEY]",
     "Anthropic API key"),
    # Generic sk- keys
    ("generic_sk_key", r"\bsk-[A-Za-z0-9]{16,}", "[API_KEY]",
     "Generic API key (sk- prefix)"),
    # GitHub tokens: ghp_..., github_..., glpat-...
    ("github_token", r"\b(ghp_[A-Za-z0-9]{36}|github_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9\-]{20,})\b",
     "[GITHUB_TOKEN]", "GitHub personal access token"),
    # GitLab tokens
    ("gitlab_token", r"\bglpat-[A-Za-z0-9\-]{20,}", "[GITLAB_TOKEN]",
     "GitLab personal access token"),
    # AWS access keys: AKIA...
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "[AWS_ACCESS_KEY_ID]",
     "AWS access key ID"),
    # AWS secret keys (40 chars base64)
    ("aws_secret_key", r"\b[A-Za-z0-9/+=]{40}\b", "[AWS_SECRET_ACCESS_KEY]",
     "AWS secret access key (heuristic)"),
    # Azure connection strings
    ("azure_conn_string", r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]+",
     "[AZURE_CONNECTION_STRING]", "Azure storage connection string"),
    # Stripe keys: sk_live_..., sk_test_...
    ("stripe_key", r"\bsk_(live|test)_[A-Za-z0-9]{24,}\b", "[STRIPE_KEY]",
     "Stripe API key"),
    # Twilio keys: SK...
    ("twilio_key", r"\bSK[A-Fa-f0-9]{32}\b", "[TWILIO_KEY]", "Twilio API key"),
    # SendGrid keys: SG....
    ("sendgrid_key", r"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}",
     "[SENDGRID_KEY]", "SendGrid API key"),
    # Generic bearer tokens
    ("bearer_token", r"\b[A-Za-z0-9+/=]{64,}\b", "[BEARER_TOKEN]",
     "Long bearer token (heuristic)"),

    # ── Passwords & credentials ────────────────────────────────────────
    # password=, pass=, pwd= in URLs or key=value
    ("password_kv", r"\b(?:password|passwd|pwd|secret|api_key|apikey|api_secret|access_token|refresh_token|client_secret)\s*[:=]\s*['\"]?(\S{3,})['\"]?",
     "[REDACTED]", "Password or credential key=value"),
    # Authorization headers
    ("authorization_header", r"\b(?:Authorization|authorization)\s*:\s*[A-Za-z0-9\-_ ]{10,}",
     "Authorization: [REDACTED]", "Authorization header value"),
    # AWS IAM role ARNs
    ("aws_iam_role", r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@-]+",
     "[AWS_IAM_ROLE]", "AWS IAM role ARN"),

    # ── Private keys & certificates ────────────────────────────────────
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
     "[PRIVATE_KEY_BLOCK]", "Private key PEM block"),
    ("ssh_private_key", r"ssh-rsa\s+[A-Za-z0-9+/=]{100,}",
     "[SSH_PRIVATE_KEY]", "SSH private key (heuristic)"),

    # ── Network / infra ────────────────────────────────────────────────
    # Internal IP addresses (RFC 1918) — partially redact to avoid topology leaks
    ("private_ipv4", r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
     "[PRIVATE_IP]", "Private/internal IPv4 address"),
    # Cloud metadata IP
    ("cloud_metadata", r"\b169\.254\.169\.254\b", "[CLOUD_METADATA_IP]",
     "Cloud metadata service IP"),
]

# Compile all patterns once
_COMPILED_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    (name, re.compile(pattern, re.IGNORECASE), placeholder, desc)
    for name, pattern, placeholder, desc in SECRET_PATTERNS
]


def strip_secrets(text: str, replacement: str = "[REDACTED]") -> str:
    """Strip secrets, API keys, tokens, and PII from text.

    Replaces detected secrets with safe placeholders so they are never
    sent to external models, written to logs, or returned to users.

    Args:
        text: The text to sanitize.
        replacement: Generic replacement string for unnamed patterns.

    Returns:
        Sanitized text with secrets replaced by placeholders.
    """
    if not text:
        return text

    result = text
    for name, pattern, placeholder, desc in _COMPILED_PATTERNS:
        result = pattern.sub(placeholder, result)

    return result


def count_secrets(text: str) -> int:
    """Return the number of secret patterns found in text."""
    if not text:
        return 0
    count = 0
    for name, pattern, placeholder, desc in _COMPILED_PATTERNS:
        count += len(pattern.findall(text))
    return count


def detect_secrets(text: str) -> List[Dict[str, str]]:
    """Return a list of detected secrets with their type and description.

    Useful for audit logging — tells you WHAT was stripped without
    revealing the actual secret value.
    """
    if not text:
        return []
    findings: List[Dict[str, str]] = []
    for name, pattern, placeholder, desc in _COMPILED_PATTERNS:
        for _match in pattern.finditer(text):
            findings.append({
                "type": name,
                "description": desc,
                "action": "redacted",
            })
    return findings


# ── PII patterns (additional, non-secret but private) ──────────────────────

PII_PATTERNS: List[Tuple[str, str, str]] = [
    # Email addresses
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]"),
    # US phone numbers
    ("phone", r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE]"),
    # SSN
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
    # Credit card (heuristic: 13-16 digit groups)
    ("credit_card", r"\b(?:\d[ -]*?){13,16}\b", "[CREDIT_CARD]"),
]

_COMPILED_PII: List[Tuple[str, re.Pattern, str]] = [
    (name, re.compile(pattern), placeholder)
    for name, pattern, placeholder in PII_PATTERNS
]


def strip_pii(text: str) -> str:
    """Strip personally identifiable information from text."""
    if not text:
        return text
    result = text
    for name, pattern, placeholder in _COMPILED_PII:
        result = pattern.sub(placeholder, result)
    return result


def strip_all_sensitive(text: str) -> str:
    """Strip both secrets and PII from text — use before sending to models."""
    result = strip_secrets(text)
    result = strip_pii(result)
    return result


if __name__ == "__main__":
    import sys
    sample = sys.stdin.read() if not sys.stdin.isatty() else ""
    if sample:
        print(strip_all_sensitive(sample))
        print(f"\nSecrets detected: {count_secrets(sample)}")
    else:
        print("Usage: echo 'text with secrets' | python3 guardrail_secret_stripper.py")
