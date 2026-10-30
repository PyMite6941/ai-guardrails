#!/usr/bin/env python3
#=============================================================================
# guardrail_models.py — Model provider configuration (local + cloud)
#=============================================================================
# Manages LLM model providers used by the guardrail system:
#   - Local providers (Ollama, LM Studio, etc.) — no API key needed
#   - Cloud providers (Nebius, OpenRouter, Groq, NVIDIA, OpenAI, etc.) — API key required
#
# A provider is selected per-session. The selection is stored in the user's
# session so every guardrail operation (outside model, classifier, trusted
# model) uses the chosen provider for that session.
#
# API keys are stored in .env (inside the repo) and loaded into the
# environment at startup. They are never written to disk by the UI/CLI.
#=============================================================================

import ipaddress
import json
import os
import re
import socket
import ssl
from typing import Optional, Dict, Any, List

from guardrail_auth import (
    is_2fa_configured, verify_2fa_code, verify_backup_code,
    SESSION_TTL_SECONDS,
)

# ── Domain validation ──────────────────────────────────────────────────────
# Validates custom domain URLs for model providers:
#   - Proper domain format (RFC 1123)
#   - Resolves to a real IP (DNS check)
#   - Not a private/internal address (SSRF protection)
#   - HTTPS required for cloud providers
#   - Certificate validity check (optional, on connect)
#=============================================================================

_PRIVATE_NETS: List[ipaddress._BaseNetwork] = [
    ipaddress.ip_network("10.0.0.0/8", strict=False),
    ipaddress.ip_network("172.16.0.0/12", strict=False),
    ipaddress.ip_network("192.168.0.0/16", strict=False),
    ipaddress.ip_network("169.254.0.0/16", strict=False),
    ipaddress.ip_network("fc00::/7", strict=False),
    ipaddress.ip_network("fe80::/10", strict=False),
    ipaddress.ip_network("127.0.0.0/8", strict=False),  # localhost
]

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def _resolve_domain(domain: str) -> List[str]:
    """Resolve a domain to all IP addresses (IPv4 + IPv6)."""
    addrs: List[str] = []
    try:
        for _fam, _type, _proto, _canon, sa in socket.getaddrinfo(domain, None):
            addr = sa[0]
            if addr not in addrs:
                addrs.append(addr)
    except Exception:
        pass
    return addrs


def is_domain_private(domain: str) -> bool:
    """Return True if the domain resolves to a private/internal address."""
    addrs = _resolve_domain(domain)
    if not addrs:
        return True  # unresolvable = unsafe
    for addr_str in addrs:
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if any(addr in net for net in _PRIVATE_NETS):
            return True
    return False


def validate_domain(domain: str) -> Dict[str, Any]:
    """Validate a domain for use as a model provider URL.

    Returns dict with: valid, reason, resolved_ips, is_private, scheme_suggestion
    """
    result: Dict[str, Any] = {
        "valid": False,
        "reason": "",
        "resolved_ips": [],
        "is_private": False,
        "scheme_suggestion": "https",
    }

    if not domain or not domain.strip():
        result["reason"] = "domain is empty"
        return result

    domain = domain.strip().lower()

    # Strip scheme if present
    if domain.startswith("http://"):
        domain = domain[7:]
        result["scheme_suggestion"] = "https"
    elif domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http:/") or domain.startswith("https:/"):
        result["reason"] = "invalid URL scheme"
        return result

    # Strip path, port, query
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    if not domain:
        result["reason"] = "no domain found"
        return result

    # Format check
    if not _DOMAIN_RE.match(domain):
        result["reason"] = "invalid domain format (RFC 1123)"
        return result

    # Resolve and check privacy
    addrs = _resolve_domain(domain)
    result["resolved_ips"] = addrs

    if not addrs:
        result["reason"] = "domain could not be resolved (DNS check failed)"
        return result

    if is_domain_private(domain):
        result["is_private"] = True
        result["reason"] = "domain resolves to a private/internal address (SSRF risk)"
        return result

    result["valid"] = True
    result["reason"] = "domain is valid and publicly resolvable"
    return result


def validate_model_base_url(url: str) -> Dict[str, Any]:
    """Validate a full model base URL.

    Returns dict with: valid, reason, domain, scheme, resolved_ips
    """
    result: Dict[str, Any] = {
        "valid": False,
        "reason": "",
        "domain": "",
        "scheme": "",
        "resolved_ips": [],
    }

    if not url or not url.strip():
        result["reason"] = "URL is empty"
        return result

    url = url.strip()

    # Determine scheme
    if url.startswith("https://"):
        scheme = "https"
        domain_part = url[8:]
    elif url.startswith("http://"):
        scheme = "http"
        domain_part = url[7:]
    else:
        # No scheme — assume https for security
        scheme = "https"
        domain_part = url

    # Strip path, port
    domain_part = domain_part.split("/")[0]
    domain_part = domain_part.split(":")[0]

    result["domain"] = domain_part
    result["scheme"] = scheme

    # Validate the domain
    domain_validation = validate_domain(domain_part)
    if not domain_validation["valid"]:
        result["reason"] = domain_validation["reason"]
        return result

    result["resolved_ips"] = domain_validation["resolved_ips"]

    # For https, that's fine. For http, warn but allow (local dev).
    if scheme == "http":
        result["reason"] = "HTTP URL accepted but HTTPS is recommended for production"
    else:
        result["reason"] = "URL is valid"

    result["valid"] = True
    return result


# ── Custom domain provider configuration ─────────────────────────────────

def make_custom_provider(
    key: str,
    name: str,
    base_url: str,
    model: str,
    endpoint: str = "chat/completions",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a custom provider config with domain validation."""
    validation = validate_model_base_url(base_url)
    if not validation["valid"]:
        raise ValueError(f"Invalid model base URL: {validation['reason']}")

    return {
        "key": key,
        "name": name,
        "type": "custom",
        "base_url": base_url.rstrip("/") + "/",
        "model": model,
        "endpoint": endpoint,
        "api_key": api_key or "",
        "api_key_required": bool(api_key),
        "description": f"Custom provider: {name} ({base_url})",
        "domain_validated": True,
        "domain": validation["domain"],
        "scheme": validation["scheme"],
        "resolved_ips": validation["resolved_ips"],
    }


# ── SSL/TLS certificate support ───────────────────────────────────────────

def validate_ssl_certificate(domain: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """Validate SSL certificate for a domain.

    Returns dict with: valid, reason, issuer, expires, days_remaining
    """
    result: Dict[str, Any] = {
        "valid": False,
        "reason": "",
        "issuer": "",
        "expires": "",
        "days_remaining": 0,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            result["reason"] = "no certificate presented"
            return result

        # Check issuer
        issuer = cert.get("issuer", ())
        issuer_str = ""
        # issuer is a tuple of tuples: ((('countryName', 'US'),), (('organizationName', '...'),))
        for component in issuer:
            if isinstance(component, tuple):
                for key, value in component:
                    if key == "commonName":
                        issuer_str = value
                        break
        result["issuer"] = issuer_str or "unknown"

        # Check expiration
        not_after = cert.get("notAfter", "")
        if not_after:
            result["expires"] = not_after
            # Parse the date (format: 'Mon DD HH:MM:SS YYYY GMT')
            try:
                from email.utils import parsedate_to_datetime
                expiry = parsedate_to_datetime(not_after)
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                days_remaining = (expiry - now).days
                result["days_remaining"] = days_remaining
                if days_remaining < 0:
                    result["reason"] = f"certificate expired {abs(days_remaining)} days ago"
                    return result
                elif days_remaining < 7:
                    result["reason"] = f"certificate expires in {days_remaining} days (renew soon)"
                    result["valid"] = True  # still valid but warning
                    return result
                else:
                    result["valid"] = True
                    result["reason"] = "certificate is valid"
                    return result
            except Exception:
                result["valid"] = True
                result["reason"] = "certificate is valid (could not parse expiry)"
                return result

        result["valid"] = True
        result["reason"] = "certificate is valid"
        return result

    except ssl.SSLCertVerificationError as e:
        result["reason"] = f"SSL certificate verification failed: {e}"
        return result
    except ssl.SSLError as e:
        result["reason"] = f"SSL error: {e}"
        return result
    except socket.gaierror as e:
        result["reason"] = f"DNS resolution failed: {e}"
        return result
    except socket.timeout:
        result["reason"] = "connection timed out"
        return result
    except ConnectionRefusedError:
        result["reason"] = "connection refused (is the server running?)"
        return result
    except Exception as e:
        result["reason"] = f"unexpected error: {e}"
        return result


def test_model_connection(
    base_url: str,
    api_key: Optional[str] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Test connectivity to a model provider endpoint.

    Attempts a lightweight connection to validate the URL is reachable
    and the server responds. Does NOT send a full completion request.
    """
    result: Dict[str, Any] = {
        "valid": False,
        "reason": "",
        "status_code": None,
        "response_time_ms": 0,
    }

    import urllib.request
    import urllib.error

    url = base_url.rstrip("/")
    if not url.endswith("/"):
        url += "/"

    # Try a simple GET to the base URL or models endpoint
    test_urls = [
        url + "models",
        url.rstrip("/") + "/v1/models",
    ]

    headers = {"User-Agent": "ai-guardrails/1.0"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    import time
    start = time.time()

    for test_url in test_urls:
        try:
            req = urllib.request.Request(test_url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result["valid"] = True
                result["status_code"] = resp.status
                result["reason"] = f"server responded with HTTP {resp.status}"
                result["response_time_ms"] = int((time.time() - start) * 1000)
                return result
        except urllib.error.HTTPError as e:
            # HTTP error codes are still responses — server is reachable
            result["valid"] = True
            result["status_code"] = e.code
            result["reason"] = f"server responded with HTTP {e.code}"
            result["response_time_ms"] = int((time.time() - start) * 1000)
            return result
        except urllib.error.URLError as e:
            continue
        except Exception:
            continue

    result["reason"] = "could not connect to model server"
    return result

# ── Provider registry ──────────────────────────────────────────────────────
# Each provider has: key (unique id), name, type (local|cloud), default base
# URL, default model, default endpoint, and whether an API key is required.

PROVIDERS: Dict[str, Dict[str, Any]] = {
    # ── Local providers ──────────────────────────────────────────────
    "ollama": {
        "key": "ollama",
        "name": "Ollama (local)",
        "type": "local",
        "default_base_url": "http://localhost:11434",
        "default_model": "llama3.2:3b",
        "default_endpoint": "generate",
        "api_key_required": False,
        "description": "Run models locally on your Pi or machine via Ollama.",
    },
    "lmstudio": {
        "key": "lmstudio",
        "name": "LM Studio (local)",
        "type": "local",
        "default_base_url": "http://localhost:1234",
        "default_model": "local-model",
        "default_endpoint": "chat/completions",
        "api_key_required": False,
        "description": "LM Studio local inference server.",
    },
    "textgen": {
        "key": "textgen",
        "name": "Text Generation WebUI (local)",
        "type": "local",
        "default_base_url": "http://localhost:5000",
        "default_model": "local-model",
        "default_endpoint": "v1/chat/completions",
        "api_key_required": False,
        "description": "Oobabooga Text Generation WebUI.",
    },
    # ── Cloud providers ──────────────────────────────────────────────
    "nebius": {
        "key": "nebius",
        "name": "Nebius Token Factory",
        "type": "cloud",
        "default_base_url": "https://api.tokenfactory.nebius.com/v1/",
        "default_model": "meta-llama/Meta-Llama-3.1-70B-Instruct",
        "default_endpoint": "chat/completions",
        "api_key_required": True,
        "description": "Hosted open-weight models via Nebius AI Studio.",
    },
    "openrouter": {
        "key": "openrouter",
        "name": "OpenRouter",
        "type": "cloud",
        "default_base_url": "https://openrouter.ai/api/v1/",
        "default_model": "meta-llama/llama-3.1-70b-instruct:free",
        "default_endpoint": "chat/completions",
        "api_key_required": True,
        "description": "Access to many models through a single API.",
    },
    "groq": {
        "key": "groq",
        "name": "Groq",
        "type": "cloud",
        "default_base_url": "https://api.groq.com/openai/v1/",
        "default_model": "llama-3.1-70b-versatile",
        "default_endpoint": "chat/completions",
        "api_key_required": True,
        "description": "Fast inference on Groq hardware.",
    },
    "nvidia": {
        "key": "nvidia",
        "name": "NVIDIA NIM",
        "type": "cloud",
        "default_base_url": "https://integrate.api.nvidia.com/v1/",
        "default_model": "meta/llama-3.1-70b-instruct",
        "default_endpoint": "chat/completions",
        "api_key_required": True,
        "description": "NVIDIA NIM inference microservices.",
    },
    "nemus": {
        "key": "nemus",
        "name": "Nemus Cloud (NVIDIA)",
        "type": "cloud",
        "default_base_url": "https://api.nemus.cloud/v1/",
        "default_model": "nvidia/nemotron-3.5-super-vl-120b-a12b",
        "default_endpoint": "chat/completions",
        "api_key_required": True,
        "description": "Nemus cloud with NVIDIA Nemotron models.",
    },
    "openai": {
        "key": "openai",
        "name": "OpenAI",
        "type": "cloud",
        "default_base_url": "https://api.openai.com/v1/",
        "default_model": "gpt-4o-mini",
        "default_endpoint": "chat/completions",
        "api_key_required": True,
        "description": "OpenAI's hosted models.",
    },
    "custom": {
        "key": "custom",
        "name": "Custom OpenAI-compatible",
        "type": "custom",
        "default_base_url": "http://localhost:8000/v1/",
        "default_model": "custom-model",
        "default_endpoint": "chat/completions",
        "api_key_required": False,
        "description": "Any OpenAI-compatible API endpoint.",
    },
}

# ── Environment variable names for API keys ────────────────────────────────
PROVIDER_API_KEY_ENV = {
    "nebius": "GUARDRAIL_NEBIUS_API_KEY",
    "openrouter": "GUARDRAIL_OPENROUTER_API_KEY",
    "groq": "GUARDRAIL_GROQ_API_KEY",
    "nvidia": "GUARDRAIL_NVIDIA_API_KEY",
    "openai": "GUARDRAIL_OPENAI_API_KEY",
    "nemus": "GUARDRAIL_NEMUS_API_KEY",
}


def get_providers() -> List[Dict[str, Any]]:
    """Return all registered providers (without secrets)."""
    return [
        {
            "key": p["key"],
            "name": p["name"],
            "type": p["type"],
            "default_base_url": p["default_base_url"],
            "default_model": p["default_model"],
            "default_endpoint": p["default_endpoint"],
            "api_key_required": p["api_key_required"],
            "description": p["description"],
            "api_key_configured": bool(
                os.environ.get(PROVIDER_API_KEY_ENV.get(p["key"], ""), "")
            )
            if p["api_key_required"]
            else False,
        }
        for p in PROVIDERS.values()
    ]


def get_provider(key: str) -> Optional[Dict[str, Any]]:
    """Return a single provider by key, or None."""
    return PROVIDERS.get(key)


def get_api_key_env_name(provider_key: str) -> Optional[str]:
    """Return the env var name for a provider's API key, or None."""
    return PROVIDER_API_KEY_ENV.get(provider_key)


def load_api_keys_into_env() -> Dict[str, str]:
    """Load provider API keys from .env into os.environ.

    Returns a dict of provider -> key for keys that were found.
    Keys already in os.environ take precedence over .env values.
    """
    env_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".env"
    )
    found: Dict[str, str] = {}
    if not os.path.exists(env_path):
        return found

    # Parse .env manually (no external deps)
    env_vars: Dict[str, str] = {}
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip()

    for provider_key, env_name in PROVIDER_API_KEY_ENV.items():
        # Environment variable already set — don't override
        if os.environ.get(env_name):
            found[provider_key] = os.environ[env_name]
            continue
        # Check .env
        if env_name in env_vars:
            os.environ[env_name] = env_vars[env_name]
            found[provider_key] = env_vars[env_name]

    return found


def resolve_provider_config(
    provider_key: str,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve a complete provider config with defaults filled in."""
    provider = get_provider(provider_key)
    if not provider:
        raise ValueError(f"Unknown provider: {provider_key}")

    # Resolve API key: explicit arg > env var > empty
    resolved_key = api_key
    if not resolved_key:
        env_name = PROVIDER_API_KEY_ENV.get(provider_key, "")
        if env_name:
            resolved_key = os.environ.get(env_name, "")

    return {
        "key": provider_key,
        "name": provider["name"],
        "type": provider["type"],
        "base_url": base_url or provider["default_base_url"],
        "model": model or provider["default_model"],
        "endpoint": endpoint or provider["default_endpoint"],
        "api_key": resolved_key or "",
        "api_key_required": provider["api_key_required"],
    }


# ── Session-bound model selection ──────────────────────────────────────────
# The active provider is stored in the session under the key "model_provider".
# When no provider is selected, the system falls back to the default (first
# local provider, or "custom" if none local).

DEFAULT_PROVIDER_KEY = "ollama"


def get_session_provider(session: Optional[Dict[str, Any]]) -> Optional[str]:
    """Return the provider key selected in a session, or None."""
    if not session:
        return None
    return session.get("model_provider")


def set_session_provider(session: Dict[str, Any], provider_key: str) -> None:
    """Store the selected provider key in a session."""
    if provider_key not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider_key}")
    session["model_provider"] = provider_key


def clear_session_provider(session: Optional[Dict[str, Any]]) -> None:
    """Remove the provider selection from a session."""
    if session:
        session.pop("model_provider", None)
