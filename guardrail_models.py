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

import json
import os
from typing import Optional, Dict, Any, List

from guardrail_auth import (
    is_2fa_configured, verify_2fa_code, verify_backup_code,
    SESSION_TTL_SECONDS,
)

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
