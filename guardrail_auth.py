#!/usr/bin/env python3
#=============================================================================
# Guardrail Auth — authentication, authorization, rate limiting, IP allowlist,
# and security headers for the guardrail HTTP API server.
#=============================================================================
# Research basis (OWASP API Security Top 10):
#   - API2:2023 Broken Authentication — authenticate every state-changing
#     request; don't trust the network (localhost/Tailscale is not a boundary).
#   - API1:2023 Broken Object Level Authorization — enforce roles on
#     write/delete endpoints.
#   - API4:2023 Lack of Resources & Rate Limiting — per-key/IP rate limits
#     and max body size to prevent DoS.
#   - Security misconfiguration — restrict CORS origins, send security
#     headers, validate Host header.
#
# Design:
#   - Password-based login for the web UI (stored as PBKDF2-HMAC-SHA256 hash
#     in ~/.ai_guardrails_auth.json — local only, never transmitted).
#   - Session tokens issued on login, required for web UI + state-changing API.
#   - API keys (GUARDRAIL_API_KEY / GUARDRAIL_VIEW_KEY) for programmatic
#     access to write/delete/monitor endpoints.
#   - IP allowlist, CORS origin restriction, security headers, max body size,
#     per-key/IP rate limiting.
#
# Endpoint tiers:
#   PUBLIC    : GET / (login page if no session), GET /api/health,
#               POST /api/auth/login, POST /api/auth/logout
#   VIEW      : GET /api/policies*, GET /api/stats, GET /api/guardrail-status
#   ADMIN     : PUT/DELETE /api/policies/*, POST /api/validate/*,
#               POST /api/monitor/validate/*, POST /api/monitor/thought|action
#
# All stdlib only — no external dependencies.
#=============================================================================

import hashlib
import ipaddress
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Set, Tuple

from urllib.parse import urlparse

# ── Paths ──────────────────────────────────────────────────────────────────

AUTH_STATE_PATH = os.path.expanduser("~/.ai_guardrails_auth.json")
SESSION_TTL_SECONDS = int(os.environ.get("GUARDRAIL_SESSION_TTL", "3600"))
PBKDF2_ITERATIONS = 200_000

# ── Configuration (env vars) ──────────────────────────────────────────────

def _env_list(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]

ADMIN_API_KEY = os.environ.get("GUARDRAIL_API_KEY", "")
VIEW_API_KEY = os.environ.get("GUARDRAIL_VIEW_KEY", "")
ALLOWED_IPS = _env_list("GUARDRAIL_ALLOWED_IPS")
ALLOWED_ORIGINS = _env_list("GUARDRAIL_ALLOWED_ORIGINS")
RATE_LIMIT = int(os.environ.get("GUARDRAIL_RATE_LIMIT", "60"))
MAX_BODY_SIZE = int(os.environ.get("GUARDRAIL_MAX_BODY_SIZE", "1048576"))
BIND_HOST = os.environ.get("GUARDRAIL_BIND_HOST", "0.0.0.0")

# Allowed Host header values (prevents BadHost / host header injection attacks).
# Empty = accept any Host. Comma-separated list of hostnames or host:port.
# Example: GUARDRAIL_ALLOWED_HOSTS=localhost,127.0.0.1,my-pi.local
ALLOWED_HOSTS = _env_list("GUARDRAIL_ALLOWED_HOSTS")


def _host_allowed(host: str) -> bool:
    """Validate the Host header against the allowed list."""
    if not ALLOWED_HOSTS:
        return True  # no restriction configured
    # Strip port from host for comparison
    host_name = host.split(":")[0]
    return host_name in ALLOWED_HOSTS or host in ALLOWED_HOSTS


# ── CSP header ────────────────────────────────────────────────────────────
# Content Security Policy for the web UI login page.
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

# ── SSRF protection ───────────────────────────────────────────────────────
# Private/internal IP ranges that external model URLs must not target when
# SSRF protection is enabled (GUARDRAIL_SSRF_PROTECTION=1).
# Disabled by default because the model URL is operator-configured, not
# user input, and localhost is the expected default for local model serving.
_PRIVATE_NETS: List[ipaddress._BaseNetwork] = [
    ipaddress.ip_network("10.0.0.0/8", strict=False),      # private
    ipaddress.ip_network("172.16.0.0/12", strict=False),   # private
    ipaddress.ip_network("192.168.0.0/16", strict=False),  # private
    ipaddress.ip_network("169.254.0.0/16", strict=False),  # link-local
    ipaddress.ip_network("fc00::/7", strict=False),        # IPv6 private
    ipaddress.ip_network("fe80::/10", strict=False),       # IPv6 link-local
]


def is_ssrf_protection_enabled() -> bool:
    return os.environ.get("GUARDRAIL_SSRF_PROTECTION", "0") == "1"


def is_url_private(url: str) -> bool:
    """Return True if the URL targets a private/internal address (SSRF risk)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return True  # treat unparseable as unsafe
    host = parsed.hostname or ""
    if not host:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # Hostname — resolve could point anywhere; allow by default but
        # note that operator should use allowed IPs for stricter control.
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def validate_model_url(url: str, label: str = "model URL") -> str:
    """Validate a model base URL for SSRF safety.

    Only enforces when GUARDRAIL_SSRF_PROTECTION=1. Returns the URL if safe,
    or raises ValueError if it targets a private/internal address.
    """
    if not is_ssrf_protection_enabled():
        return url
    if is_url_private(url):
        raise ValueError(f"{label} points to a private/internal address: {url}")
    return url

# Parse allowed IP networks once.
ALLOWED_NETS: List[ipaddress._BaseNetwork] = []
for entry in ALLOWED_IPS:
    try:
        ALLOWED_NETS.append(ipaddress.ip_network(entry, strict=False))
    except ValueError:
        try:
            ALLOWED_NETS.append(ipaddress.ip_network(entry + "/32", strict=False))
        except ValueError:
            pass  # skip invalid entries

# ── Password hashing (PBKDF2-HMAC-SHA256, stdlib only) ────────────────────

def _hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Hash a password with PBKDF2-HMAC-SHA256.

    Returns (salt_hex, hash_hex). If salt is None, a random 16-byte salt is
    generated.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             PBKDF2_ITERATIONS)
    return salt.hex(), dk.hex()


def _verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """Verify a password against a stored salt+hash."""
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             PBKDF2_ITERATIONS)
    return secrets.compare_digest(dk, expected)


# ── Auth state (local file) ───────────────────────────────────────────────

def _load_auth_state() -> Dict[str, Any]:
    if os.path.exists(AUTH_STATE_PATH):
        try:
            with open(AUTH_STATE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"password_hash": None, "salt": None, "created_at": None}


def _save_auth_state(state: Dict[str, Any]) -> None:
    try:
        with open(AUTH_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.chmod(AUTH_STATE_PATH, 0o600)
    except Exception:
        pass


def set_password(password: str) -> Dict[str, Any]:
    """Set the web UI login password (stored as PBKDF2 hash locally)."""
    salt_hex, hash_hex = _hash_password(password)
    state = _load_auth_state()
    state["password_hash"] = hash_hex
    state["salt"] = salt_hex
    state["created_at"] = datetime.now(timezone.utc).isoformat()
    _save_auth_state(state)
    return {"ok": True, "message": "password set (stored locally as hash)"}


def verify_password(password: str) -> bool:
    """Verify a login password against the stored local hash."""
    state = _load_auth_state()
    if not state.get("password_hash") or not state.get("salt"):
        return False
    return _verify_password(password, state["salt"], state["password_hash"])


def has_password() -> bool:
    state = _load_auth_state()
    return bool(state.get("password_hash") and state.get("salt"))


# ── Sessions (in-memory, TTL-based) ────────────────────────────────────────

_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _new_session_token() -> str:
    return secrets.token_urlsafe(32)


def create_session(ip: str, user_agent: str = "") -> str:
    """Create a new session token. Returns the token string."""
    token = _new_session_token()
    now = time.time()
    _SESSIONS[token] = {
        "token": token,
        "created_at": now,
        "expires_at": now + SESSION_TTL_SECONDS,
        "ip": ip,
        "user_agent": user_agent,
    }
    return token


def validate_session(token: str) -> Optional[Dict[str, Any]]:
    """Validate a session token. Returns session dict or None if invalid."""
    if not token:
        return None
    session = _SESSIONS.get(token)
    if not session:
        return None
    if time.time() > session["expires_at"]:
        _SESSIONS.pop(token, None)
        return None
    return session


def destroy_session(token: str) -> None:
    _SESSIONS.pop(token, None)


def cleanup_sessions() -> int:
    """Remove expired sessions. Returns count removed."""
    now = time.time()
    expired = [t for t, s in _SESSIONS.items() if now > s["expires_at"]]
    for t in expired:
        _SESSIONS.pop(t, None)
    return len(expired)


# ── Rate limiter (token bucket per key-or-IP) ─────────────────────────────

class RateLimiter:
    """Simple token-bucket rate limiter keyed by identifier."""

    def __init__(self, rate_per_minute: int):
        self.rate = max(rate_per_minute, 1)
        self.buckets: Dict[str, deque] = defaultdict(deque)

    def allow(self, ident: str) -> bool:
        now = time.time()
        window = self.buckets[ident]
        while window and window[0] < now - 60:
            window.popleft()
        if len(window) >= self.rate:
            return False
        window.append(now)
        return True

    def remaining(self, ident: str) -> int:
        now = time.time()
        window = self.buckets.get(ident, deque())
        while window and window[0] < now - 60:
            window.popleft()
        return max(self.rate - len(window), 0)


_rate_limiter = RateLimiter(RATE_LIMIT)


# ── Helpers ───────────────────────────────────────────────────────────────

def _client_ip(handler) -> str:
    try:
        host, _ = handler.client_address
        return host
    except Exception:
        return "unknown"


def _ip_allowed(ip: str) -> bool:
    if not ALLOWED_NETS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in ALLOWED_NETS)


def _origin_allowed(origin: Optional[str]) -> bool:
    if not ALLOWED_ORIGINS:
        return False
    return origin in ALLOWED_ORIGINS


def _verify_key(key: str, required: str) -> bool:
    if not required or not key:
        return False
    if len(key) != len(required):
        return False
    result = 0
    for a, b in zip(key, required):
        result |= ord(a) ^ ord(b)
    return result == 0


# ── Tier definitions ──────────────────────────────────────────────────────

PUBLIC_PATHS: Set[str] = {
    "/",
    "/login",
    "/api/health",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/session",
}

VIEW_PATH_PREFIXES = (
    "/api/policies",
    "/api/stats",
    "/api/guardrail-status",
)

ADMIN_PATH_PREFIXES = (
    "/api/validate/",
    "/api/monitor/validate/",
    "/api/monitor/thought",
    "/api/monitor/action",
)


def path_tier(path: str) -> str:
    if path in PUBLIC_PATHS:
        return "public"
    for prefix in ADMIN_PATH_PREFIXES:
        if path.startswith(prefix):
            return "admin"
    for prefix in VIEW_PATH_PREFIXES:
        if path.startswith(prefix):
            return "view"
    return "public"


# ── Auth middleware ───────────────────────────────────────────────────────

class AuthResult:
    def __init__(self, ok: bool, status: int = 200, reason: str = "",
                 headers: Optional[Dict[str, str]] = None,
                 session_token: Optional[str] = None):
        self.ok = ok
        self.status = status
        self.reason = reason
        self.headers = headers or {}
        self.session_token = session_token


def authenticate(handler, tier: str) -> AuthResult:
    """Authenticate + authorize a request for the given tier."""
    cleanup_sessions()

    ident = _client_ip(handler)
    api_key = handler.headers.get("X-API-Key", "")
    if api_key:
        ident = f"key:{api_key[:8]}"
    if not _rate_limiter.allow(ident):
        return AuthResult(False, 429, "rate limit exceeded",
                          {"Retry-After": "60"})

    if not _ip_allowed(_client_ip(handler)):
        return AuthResult(False, 403, "ip not allowed")

    # ── Host header validation (BadHost / host header injection) ──
    host = handler.headers.get("Host", "")
    if not _host_allowed(host):
        return AuthResult(False, 400, "invalid host header")

    origin = handler.headers.get("Origin", "")
    cors_headers: Dict[str, str] = {}
    if ALLOWED_ORIGINS:
        if origin and _origin_allowed(origin):
            cors_headers["Access-Control-Allow-Origin"] = origin
            cors_headers["Access-Control-Allow-Credentials"] = "true"
            cors_headers["Access-Control-Allow-Methods"] = (
                "GET, POST, PUT, DELETE, OPTIONS"
            )
            cors_headers["Access-Control-Allow-Headers"] = (
                "Authorization, X-API-Key, Content-Type, X-Session-Token"
            )
            cors_headers["Access-Control-Max-Age"] = "86400"
    cors_headers["X-Content-Type-Options"] = "nosniff"
    cors_headers["X-Frame-Options"] = "DENY"
    cors_headers["Referrer-Policy"] = "no-referrer"
    cors_headers["Content-Security-Policy"] = CSP_POLICY

    # ── Auth by tier ──
    if tier == "public":
        return AuthResult(True, 200, "", cors_headers)

    # VIEW and ADMIN require either a valid session OR a valid API key.
    session_token = handler.headers.get("X-Session-Token", "") or \
        handler.headers.get("Cookie", "").replace("session=", "", 1)
    session = validate_session(session_token) if session_token else None

    api_key = handler.headers.get("X-API-Key", "") or \
        handler.headers.get("Authorization", "").replace("Bearer ", "", 1)

    has_session = session is not None
    has_admin_key = bool(ADMIN_API_KEY and _verify_key(api_key, ADMIN_API_KEY))
    has_view_key = bool(VIEW_API_KEY and _verify_key(api_key, VIEW_API_KEY))

    if tier == "view":
        if not (has_session or has_view_key or has_admin_key):
            return AuthResult(False, 401,
                              "authentication required (session or API key)",
                              cors_headers)
        return AuthResult(True, 200, "", cors_headers)

    if tier == "admin":
        if not ADMIN_API_KEY and not has_password():
            return AuthResult(
                False, 503, "admin endpoints not configured (no API key or "
                            "login password set)", cors_headers)
        if not (has_session or has_admin_key):
            return AuthResult(False, 401,
                              "authentication required (session or admin API "
                              "key)", cors_headers)
        return AuthResult(True, 200, "", cors_headers, session_token)

    return AuthResult(True, 200, "", cors_headers)


# ── Response helpers ──────────────────────────────────────────────────────

def send_json(handler, status: int, payload: dict,
              extra_headers: Optional[Dict[str, str]] = None,
              session_token: Optional[str] = None) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    headers.update(extra_headers or {})
    if session_token:
        headers["Set-Cookie"] = f"session={session_token}; HttpOnly; " \
                                f"SameSite=Strict; Path=/; Max-Age={SESSION_TTL_SECONDS}"
    handler.send_response(status)
    for k, v in headers.items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


def send_auth_error(handler, result: AuthResult) -> None:
    send_json(handler, result.status,
              {"error": result.reason or "unauthorized"},
              result.headers)


def read_body_limited(handler, max_size: int = MAX_BODY_SIZE) -> bytes:
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return b""
    if length > max_size:
        try:
            handler.rfile.read(max_size)
        except Exception:
            pass
        raise ValueError("request body too large")
    return handler.rfile.read(length)


# ── Global convenience ───────────────────────────────────────────────────

def is_auth_configured() -> bool:
    return bool(ADMIN_API_KEY or VIEW_API_KEY or ALLOWED_IPS or ALLOWED_ORIGINS
                or has_password())
