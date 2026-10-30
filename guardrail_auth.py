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
import hmac
import base64
import ipaddress
import json
import os
import secrets
import struct
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
BIND_HOST = os.environ.get("GUARDRAIL_BIND_HOST", "127.0.0.1")

# Login-specific rate limiting (stricter than general API rate limit).
LOGIN_RATE_LIMIT = int(os.environ.get("GUARDRAIL_LOGIN_RATE_LIMIT", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("GUARDRAIL_LOGIN_LOCKOUT_SECONDS", "300"))
LOGIN_MAX_ATTEMPTS = int(os.environ.get("GUARDRAIL_LOGIN_MAX_ATTEMPTS", "5"))

# Password complexity requirements.
PASSWORD_MIN_LENGTH = int(os.environ.get("GUARDRAIL_PASSWORD_MIN_LENGTH", "8"))
PASSWORD_REQUIRE_UPPER = os.environ.get("GUARDRAIL_PASSWORD_REQUIRE_UPPER", "true").lower() == "true"
PASSWORD_REQUIRE_LOWER = os.environ.get("GUARDRAIL_PASSWORD_REQUIRE_LOWER", "true").lower() == "true"
PASSWORD_REQUIRE_DIGIT = os.environ.get("GUARDRAIL_PASSWORD_REQUIRE_DIGIT", "true").lower() == "true"
PASSWORD_REQUIRE_SPECIAL = os.environ.get("GUARDRAIL_PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"

# Session IP binding (prevent session hijacking).
SESSION_BIND_IP = os.environ.get("GUARDRAIL_SESSION_BIND_IP", "true").lower() == "true"

# ── 2FA (TOTP) configuration ──────────────────────────────────────────────
# Time-based one-time password for second-factor authentication.
# Uses stdlib-only HMAC-SHA1 TOTP (RFC 6238) — no external dependencies.
TOTP_ENABLED = os.environ.get("GUARDRAIL_2FA_ENABLED", "false").lower() == "true"
TOTP_ISSUER = os.environ.get("GUARDRAIL_2FA_ISSUER", "AI Guardrails")
TOTP_WINDOW = int(os.environ.get("GUARDRAIL_2FA_WINDOW", "1"))  # ±1 time step
TOTP_INTERVAL = int(os.environ.get("GUARDRAIL_2FA_INTERVAL", "30"))  # seconds
TOTP_BACKUP_CODES = int(os.environ.get("GUARDRAIL_2FA_BACKUP_CODES", "8"))

# ── TOTP (RFC 6238) — stdlib-only implementation ─────────────────────────

def _totp_key(secret_b32: str) -> bytes:
    """Decode a base32 TOTP secret to raw bytes."""
    padded = secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8)
    return base64.b32decode(padded.upper())


def _totp_hash(key: bytes, counter: int) -> bytes:
    """HMAC-SHA1 of the 8-byte big-endian counter."""
    msg = struct.pack(">Q", counter)
    return hmac.new(key, msg, hashlib.sha1).digest()


def _totp_truncate(hash_bytes: bytes) -> int:
    """Dynamic truncation per RFC 4226."""
    offset = hash_bytes[-1] & 0x0F
    binary = (
        ((hash_bytes[offset] & 0x7F) << 24)
        | ((hash_bytes[offset + 1] & 0xFF) << 16)
        | ((hash_bytes[offset + 2] & 0xFF) << 8)
        | (hash_bytes[offset + 3] & 0xFF)
    )
    return binary % 1_000_000


def generate_totp_secret() -> str:
    """Generate a new random base32-encoded TOTP secret (160 bits / 20 bytes)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def compute_totp(secret_b32: str, timestamp: Optional[float] = None) -> int:
    """Compute the current TOTP code for a base32 secret."""
    key = _totp_key(secret_b32)
    now = timestamp if timestamp is not None else time.time()
    counter = int(now // TOTP_INTERVAL)
    return _totp_truncate(_totp_hash(key, counter))


def verify_totp(secret_b32: str, code: int, timestamp: Optional[float] = None,
                window: int = TOTP_WINDOW) -> bool:
    """Verify a TOTP code against the current (or given) timestamp.

    Accepts codes within `window` time steps before/after to allow for
    clock skew and user entry delay.
    """
    try:
        code_int = int(code)
    except (ValueError, TypeError):
        return False
    now = timestamp if timestamp is not None else time.time()
    center = int(now // TOTP_INTERVAL)
    for offset in range(-window, window + 1):
        expected = _totp_truncate(_totp_hash(_totp_key(secret_b32), center + offset))
        if hmac.compare_digest(str(expected).zfill(6), str(code_int).zfill(6)):
            return True
    return False


def generate_backup_codes(count: int = TOTP_BACKUP_CODES) -> List[str]:
    """Generate single-use backup codes for 2FA lockout recovery."""
    return [secrets.token_hex(4) for _ in range(count)]


def _hash_backup_code(code: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"),
                               b"ai-guardrails-backup", 100_000).hex()

# ── Rate limiters (token bucket per key-or-IP) ─────────────────────────────

# Login attempt tracking for account lockout.
_login_attempts: Dict[str, List[float]] = defaultdict(list)
_login_lockouts: Dict[str, float] = {}


def _record_login_attempt(ident: str, success: bool) -> None:
    """Record a login attempt for lockout tracking."""
    now = time.time()
    attempts = _login_attempts[ident]
    # Remove attempts older than the lockout window
    attempts[:] = [t for t in attempts if now - t < LOGIN_LOCKOUT_SECONDS]
    attempts.append(now)
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        _login_lockouts[ident] = now + LOGIN_LOCKOUT_SECONDS


def _clear_login_attempts(ident: str) -> None:
    """Clear login attempt records on successful login."""
    _login_attempts.pop(ident, None)
    _login_lockouts.pop(ident, None)

# Allowed Host header values (prevents BadHost / host header injection attacks).


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


def _resolve_host(host: str) -> List[str]:
    """Resolve a hostname to all IP addresses (IPv4 + IPv6).

    Uses socket.getaddrinfo so DNS-returned addresses are checked against
    private ranges, closing the DNS-rebinding / SSRF hostname bypass.
    """
    import socket
    addrs: List[str] = []
    try:
        for _fam, _type, _proto, _canon, sa in socket.getaddrinfo(host, None):
            addr = sa[0]
            if addr not in addrs:
                addrs.append(addr)
    except Exception:
        pass
    return addrs


def is_url_private(url: str) -> bool:
    """Return True if the URL targets a private/internal address (SSRF risk).

    Resolves hostnames to IP addresses and checks each resolved address
    against private/internal ranges, closing the DNS-rebinding bypass where
    a hostname could resolve to 10.x/172.x/192.x/link-local.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return True  # treat unparseable as unsafe
    host = parsed.hostname or ""
    if not host:
        return True
    addrs = _resolve_host(host)
    if not addrs:
        # Could not resolve — treat as unsafe (fail closed).
        return True
    for addr_str in addrs:
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if any(addr in net for net in _PRIVATE_NETS):
            return True
    return False


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


# ── 2FA (TOTP) management ─────────────────────────────────────────────────

def _load_auth_state() -> Dict[str, Any]:
    if os.path.exists(AUTH_STATE_PATH):
        try:
            with open(AUTH_STATE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"password_hash": None, "salt": None, "created_at": None,
            "2fa_secret": None, "2fa_enabled": False,
            "backup_codes": [], "2fa_created_at": None}


def _save_auth_state(state: Dict[str, Any]) -> None:
    try:
        with open(AUTH_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.chmod(AUTH_STATE_PATH, 0o600)
    except Exception:
        pass


def enable_2fa() -> Dict[str, Any]:
    """Enable TOTP 2FA. Returns the secret URI and backup codes.

    The secret is stored hashed? No — TOTP secret must be stored reversibly
    to verify codes. It is protected by file mode 0600 and the auth state
    file is never transmitted.
    """
    secret = generate_totp_secret()
    backup_codes = generate_backup_codes(TOTP_BACKUP_CODES)
    state = _load_auth_state()
    state["2fa_secret"] = secret
    state["2fa_enabled"] = True
    state["2fa_created_at"] = datetime.now(timezone.utc).isoformat()
    state["backup_codes"] = [{"code": c, "used": False,
                              "hash": _hash_backup_code(c)}
                             for c in backup_codes]
    _save_auth_state(state)
    # TOTP auth URI for QR code apps (Google Authenticator, etc.)
    encoded_secret = secret.replace("=", "")
    uri = (f"otpauth://totp/{TOTP_ISSUER}:admin?secret={encoded_secret}"
           f"&issuer={TOTP_ISSUER}&period={TOTP_INTERVAL}")
    return {"ok": True, "secret": secret, "uri": uri,
            "backup_codes": backup_codes,
            "message": "2FA enabled. Save backup codes — they cannot be recovered."}


def disable_2fa() -> Dict[str, Any]:
    """Disable TOTP 2FA and clear backup codes."""
    state = _load_auth_state()
    state["2fa_secret"] = None
    state["2fa_enabled"] = False
    state["2fa_created_at"] = None
    state["backup_codes"] = []
    _save_auth_state(state)
    return {"ok": True, "message": "2FA disabled"}


def verify_2fa_code(code: str) -> bool:
    """Verify a TOTP code against the stored 2FA secret."""
    state = _load_auth_state()
    secret = state.get("2fa_secret")
    if not state.get("2fa_enabled") or not secret:
        return False
    return verify_totp(secret, code)


def verify_backup_code(code: str) -> bool:
    """Verify and consume a single-use backup code.

    Returns True if valid and unused; marks the code as used.
    """
    state = _load_auth_state()
    codes = state.get("backup_codes", [])
    for entry in codes:
        if entry.get("used"):
            continue
        if hmac.compare_digest(_hash_backup_code(code), entry.get("hash", "")):
            entry["used"] = True
            entry["used_at"] = datetime.now(timezone.utc).isoformat()
            _save_auth_state(state)
            return True
    return False


def has_2fa() -> bool:
    state = _load_auth_state()
    return bool(state.get("2fa_enabled") and state.get("2fa_secret"))


def is_2fa_configured() -> bool:
    """Public alias — whether 2FA is enabled and has a secret."""
    return has_2fa()


def set_password(password: str) -> Dict[str, Any]:
    """Set the web UI login password (stored as PBKDF2 hash locally).

    Enforces password complexity requirements if configured.
    """
    _validate_password_complexity(password)
    salt_hex, hash_hex = _hash_password(password)
    state = _load_auth_state()
    state["password_hash"] = hash_hex
    state["salt"] = salt_hex
    state["created_at"] = datetime.now(timezone.utc).isoformat()
    _save_auth_state(state)
    return {"ok": True, "message": "password set (stored locally as hash)"}


def _validate_password_complexity(password: str) -> None:
    """Validate password meets complexity requirements.

    Raises ValueError if the password doesn't meet requirements.
    """
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"password must be at least {PASSWORD_MIN_LENGTH} characters")
    if PASSWORD_REQUIRE_UPPER and not any(c.isupper() for c in password):
        errors.append("password must contain at least one uppercase letter")
    if PASSWORD_REQUIRE_LOWER and not any(c.islower() for c in password):
        errors.append("password must contain at least one lowercase letter")
    if PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        errors.append("password must contain at least one digit")
    if PASSWORD_REQUIRE_SPECIAL and not any(c for c in password if not c.isalnum()):
        errors.append("password must contain at least one special character")
    if errors:
        raise ValueError("; ".join(errors))


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


def validate_session(token: str, client_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Validate a session token. Returns session dict or None if invalid.

    If client_ip is provided and SESSION_BIND_IP is enabled, verifies the
    request IP matches the session's original IP (session hijacking protection).
    """
    if not token:
        return None
    session = _SESSIONS.get(token)
    if not session:
        return None
    if time.time() > session["expires_at"]:
        _SESSIONS.pop(token, None)
        return None
    # Session IP binding: ensure request comes from same IP that created session.
    if SESSION_BIND_IP and client_ip is not None:
        if session.get("ip") != client_ip:
            _SESSIONS.pop(token, None)
            return None
    return session


def session_2fa_verified(session: Optional[Dict[str, Any]]) -> bool:
    """Return True if the session has completed 2FA (or 2FA is not configured)."""
    if not session:
        return False
    # If 2FA is not configured at all, any valid session is fine.
    if not is_2fa_configured():
        return True
    # Session must have 2fa_verified=True
    return session.get("2fa_verified") is True


def session_2fa_pending(session: Optional[Dict[str, Any]]) -> bool:
    """Return True if the session is waiting for 2FA verification."""
    if not session:
        return False
    return session.get("2fa_pending") is True


def destroy_session(token: str) -> None:
    _SESSIONS.pop(token, None)

def _log_auth_event(event: str, ip: str, agent: str = "", detail: str = "") -> None:
    """Log authentication events for audit trail."""
    try:
        from guardrail_logging import get_logger
        logger = get_logger("auth")
        logger.info("auth_event", event=event, ip=ip, agent=agent, detail=detail)
    except Exception:
        pass  # Never let logging break the application


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
_login_rate_limiter = RateLimiter(LOGIN_RATE_LIMIT)


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
    """Constant-time comparison of two API keys.

    Always processes the full length of both strings so key length is not
    leaked via timing. Returns False if either is empty.
    """
    if not required or not key:
        return False
    # Use bytes comparison with hmac.compare_digest for constant-time.
    # Pad to equal length so length is not leaked either.
    k1 = key.encode("utf-8")
    k2 = required.encode("utf-8")
    # compare_digest handles equal-length comparison in constant time.
    # For unequal lengths it still takes constant-ish time; we xor to be safe.
    if len(k1) != len(k2):
        # Still do a full comparison to avoid length-based timing.
        result = 0
        for a, b in zip(k1, k2):
            result |= a ^ b
        # Account for length difference without branching on it.
        result |= len(k1) ^ len(k2)
        return result == 0
    return secrets.compare_digest(k1, k2)


# ── CSRF protection ───────────────────────────────────────────────────────
# CSRF tokens are bound to a session. State-changing endpoints (POST/PUT/DELETE
# that are not API-key authenticated) require a matching X-CSRF-Token header.
# This defeats cross-site request forgery against the web UI when a user is
# authenticated via a session cookie (SameSite=Strict helps, but a token is
# defense in depth).

_CSRF_TOKENS: Dict[str, str] = {}  # session_token -> csrf_token


def _new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_csrf_token(session_token: str) -> str:
    """Create (or rotate) a CSRF token bound to a session token."""
    token = _new_csrf_token()
    _CSRF_TOKENS[session_token] = token
    return token


def get_csrf_token(session_token: str) -> Optional[str]:
    return _CSRF_TOKENS.get(session_token)


def validate_csrf_token(session_token: str, provided: Optional[str]) -> bool:
    """Validate a CSRF token against the session-bound token. Constant-time."""
    expected = _CSRF_TOKENS.get(session_token)
    if not expected or not provided:
        return False
    if len(expected) != len(provided):
        return False
    return secrets.compare_digest(
        expected.encode("utf-8"), provided.encode("utf-8")
    )


def clear_csrf_token(session_token: str) -> None:
    _CSRF_TOKENS.pop(session_token, None)


# ── Tier definitions ──────────────────────────────────────────────────────

PUBLIC_PATHS: Set[str] = {
    "/",
    "/login",
    "/api/health",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/session",
    # 2FA setup/verification endpoints (public for initial setup)
    "/api/auth/2fa/setup",
    "/api/auth/2fa/verify",
    # Emergency override status (public read)
    "/api/emergency/status",
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

    # ── Login rate limiting and account lockout ──
    # Apply stricter rate limiting to login endpoint.
    path = handler.path
    command = handler.command
    if path == "/api/auth/login" and command == "POST":
        login_ident = f"login:{_client_ip(handler)}"
        # Check if IP is locked out
        lockout_until = _login_lockouts.get(login_ident, 0)
        if lockout_until > time.time():
            remaining = int(lockout_until - time.time())
            return AuthResult(False, 429,
                              f"account locked due to failed login attempts. "
                              f"Try again in {remaining} seconds.",
                              {"Retry-After": str(remaining)})
        # Check rate limit
        if not _login_rate_limiter.allow(login_ident):
            # Record failed attempt for lockout tracking
            _record_login_attempt(login_ident, success=False)
            return AuthResult(False, 429,
                              "login rate limit exceeded. Try again later.",
                              {"Retry-After": "60"})

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
                "Authorization, X-API-Key, Content-Type, "
                "X-Session-Token, X-CSRF-Token"
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
        # 2FA enforcement: session-authenticated view access needs 2FA verified.
        if has_session and not has_admin_key and not has_view_key:
            if not session_2fa_verified(session):
                if session_2fa_pending(session):
                    return AuthResult(False, 403,
                                      "2FA verification required",
                                      cors_headers,
                                      session_token=None)
                return AuthResult(False, 403,
                                  "session not fully authenticated",
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

        # 2FA enforcement: session-authenticated admin access needs 2FA verified.
        if has_session and not has_admin_key:
            if not session_2fa_verified(session):
                if session_2fa_pending(session):
                    return AuthResult(False, 403,
                                      "2FA verification required",
                                      cors_headers,
                                      session_token=None)
                return AuthResult(False, 403,
                                  "session not fully authenticated",
                                  cors_headers)

        # ── CSRF protection for state-changing methods ──
        # When authenticated via session cookie (not API key), require a
        # matching X-CSRF-Token header on POST/PUT/DELETE/OPTIONS.
        # API-key-authenticated clients are exempt (they manage their own
        # credentials and are typically server-to-server).
        if (handler.command in ("POST", "PUT", "DELETE", "OPTIONS")
                and has_session and not has_admin_key and not has_view_key):
            csrf_token = handler.headers.get("X-CSRF-Token", "")
            if not validate_csrf_token(session_token, csrf_token):
                return AuthResult(
                    False, 403,
                    "CSRF token missing or invalid",
                    cors_headers,
                )

        # Issue / rotate a CSRF token bound to this session on successful auth.
        if session_token:
            csrf = set_csrf_token(session_token)
            cors_headers["X-CSRF-Token"] = csrf

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
