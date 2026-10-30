#!/usr/bin/env python3
#=============================================================================
# guardrail_users.py — users, roles, permissions, and API keys
#=============================================================================
# Adds a real identity model on top of the single-admin model that existed
# before this module:
#
#   - Independent user accounts (username, PBKDF2 password, role, own TOTP
#     secret, own backup codes, own sessions).
#   - Three roles: admin / developer / viewer, enforced server-side.
#   - Independent API keys with scopes, revocation and rotation. Only a
#     SHA-256 hash of the secret is stored; the secret is shown once.
#
# Backward compatibility: on first use, if the legacy single-admin auth state
# exists (~/.ai_guardrails_auth.json) it is migrated into a user named
# "admin" *without* touching the stored password hash, TOTP secret or backup
# codes, so existing devices keep working.
#
# Nothing in this module changes the deterministic guardrail engine.
#=============================================================================
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

USERS_PATH = os.path.expanduser(
    os.environ.get("GUARDRAIL_USERS_PATH", "~/.ai_guardrails_users.json"))
KEYS_PATH = os.path.expanduser(
    os.environ.get("GUARDRAIL_KEYS_PATH", "~/.ai_guardrails_keys.json"))

PBKDF2_ITERATIONS = 200_000
MIN_PASSWORD_LENGTH = int(os.environ.get("GUARDRAIL_PASSWORD_MIN_LENGTH", "8"))

# ── Roles and permissions ─────────────────────────────────────────────────

PERMISSIONS = {
    "policies:read":    "Read page policies",
    "policies:write":   "Create, edit and delete page policies",
    "validate":         "Run input/output validation and monitor submissions",
    "monitor:read":     "Read stats, status and audit logs",
    "users:manage":     "Create, disable and re-role users",
    "keys:manage":      "Create, revoke and rotate API keys",
    "security:manage":  "Enrol/replace 2FA and change authentication settings",
    "emergency":        "Containment, shutdown and re-enable operations",
}

ROLE_PERMISSIONS: Dict[str, set] = {
    "admin": set(PERMISSIONS.keys()),
    "developer": {"policies:read", "validate", "monitor:read"},
    "viewer": {"policies:read", "monitor:read"},
}

ROLE_LABELS = {
    "admin": "Admin — users, security, system configuration",
    "developer": "Developer — agent configuration and validation",
    "viewer": "Viewer — read-only dashboard and logs",
}


def role_has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


# ── Password hashing (stdlib PBKDF2-HMAC-SHA256) ──────────────────────────

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Returns (salt_hex, hash_hex)."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             PBKDF2_ITERATIONS)
    return salt.hex(), dk.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (TypeError, ValueError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt,
                             PBKDF2_ITERATIONS)
    return hmac.compare_digest(dk, expected)


def validate_password_complexity(password: str) -> None:
    """Raises ValueError when the password does not meet policy."""
    p = password or ""
    problems = []
    if len(p) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    if not any(c.isupper() for c in p):
        problems.append("an uppercase letter")
    if not any(c.islower() for c in p):
        problems.append("a lowercase letter")
    if not any(c.isdigit() for c in p):
        problems.append("a digit")
    if not any(not c.isalnum() for c in p):
        problems.append("a symbol")
    if problems:
        raise ValueError("Password must contain " + ", ".join(problems) + ".")


# ── Store helpers ─────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load(path: str, empty: Dict[str, Any]) -> Dict[str, Any]:
    if not os.path.exists(path):
        return dict(empty)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else dict(empty)
    except (OSError, json.JSONDecodeError):
        return dict(empty)


def _save(path: str, data: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _users_doc() -> Dict[str, Any]:
    doc = _load(USERS_PATH, {"version": 1, "users": {}})
    doc.setdefault("users", {})
    return doc


def _keys_doc() -> Dict[str, Any]:
    doc = _load(KEYS_PATH, {"version": 1, "keys": {}})
    doc.setdefault("keys", {})
    return doc


# ── Migration from the legacy single-admin state ──────────────────────────

def ensure_initialised() -> None:
    """Create the user store, migrating the legacy admin if present.

    Never invalidates an existing password, TOTP secret or backup codes: the
    legacy values are copied verbatim into the "admin" user record.
    """
    if os.path.exists(USERS_PATH):
        return

    users: Dict[str, Any] = {}
    legacy_path = os.path.expanduser(
        os.environ.get("GUARDRAIL_AUTH_STATE_PATH", "~/.ai_guardrails_auth.json"))
    legacy = _load(legacy_path, {})
    if legacy.get("password_hash"):
        users["admin"] = {
            "id": "u_" + secrets.token_hex(6),
            "username": "admin",
            "role": "admin",
            "password_hash": legacy.get("password_hash"),
            "salt": legacy.get("salt"),
            "totp_secret": legacy.get("2fa_secret"),
            "totp_enabled": bool(legacy.get("2fa_enabled")),
            "backup_codes": legacy.get("backup_codes", []),
            "created_at": legacy.get("created_at") or _now_iso(),
            "disabled": False,
            "migrated_from": "single-admin",
        }
    if not users:
        # Fresh install: bootstrap an admin with the env password if one is set
        env_pw = os.environ.get("GUARDRAIL_ADMIN_PASSWORD", "")
        if env_pw:
            salt, h = hash_password(env_pw)
            users["admin"] = {
                "id": "u_" + secrets.token_hex(6),
                "username": "admin",
                "role": "admin",
                "password_hash": h,
                "salt": salt,
                "totp_secret": None,
                "totp_enabled": False,
                "backup_codes": [],
                "created_at": _now_iso(),
                "disabled": False,
            }
    if users:
        _save(USERS_PATH, {"version": 1, "users": users})


# ── User operations ───────────────────────────────────────────────────────

def list_users() -> List[Dict[str, Any]]:
    """Public view of users — never includes hashes or secrets."""
    ensure_initialised()
    out = []
    for u in _users_doc()["users"].values():
        out.append({
            "id": u.get("id"),
            "username": u.get("username"),
            "role": u.get("role"),
            "totp_enabled": bool(u.get("totp_enabled")),
            "backup_codes_remaining": len(
                [c for c in u.get("backup_codes", []) if not c.get("used")]),
            "created_at": u.get("created_at"),
            "disabled": bool(u.get("disabled")),
        })
    return sorted(out, key=lambda x: x["username"] or "")


def get_user(username: str) -> Optional[Dict[str, Any]]:
    ensure_initialised()
    return _users_doc()["users"].get((username or "").strip().lower())


def create_user(username: str, password: str, role: str) -> Dict[str, Any]:
    ensure_initialised()
    uname = (username or "").strip().lower()
    if not uname or not all(c.isalnum() or c in "._-" for c in uname):
        return {"ok": False, "error": "username may contain letters, digits, dot, dash, underscore"}
    if role not in ROLE_PERMISSIONS:
        return {"ok": False, "error": f"unknown role '{role}'"}
    doc = _users_doc()
    if uname in doc["users"]:
        return {"ok": False, "error": "user already exists"}
    try:
        validate_password_complexity(password)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    salt, h = hash_password(password)
    doc["users"][uname] = {
        "id": "u_" + secrets.token_hex(6),
        "username": uname,
        "role": role,
        "password_hash": h,
        "salt": salt,
        "totp_secret": None,
        "totp_enabled": False,
        "backup_codes": [],
        "created_at": _now_iso(),
        "disabled": False,
    }
    _save(USERS_PATH, doc)
    return {"ok": True, "user": {"username": uname, "role": role}}


def set_role(username: str, role: str) -> Dict[str, Any]:
    ensure_initialised()
    if role not in ROLE_PERMISSIONS:
        return {"ok": False, "error": f"unknown role '{role}'"}
    doc = _users_doc()
    u = doc["users"].get((username or "").strip().lower())
    if not u:
        return {"ok": False, "error": "no such user"}
    # Never allow the last enabled admin to be demoted.
    if u.get("role") == "admin" and role != "admin":
        admins = [x for x in doc["users"].values()
                  if x.get("role") == "admin" and not x.get("disabled")]
        if len(admins) <= 1:
            return {"ok": False, "error": "cannot demote the last admin"}
    u["role"] = role
    _save(USERS_PATH, doc)
    return {"ok": True, "username": u["username"], "role": role}


def set_disabled(username: str, disabled: bool) -> Dict[str, Any]:
    ensure_initialised()
    doc = _users_doc()
    u = doc["users"].get((username or "").strip().lower())
    if not u:
        return {"ok": False, "error": "no such user"}
    if disabled and u.get("role") == "admin":
        admins = [x for x in doc["users"].values()
                  if x.get("role") == "admin" and not x.get("disabled")]
        if len(admins) <= 1:
            return {"ok": False, "error": "cannot disable the last admin"}
    u["disabled"] = bool(disabled)
    _save(USERS_PATH, doc)
    return {"ok": True, "username": u["username"], "disabled": bool(disabled)}


def set_user_password(username: str, password: str) -> Dict[str, Any]:
    ensure_initialised()
    doc = _users_doc()
    u = doc["users"].get((username or "").strip().lower())
    if not u:
        return {"ok": False, "error": "no such user"}
    try:
        validate_password_complexity(password)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    salt, h = hash_password(password)
    u["salt"], u["password_hash"] = salt, h
    _save(USERS_PATH, doc)
    return {"ok": True}


def verify_credentials(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Returns the user record on success, else None. Disabled users fail."""
    ensure_initialised()
    u = _users_doc()["users"].get((username or "").strip().lower())
    if not u or u.get("disabled"):
        return None
    if not verify_password(password, u.get("salt", ""), u.get("password_hash", "")):
        return None
    return u


# ── Per-user 2FA ──────────────────────────────────────────────────────────

def set_user_2fa(username: str, secret: str, backup_codes: List[Dict[str, Any]]) -> Dict[str, Any]:
    ensure_initialised()
    doc = _users_doc()
    u = doc["users"].get((username or "").strip().lower())
    if not u:
        return {"ok": False, "error": "no such user"}
    u["totp_secret"] = secret
    u["totp_enabled"] = True
    u["totp_created_at"] = _now_iso()
    u["backup_codes"] = backup_codes
    _save(USERS_PATH, doc)
    return {"ok": True}


def clear_user_2fa(username: str) -> Dict[str, Any]:
    ensure_initialised()
    doc = _users_doc()
    u = doc["users"].get((username or "").strip().lower())
    if not u:
        return {"ok": False, "error": "no such user"}
    u["totp_secret"] = None
    u["totp_enabled"] = False
    u["backup_codes"] = []
    _save(USERS_PATH, doc)
    return {"ok": True}


def user_2fa_state(username: str) -> Dict[str, Any]:
    u = get_user(username) or {}
    codes = u.get("backup_codes", []) or []
    return {
        "enabled": bool(u.get("totp_enabled") and u.get("totp_secret")),
        "backup_codes_remaining": len([c for c in codes if not c.get("used")]),
    }


def hash_backup_code(code: str) -> str:
    """PBKDF2, matching guardrail_auth._hash_backup_code exactly."""
    return hashlib.pbkdf2_hmac("sha256", (code or "").strip().encode("utf-8"),
                               b"ai-guardrails-backup", 100_000).hex()


def consume_user_backup_code(username: str, code: str) -> bool:
    """Single-use backup code check, per user."""
    ensure_initialised()
    doc = _users_doc()
    u = doc["users"].get((username or "").strip().lower())
    if not u:
        return False
    digest = hash_backup_code(code)
    for entry in u.get("backup_codes", []):
        if entry.get("used"):
            continue
        if hmac.compare_digest(digest, entry.get("hash", "")):
            entry["used"] = True
            entry["used_at"] = _now_iso()
            _save(USERS_PATH, doc)
            return True
    return False


# ── API keys (hashed, scoped, revocable, rotatable) ───────────────────────

def _key_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def create_api_key(name: str, role: str) -> Dict[str, Any]:
    """Creates a key. The secret is returned ONCE and never stored."""
    ensure_initialised()
    if role not in ROLE_PERMISSIONS:
        return {"ok": False, "error": f"unknown role '{role}'"}
    secret = "agk_" + secrets.token_urlsafe(32)
    kid = "k_" + secrets.token_hex(8)
    doc = _keys_doc()
    doc["keys"][kid] = {
        "id": kid,
        "name": (name or "unnamed")[:60],
        "role": role,
        "hash": _key_hash(secret),
        "created_at": _now_iso(),
        "last_used_at": None,
        "revoked": False,
    }
    _save(KEYS_PATH, doc)
    return {"ok": True, "id": kid, "secret": secret, "role": role,
            "note": "Store this secret now — it is not shown again."}


def list_api_keys() -> List[Dict[str, Any]]:
    ensure_initialised()
    out = []
    for k in _keys_doc()["keys"].values():
        out.append({k2: k.get(k2) for k2 in
                    ("id", "name", "role", "created_at", "last_used_at", "revoked")})
    return sorted(out, key=lambda x: x.get("created_at") or "")


def verify_api_key(secret: str) -> Optional[Dict[str, Any]]:
    """Returns the key record for a valid, unrevoked secret."""
    if not secret:
        return None
    ensure_initialised()
    digest = _key_hash(secret)
    doc = _keys_doc()
    for k in doc["keys"].values():
        if k.get("revoked"):
            continue
        if hmac.compare_digest(digest, k.get("hash", "")):
            k["last_used_at"] = _now_iso()
            _save(KEYS_PATH, doc)
            return k
    return None


def revoke_api_key(kid: str) -> Dict[str, Any]:
    ensure_initialised()
    doc = _keys_doc()
    k = doc["keys"].get(kid)
    if not k:
        return {"ok": False, "error": "no such key"}
    k["revoked"] = True
    k["revoked_at"] = _now_iso()
    _save(KEYS_PATH, doc)
    return {"ok": True, "id": kid}


def rotate_api_key(kid: str) -> Dict[str, Any]:
    """Replaces the secret for an existing key; old secret stops working."""
    ensure_initialised()
    doc = _keys_doc()
    k = doc["keys"].get(kid)
    if not k:
        return {"ok": False, "error": "no such key"}
    secret = "agk_" + secrets.token_urlsafe(32)
    k["hash"] = _key_hash(secret)
    k["rotated_at"] = _now_iso()
    k["revoked"] = False
    _save(KEYS_PATH, doc)
    return {"ok": True, "id": kid, "secret": secret,
            "note": "Store this secret now — it is not shown again."}


# ── Principal resolution used by guardrail_auth.authenticate ──────────────

class Principal:
    """Who is making this request, and what may they do."""

    __slots__ = ("kind", "name", "role", "perms", "via")

    def __init__(self, kind: str, name: str, role: str, via: str):
        self.kind = kind          # "session" | "api_key" | "legacy_env"
        self.name = name
        self.role = role
        self.via = via
        self.perms = ROLE_PERMISSIONS.get(role, set())

    def can(self, permission: str) -> bool:
        return permission in self.perms

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "role": self.role,
                "via": self.via, "permissions": sorted(self.perms)}
