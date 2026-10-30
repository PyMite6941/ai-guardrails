#!/usr/bin/env python3
#=============================================================================
# tests/test_security.py — regression tests for the security hardening
#=============================================================================
# Covers: default-deny routing, 2FA enrolment protection, hash-only backup
# codes, independent users, role permissions, API key scopes/revocation.
#
#   python3 tests/test_security.py
#=============================================================================
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FAILS = []


def check(name, condition, detail=""):
    if condition:
        print(f"ok:   {name}")
    else:
        FAILS.append(name)
        print(f"FAIL: {name} {detail}")


# ── Isolate state into a temp dir before importing the modules ────────────
tmp = tempfile.mkdtemp(prefix="ag-test-")
os.environ["GUARDRAIL_USERS_PATH"] = os.path.join(tmp, "users.json")
os.environ["GUARDRAIL_KEYS_PATH"] = os.path.join(tmp, "keys.json")
os.environ["GUARDRAIL_AUTH_STATE_PATH"] = os.path.join(tmp, "auth.json")
os.environ["GUARDRAIL_ADMIN_PASSWORD"] = "SeedAdmin!2026"

import guardrail_auth as auth
import guardrail_users as users

# Redirect the legacy auth-state file into the temp dir as well
auth.AUTH_STATE_PATH = os.path.join(tmp, "auth.json")
auth._SESSIONS.clear()

print("\n== default-deny route policy")
check("health is public", auth.required_permission("/api/health", "GET") == "public")
check("unknown route has no permission",
      auth.required_permission("/api/not-a-route", "GET") is None)
check("unknown route tier is deny", auth.path_tier("/api/not-a-route") == "deny")
check("emergency POST requires emergency permission",
      auth.required_permission("/api/emergency/contain", "POST") == "emergency")
check("emergency is not public",
      auth.required_permission("/api/emergency/shutdown", "POST") != "public")
check("2fa setup requires security:manage",
      auth.required_permission("/api/auth/2fa/setup", "POST") == "security:manage")
check("2fa setup GET is not allowed",
      auth.required_permission("/api/auth/2fa/setup", "GET") is None)
check("policy PUT requires policies:write",
      auth.required_permission("/api/policies/example.com", "PUT") == "policies:write")
check("policy GET requires only read",
      auth.required_permission("/api/policies/example.com", "GET") == "policies:read")
check("models GET is not public",
      auth.required_permission("/api/models", "GET") != "public")
check("monitor audit is not public",
      auth.required_permission("/api/monitor/audit", "GET") != "public")
check("users admin requires users:manage",
      auth.required_permission("/api/users", "POST") == "users:manage")

print("\n== roles")
check("admin has emergency", users.role_has_permission("admin", "emergency"))
check("developer cannot manage users",
      not users.role_has_permission("developer", "users:manage"))
check("developer can validate", users.role_has_permission("developer", "validate"))
check("viewer is read-only", users.role_has_permission("viewer", "policies:read")
      and not users.role_has_permission("viewer", "policies:write"))
check("viewer cannot validate", not users.role_has_permission("viewer", "validate"))

print("\n== users")
r = users.create_user("alice", "AlicePass!2026", "developer")
check("create developer", r.get("ok"))
r = users.create_user("alice", "AlicePass!2026", "viewer")
check("duplicate username rejected", not r.get("ok"))
r = users.create_user("weak", "short", "viewer")
check("weak password rejected", not r.get("ok"))
check("verify good credentials", users.verify_credentials("alice", "AlicePass!2026") is not None)
check("verify wrong password", users.verify_credentials("alice", "nope") is None)
r = users.set_role("alice", "admin")
check("promote alice", r.get("ok"))
u = users.get_user("alice")
check("alice is admin", u["role"] == "admin")
# Last-admin guard: there is exactly one admin after promotion? admin + alice,
# so demoting one is allowed. Disable alice, then demoting admin must fail.
users.set_disabled("alice", True)
r = users.set_role("admin", "viewer")
check("cannot demote the last enabled admin", not r.get("ok"))
r = users.set_disabled("alice", False)
check("re-enable alice", r.get("ok"))

print("\n== per-user 2FA is independent and non-destructive")
res_a = auth.enable_user_2fa("admin", replace=False)
check("enrol admin device", res_a.get("ok"))
check("admin has 2FA", auth.has_2fa_for("admin"))
check("alice has no 2FA", not auth.has_2fa_for("alice"))
again = auth.enable_user_2fa("admin", replace=False)
check("second enrolment refused", not again.get("ok") and again.get("code") == "already_configured")
# The secret must be unchanged after the refused attempt
before = users.get_user("admin")["totp_secret"]
auth.enable_user_2fa("admin", replace=False)
after = users.get_user("admin")["totp_secret"]
check("refused enrolment keeps the existing secret", before == after)
res_b = auth.enable_user_2fa("alice", replace=False)
check("alice enrols her own device", res_b.get("ok"))
check("alice's secret differs from admin's",
      users.get_user("alice")["totp_secret"] != users.get_user("admin")["totp_secret"])

print("\n== backup codes are hash-only and single use")
stored = users.get_user("alice")["backup_codes"]
check("backup codes stored", len(stored) > 0)
check("no plaintext code stored", all("code" not in e for e in stored))
check("hashes present", all(e.get("hash") for e in stored))
code = res_b["backup_codes"][0]
check("valid backup code accepted", users.consume_user_backup_code("alice", code))
check("same code rejected second time", not users.consume_user_backup_code("alice", code))
other = res_b["backup_codes"][1]
check("different code still works", users.consume_user_backup_code("alice", other))

print("\n== legacy state migration strips plaintext codes")
legacy = {"password_hash": "x", "salt": "y", "2fa_secret": "S", "2fa_enabled": True,
          "backup_codes": [{"code": "PLAINTEXT123", "used": False, "hash": "abc"}]}
auth._save_auth_state(legacy)
loaded = auth._load_auth_state()
check("plaintext code removed on load",
      all("code" not in e for e in loaded["backup_codes"]))
check("hash preserved", loaded["backup_codes"][0]["hash"] == "abc")

print("\n== API keys: scopes, rotation, revocation")
k = users.create_api_key("ci", "viewer")
check("key created", k.get("ok"))
secret = k["secret"]
kid = k["id"]
check("secret returned once", bool(secret) and secret.startswith("agk_"))
check("key verifies", users.verify_api_key(secret) is not None)
rec = users.verify_api_key(secret)
check("key carries viewer role", rec.get("role") == "viewer")
check("unknown secret rejected", users.verify_api_key("agk_nope") is None)
rot = users.rotate_api_key(kid)
check("rotation returns new secret", rot.get("ok") and rot["secret"] != secret)
check("old secret dead after rotation", users.verify_api_key(secret) is None)
check("new secret works", users.verify_api_key(rot["secret"]) is not None)
check("revoke", users.revoke_api_key(kid).get("ok"))
check("revoked key rejected", users.verify_api_key(rot["secret"]) is None)

print("\n== sessions carry identity")
tok = auth.create_session("127.0.0.1", "ua", "alice", "admin")
sess = auth.validate_session(tok)
check("session has username", sess.get("username") == "alice")
check("session has role", sess.get("role") == "admin")
check("session not 2FA verified by default", not auth.session_2fa_verified(sess))
auth.destroy_session(tok)

print("\n== TOTP round trip")
secret_b32 = auth.generate_totp_secret()
code_now = auth.compute_totp(secret_b32)
check("computed code verifies", auth.verify_totp(secret_b32, code_now))
check("wrong code rejected", not auth.verify_totp(secret_b32, (code_now + 1) % 1000000))

print("\n== per-user 2FA gates API access")
users.create_user("carol", "Carol-Pass!9", "admin")
users.set_user_2fa("carol", auth.generate_totp_secret(), [])
_carol = users.get_user("carol") or {}
check("carol has a TOTP secret", bool(_carol.get("totp_secret")))
check("carol is marked as 2FA enabled", bool(_carol.get("totp_enabled")))
_carol_tok = auth.create_session("127.0.0.1", "ua", "carol", "admin")
_carol_sess = auth.validate_session(_carol_tok) or {}
check("password-only session is not 2FA verified for an enrolled user",
      not auth.session_2fa_verified(_carol_sess),
      "a session opened with only a password must not satisfy the 2FA gate")
_carol_sess["2fa_verified"] = True
check("verified session satisfies the gate", auth.session_2fa_verified(_carol_sess))
auth.destroy_session(_carol_tok)

print("\n" + ("-" * 56))
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s): {', '.join(FAILS)}")
    sys.exit(1)
print("All security checks passed.")
