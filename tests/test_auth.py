#!/usr/bin/env python3
#=============================================================================
# Tests for guardrail_auth.py — authentication, authorization, rate limiting,
# IP allowlist, and security headers.
#=============================================================================
import json
import os
import sys
import time
import ipaddress

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardrail_auth import (
    _verify_key, _ip_allowed, _origin_allowed, _host_allowed,
    is_ssrf_protection_enabled, is_url_private, validate_model_url,
    set_password, verify_password, has_password,
    create_session, validate_session, destroy_session,
    RateLimiter, AuthResult,
)

failures = []


def check(name, condition, detail=""):
    if not condition:
        failures.append((name, detail))
        print(f"FAIL: {name} {detail}")
    else:
        print(f"ok:   {name}")


def cleanup(paths):
    for p in paths:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


# ── Password hashing tests ─────────────────────────────────────────────────

print("=== Password hashing ===")
AUTH_STATE = os.path.expanduser("~/.ai_guardrails_auth.json")
cleanup([AUTH_STATE])

# No password set initially
check("no password initially", not has_password())

# Set and verify (strong password: upper + lower + digit + special)
set_password("TestPass123!")
check("password set", has_password())
check("correct password verifies", verify_password("TestPass123!"))
check("wrong password fails", not verify_password("wrong"))
check("empty password fails", not verify_password(""))

# Weak password rejected by complexity rules
try:
    set_password("weak")
    check("weak password rejected", False, "should have raised ValueError")
except ValueError:
    check("weak password rejected", True)

cleanup([AUTH_STATE])


# ── Session tests ──────────────────────────────────────────────────────────

print("=== Sessions ===")
cleanup([AUTH_STATE])

token = create_session("127.0.0.1", "test-agent")
check("session created", token is not None and len(token) > 0)

session = validate_session(token)
check("session valid", session is not None)
check("session has token", session["token"] == token)
check("session has ip", session["ip"] == "127.0.0.1")

# Invalid token
check("invalid token returns None", validate_session("invalid") is None)
check("empty token returns None", validate_session("") is None)

# Destroy session
destroy_session(token)
check("session destroyed", validate_session(token) is None)

cleanup([AUTH_STATE])


# ── Rate limiter tests ─────────────────────────────────────────────────────

print("=== Rate limiter ===")
rl = RateLimiter(rate_per_minute=3)

check("first request allowed", rl.allow("user1"))
check("second request allowed", rl.allow("user1"))
check("third request allowed", rl.allow("user1"))
check("fourth request blocked (rate limit)", not rl.allow("user1"))

# Different user not affected
check("different user allowed", rl.allow("user2"))

# Check remaining
check("remaining for user1 is 0", rl.remaining("user1") == 0)
check("remaining for user2 is 2", rl.remaining("user2") == 2)


# ── API key verification tests ─────────────────────────────────────────────

print("=== API key verification ===")
check("matching keys verify", _verify_key("abc123", "abc123"))
check("different keys fail", not _verify_key("abc123", "def456"))
check("empty key fails", not _verify_key("", "abc123"))
check("empty required fails", not _verify_key("abc123", ""))
check("length mismatch fails", not _verify_key("abc", "abcdef"))


# ── IP allowlist tests ─────────────────────────────────────────────────────

print("=== IP allowlist ===")
# No IPs configured = allow all
check("no IPs = allow all", _ip_allowed("1.2.3.4"))
check("no IPs = allow localhost", _ip_allowed("127.0.0.1"))

# With specific IPs
ALLOWED_IPS_OLD = []
import guardrail_auth
ALLOWED_IPS_OLD = guardrail_auth.ALLOWED_IPS[:]
guardrail_auth.ALLOWED_IPS = ["10.0.0.0/8", "192.168.1.50"]
guardrail_auth.ALLOWED_NETS = []
for entry in guardrail_auth.ALLOWED_IPS:
    try:
        guardrail_auth.ALLOWED_NETS.append(
            ipaddress.ip_network(entry, strict=False))
    except ValueError:
        guardrail_auth.ALLOWED_NETS.append(
            ipaddress.ip_network(entry + "/32", strict=False))

check("10.0.0.1 allowed", _ip_allowed("10.0.0.1"))
check("10.255.255.255 allowed", _ip_allowed("10.255.255.255"))
check("192.168.1.50 allowed", _ip_allowed("192.168.1.50"))
check("172.16.0.1 blocked", not _ip_allowed("172.16.0.1"))
check("1.2.3.4 blocked", not _ip_allowed("1.2.3.4"))

# Restore
guardrail_auth.ALLOWED_IPS = ALLOWED_IPS_OLD
guardrail_auth.ALLOWED_NETS = []
for entry in guardrail_auth.ALLOWED_IPS:
    try:
        guardrail_auth.ALLOWED_NETS.append(
            ipaddress.ip_network(entry, strict=False))
    except ValueError:
        guardrail_auth.ALLOWED_NETS.append(
            ipaddress.ip_network(entry + "/32", strict=False))


# ── Host header validation tests ───────────────────────────────────────────

print("=== Host header validation ===")
# No hosts configured = allow all
check("no hosts = allow any", _host_allowed("anything.com"))
check("no hosts = allow ip", _host_allowed("1.2.3.4"))

# With specific hosts
guardrail_auth.ALLOWED_HOSTS = ["example.com", "127.0.0.1", "my-pi.local"]
check("example.com allowed", _host_allowed("example.com"))
check("127.0.0.1 allowed", _host_allowed("127.0.0.1"))
check("my-pi.local allowed", _host_allowed("my-pi.local"))
check("evil.com blocked", not _host_allowed("evil.com"))
check("subdomain blocked", not _host_allowed("evil.example.com"))

guardrail_auth.ALLOWED_HOSTS = []


# ── Origin validation tests ────────────────────────────────────────────────

print("=== Origin validation ===")
guardrail_auth.ALLOWED_ORIGINS = ["https://example.com"]
check("matching origin allowed", _origin_allowed("https://example.com"))
check("different origin blocked", not _origin_allowed("https://evil.com"))
check("no origin = not allowed", not _origin_allowed(None))

guardrail_auth.ALLOWED_ORIGINS = []


# ── SSRF protection tests ──────────────────────────────────────────────────

print("=== SSRF protection ===")
# Always enabled — model URLs are operator-configured, not end-user input
check("SSRF protection always enabled", is_ssrf_protection_enabled())

# URL validation — always enforced
check("localhost allowed", validate_model_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434")
try:
    validate_model_url("http://10.0.0.1:8000", "test")
    check("private IP blocked", False, "should have raised")
except ValueError:
    check("private IP blocked", True)

# is_url_private checks the address regardless of env
check("10.0.0.1 is private", is_url_private("http://10.0.0.1:8000"))
check("192.168.1.1 is private", is_url_private("http://192.168.1.1:8000"))
check("172.16.0.1 is private", is_url_private("http://172.16.0.1:8000"))
check("127.0.0.1 not private (loopback allowed)", not is_url_private("http://127.0.0.1:11434"))
check("public IP not private", not is_url_private("http://1.2.3.4:8000"))

# SSRF blocks private IPs even when env var is not set
try:
    validate_model_url("http://10.0.0.1:8000", "test")
    check("SSRF blocks private IP", False, "should have raised")
except ValueError:
    check("SSRF blocks private IP", True)
try:
    validate_model_url("http://127.0.0.1:11434", "test")
    check("SSRF allows localhost", True)
except ValueError:
    check("SSRF allows localhost", False, "should allow localhost")


# ── AuthResult tests ───────────────────────────────────────────────────────

print("=== AuthResult ===")
ar = AuthResult(True, 200, "ok", {"X-Custom": "value"}, "token123")
check("AuthResult ok", ar.ok)
check("AuthResult status", ar.status == 200)
check("AuthResult reason", ar.reason == "ok")
check("AuthResult headers", ar.headers == {"X-Custom": "value"})
check("AuthResult session token", ar.session_token == "token123")

ar2 = AuthResult(False, 401, "unauthorized")
check("AuthResult not ok", not ar2.ok)
check("AuthResult status 401", ar2.status == 401)


print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for name, detail in failures:
        print(f"  - {name}: {detail}")
    sys.exit(1)
print("All auth tests passed.")
