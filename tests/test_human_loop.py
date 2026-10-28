#!/usr/bin/env python3
#=============================================================================
# Tests for guardrail_human_loop.py
#=============================================================================
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardrail_human_loop import HumanLoopEscalator, HumanLoopConfig

failures = []


def check(name, condition, detail=""):
    if not condition:
        failures.append((name, detail))
        print(f"FAIL: {name} {detail}")
    else:
        print(f"ok:   {name}")


print("=== Human Loop ===")

# Disabled by default
hl = HumanLoopEscalator()
check("disabled by default", hl.config.enabled is False)
check("should not escalate when disabled", hl.should_escalate("critical") is False)

# Enabled, escalate_at medium
hl = HumanLoopEscalator(HumanLoopConfig({
    "enabled": True, "mode": "console", "escalate_at": "medium"}))
check("enabled", hl.config.enabled is True)
check("escalate at medium", hl.should_escalate("medium") is True)
check("escalate at high", hl.should_escalate("high") is True)
check("escalate at critical", hl.should_escalate("critical") is True)
check("not escalate at low", hl.should_escalate("low") is False)

# Escalate + decide
rec = hl.escalate("e1", "s1", "p1", "input", "dangerous content",
                  "jailbreak attempt", "high")
check("escalation record", rec["status"] == "pending")
check("escalation id", rec["escalation_id"] == "e1")

# No decision yet -> None
check("no decision initially", hl.get_decision("e1") is None)

# Block decision
res = hl.decide("e1", "block", "reviewer1")
check("decision recorded", res["ok"] is True and res["decision"] == "block")
check("get decision block", hl.get_decision("e1") == "block")

# Approve decision on new escalation
hl2 = HumanLoopEscalator(HumanLoopConfig({
    "enabled": True, "mode": "console", "escalate_at": "low"}))
hl2.escalate("e2", "s2", "p2", "output", "some content", "risky", "medium")
res2 = hl2.decide("e2", "approve", "reviewer2")
check("approve decision", res2["ok"] is True and res2["decision"] == "approve")
check("get decision approve", hl2.get_decision("e2") == "approve")

# Invalid decision
res3 = hl2.decide("e2", "ignore", "reviewer")
check("invalid decision rejected", res3["ok"] is False)

# Unknown escalation
res4 = hl2.decide("nonexistent", "block")
check("unknown escalation rejected", res4["ok"] is False)

# Stats
stats = hl2.get_stats()
check("stats has enabled", stats["enabled"] is True)
check("stats pending count", stats["pending"] >= 0)

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for name, detail in failures:
        print(f"  - {name}: {detail}")
    sys.exit(1)
print("All human loop tests passed.")
