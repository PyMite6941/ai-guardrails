#!/usr/bin/env python3
#=============================================================================
# Tests for guardrail_canary.py
#=============================================================================
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardrail_canary import GuardrailCanary, CANARY_DIR, CANARY_STATE, CANARY_LOG
from guardrail import GuardrailEngine

failures = []


def check(name, condition, detail=""):
    if not condition:
        failures.append((name, detail))
        print(f"FAIL: {name} {detail}")
    else:
        print(f"ok:   {name}")


def cleanup():
    for p in (CANARY_STATE, CANARY_LOG):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


print("=== Canary ===")
cleanup()

engine = GuardrailEngine()
canary = GuardrailCanary(engine=engine, interval_sec=0,
                         alert_after_failures=2)

# All cases should pass on a healthy engine
res = canary.run_probe()
check("canary all passed", res["status"] == "ok", res["status"])
check("canary 0 failures", res["failures"] == 0, str(res["failures"]))
check("canary all cases", res["total"] == 6)

# Jailbreak case blocked
jb = [r for r in res["results"] if r["case"] == "canary_jailbreak"][0]
check("jailbreak blocked", jb["actual_safe"] is False)

# Benign case passed
bg = [r for r in res["results"] if r["case"] == "canary_benign"][0]
check("benign passed", bg["actual_safe"] is True)

# State updated
state = canary.get_state()
check("state last_run set", state["last_run"] is not None)
check("state consecutive failures 0", state["consecutive_failures"] == 0)

# Simulate a degraded engine: monkey-patch to always pass (gate stopped blocking)
original = engine.validate_input
def always_pass(text, **kw):
    return {"safe": True, "reason": "tampered gate", "blocked_by": None}
engine.validate_input = always_pass

res2 = canary.run_probe()
check("canary detects degraded gate", res2["status"] == "degraded", res2["status"])
check("consecutive failures incremented",
      res2["consecutive_failures"] >= 1)

# Run again to hit alert threshold (alert_after_failures=2)
res3 = canary.run_probe()
check("alert triggered at threshold", res3["status"] == "alerted",
      res3["status"])

# Restore engine
engine.validate_input = original

# After restore, probe passes again and consecutive resets
res4 = canary.run_probe()
check("canary recovers after restore", res4["status"] == "ok",
      res4["status"])
check("consecutive failures reset", res4["consecutive_failures"] == 0)

# Reset clears state
canary.reset()
state2 = canary.get_state()
check("reset clears consecutive failures", state2["consecutive_failures"] == 0)

cleanup()

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for name, detail in failures:
        print(f"  - {name}: {detail}")
    sys.exit(1)
print("All canary tests passed.")
