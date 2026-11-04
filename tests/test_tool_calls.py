#!/usr/bin/env python3
#=============================================================================
# Agentic tool-call guardrail tests
#=============================================================================
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardrail_tool_calls import (ToolCallGuardrail, ToolSpec,
                                  DEFAULT_TOOL_SPECS)
from guardrail_resource import ResourceGuard

failures = []
checks_run = 0


def check(name, condition, detail=""):
    global checks_run
    checks_run += 1
    if not condition:
        failures.append((name, detail))
        print(f"FAIL: {name} {detail}")
    else:
        print(f"ok:   {name}")


# Fresh guardrail with the default tool registry.
g = ToolCallGuardrail()
for spec in DEFAULT_TOOL_SPECS:
    g.register_tool(spec)

# 1. Safe tool call passes
r = g.validate_call("system_info", {}, session_id="t1")
check("safe tool call passes", r["safe"] is True and not r["blocked"],
      r["reason"])

# 2. Unknown tool blocked (default-deny)
r = g.validate_call("rm", {}, session_id="t1")
check("unknown tool blocked", r["safe"] is False
      and r["blocked_by"] == "unknown_tool", r["reason"])

# 3. Disabled tool blocked
g.register_tool(ToolSpec("disabled_tool", "desc", allowed=False))
r = g.validate_call("disabled_tool", {}, session_id="t1")
check("disabled tool blocked", r["safe"] is False
      and r["blocked_by"] == "tool_disabled", r["reason"])

# 4. Dangerous argument content blocked and redacted
r = g.validate_call("guardrail_validate",
                    {"text": "rm -rf /tmp/x"}, session_id="t1")
check("dangerous argument blocked", r["safe"] is False
      and r["blocked_by"] == "dangerous_arguments", r["reason"])
check("dangerous argument redacted",
      r.get("sanitized_args", {}).get("text") == "[redacted]",
      str(r.get("sanitized_args")))

# 5. Shell-style argument name blocked unless allows_shell
r = g.validate_call("guardrail_validate",
                    {"text": "hi", "shell": "echo hi"}, session_id="t1")
check("shell argument name blocked", r["safe"] is False
      and r["blocked_by"] == "dangerous_arguments", r["reason"])

# 6. Missing required argument blocked
r = g.validate_call("file_write", {"path": "x.txt"}, session_id="t1")
check("missing required argument blocked", r["safe"] is False
      and r["blocked_by"] == "schema", r["reason"])

# 7. Wrong argument type blocked
r = g.validate_call("file_write", {"path": 123, "content": "hi"},
                    session_id="t1")
check("wrong argument type blocked", r["safe"] is False
      and r["blocked_by"] == "schema", r["reason"])

# 8. Argument too long blocked
r = g.validate_call("guardrail_validate",
                    {"text": "x" * 5000}, session_id="t1")
check("over-long argument blocked", r["safe"] is False
      and r["blocked_by"] == "schema", r["reason"])

# 9. Destructive tool requires confirmation
r = g.validate_call("emergency_contain", {}, session_id="t1")
check("destructive tool blocked without confirm", r["safe"] is False
      and r["blocked_by"] == "confirmation_required", r["reason"])
r = g.validate_call("emergency_contain", {}, session_id="t1",
                    confirm=True)
check("destructive tool allowed with confirm", r["safe"] is True, r["reason"])

# 10. Per-session call budget
tight = ToolCallGuardrail(resource_guard=ResourceGuard(
    max_calls_per_session=1, max_arg_bytes_per_session=10000,
    max_concurrent_calls=1))
tight.register_tool(DEFAULT_TOOL_SPECS[3])  # system_info
r1 = tight.validate_call("system_info", {}, session_id="budget")
check("budget first call allowed", r1["safe"] is True, r1["reason"])
r2 = tight.validate_call("system_info", {}, session_id="budget")
check("budget second call blocked", r2["safe"] is False
      and r2["blocked_by"] == "budget_exceeded", r2["reason"])

# 11. Per-session argument bytes budget
tight2 = ToolCallGuardrail(resource_guard=ResourceGuard(
    max_calls_per_session=100, max_arg_bytes_per_session=50,
    max_concurrent_calls=1))
tight2.register_tool(DEFAULT_TOOL_SPECS[3])
r = tight2.validate_call("system_info", {"extra": "a" * 100},
                         session_id="bytes")
check("argument bytes budget blocked", r["safe"] is False
      and r["blocked_by"] == "budget_exceeded", r["reason"])

# 12. Stats recorded
stats = g.get_stats()
check("stats recorded", stats["calls_validated"] > 0
      and stats["calls_blocked"] > 0, str(stats))
check("stats by_reason has dangerous_arguments",
      "dangerous_arguments" in stats["by_reason"], str(stats["by_reason"]))

# 13. List / unregister tools
tools = g.list_tools()
check("list tools", any(t["name"] == "system_info" for t in tools),
      str([t["name"] for t in tools]))
check("unregister tool", g.unregister_tool("system_info") is True)
check("unregistered tool now blocked",
      g.validate_call("system_info", {}, session_id="t1")["blocked_by"]
      == "unknown_tool")

print()
if failures:
    print(f"{len(failures)} FAILURE(S):")
    for name, detail in failures:
        print(f"  - {name}: {detail}")
    raise SystemExit(1)
print(f"All {checks_run} checks passed.")
