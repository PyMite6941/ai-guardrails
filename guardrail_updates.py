#!/usr/bin/env python3
#=============================================================================
# Guardrail Updates — security update tracker
#=============================================================================
# Tracks installed package/component versions and flags when security updates
# are due. Works offline (no constant internet required): it records current
# versions locally, lets the operator mark an update as "due" with a due date,
# and reports which components are past due. The operator applies updates
# manually (e.g., `pip install --upgrade`, rebuilding the Rust scanner, or
# pulling a new model) and then records the new version.
#
# Components tracked by default: Python interpreter, the guardrails package
# itself, the Rust pattern scanner, and any models used (outside/trusted/
# classifier). Additional components can be added at runtime.
#
# All state is stored in logs/updates_state.json — no host-specific paths,
# no network calls.
#=============================================================================

import json
import os
import sys
import platform
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

STATE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "updates_state.json"
)
RUST_SCANNER_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rust", "target", "release",
    "guardrail-scanner",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    # Make naive datetimes timezone-aware (assume UTC) so they compare
    # against the timezone-aware "now" used in get_due_updates.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _python_version() -> str:
    return platform.python_version()


def _guardrails_version() -> str:
    # Read from package.json if present, else a placeholder.
    pkg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "package.json")
    try:
        with open(pkg, "r", encoding="utf-8") as f:
            data = json.load(f)
        return str(data.get("version", "unknown"))
    except Exception:
        return "unknown"


def _rust_scanner_version() -> str:
    # Rust binaries don't embed a version by default; use file mtime as a
    # proxy for "when last built" plus presence.
    if os.path.exists(RUST_SCANNER_PATH):
        try:
            mtime = os.path.getmtime(RUST_SCANNER_PATH)
            return f"built {datetime.utcfromtimestamp(mtime).isoformat()}Z"
        except Exception:
            return "present"
    return "not built"


def _load_state() -> Dict[str, Any]:
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"components": {}, "last_checked": None}


def _save_state(state: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def snapshot_components() -> Dict[str, Any]:
    """Record current versions of all known components."""
    return {
        "python": _python_version(),
        "guardrails": _guardrails_version(),
        "rust_scanner": _rust_scanner_version(),
    }


def ensure_component(state: Dict[str, Any], name: str, version: str,
                     due_date: Optional[str] = None) -> None:
    """Make sure a component is tracked, initializing it if new."""
    comps = state.setdefault("components", {})
    if name not in comps:
        comps[name] = {
            "version": version,
            "due_date": due_date,
            "last_checked": _now_iso(),
            "update_applied": False,
            "notes": "",
        }


def refresh_state() -> Dict[str, Any]:
    """Refresh tracked component versions from the live system."""
    state = _load_state()
    current = snapshot_components()
    for name, version in current.items():
        ensure_component(state, name, version)
    state["last_checked"] = _now_iso()
    _save_state(state)
    return state


def set_due_date(state: Dict[str, Any], component: str,
                 due_date: str, notes: str = "") -> bool:
    """Mark a component as needing a security update by `due_date` (ISO)."""
    comps = state.setdefault("components", {})
    if component not in comps:
        comps[component] = {
            "version": "", "due_date": due_date, "last_checked": _now_iso(),
            "update_applied": False, "notes": notes,
        }
        _save_state(state)
        return True
    comps[component]["due_date"] = due_date
    if notes:
        comps[component]["notes"] = notes
    _save_state(state)
    return True


def mark_applied(state: Dict[str, Any], component: str,
                 new_version: str, notes: str = "") -> bool:
    """Record that a security update was applied to a component."""
    comps = state.setdefault("components", {})
    if component not in comps:
        return False
    comps[component]["version"] = new_version
    comps[component]["update_applied"] = True
    comps[component]["due_date"] = None
    comps[component]["last_checked"] = _now_iso()
    if notes:
        comps[component]["notes"] = notes
    _save_state(state)
    return True


def get_due_updates(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return components whose update due date has passed."""
    now = datetime.now(timezone.utc)
    due: List[Dict[str, Any]] = []
    for name, comp in state.get("components", {}).items():
        due_date = comp.get("due_date")
        if not due_date:
            continue
        dt = _parse_iso(due_date)
        if dt and dt <= now:
            due.append({
                "component": name,
                "version": comp.get("version", "unknown"),
                "due_date": due_date,
                "days_overdue": max(0, (now - dt).days),
                "notes": comp.get("notes", ""),
                "update_applied": comp.get("update_applied", False),
            })
    due.sort(key=lambda d: d["days_overdue"], reverse=True)
    return due


def get_summary(state: Dict[str, Any]) -> Dict[str, Any]:
    due = get_due_updates(state)
    return {
        "last_checked": state.get("last_checked"),
        "tracked_components": len(state.get("components", {})),
        "updates_due": len(due),
        "components": state.get("components", {}),
        "due_updates": due,
    }


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Guardrail security update tracker")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("refresh", help="refresh component versions from live system")
    sub.add_parser("summary", help="show summary of tracked components & due updates")

    p_due = sub.add_parser("due", help="list updates past their due date")
    p_due.add_argument("--set", nargs=2, metavar=("COMPONENT", "DUE_DATE"),
                       help="set due date for a component (ISO date)")
    p_due.add_argument("--notes", default="", help="notes for --set")

    p_apply = sub.add_parser("applied", help="mark a component update as applied")
    p_apply.add_argument("component")
    p_apply.add_argument("new_version")
    p_apply.add_argument("--notes", default="")

    args = parser.parse_args()
    state = _load_state()

    if args.cmd == "refresh":
        state = refresh_state()
        print(json.dumps(get_summary(state), indent=2))
    elif args.cmd == "summary":
        print(json.dumps(get_summary(state), indent=2))
    elif args.cmd == "due":
        if args.set:
            comp, due_date = args.set
            set_due_date(state, comp, due_date, args.notes)
            print(f"Set due date for {comp} to {due_date}")
        else:
            due = get_due_updates(state)
            if due:
                print("Updates past due:")
                for d in due:
                    print(f"  {d['component']} (v{d['version']}) due {d['due_date']} "
                          f"{d['days_overdue']} days overdue: {d['notes']}")
            else:
                print("No updates past due.")
    elif args.cmd == "applied":
        ok = mark_applied(state, args.component, args.new_version, args.notes)
        if ok:
            print(f"Marked {args.component} updated to {args.new_version}")
        else:
            print(f"Component {args.component} not tracked.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
