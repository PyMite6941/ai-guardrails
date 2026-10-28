#!/usr/bin/env python3
#=============================================================================
# Guardrail Policy Versioning — versioned policies with rollback
#=============================================================================
# Production best practice (Patronus AI): "Guardrails are not set-and-forget;
# they must be adapted to new attack patterns... Always implement guardrail
# versioning so that you can roll back problematic changes."
#
# Every saved page policy is versioned. A new version is created on each
# save, keyed by (page_id, version). rollback lets an operator restore a
# previous version if a new policy causes false positives or misses attacks.
# Versions are append-only JSON files in policies/versions/<page>/v<N>.json.
#=============================================================================

import json
import os
import re
import sys
from datetime import datetime
from typing import Optional, Dict, Any, List

from guardrail import GuardrailPolicy, DEFAULT_POLICY

VERSIONS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "policies", "versions"
)
os.makedirs(VERSIONS_DIR, exist_ok=True)


def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _safe_page(page_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", page_id)


def _page_version_dir(page_id: str) -> str:
    d = os.path.join(VERSIONS_DIR, _safe_page(page_id))
    os.makedirs(d, exist_ok=True)
    return d


def _next_version(page_id: str) -> int:
    d = _page_version_dir(page_id)
    existing = 0
    for name in os.listdir(d):
        m = re.fullmatch(r"v(\d+)\.json", name)
        if m:
            existing = max(existing, int(m.group(1)))
    return existing + 1


def save_policy_version(page_id: str, policy: Dict[str, Any],
                        changed_by: str = "operator",
                        note: str = "") -> Dict[str, Any]:
    """Save a new version of a page policy. Returns the version record."""
    version = _next_version(page_id)
    record = {
        "page": page_id,
        "version": version,
        "saved_at": _now(),
        "changed_by": changed_by,
        "note": note,
        "policy": policy,
    }
    path = os.path.join(_page_version_dir(page_id), f"v{version}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    # Also write a "latest" symlink-friendly copy.
    latest = os.path.join(_page_version_dir(page_id), "latest.json")
    with open(latest, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return record


def list_policy_versions(page_id: str) -> List[Dict[str, Any]]:
    """List all saved versions for a page (newest first), minus policy body."""
    d = _page_version_dir(page_id)
    versions: List[Dict[str, Any]] = []
    for name in os.listdir(d):
        m = re.fullmatch(r"v(\d+)\.json", name)
        if not m:
            continue
        path = os.path.join(d, name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                rec = json.load(f)
            versions.append({
                "page": rec.get("page"),
                "version": rec.get("version"),
                "saved_at": rec.get("saved_at"),
                "changed_by": rec.get("changed_by"),
                "note": rec.get("note"),
                "file": name,
            })
        except Exception:
            continue
    versions.sort(key=lambda v: v["version"], reverse=True)
    return versions


def load_policy_version(page_id: str, version: int) -> Optional[Dict[str, Any]]:
    """Load a specific version's full record (including policy body)."""
    path = os.path.join(_page_version_dir(page_id), f"v{version}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def rollback_policy(page_id: str, version: int,
                    changed_by: str = "operator",
                    note: str = "") -> Dict[str, Any]:
    """Roll back a page policy to a previous version by saving it as a new
    version. Returns the new version record."""
    rec = load_policy_version(page_id, version)
    if rec is None:
        return {"ok": False, "reason": f"version {version} not found for {page_id}"}
    policy = rec["policy"]
    # Ensure the rolled-back policy is valid.
    GuardrailPolicy(policy)  # raises if invalid
    new_rec = save_policy_version(page_id, policy,
                                  changed_by=changed_by,
                                  note=(note or
                                        f"rollback to v{version}"))
    return {"ok": True, "rolled_back_to": version,
            "new_version": new_rec["version"],
            "record": new_rec}


def apply_policy_to_engine(page_id: str, version: int,
                           engine) -> bool:
    """Load a policy version and apply it to the engine's per-page cache."""
    rec = load_policy_version(page_id, version)
    if rec is None:
        return False
    policy = GuardrailPolicy(rec["policy"])
    engine.save_page_policy(page_id, policy)
    return True


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("  Guardrail Policy Versioning — versioned policies + rollback")
    print("=" * 60)
    print("  Commands:  list <page>        |   save <page> <note>")
    print("             load <page> <ver>  |   rollback <page> <ver> [note]")
    print("             quit")
    print("=" * 60)
    while True:
        try:
            line = input("guardrail-versions> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not line:
            continue
        if line == "quit":
            print("Goodbye!")
            break
        parts = line.split(None, 3)
        if parts[0] == "list" and len(parts) == 2:
            for v in list_policy_versions(parts[1]):
                print(json.dumps(v))
        elif parts[0] == "save" and len(parts) >= 3:
            page = parts[1]
            note = parts[2] if len(parts) > 2 else ""
            # Read policy from stdin for simplicity
            print("  Paste policy JSON, then Ctrl-D:")
            data = sys.stdin.read()
            try:
                policy = json.loads(data)
            except Exception as e:
                print(f"  Invalid JSON: {e}")
                continue
            rec = save_policy_version(page, policy, note=note)
            print(f"  Saved v{rec['version']} for {page}")
        elif parts[0] == "load" and len(parts) == 3:
            rec = load_policy_version(parts[1], int(parts[2]))
            print(json.dumps(rec, indent=2) if rec else "not found")
        elif parts[0] == "rollback" and len(parts) >= 3:
            note = parts[3] if len(parts) > 3 else ""
            res = rollback_policy(parts[1], int(parts[2]), note=note)
            print(json.dumps(res, indent=2))
        else:
            print("  Usage: list|save|load|rollback|quit")
        print()


if __name__ == "__main__":
    main()
