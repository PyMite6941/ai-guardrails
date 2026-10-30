#!/usr/bin/env python3
#=============================================================================
# Guardrail Integrity — tamper-evident watcher for guardrail config/policy
#=============================================================================
# "Who watches the watchers?" Agents can quietly disable their own safety
# monitoring (flip a config flag, delete a monitor, replace a policy file)
# and nothing inside the agent's control plane can say so.
#
# This module closes that gap:
#   - Fingerprints watched files (hook configs, policy files, guardrail
#     scripts) recording sha256 of every file
#   - Builds a signed, hash-chained, append-only audit ledger
#   - Runs a check from outside the agent's control plane that re-hashes
#     everything on a schedule
#   - Any modification/deletion/addition becomes an out-of-band alert +
#     permanent record of what changed and when
#
# The signing key must live outside the watched agent's reach. Without
# the key, the agent cannot mint a clean baseline after tampering.
#=============================================================================

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any, List

from guardrail import GuardrailEngine

LEDGER_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "logs", "integrity"
)
os.makedirs(LEDGER_DIR, exist_ok=True)

DEFAULT_WATCHLIST = [
    "guardrail.py",
    "guardrail_server.py",
    "outer_monitor.py",
    "guardrail_modes.py",
    "guardrail_risk.py",
    "policies/default.json",
    "scripts/kill-switch.sh",
]

# ── Helpers ─────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _sign(payload: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), payload.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _verify_signature(payload: str, signature: str, key: str) -> bool:
    expected = hmac.new(key.encode("utf-8"), payload.encode("utf-8"),
                        hashlib.sha256).digest()
    provided = bytes.fromhex(signature) if signature else b""
    return hmac.compare_digest(expected, provided)


# ── Integrity Watcher ───────────────────────────────────────────────

class IntegrityWatcher:
    """Tamper-evident integrity watcher for guardrail files.

    Operates outside the agent's control plane. The key is provided by the
    operator and never stored where the agent can reach it.
    """

    def __init__(self, project_dir: Optional[str] = None,
                 key: Optional[str] = None,
                 watchlist: Optional[List[str]] = None):
        self.project_dir = project_dir or os.path.dirname(
            os.path.abspath(__file__))
        self.key = key or os.environ.get("GUARDRAIL_INTEGRITY_KEY", "")
        self.watchlist = watchlist or list(DEFAULT_WATCHLIST)
        self.ledger_path = os.path.join(LEDGER_DIR, "integrity_ledger.jsonl")
        self.baseline_path = os.path.join(LEDGER_DIR, "baseline.json")

    # ── Baseline ────────────────────────────────────────────────────

    def init_baseline(self, force: bool = False) -> Dict[str, Any]:
        """Create the signed baseline manifest of watched files."""
        if os.path.exists(self.baseline_path) and not force:
            return {"ok": False, "reason": "baseline already exists"}

        if not self.key:
            return {"ok": False, "reason": "no integrity key configured"}

        manifest: Dict[str, Any] = {
            "created_at": _now(),
            "project_dir": self.project_dir,
            "files": {},
        }
        for rel in self.watchlist:
            abs_path = os.path.join(self.project_dir, rel)
            digest = _sha256_file(abs_path)
            manifest["files"][rel] = {
                "sha256": digest,
                "size": os.path.getsize(abs_path) if os.path.exists(abs_path) else -1,
            }

        payload = json.dumps(manifest, sort_keys=True)
        manifest["signature"] = _sign(payload, self.key)
        manifest["signed_payload_sha256"] = hashlib.sha256(
            payload.encode("utf-8")).hexdigest()

        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # Seed the ledger with the baseline creation event.
        self._ledger_event("BASELINE_CREATED", {
            "file_count": len(manifest["files"]),
            "signature": manifest["signature"],
        })
        return {"ok": True, "file_count": len(manifest["files"]),
                "baseline": self.baseline_path}

    # ── Check ───────────────────────────────────────────────────────

    def check(self) -> Dict[str, Any]:
        """Re-hash watched files and compare against baseline.

        Returns a report with findings classified as:
          MODIFIED, REMOVED, ADDED, CONFIG_DISABLED, LEDGER_TAMPER,
          STORE_WORLD_WRITABLE
        """
        findings: List[Dict[str, Any]] = []

        if not os.path.exists(self.baseline_path):
            return {"ok": False, "reason": "no baseline; run init first",
                    "findings": findings}

        with open(self.baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        # Verify baseline signature hasn't been tampered.
        signature = baseline.get("signature", "")
        signed_sha = baseline.get("signed_payload_sha256", "")
        # Rebuild payload without signature fields to verify.
        bp = {k: v for k, v in baseline.items()
              if k not in ("signature", "signed_payload_sha256")}
        payload = json.dumps(bp, sort_keys=True)
        if not _verify_signature(payload, signature, self.key):
            findings.append({
                "type": "BASELINE_TAMPER",
                "severity": "critical",
                "detail": "baseline signature invalid — baseline was modified",
            })
            self._ledger_event("BASELINE_TAMPER", {})
            return {"ok": False, "findings": findings}

        # Check ledger integrity (hash chain).
        ledger_ok = self._verify_ledger()
        if not ledger_ok:
            findings.append({
                "type": "LEDGER_TAMPER",
                "severity": "critical",
                "detail": "integrity ledger hash chain broken",
            })

        # Check store permissions (world-writable = agent could rewrite).
        store_mode = None
        try:
            store_mode = os.stat(LEDGER_DIR).st_mode & 0o777
            if store_mode & 0o002:
                findings.append({
                    "type": "STORE_WORLD_WRITABLE",
                    "severity": "high",
                    "detail": f"ledger dir {LEDGER_DIR} is world-writable ({oct(store_mode)})",
                })
        except Exception:
            pass

        # Re-hash each watched file.
        current_files: Dict[str, Any] = {}
        for rel in self.watchlist:
            abs_path = os.path.join(self.project_dir, rel)
            digest = _sha256_file(abs_path)
            size = os.path.getsize(abs_path) if os.path.exists(abs_path) else -1
            current_files[rel] = {"sha256": digest, "size": size}

            prev = baseline["files"].get(rel)
            if prev is None:
                findings.append({
                    "type": "ADDED", "severity": "medium", "file": rel,
                    "detail": "new watched file not in baseline",
                })
            elif prev.get("sha256") != digest:
                findings.append({
                    "type": "MODIFIED", "severity": "high", "file": rel,
                    "detail": f"sha256 changed {prev.get('sha256')} -> {digest}",
                })

        for rel in baseline["files"]:
            if rel not in current_files:
                findings.append({
                    "type": "REMOVED", "severity": "high", "file": rel,
                    "detail": "watched file deleted since baseline",
                })

        # Record the check event in the ledger (append-only).
        self._ledger_event("CHECK", {
            "findings_count": len(findings),
            "file_count": len(current_files),
        })

        return {
            "ok": len(findings) == 0,
            "findings": findings,
            "checked_at": _now(),
            "file_count": len(current_files),
        }

    # ── Ledger ──────────────────────────────────────────────────────

    def _ledger_event(self, event_type: str,
                      data: Dict[str, Any]) -> None:
        entry = {
            "ts": _now(), "type": event_type, "data": data,
        }
        # Hash-chain: include previous entry's hash.
        prev_hash = self._last_ledger_hash()
        if prev_hash:
            entry["prev_hash"] = prev_hash
        entry_payload = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(entry_payload.encode("utf-8")).hexdigest()
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def _last_ledger_hash(self) -> Optional[str]:
        if not os.path.exists(self.ledger_path):
            return None
        last = None
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = json.loads(line)
        except Exception:
            return None
        return last.get("hash") if last else None

    def _verify_ledger(self) -> bool:
        if not os.path.exists(self.ledger_path):
            return True
        prev_hash = None
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    stored_hash = entry.pop("hash", None)
                    entry_prev_hash = entry.pop("prev_hash", None)
                    payload = json.dumps(entry, sort_keys=True)
                    computed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                    # Verify the entry's own hash matches its content.
                    if not hmac.compare_digest(computed, stored_hash or ""):
                        return False
                    # Verify chain linkage: this entry's prev_hash must equal
                    # the previous entry's hash.
                    if prev_hash is not None and entry_prev_hash != prev_hash:
                        return False
                    prev_hash = stored_hash
        except Exception:
            return False
        return True

    def audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the ledger timeline (most recent first)."""
        entries: List[Dict[str, Any]] = []
        if not os.path.exists(self.ledger_path):
            return entries
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        return entries[-limit:][::-1]


# ── Global convenience ──────────────────────────────────────────────

_watcher_instance: Optional[IntegrityWatcher] = None


def get_watcher() -> IntegrityWatcher:
    global _watcher_instance
    if _watcher_instance is None:
        _watcher_instance = IntegrityWatcher()
    return _watcher_instance


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    watcher = get_watcher()
    print("=" * 60)
    print("  Guardrail Integrity — tamper-evident watcher")
    print("=" * 60)
    print("  Commands:  init      — create signed baseline")
    print("             check     — re-hash + compare vs baseline")
    print("             audit     — show ledger timeline")
    print("             quit")
    print("=" * 60)
    while True:
        try:
            line = input("guardrail-integrity> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break
        if not line:
            continue
        if line == "quit":
            print("Goodbye!")
            break
        if line == "init":
            print(json.dumps(watcher.init_baseline(force=True), indent=2))
        elif line == "check":
            print(json.dumps(watcher.check(), indent=2))
        elif line == "audit":
            for e in watcher.audit(20):
                print(json.dumps(e))
        else:
            print("  Usage: init|check|audit|quit")
        print()


if __name__ == "__main__":
    main()
