#!/usr/bin/env python3
"""Run every tests/test_*.py script in its own process and summarize.

The suites are standalone scripts (they exit non-zero on failure), so each one
gets a fresh interpreter and its own temporary state.

    python3 tests/run_all.py            # all suites
    python3 tests/run_all.py detection  # suites whose name contains "detection"
"""
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "600"))


def main(argv):
    filters = argv[1:]
    suites = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
    if filters:
        suites = [s for s in suites if any(f in os.path.basename(s) for f in filters)]
    failed = []
    for path in suites:
        name = os.path.basename(path)
        t0 = time.perf_counter()
        try:
            proc = subprocess.run([sys.executable, "-W", "ignore::DeprecationWarning", path],
                                  cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT)
            code, out = proc.returncode, proc.stdout + proc.stderr
        except subprocess.TimeoutExpired as exc:
            code, out = -1, f"TIMEOUT after {TIMEOUT}s\n{exc.stdout or ''}"
        dt = time.perf_counter() - t0
        status = "PASS" if code == 0 else "FAIL"
        print(f"{status}  {name:32s} {dt:6.1f}s")
        if code != 0:
            failed.append(name)
            print("\n".join("      " + line for line in out.splitlines()[-40:]))
    print(f"\n{len(suites) - len(failed)}/{len(suites)} suites passed")
    return 1 if failed or not suites else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
