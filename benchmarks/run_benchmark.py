#!/usr/bin/env python3
"""Guardrail detection benchmark.

Measures, for the prompt-injection detector and the full input pipeline:

* detection rate per attack category and per evasion technique, and
* false-positive rate on a benign corpus that includes known traps
  ("abundant", "secret santa", "enable developer mode on Android", ...).

Usage:
    python3 benchmarks/run_benchmark.py                 # gate against thresholds
    python3 benchmarks/run_benchmark.py --seeds 20      # fuzz with 20 RNG seeds
    python3 benchmarks/run_benchmark.py --json out.json # machine-readable report
    python3 benchmarks/run_benchmark.py --show-misses   # list what got through

Exit status is 1 when any metric falls below benchmarks/thresholds.json, so
CI blocks detection regressions. Thresholds only ever ratchet upward.
"""

import argparse
import json
import os
import random
import sys
import tempfile
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from mutators import LATIN_ONLY, MUTATORS  # noqa: E402


def _load(name):
    with open(os.path.join(HERE, "corpus", name), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _is_latin(text):
    return all(ord(c) < 0x250 or not c.isalpha() for c in text)


def _detectors():
    from guardrail_prompt_injection import PromptInjectionDetector
    det = PromptInjectionDetector()
    out = {"prompt_injection": lambda t: not det.scan(t)[0]}
    if os.environ.get("BENCH_SKIP_ENGINE") != "1":
        # Isolate engine side effects (logs, personal config) in a temp dir.
        tmp = tempfile.mkdtemp(prefix="ag-bench-")
        os.environ.setdefault("GUARDRAIL_CONFIG_PATH", os.path.join(tmp, "config.json"))
        from guardrail import GuardrailEngine
        engine = GuardrailEngine()
        out["engine_input"] = lambda t: not engine.validate_input(t, "default")["safe"]
    return out


def run(seeds, show_misses=False):
    attacks = _load("attacks.jsonl")
    benign = _load("benign.jsonl")
    detectors = _detectors()
    report = {}
    for name, blocked in detectors.items():
        by_cat = defaultdict(lambda: [0, 0])
        by_mut = defaultdict(lambda: [0, 0])
        misses = []
        t0 = time.perf_counter()
        for seed in seeds:
            for i, item in enumerate(attacks):
                for mname, mut in MUTATORS.items():
                    if mname in LATIN_ONLY and not _is_latin(item["text"]):
                        continue
                    rng = random.Random(f"{seed}:{i}:{mname}")
                    text = mut(item["text"], rng)
                    hit = blocked(text)
                    by_cat[item["category"]][0] += hit
                    by_cat[item["category"]][1] += 1
                    by_mut[mname][0] += hit
                    by_mut[mname][1] += 1
                    if not hit:
                        misses.append((item["category"], mname, item["text"]))
        fps = [b["text"] for b in benign if blocked(b["text"])]
        elapsed = time.perf_counter() - t0
        total_hit = sum(v[0] for v in by_cat.values())
        total = sum(v[1] for v in by_cat.values())
        report[name] = {
            "detection_rate": round(total_hit / total, 4),
            "false_positive_rate": round(len(fps) / len(benign), 4),
            "by_category": {k: round(v[0] / v[1], 4) for k, v in sorted(by_cat.items())},
            "by_mutator": {k: round(v[0] / v[1], 4) for k, v in sorted(by_mut.items())},
            "false_positives": fps,
            "samples": total + len(benign),
            "seconds": round(elapsed, 2),
        }
        if show_misses:
            report[name]["misses"] = sorted(set(misses))
    return report


def gate(report, thresholds):
    failures = []
    for name, limits in thresholds.items():
        r = report.get(name)
        if r is None:
            continue
        if r["detection_rate"] < limits.get("min_detection_rate", 0):
            failures.append(f"{name}: detection {r['detection_rate']} < "
                            f"{limits['min_detection_rate']}")
        if r["false_positive_rate"] > limits.get("max_false_positive_rate", 1):
            failures.append(f"{name}: false positives {r['false_positive_rate']} > "
                            f"{limits['max_false_positive_rate']}")
        for cat, floor in limits.get("min_category", {}).items():
            if r["by_category"].get(cat, 0) < floor:
                failures.append(f"{name}: category {cat} {r['by_category'].get(cat)} < {floor}")
        for mut, floor in limits.get("min_mutator", {}).items():
            if r["by_mutator"].get(mut, 0) < floor:
                failures.append(f"{name}: mutator {mut} {r['by_mutator'].get(mut)} < {floor}")
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seeds", type=int, default=1, help="number of RNG seeds to fuzz with")
    ap.add_argument("--seed-offset", type=int, default=0)
    ap.add_argument("--json", help="write the full report to this path")
    ap.add_argument("--show-misses", action="store_true")
    ap.add_argument("--no-gate", action="store_true", help="report only, never fail")
    args = ap.parse_args()

    seeds = list(range(args.seed_offset, args.seed_offset + args.seeds))
    report = run(seeds, show_misses=args.show_misses)

    for name, r in report.items():
        print(f"\n== {name} ==  detection {r['detection_rate']:.1%}  "
              f"false-positive {r['false_positive_rate']:.1%}  "
              f"({r['samples']} samples, {r['seconds']}s)")
        print("  by category: " + ", ".join(f"{k} {v:.0%}" for k, v in r["by_category"].items()))
        print("  by evasion:  " + ", ".join(f"{k} {v:.0%}" for k, v in r["by_mutator"].items()))
        if r["false_positives"]:
            print("  false positives:")
            for t in r["false_positives"]:
                print(f"    - {t}")
        for cat, mut, text in r.get("misses", []):
            print(f"  MISS [{cat}/{mut}] {text}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

    if args.no_gate:
        return 0
    with open(os.path.join(HERE, "thresholds.json"), encoding="utf-8") as fh:
        thresholds = json.load(fh)
    failures = gate(report, thresholds)
    if failures:
        print("\nBENCHMARK GATE FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nBenchmark gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
