#!/usr/bin/env python3
"""Evaluate the detector on public, independently labelled datasets.

The in-repo corpus (benchmarks/corpus) was written alongside the rules, so
its numbers are optimistic. These datasets were labelled by other people for
other purposes, which makes them a holdout: rules must never be tuned to
individual rows here, only to the *classes* of miss they reveal.

    python3 benchmarks/external_eval.py                     # holdout (test) numbers
    python3 benchmarks/external_eval.py --split train --show-misses 20

Hygiene: look at misses on the train split only, fix the *class* of miss,
then check that the test split moved too. The test split is never read row
by row; that keeps it an honest estimate of unseen-data performance.

Data is fetched from the Hugging Face datasets-server API on first use and
cached under benchmarks/external/ (git-ignored; each dataset keeps its own
licence). Report-only: label noise in these sets makes a hard gate unfair,
so the weekly research workflow publishes the numbers instead.
"""
import argparse
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from guardrail_net import urlopen_http  # noqa: E402
from guardrail_prompt_injection import PromptInjectionDetector  # noqa: E402

API = "https://datasets-server.huggingface.co/rows"
CACHE = os.path.join(HERE, "external")

# name -> (hf dataset, splits, text field, function(row) -> is_attack)
DATASETS = {
    "deepset": ("deepset/prompt-injections", ["train", "test"], "text",
                lambda r: int(r["label"]) == 1),
    "jackhhao": ("jackhhao/jailbreak-classification", ["train", "test"], "prompt",
                 lambda r: r["type"] == "jailbreak"),
    # Benign only: real human-written instructions, the false-positive check.
    "dolly": ("databricks/databricks-dolly-15k", ["train"], "instruction",
              lambda r: False),
    # Real people attacking Lakera's Gandalf game to make it leak a password:
    # adaptive human override / extraction attempts. All rows are attacks.
    "gandalf": ("Lakera/gandalf_ignore_instructions", ["train", "validation", "test"], "text",
                lambda r: True),
    # Injections hidden inside text the model was asked to summarize (indirect).
    "gandalf_summ": ("Lakera/gandalf_summarization", ["train", "validation", "test"], "text",
                     lambda r: True),
    # Jailbreaks collected in the wild (Discord, Reddit, websites; Shen et al., CCS 2024).
    "wild_jailbreak": ("TrustAIRLab/in-the-wild-jailbreak-prompts@jailbreak_2023_12_25",
                       ["train"], "prompt", lambda r: True),
    # Ordinary prompts from the same communities: the hardest realistic FP test
    # (persona and prompt-engineering requests that are not jailbreaks).
    "wild_regular": ("TrustAIRLab/in-the-wild-jailbreak-prompts@regular_2023_12_25",
                     ["train"], "prompt", lambda r: False),
}
MAX_ROWS = {"dolly": 2000, "wild_regular": 3000}
# Datasets with a single split: alternate rows into pseudo train/test halves.
PSEUDO_SPLIT = {"dolly", "wild_jailbreak", "wild_regular"}
NOTES = {
    "deepset": "Apache-2.0. Labels are broad: role-play requests and some plain tasks "
               "('Generate SQL code') are labelled injection; ~half the rows are German.",
    "jackhhao": "Apache-2.0. Jailbreak vs benign prompts, many long role-play jailbreaks.",
    "dolly": "CC-BY-SA-3.0. First 2000 human-written instructions; all benign (FPR only).",
    "gandalf": "MIT. Real human attempts to make Gandalf ignore instructions / leak a password.",
    "gandalf_summ": "MIT. Injections embedded in text given to a summarizer (indirect).",
    "wild_jailbreak": "MIT. In-the-wild jailbreak prompts (Shen et al., CCS 2024).",
    "wild_regular": "MIT. First 3000 regular prompts from the same communities (FPR only).",
}


def fetch(dataset, split, max_rows=None):
    rows, offset = [], 0
    dataset, _, config = dataset.partition("@")
    while True:
        q = urllib.parse.urlencode({"dataset": dataset, "config": config or "default", "split": split,
                                    "offset": offset, "length": 100})
        for attempt in range(6):
            try:
                with urlopen_http(f"{API}?{q}", timeout=60) as resp:
                    page = json.loads(resp.read())
                break
            except Exception:
                if attempt == 5:
                    raise
                time.sleep(2 ** attempt)
        batch = [r["row"] for r in page.get("rows", [])]
        rows += batch
        offset += len(batch)
        if not batch or offset >= page.get("num_rows_total", 0) or \
                (max_rows and offset >= max_rows):
            return rows[:max_rows] if max_rows else rows


def load(name):
    dataset, splits, field, is_attack = DATASETS[name]
    path = os.path.join(CACHE, f"{name}.jsonl")
    if not os.path.exists(path):
        os.makedirs(CACHE, exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            for split in splits:
                for i, r in enumerate(fetch(dataset, split, MAX_ROWS.get(name))):
                    tag = ("train", "test")[i % 2] if name in PSEUDO_SPLIT else split
                    fh.write(json.dumps({"text": r[field], "attack": bool(is_attack(r)),
                                         "split": tag}) + "\n")
        os.replace(path + ".tmp", path)
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def evaluate(name, det, show, split):
    rows = [r for r in load(name) if split == "all" or r["split"] == split]
    tp = fn = fp = tn = 0
    misses, false_alarms = [], []
    t0 = time.perf_counter()
    for r in rows:
        flagged = not det.scan(r["text"])[0]
        if r["attack"]:
            tp += flagged
            fn += not flagged
            if not flagged:
                misses.append(r["text"])
        else:
            fp += flagged
            tn += not flagged
            if flagged:
                false_alarms.append((det.scan(r["text"])[2], r["text"]))
    dt = time.perf_counter() - t0
    res = {"dataset": DATASETS[name][0], "rows": len(rows), "attacks": tp + fn,
           "benign": fp + tn, "tpr": tp / max(tp + fn, 1), "fpr": fp / max(fp + tn, 1),
           "precision": tp / max(tp + fp, 1), "seconds": round(dt, 2), "note": NOTES[name]}
    res["split"] = split
    print(f"== {name} [{split}] ({res['dataset']}) ==  rows {res['rows']}  "
          f"TPR {res['tpr']:.1%}  FPR {res['fpr']:.1%}  precision {res['precision']:.1%}  "
          f"({dt:.1f}s)")
    print(f"   {NOTES[name]}")
    if false_alarms and name == "wild_regular":
        # Transparency: how many false alarms are explicit override boilerplate
        # ("ignore all previous instructions ..."), which this detector flags by
        # design because, for an injection guardrail, that is an override.
        explicit = sum(1 for rid, _ in false_alarms if rid and rid.startswith("override."))
        rest = len(false_alarms) - explicit
        res["fpr_excluding_explicit_override"] = rest / max(fp + tn - explicit, 1)
        print(f"   of {len(false_alarms)} false alarms, {explicit} are explicit instruction "
              f"overrides; FPR on the rest {res['fpr_excluding_explicit_override']:.1%}")
    if split == "test" and show:
        print("   (misses are not shown for the test split: it is the holdout)")
        show = 0
    for rid, text in false_alarms[:show]:
        print(f"   FALSE ALARM [{rid}] {' '.join(text.split())[:140]}")
    for text in misses[:show]:
        print(f"   MISS {' '.join(text.split())[:140]}")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("datasets", nargs="*", default=list(DATASETS))
    ap.add_argument("--json")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 if a test-split result is below thresholds.json 'external'")
    ap.add_argument("--show-misses", type=int, default=0)
    ap.add_argument("--split", choices=["train", "test", "all"], default="test",
                    help="test (default) is the holdout; study misses on train only")
    args = ap.parse_args()
    det = PromptInjectionDetector()
    results = [evaluate(n, det, args.show_misses, args.split) for n in args.datasets]
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
    if not args.gate:
        return 0
    with open(os.path.join(HERE, "thresholds.json")) as fh:
        floors = json.load(fh).get("external", {})
    failed = []
    for name, res in zip(args.datasets, results):
        f = floors.get(name, {})
        if res["split"] == "test" and res["tpr"] < f.get("min_tpr", 0) and res["attacks"]:
            failed.append(f"{name}: TPR {res['tpr']:.1%} < {f['min_tpr']:.0%}")
        if res["split"] == "test" and res["fpr"] > f.get("max_fpr", 1):
            failed.append(f"{name}: FPR {res['fpr']:.1%} > {f['max_fpr']:.1%}")
        excl = res.get("fpr_excluding_explicit_override")
        if res["split"] == "test" and excl is not None and excl > f.get("max_fpr_excl_override", 1):
            failed.append(f"{name}: FPR excluding explicit overrides {excl:.1%} > "
                          f"{f['max_fpr_excl_override']:.1%}")
    for line in failed:
        print("GATE FAIL", line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
