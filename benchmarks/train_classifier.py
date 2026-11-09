#!/usr/bin/env python3
"""Train guardrail_textclf_model.json from TRAIN data only.

    python3 benchmarks/train_classifier.py            # train, calibrate, save
    python3 benchmarks/train_classifier.py --dry-run  # report only

Never used for training (they are the evaluation): every dataset's test
split / pseudo-test half, benchmarks/corpus/handwritten_holdout.jsonl, and
red-team seeds below 1000 (CI gates on seed 1).

Calibration: 15% of the benign training rows are held out of training and
used only to pick the two thresholds, so they are not tuned on rows the
model has memorised:
  threshold_high = the score exceeded by at most TARGET_FPR_HIGH of them
  threshold_med  = the score exceeded by at most TARGET_FPR_MED of them
"""
import argparse
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import external_eval  # noqa: E402
import redteam  # noqa: E402
from mutators import LATIN_ONLY, MUTATORS  # noqa: E402
from guardrail_textclf import TextClassifier, train  # noqa: E402

TARGET_FPR_HIGH = 0.002
TARGET_FPR_MED = 0.01
TRAIN_SEEDS = range(1000, 1004)
EXTERNAL = ["deepset", "jackhhao", "dolly", "gandalf", "gandalf_summ", "wild_jailbreak",
            "wild_regular"]


def _jsonl(name):
    path = os.path.join(HERE, "corpus", name)
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def assemble(rng):
    pos, neg, sources = [], [], {}

    def add(label, texts, src):
        (pos if label else neg).extend(texts)
        sources[src] = sources.get(src, 0) + len(texts)

    for name in EXTERNAL:
        rows = [r for r in external_eval.load(name) if r["split"] != "test"]
        add(1, [r["text"] for r in rows if r["attack"]], f"{name}:attack")
        add(0, [r["text"] for r in rows if not r["attack"]], f"{name}:benign")

    seeds = _jsonl("attacks.jsonl")
    add(1, [s["text"] for s in seeds], "corpus:attacks")
    mutated = []
    for seed in TRAIN_SEEDS:
        r = random.Random(seed)
        for s in seeds:
            for mname, fn in MUTATORS.items():
                if mname in LATIN_ONLY and not s["text"].isascii():
                    continue
                if r.random() < 0.35:
                    mutated.append(fn(s["text"], r))
    add(1, mutated, "corpus:attacks:mutated")
    add(0, [r["text"] for r in _jsonl("benign.jsonl") + _jsonl("benign_hard.jsonl")],
        "corpus:benign")
    add(1, [r["text"] for r in _jsonl("handwritten_dev.jsonl")], "handwritten_dev")
    for seed in TRAIN_SEEDS:
        attacks, benign = redteam.generate(1500, seed)
        add(1, [a["text"] for a in attacks], "redteam:attacks")
        add(0, [b["text"] for b in benign], "redteam:benign_wrappers")
    return pos, neg, sources


def quantile_threshold(scores, fpr):
    scores = sorted(scores, reverse=True)
    k = int(len(scores) * fpr)
    return min(0.999, max(0.5, scores[k] + 1e-6 if k < len(scores) else 0.5))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    rng = random.Random(7)
    pos, neg, sources = assemble(rng)
    rng.shuffle(neg)
    n_cal = int(len(neg) * 0.15)
    calib, neg_train = neg[:n_cal], neg[n_cal:]
    print(f"positives {len(pos)}, negatives {len(neg_train)} (+{len(calib)} calibration)")
    for k, v in sorted(sources.items()):
        print(f"  {k:30s} {v}")
    t0 = time.perf_counter()
    model = train([(t, 1) for t in pos] + [(t, 0) for t in neg_train], epochs=args.epochs)
    print(f"trained in {time.perf_counter() - t0:.0f}s")
    cal_scores = [model.prob(t) for t in calib]
    t_high = quantile_threshold(cal_scores, TARGET_FPR_HIGH)
    t_med = min(t_high, quantile_threshold(cal_scores, TARGET_FPR_MED))
    train_pos = [model.prob(t) for t in pos[:3000]]
    print(f"threshold_high {t_high:.4f}  threshold_med {t_med:.4f}")
    print(f"train recall at high {sum(p >= t_high for p in train_pos) / len(train_pos):.1%}, "
          f"at med {sum(p >= t_med for p in train_pos) / len(train_pos):.1%}")
    model.meta = {"threshold_high": round(t_high, 6), "threshold_med": round(t_med, 6),
                  "target_fpr_high": TARGET_FPR_HIGH, "target_fpr_med": TARGET_FPR_MED,
                  "trained_on": sources, "epochs": args.epochs,
                  "trained": time.strftime("%Y-%m-%d"),
                  "never_trained_on": ["test splits / pseudo-test halves of every external "
                                       "dataset", "corpus/handwritten_holdout.jsonl",
                                       "red-team seeds < 1000"]}
    if not args.dry_run:
        model.save()
        print("saved guardrail_textclf_model.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
