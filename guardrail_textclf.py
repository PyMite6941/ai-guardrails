#!/usr/bin/env python3
#=============================================================================
# Guardrail Text Classifier — learned prompt-injection / jailbreak scorer
#=============================================================================
# Rules match phrasing; attackers paraphrase. This module adds a learned
# layer that generalises over wording: logistic regression on hashed word
# 1-2-grams and character 3-5-grams of the *folded* text (the same
# homoglyph/leet/diacritic-normalised view the rules use), so character
# tricks do not change its features either.
#
# Stdlib only, no numpy: weights ship as a base64 float32 array in
# guardrail_textclf_model.json, trained by benchmarks/train_classifier.py on
# train splits only (test splits and the hand-written holdout are never
# seen). Scoring one input is a few thousand dict/array lookups.
#
# The classifier is one signal in the detector's risk score, not a verdict:
#   p >= threshold_high  -> "high" finding   (blocks on its own)
#   p >= threshold_med   -> "medium" finding (blocks with one more weak signal)
#   p >= threshold_low   -> "low" finding    (tips an already-suspicious input)
# Thresholds are chosen on TRAIN splits only (benchmarks/train_classifier.py
# grid: catch rate on attack train splits vs false positives on benign train
# sets, including the red-team wrappers the classifier itself learned).
#=============================================================================

import array
import base64
import json
import math
import os
import re
import zlib
from typing import Dict, Iterable, List, Optional, Tuple

from guardrail_normalize import fold, leet

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "guardrail_textclf_model.json")
N_FEATURES = 1 << 18
MAX_CHARS = 4000            # long inputs: score head and tail windows
_WORD = re.compile(r"[a-z0-9']+|[^\sa-z0-9]")


def _h(s: str) -> int:
    return zlib.crc32(s.encode("utf-8")) & (N_FEATURES - 1)


def features(text: str) -> Dict[int, float]:
    """Hashed, L2-normalised n-gram features of the folded text."""
    view = leet(fold(text[:MAX_CHARS] if len(text) <= MAX_CHARS
                     else text[:MAX_CHARS // 2] + " " + text[-MAX_CHARS // 2:]))
    feats: Dict[int, float] = {}
    toks = _WORD.findall(view)
    words = [t for t in toks if t[0].isalnum()]
    for i, w in enumerate(words):
        k = _h("w:" + w)
        feats[k] = feats.get(k, 0.0) + 1.0
        if i:
            k = _h("b:" + words[i - 1] + " " + w)
            feats[k] = feats.get(k, 0.0) + 1.0
    squashed = " ".join(words)
    for n in (3, 4, 5):
        for i in range(len(squashed) - n + 1):
            k = _h("c%d:%s" % (n, squashed[i:i + n]))
            feats[k] = feats.get(k, 0.0) + 0.5
    norm = math.sqrt(sum(v * v for v in feats.values())) or 1.0
    return {k: v / norm for k, v in feats.items()}


class TextClassifier:
    def __init__(self, weights: array.array, bias: float, meta: Dict):
        self.w = weights
        self.b = bias
        self.meta = meta
        self.threshold_high = float(meta.get("threshold_high", 0.97))
        self.threshold_med = float(meta.get("threshold_med", 0.85))
        self.threshold_low = float(meta.get("threshold_low", 0.75))

    def prob(self, text: str) -> float:
        if not text or not text.strip():
            return 0.0
        z = self.b + sum(self.w[k] * v for k, v in features(text).items())
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    # ── persistence ────────────────────────────────────────────────────
    def save(self, path: str = MODEL_PATH) -> None:
        blob = base64.b64encode(zlib.compress(self.w.tobytes(), 9)).decode("ascii")
        with open(path + ".tmp", "w") as fh:
            json.dump({"format": "hashed-logreg-v1", "n_features": N_FEATURES, "bias": self.b,
                       "weights_zlib_b64": blob, "meta": self.meta}, fh)
        os.replace(path + ".tmp", path)

    @classmethod
    def load(cls, path: str = MODEL_PATH) -> "TextClassifier":
        with open(path) as fh:
            d = json.load(fh)
        if d.get("format") != "hashed-logreg-v1" or d.get("n_features") != N_FEATURES:
            raise ValueError("incompatible classifier model file")
        w = array.array("f")
        w.frombytes(zlib.decompress(base64.b64decode(d["weights_zlib_b64"])))
        if len(w) != N_FEATURES:
            raise ValueError("corrupt classifier weights")
        return cls(w, float(d["bias"]), d.get("meta", {}))


def train(samples: Iterable[Tuple[str, int]], epochs: int = 6, lr: float = 0.5,
          l2: float = 1e-6, seed: int = 0, pos_weight: Optional[float] = None) -> TextClassifier:
    """Plain SGD logistic regression with a decaying learning rate."""
    import random
    data = [(features(t), y) for t, y in samples if t]
    rng = random.Random(seed)
    n_pos = sum(y for _, y in data) or 1
    n_neg = (len(data) - n_pos) or 1
    pw = pos_weight if pos_weight is not None else n_neg / n_pos
    w = array.array("f", bytes(4 * N_FEATURES))
    b = 0.0
    step = 0
    for _ in range(epochs):
        rng.shuffle(data)
        for x, y in data:
            step += 1
            eta = lr / (1.0 + step * 1e-5)
            z = b + sum(w[k] * v for k, v in x.items())
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            g = (p - y) * (pw if y else 1.0)
            for k, v in x.items():
                w[k] -= eta * (g * v + l2 * w[k])
            b -= eta * g
    return TextClassifier(w, b, {})


_MODEL: Optional[TextClassifier] = None
_LOAD_FAILED = False


def get_model() -> Optional[TextClassifier]:
    """The shipped model, or None if absent (the rules still run)."""
    global _MODEL, _LOAD_FAILED
    if _MODEL is None and not _LOAD_FAILED:
        try:
            _MODEL = TextClassifier.load()
        except (OSError, ValueError, KeyError):
            _LOAD_FAILED = True
    return _MODEL


def score(text: str) -> Optional[float]:
    m = get_model()
    return m.prob(text) if m else None


__all__ = ["TextClassifier", "features", "train", "get_model", "score", "MODEL_PATH"]
