#!/usr/bin/env python3
#=============================================================================
# guardrail_token_compressor.py — Token usage compression for cost savings
#=============================================================================
# Compresses text before sending to external models to reduce token usage
# and save on API costs. Uses multiple strategies:
#
#   1. Whitespace normalization — collapse repeated spaces/newlines
#   2. Stopword removal — remove low-value words when compression is high
#   3. Abbreviation — replace common phrases with shorter forms
#   4. Truncation — cap text length with ellipsis
#
# All stdlib-only — no external dependencies.
#=============================================================================

import re
from typing import Optional, Dict, Any, List, Tuple

# ── Compression levels ─────────────────────────────────────────────────────
# "none"   — no compression, pass through as-is
# "light"  — whitespace normalization only
# "medium" — whitespace + common abbreviation
# "high"   — whitespace + abbreviation + stopword removal
# "aggressive" — medium + aggressive truncation

COMPRESSION_LEVELS = {
    "none": 0,
    "light": 1,
    "medium": 2,
    "high": 3,
    "aggressive": 4,
}

DEFAULT_COMPRESSION_LEVEL = "light"

# ── Common phrase abbreviations ────────────────────────────────────────────
# Replaces longer phrases with shorter equivalents to save tokens.
ABBREVIATIONS: List[Tuple[str, str]] = [
    (r"\bartificial intelligence\b", "AI"),
    (r"\bmachine learning\b", "ML"),
    (r"\blarge language model\b", "LLM"),
    (r"\bnatural language processing\b", "NLP"),
    (r"\bapplication programming interface\b", "API"),
    (r"\bvirtual private network\b", "VPN"),
    (r"\bhypertext transfer protocol\b", "HTTP"),
    (r"\btransmission control protocol\b", "TCP"),
    (r"\binternet protocol\b", "IP"),
    (r"\bdomain name system\b", "DNS"),
    (r"\bsecure shell\b", "SSH"),
    (r"\bvirtual machine\b", "VM"),
    (r"\bcontainer\b", "ctr"),
    (r"\bkubernetes\b", "k8s"),
    (r"\bdocker\b", "dckr"),
    (r"\bapproximately\b", "approx."),
    (r"\binformation\b", "info"),
    (r"\bexample\b", "e.g."),
    (r"\bthat is\b", "i.e."),
    (r"\bversus\b", "vs."),
    (r"\bnumber\b", "no."),
    (r"\bplease\b", "pls"),
    (r"\bthank you\b", "ty"),
]

_COMPILED_ABBREVIATIONS = [
    (re.compile(pattern, re.IGNORECASE), replacement)
    for pattern, replacement in ABBREVIATIONS
]

# ── Stopwords for high/aggressive compression ──────────────────────────────
STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "as", "is", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "must", "shall", "can", "need",
    "this", "that", "these", "those", "here", "there", "where", "when",
    "why", "how", "what", "who", "whom", "which", "whose", "not", "no",
    "yes", "so", "just", "only", "even", "still", "then", "now", "also",
    "very", "quite", "rather", "some", "any", "all", "most", "many",
    "much", "more", "most", "least", "less", "few", "several", "own",
    "same", "other", "another", "such", "than", "too", "own", "same",
}


def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 characters per token for English text.

    This is a conservative approximation (OpenAI's rule of thumb).
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


def compress_text(
    text: str,
    level: str = DEFAULT_COMPRESSION_LEVEL,
    max_length: Optional[int] = None,
    preserve_newlines: bool = True,
) -> str:
    """Compress text to reduce token usage.

    Args:
        text: The text to compress.
        level: Compression level ("none", "light", "medium", "high", "aggressive").
        max_length: If set, truncate text to this many characters (with ellipsis).
        preserve_newlines: If True, keep paragraph breaks; otherwise collapse all whitespace.

    Returns:
        Compressed text.
    """
    if not text:
        return text

    level_int = COMPRESSION_LEVELS.get(level, COMPRESSION_LEVELS["light"])
    if level_int == 0:
        result = text
    else:
        result = text

        # ── Light: whitespace normalization ────────────────────────────
        if level_int >= 1:
            if preserve_newlines:
                # Collapse multiple spaces/tabs within lines
                result = re.sub(r"[ \t]+", " ", result)
                # Collapse 3+ newlines to 2
                result = re.sub(r"\n{3,}", "\n\n", result)
                # Trim trailing whitespace on each line
                result = re.sub(r"[ \t]+\n", "\n", result)
            else:
                result = re.sub(r"\s+", " ", result)
            result = result.strip()

        # ── Medium: abbreviations ──────────────────────────────────────
        if level_int >= 2:
            for pattern, replacement in _COMPILED_ABBREVIATIONS:
                result = pattern.sub(replacement, result)

        # ── High: stopword removal ─────────────────────────────────────
        if level_int >= 3:
            words = result.split()
            filtered = [
                w for w in words
                if w.lower().strip(".,!?;:\"'()[]{}") not in STOPWORDS
                or len(w) <= 2  # keep short words like "a", "I"
            ]
            result = " ".join(filtered)

        # ── Aggressive: further truncation ─────────────────────────────
        if level_int >= 4:
            # Remove vowels from words longer than 6 chars (aggressive)
            def _disemvowel(word: str) -> str:
                if len(word) > 6:
                    return re.sub(r"[aeiouAEIOU]", "", word)
                return word
            result = " ".join(_disemvowel(w) for w in result.split())

    # ── Max length truncation ──────────────────────────────────────────
    if max_length is not None and len(result) > max_length:
        result = result[:max_length].rstrip() + "…[truncated]"

    return result


def compress_for_model(
    text: str,
    compression_level: str = DEFAULT_COMPRESSION_LEVEL,
    max_tokens: Optional[int] = None,
) -> Dict[str, Any]:
    """Compress text specifically for sending to an LLM model.

    Returns a dict with:
        - compressed: the compressed text
        - original_tokens: estimated token count of original
        - compressed_tokens: estimated token count after compression
        - tokens_saved: difference
        - savings_percent: percentage saved
        - compression_level: level used
    """
    if not text:
        return {
            "compressed": "",
            "original_tokens": 0,
            "compressed_tokens": 0,
            "tokens_saved": 0,
            "savings_percent": 0.0,
            "compression_level": compression_level,
        }

    original_tokens = estimate_tokens(text)

    # Determine max_length from max_tokens (4 chars per token)
    max_length = None
    if max_tokens is not None:
        max_length = max_tokens * 4

    compressed = compress_text(
        text,
        level=compression_level,
        max_length=max_length,
    )

    compressed_tokens = estimate_tokens(compressed)
    tokens_saved = max(0, original_tokens - compressed_tokens)
    savings_percent = (tokens_saved / original_tokens * 100) if original_tokens > 0 else 0.0

    return {
        "compressed": compressed,
        "original_tokens": original_tokens,
        "compressed_tokens": compressed_tokens,
        "tokens_saved": tokens_saved,
        "savings_percent": round(savings_percent, 1),
        "compression_level": compression_level,
    }


if __name__ == "__main__":
    import sys
    sample = sys.stdin.read() if not sys.stdin.isatty() else ""
    if sample:
        result = compress_for_model(sample, level="medium")
        print(f"Original tokens: {result['original_tokens']}")
        print(f"Compressed tokens: {result['compressed_tokens']}")
        print(f"Tokens saved: {result['tokens_saved']} ({result['savings_percent']}%)")
        print(f"\n--- Compressed ---\n{result['compressed']}")
    else:
        print("Usage: echo 'text' | python3 guardrail_token_compressor.py")
