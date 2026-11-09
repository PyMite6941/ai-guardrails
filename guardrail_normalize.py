#!/usr/bin/env python3
#=============================================================================
# Guardrail Normalize — evasion-resistant text views for detection
#=============================================================================
# Every detector in this project matches against text. Attackers therefore
# attack the *text*, not the detector. Hackett et al., "Bypassing Prompt
# Injection and Jailbreak Detection in LLM Guardrails" (arXiv:2504.11168,
# 2025) fully evaded six commercial guardrails with character injection
# alone: homoglyphs, zero-width insertion, Unicode tag smuggling and emoji
# variation-selector smuggling. NFKC normalization defeats none of these.
#
# This module turns one input into several *detection views*:
#
#   canonical  invisible/format characters removed, NFKC, whitespace
#              collapsed. Safe to forward to the model.
#   folded     canonical + lowercase + diacritics stripped + homoglyphs
#              (Cyrillic/Greek/Armenian/etc. look-alikes) mapped to Latin.
#   leet       folded + leetspeak digits/symbols mapped to letters.
#   squashed   leet with every non-alphanumeric removed, which defeats
#              "i g n o r e", "ig.no-re" and similar separator insertion.
#   smuggled   payloads *hidden* in Unicode tag characters or variation
#              selectors, decoded back to text. Stripping these silently
#              would hide the attack; decoding it lets detectors see it.
#
# Detectors scan every view. Only `canonical` is ever forwarded downstream.
# Everything here is stdlib-only, linear time, and bounded in size.
#=============================================================================

import re
from functools import lru_cache
import unicodedata
from typing import Dict, List

# Upper bound on how much text we build views for. Inputs longer than this
# are still scanned, just truncated for the derived views (the engine's
# length check rejects oversize input separately).
MAX_VIEW_CHARS = 200_000

# ── Invisible / smuggling code points ────────────────────────────────────
TAG_START, TAG_END = 0xE0000, 0xE007F            # Unicode tag block
VS_BASIC = (0xFE00, 0xFE0F)                       # VS1-VS16
VS_SUPPLEMENT = (0xE0100, 0xE01EF)                # VS17-VS256
ZWJ = 0x200D

# Code points that are not category Cf but are still invisible/blank and
# used to split keywords.
EXTRA_INVISIBLE = {
    0x115F, 0x1160, 0x3164, 0xFFA0,  # Hangul fillers
    0x034F,                          # combining grapheme joiner
    0x180B, 0x180C, 0x180D, 0x180E, 0x180F,  # Mongolian FVS / vowel sep
    0x2800,                          # braille blank
}


def _is_variation_selector(cp: int) -> bool:
    return VS_BASIC[0] <= cp <= VS_BASIC[1] or VS_SUPPLEMENT[0] <= cp <= VS_SUPPLEMENT[1]


def _is_pictographic(cp: int) -> bool:
    """Rough Extended_Pictographic test, enough to keep emoji ZWJ sequences."""
    return (0x1F000 <= cp <= 0x1FAFF) or (0x2600 <= cp <= 0x27BF) or (0x2B00 <= cp <= 0x2BFF)


def _is_invisible(cp: int) -> bool:
    if cp in EXTRA_INVISIBLE:
        return True
    if _is_variation_selector(cp):
        return True
    cat = unicodedata.category(chr(cp))
    # Cf = format (ZW space/joiners, bidi controls, tags, soft hyphen, ...)
    # Co = private use, Cs = surrogates, Cn = unassigned
    return cat in ("Cf", "Co", "Cs", "Cn")


@lru_cache(maxsize=8192)
def _invisible_char(ch: str) -> bool:
    cp = ord(ch)
    return cp == ZWJ or cp in (0xFE0E, 0xFE0F) or _is_invisible(cp)


def strip_invisible(text: str) -> str:
    """Remove invisible/format/smuggling characters.

    Keeps a ZWJ (U+200D) only when it joins two pictographs, and keeps
    VS15/VS16 (U+FE0E/U+FE0F) only directly after a pictograph, so ordinary
    emoji sequences survive. Everything else in Cf/Co/Cs/Cn is removed.
    """
    if text.isascii():
        return text  # ASCII contains no Cf/Co/Cs/Cn or variation selectors
    # Fast path: decide per *distinct* character (cached), not per position.
    # Typical non-ASCII text (curly quotes, accents, emoji) has no invisible
    # characters at all and returns unchanged without a Python-level loop.
    if not any(_invisible_char(c) for c in set(text)):
        return text
    out: List[str] = []
    n = len(text)
    for i, ch in enumerate(text):
        cp = ord(ch)
        if ch in "\t\n\r":
            out.append(ch)
            continue
        if cp == ZWJ:
            prev_ok = bool(out) and _is_pictographic(ord(out[-1][-1]))
            next_ok = i + 1 < n and _is_pictographic(ord(text[i + 1]))
            if prev_ok and next_ok:
                out.append(ch)
            continue
        if cp in (0xFE0E, 0xFE0F) and out and _is_pictographic(ord(out[-1][-1])):
            out.append(ch)
            continue
        if _is_invisible(cp):
            continue
        out.append(ch)
    return "".join(out)


def decode_smuggled(text: str) -> str:
    """Decode payloads hidden in tag characters or variation selectors.

    * Tag smuggling: U+E0020..U+E007E mirror printable ASCII 0x20..0x7E.
    * Emoji / variation-selector smuggling: each byte 0..255 is encoded as
      one variation selector (VS1-16 = 0..15, VS17-256 = 16..255) and the
      run of selectors is attached to an innocuous carrier character.

    Returns the decoded hidden text (possibly empty). Runs separated by
    visible text are joined with spaces.
    """
    if text.isascii():
        return ""
    tag_runs: List[str] = []
    vs_runs: List[bytearray] = []
    cur_tag: List[str] = []
    cur_vs = bytearray()
    prev_visible = ""
    flag_run = False
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            # Emoji subdivision flags (England, Scotland, Wales) are a black
            # flag U+1F3F4 + up to 6 lowercase/digit tags + CANCEL TAG.
            if not cur_tag and prev_visible == "\U0001F3F4":
                flag_run = True
            cur_tag.append(chr(cp - 0xE0000))
            continue
        if cp == 0xE007F and flag_run and len(cur_tag) <= 6 and \
                all(c.islower() or c.isdigit() for c in cur_tag):
            cur_tag = []
            flag_run = False
            continue
        flag_run = False
        if VS_BASIC[0] <= cp <= VS_BASIC[1]:
            cur_vs.append(cp - VS_BASIC[0])
            continue
        if VS_SUPPLEMENT[0] <= cp <= VS_SUPPLEMENT[1]:
            cur_vs.append(cp - VS_SUPPLEMENT[0] + 16)
            continue
        if cur_tag:
            tag_runs.append("".join(cur_tag))
            cur_tag = []
        if cur_vs:
            vs_runs.append(cur_vs)
            cur_vs = bytearray()
        if not _is_invisible(cp):
            prev_visible = ch
    if cur_tag:
        tag_runs.append("".join(cur_tag))
    if cur_vs:
        vs_runs.append(cur_vs)

    decoded: List[str] = list(tag_runs)
    for run in vs_runs:
        # A single VS16 after an emoji is normal presentation, not a payload.
        if len(run) < 2:
            continue
        decoded.append(run.decode("utf-8", errors="ignore"))
    return " ".join(s for s in decoded if s.strip())


# ── Homoglyph / confusable folding ───────────────────────────────────────
# Focused subset of Unicode TR39 confusables: the look-alikes actually used
# against English-language guardrails. NFKC already handles fullwidth and
# mathematical alphanumerics, so those are not listed here.
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h",
    "і": "i", "ї": "i", "ј": "j", "к": "k", "ӏ": "l", "м": "m", "н": "h",
    "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t", "у": "y",
    "х": "x", "ѡ": "w", "ԝ": "w", "ь": "b", "п": "n", "и": "u", "л": "n",
    # Greek
    "α": "a", "β": "b", "ϲ": "c", "δ": "d", "ε": "e", "η": "n", "ι": "i",
    "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ω": "w", "γ": "y", "μ": "u", "ϳ": "j",
    # Armenian / Cherokee / misc Latin look-alikes
    "օ": "o", "ս": "u", "ց": "g", "հ": "h", "ո": "n", "ա": "w",
    "ɑ": "a", "ɡ": "g", "ı": "i", "ɩ": "i", "ʟ": "l", "ɴ": "n", "ʀ": "r",
    "ꞁ": "l", "ꮃ": "w", "ꭰ": "d",
    # Punctuation look-alikes that hide separators
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "―": "-", "−": "-",
    "‘": "'", "’": "'", "‚": "'", "“": '"', "”": '"', "„": '"',
    "․": ".", "‧": ".", "∙": ".", "·": ".",
    "ⅰ": "i", "ⅼ": "l",
}


def _letterlike_from_names() -> Dict[str, str]:
    """Letters that NFKC leaves alone but that read as a Latin letter.

    Generated from Unicode names so whole families are covered, not a
    hand-picked few: small capitals (ɪɢɴᴏʀᴇ, the "small caps" font trick),
    turned/reversed/script/dotless forms (upside-down text), and the
    regional-indicator letters 🇦-🇿 (text written as "flags").
    """
    out: Dict[str, str] = {}
    pattern = re.compile(r"^LATIN (?:SMALL |CAPITAL )?LETTER (?:SMALL CAPITAL |TURNED |REVERSED |"
                         r"SCRIPT |DOTLESS |CLOSED |OPEN |SIDEWAYS |INVERTED |BARRED |STROKE )*([A-Z])$")
    for start, end in ((0x0180, 0x0250), (0x0250, 0x02B0), (0x1D00, 0x1D80), (0xA720, 0xA800),
                       (0x1DF00, 0x1E000)):
        for cp in range(start, end):
            m = pattern.match(unicodedata.name(chr(cp), ""))
            if m:
                out[chr(cp)] = m.group(1).lower()
    for i in range(26):
        out[chr(0x1F1E6 + i)] = chr(97 + i)  # regional indicators
    return out


for _ch, _latin in _letterlike_from_names().items():
    _CONFUSABLES.setdefault(_ch, _latin)
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# Upside-down text ("ǝɹouƃᴉ"): reversed order and turned letters, where some
# turned letters are ordinary ASCII (u = n, p = d, q = b). Only decoded when
# the text clearly is upside-down, so ordinary "up" never becomes "dn".
_UPSIDE = {"ɐ": "a", "q": "b", "ɔ": "c", "p": "d", "ǝ": "e", "ɟ": "f", "ƃ": "g", "ɥ": "h",
           "ᴉ": "i", "ı": "i", "ɾ": "j", "ʞ": "k", "ɯ": "m", "u": "n", "d": "p", "b": "q",
           "ɹ": "r", "ʇ": "t", "n": "u", "ʌ": "v", "ʍ": "w", "ʎ": "y", "˙": ".", "¿": "?",
           "¡": "!", "'": ",", ",": "'"}
_UPSIDE_TABLE = str.maketrans(_UPSIDE)
_UPSIDE_MARKERS = frozenset("ɐɔǝɟƃɥᴉɾʞɯɹʇʌʍʎ")


def upside_down(text: str) -> str:
    """Decode upside-down text; "" unless >= 3 turned letters are present."""
    if not text or text.isascii() or sum(c in _UPSIDE_MARKERS for c in text) < 3:
        return ""
    return text[::-1].translate(_UPSIDE_TABLE)

_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "9": "g", "@": "a", "$": "s", "!": "i", "|": "l", "€": "e", "£": "l",
    "+": "t",
})
# Leet folding for views where shell/markdown syntax must survive.
_LEET_SYNTAX_SAFE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "€": "e", "£": "l",
})


def _strip_marks(text: str) -> str:
    """Remove combining marks (ïgnörè -> ignore, Zalgo text -> plain).

    Recomposes with NFC afterwards so scripts that decompose into
    non-combining parts (Korean Hangul -> jamo) come back intact.
    """
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return unicodedata.normalize("NFC", stripped)


def _collapse_ws(text: str) -> str:
    return " ".join(text.split())


# Letter forms whose NFKC decomposition inserts punctuation: parenthesized
# "⒜" -> "(a)" would turn every letter into its own bracketed token. Map them
# to the bare letter before NFKC (the meaning is unchanged).
_PRE_NFKC = str.maketrans({chr(0x249C + i): chr(97 + i) for i in range(26)})


def canonicalize(text: str) -> str:
    """Model-safe canonical form: invisibles stripped, NFKC, spaces collapsed."""
    if not text:
        return text or ""
    text = strip_invisible(text).translate(_PRE_NFKC)
    text = unicodedata.normalize("NFKC", text)
    return _collapse_ws(text)




def fold(text: str) -> str:
    """Lowercase, diacritic-free, homoglyph-folded form (detection only)."""
    text = canonicalize(text.translate(_PRE_NFKC)).casefold()
    text = _strip_marks(text)
    return text.translate(_CONFUSABLE_TABLE)


def fold_lines(text: str) -> str:
    """Like fold() but keeps line breaks, for line-anchored syntax rules."""
    text = text.translate(_PRE_NFKC)
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", strip_invisible(text)).casefold()
    return _strip_marks(text).translate(_CONFUSABLE_TABLE)


def leet(text: str, syntax_safe: bool = False) -> str:
    return text.translate(_LEET_SYNTAX_SAFE if syntax_safe else _LEET)


def squash(text: str) -> str:
    """Drop every non-alphanumeric character ("i.g n-o_r e" -> "ignore")."""
    return "".join(c for c in text if c.isalnum())


# ── Structural de-obfuscation ────────────────────────────────────────────
# Two evasions survive character folding because they change *token*
# structure rather than characters:
#   * separator insertion inside words: "b-a-s-h", "s.y.s.t.e.m", "r m"
#   * filler words between trigger words: "system really prompt"
# `despace` and `drop_filler` undo them; detectors scan their output as
# extra sources, never instead of the original text.

_SEPARATORS = frozenset(".-_·•*~+|/\\")
# Any one repeated non-word, non-space character can separate letters:
# "b-a-s-h", "c🙂a🙂l🙂l", "r♦u♦n".
_SEP_TOKEN = re.compile(r"(?<!\S)(\S)((?:(?:[^\w\s]|_)\S){1,})(?=\s|$)")

# Words that carry no instruction content: intensifiers, hedges, politeness
# and discourse markers. Deliberately broad and generic rather than tuned to
# the benchmark; the benchmark's `filler_novel` mutator measures how far this
# generalises to words that are not on the list.
FILLER_WORDS = frozenset("""
    really kindly just now totally please pls plz very actually simply basically
    literally seriously honestly definitely certainly absolutely truly quite
    rather completely entirely fully quickly immediately promptly also still
    even so well um uh umm er hmm like okay ok hey yo fyi btw perhaps maybe
    surely obviously clearly merely quietly carefully gently right sure anyway
    anyways essentially practically virtually somewhat super extremely highly
    deeply strongly genuinely legitimately officially formally urgently asap
    respectfully politely nicely thanks thank thx dear friend buddy bro pal
""".split())
_WORD = re.compile(r"[^\W_]+(?:'[^\W_]+)?")


def despace(text: str) -> str:
    """Rejoin characters an attacker spaced apart.

    * one token of single characters joined by one repeated separator:
      "b-a-s-h" / "s.y.s.t.e.m" / ":-(-)-{"  ->  "bash" / "system" / ":(){"
    * a run of >= 3 single-character tokens: "b a s h", "b . a . s . h",
      "무 시 하 고" -> "bash" / "무시하고"
    Returns "" when nothing changed (callers skip the extra view).
    """
    if not text:
        return ""
    text = text[:MAX_VIEW_CHARS]

    def _join_token(m):
        tail = m.group(2)
        sep = tail[0]
        if any(tail[i] != sep for i in range(0, len(tail), 2)):
            return m.group(0)
        return m.group(1) + tail[1::2]

    out = _SEP_TOKEN.sub(_join_token, text)
    tokens = out.split()
    joined: List[str] = []
    run: List[str] = []

    def _flush():
        if len(run) < 3:
            joined.extend(run)
        elif sum(not c.isalnum() for c in run) * 10 >= len(run) * 3:
            # "b . a . s . h f . o . o": separators join letters into a word;
            # two letters side by side, or a doubled separator, mark a word
            # boundary.
            word = run[0] if run[0].isalnum() else ""
            seps = 0
            for prev, cur in zip(run, run[1:]):
                if cur.isalnum():
                    if (prev.isalnum() or seps >= 2) and word:
                        joined.append(word)
                        word = ""
                    word += cur
                    seps = 0
                else:
                    seps += 1
            joined.append(word)
        else:
            joined.append("".join(run))  # "b a s h": no boundary information
        run.clear()

    for tok in tokens:
        if len(tok) == 1:
            run.append(tok)
        else:
            _flush()
            joined.append(tok)
    _flush()
    out = " ".join(joined)
    return out if out != " ".join(text.split()) else ""


def drop_filler(text: str) -> str:
    """Remove FILLER_WORDS (see above). Returns "" when nothing changed."""
    if not text:
        return ""
    text = text[:MAX_VIEW_CHARS]
    hit = False

    def _drop(m):
        nonlocal hit
        if m.group(0).lower() in FILLER_WORDS:
            hit = True
            return ""
        return m.group(0)

    out = _WORD.sub(_drop, text)
    return " ".join(out.split()) if hit else ""


_ASCII_WORD = re.compile(r"(?<![^\W\d_])[A-Za-z][A-Za-z']*(?![^\W\d_])")


def drop_foreign_words(text: str) -> str:
    """In mostly non-Latin text, drop Latin-script words.

    "Игнорируй все предыдущие seventeen инструкции" hides a Russian override
    from phrase rules by inserting an English word. Returns "" when the text
    is mostly Latin or nothing was dropped.
    """
    if not text or text.isascii():
        return ""
    text = text[:MAX_VIEW_CHARS]
    letters = [c for c in text if c.isalpha()]
    latin = sum(1 for c in letters if c.isascii())
    if not letters or latin * 2 >= len(letters):
        return ""
    out = _ASCII_WORD.sub("", text)
    return " ".join(out.split()) if out != text else ""


def native_lower(text: str) -> str:
    """Canonical, lowercased, marks stripped, scripts left as they are."""
    return _strip_marks(canonicalize(text.translate(_PRE_NFKC))).lower()


def detection_views(text: str) -> Dict[str, str]:
    """Return every detection view of `text`. Views may repeat; callers
    should de-duplicate when that matters."""
    if not text:
        return {"canonical": "", "folded": "", "leet": "", "squashed": "", "smuggled": ""}
    text = text[:MAX_VIEW_CHARS]
    smuggled = decode_smuggled(text)
    canonical = canonicalize(text)
    folded = fold(text)
    leet_view = leet(folded)
    return {
        "canonical": canonical,
        "folded": folded,
        "leet": leet_view,
        "squashed": squash(leet_view),
        "smuggled": smuggled,
    }


def has_smuggling(text: str) -> bool:
    """True when the text carries a hidden tag/variation-selector payload."""
    return bool(decode_smuggled(text or ""))


# ── Policy phrase matching ───────────────────────────────────────────────
# Policy lists (blocked patterns/keywords, breakout and harmful-content
# lists) are plain phrases written by operators. They are matched:
#   * against the folded and leet views, so homoglyph / zero-width / case /
#     diacritic tricks do not bypass them;
#   * with word boundaries at alphanumeric edges plus common English
#     inflections, so "dig" no longer fires on "digital", "nc " on "sync ",
#     while "jailbreak" still matches "jailbreaking";
#   * and, for long phrases, against the separator-free view, so
#     "p r i v i l e g e  e s c a l a t i o n" is still caught.
import re as _re  # noqa: E402
_lru_cache = lru_cache

_SUFFIX = r"(?:s|es|ed|d|ing|er|ers|ion|ions)?"
SQUASH_MIN_LEN = 12


@_lru_cache(maxsize=4096)
def _phrase_regex(phrase: str):
    p = fold(phrase)
    if not p.strip():
        return None
    body = r"\s+".join(_re.escape(w) for w in p.split())
    if p[0].isalnum():
        body = r"(?<![a-z0-9])" + body
    elif p[0].isspace():
        body = r"\s+" + body
    if p[-1].isalnum():
        body = body + _SUFFIX + r"(?![a-z0-9])"
    elif p[-1].isspace():
        body = body + r"\s"
    return _re.compile(body)


@_lru_cache(maxsize=4096)
def _phrase_squashed(phrase: str) -> str:
    sq = squash(leet(fold(phrase)))
    return sq if len(sq) >= SQUASH_MIN_LEN else ""


class PhraseViews:
    """Precomputed views of one text for repeated phrase lookups."""

    __slots__ = ("views", "squashed")

    def __init__(self, text: str):
        v = detection_views(text or "")
        self.views = list(dict.fromkeys(x for x in (v["folded"], v["leet"]) if x))
        smuggled = v["smuggled"]
        if smuggled:
            self.views.append(fold(smuggled))
        self.squashed = v["squashed"]

    def find(self, phrases) -> "str | None":
        for phrase in phrases or []:
            if not isinstance(phrase, str) or not phrase.strip():
                continue
            rx = _phrase_regex(phrase)
            if rx is not None and any(rx.search(view) for view in self.views):
                return phrase
            sq = _phrase_squashed(phrase)
            if sq and sq in self.squashed:
                return phrase
        return None


def find_phrase(phrases, text: str):
    """Return the first policy phrase present in `text`, or None."""
    return PhraseViews(text).find(phrases)
