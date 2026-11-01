#!/usr/bin/env python3
"""Weekly research digest: new LLM-attack and guardrail papers from arXiv.

Used by .github/workflows/research.yml to open a triage issue, so every new
published attack technique is reviewed and, where it applies, turned into a
benchmark mutator, a corpus entry or a detection rule.

    python3 scripts/research_digest.py --days 7 > digest.md

Exit status 0 always; prints nothing when there are no new papers.
"""
import argparse
import datetime as dt
import sys
import urllib.parse
import xml.etree.ElementTree as ET  # nosec B405 - trusted arXiv feed; expat>=2.4.1 limits entity expansion

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__))))
from guardrail_net import urlopen_http  # noqa: E402

API = "https://export.arxiv.org/api/query"
ATOM = "{http://www.w3.org/2005/Atom}"

# Queries over title+abstract. Kept narrow: guardrail-relevant attacks only.
QUERIES = [
    'abs:"prompt injection"',
    'abs:jailbreak AND (abs:guardrail OR abs:detector OR abs:defense)',
    'abs:"indirect prompt injection"',
    'abs:"system prompt" AND (abs:leakage OR abs:extraction)',
    'abs:"LLM agent" AND (abs:attack OR abs:exfiltration) AND abs:tool',
    'abs:"guardrail" AND (abs:evasion OR abs:bypass OR abs:adversarial)',
]

# Words that suggest an actionable technique (raises a paper in the list).
SIGNALS = ["evasion", "bypass", "obfuscat", "unicode", "homoglyph", "encoding", "smuggl",
           "multilingual", "indirect", "exfiltrat", "agent", "tool", "benchmark", "dataset",
           "detector", "classifier", "guardrail", "adaptive", "multi-turn", "multiturn"]


def fetch(query, max_results=50):
    params = urllib.parse.urlencode({"search_query": query, "sortBy": "submittedDate",
                                     "sortOrder": "descending", "max_results": max_results})
    with urlopen_http(f"{API}?{params}", timeout=60) as resp:
        return ET.fromstring(resp.read())  # nosec B314 - see import note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    args = ap.parse_args()
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.days)

    papers = {}
    for q in QUERIES:
        try:
            root = fetch(q)
        except Exception as exc:  # network hiccup: report, keep going
            print(f"<!-- query failed: {q}: {type(exc).__name__} -->", file=sys.stderr)
            continue
        for entry in root.findall(f"{ATOM}entry"):
            published = dt.datetime.fromisoformat(
                entry.findtext(f"{ATOM}published", "").replace("Z", "+00:00"))
            if published < since:
                continue
            pid = entry.findtext(f"{ATOM}id", "").strip()
            title = " ".join(entry.findtext(f"{ATOM}title", "").split())
            summary = " ".join(entry.findtext(f"{ATOM}summary", "").split())
            score = sum(s in (title + " " + summary).lower() for s in SIGNALS)
            papers[pid] = (score, published.date().isoformat(), title, summary, pid)

    if not papers:
        return 0
    ranked = sorted(papers.values(), key=lambda p: (-p[0], p[1]), reverse=False)
    print(f"New papers on LLM attacks and guardrails since {since.date().isoformat()} "
          f"({len(ranked)} found). Triage each one:\n")
    print("- [ ] **new attack technique?** add a mutator in `benchmarks/mutators.py` or seeds in "
          "`benchmarks/corpus/attacks.jsonl`")
    print("- [ ] **detector gap?** add a rule in `guardrail_prompt_injection.py` + a named case "
          "in `tests/test_detection.py`")
    print("- [ ] **better metrics?** ratchet `benchmarks/thresholds.json` upward\n")
    for score, date, title, summary, pid in ranked[:25]:
        abstract = summary[:400] + ("…" if len(summary) > 400 else "")
        print(f"### [{title}]({pid})\n_{date} · relevance {score}_\n\n> {abstract}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
