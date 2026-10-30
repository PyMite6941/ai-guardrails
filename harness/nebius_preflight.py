#!/usr/bin/env python3
"""Nebius Token Factory preflight — from a key to a working model layer.

Run this the moment you have a Nebius API key. It does four things and tells
you plainly which step failed:

  1. lists the models your key can see (and which of them are NVIDIA Nemotron)
  2. sends one real chat completion to the model you pick
  3. prints the exact .env lines that enable it
  4. with --write-env, appends those lines to .env (backing up the old one)

    export GUARDRAIL_NEBIUS_API_KEY=...        # never commit this
    python3 harness/nebius_preflight.py
    python3 harness/nebius_preflight.py --model nvidia/Nemotron-3.5-Super-VL --write-env

Exit codes: 0 ok · 2 no key · 3 auth failed · 4 no Nemotron model · 5 call failed.
Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE = "https://api.tokenfactory.nebius.com/v1"
KEY_ENVS = ("GUARDRAIL_NEBIUS_API_KEY", "NEBIUS_API_KEY", "TOKEN_FACTORY_API_KEY")

# Same CA-bundle fallback the server uses: python.org builds on macOS ship
# without one, so HTTPS fails while curl works.
if not os.environ.get("SSL_CERT_FILE"):
    for _ca in ("/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem"):
        if os.path.exists(_ca):
            os.environ["SSL_CERT_FILE"] = _ca
            break


def get_key(arg_file: str | None) -> str:
    if arg_file:
        value = Path(arg_file).expanduser().read_text().strip()
        if value:
            return value
    for name in KEY_ENVS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    # last resort: a .env in the repo
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            if name.strip() in KEY_ENVS and value.strip():
                return value.strip().strip('"').strip("'")
    return ""


def call(url: str, key: str, payload: dict | None = None, timeout: int = 60) -> tuple[int, dict | str]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if data else "GET",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, json.loads(body)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        return e.code, detail
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=DEFAULT_BASE)
    ap.add_argument("--model", help="Nemotron model id (default: first one the key can see)")
    ap.add_argument("--key-file", help="file containing the key")
    ap.add_argument("--write-env", action="store_true", help="append working config to .env")
    ap.add_argument("--rounds", type=int, default=3, help="timing rounds (default 3)")
    args = ap.parse_args()

    key = get_key(args.key_file)
    if not key:
        print("No API key found.")
        print("  export GUARDRAIL_NEBIUS_API_KEY=<your key>   # or put it in .env")
        print("  then re-run this script.")
        return 2

    base = args.base_url.rstrip("/")
    print(f"endpoint : {base}")
    print(f"key      : {key[:4]}…{key[-4:]} ({len(key)} chars)")

    status, body = call(f"{base}/models", key)
    if status != 200 or not isinstance(body, dict):
        print(f"\nmodel list failed (HTTP {status}): {str(body)[:300]}")
        if status in (401, 403):
            print("The key was rejected. Check it is a Token Factory key for this project.")
            return 3
        return 5

    ids = [m.get("id", "") for m in body.get("data", []) if isinstance(m, dict)]
    nemotrons = [i for i in ids if "nemotron" in i.lower()]
    print(f"\nmodels visible to this key: {len(ids)}")
    if nemotrons:
        print("NVIDIA Nemotron models:")
        for i in nemotrons:
            print(f"  - {i}")
    else:
        print("No Nemotron model is visible to this key. First 20 ids:")
        for i in ids[:20]:
            print(f"  - {i}")
        print("\nThe hackathon requires an NVIDIA open model, so this needs fixing "
              "before the model layer can count.")
        return 4

    model = args.model or nemotrons[0]
    if args.model and args.model not in ids:
        print(f"\nwarning: {model} is not in the list above — trying it anyway")
    print(f"\nmodel    : {model}")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a strict input-safety classifier. Reply with exactly one line: SAFE or BLOCK: <reason>."},
            {"role": "user", "content": "Classify this user input:\n---\nWhat is the capital of France?\n---"},
        ],
        "temperature": 0,
        "max_tokens": 40,
        "stream": False,
    }

    latencies, verdicts = [], []
    for n in range(max(1, args.rounds)):
        t0 = time.perf_counter()
        status, resp = call(f"{base}/chat/completions", key, payload)
        latencies.append((time.perf_counter() - t0) * 1000)
        if status != 200 or not isinstance(resp, dict):
            print(f"call {n + 1} failed (HTTP {status}): {str(resp)[:300]}")
            return 5
        try:
            text = resp["choices"][0]["message"]["content"].strip()
        except Exception:
            text = json.dumps(resp)[:120]
        verdicts.append(text)

    print(f"reply    : {verdicts[0][:80]!r}")
    print(f"latency  : avg {statistics.mean(latencies):.0f} ms · "
          f"max {max(latencies):.0f} ms over {len(latencies)} calls")
    if len(set(verdicts)) > 1:
        print("warning  : the model gave different answers for the same input — "
              "check temperature/seed support on this endpoint")

    env_lines = [
        "GUARDRAIL_CLASSIFIER_ENABLED=1",
        f"GUARDRAIL_CLASSIFIER_BASE_URL={base}",
        f"GUARDRAIL_CLASSIFIER_MODEL={model}",
        "GUARDRAIL_CLASSIFIER_API_STYLE=openai",
        f"GUARDRAIL_CLASSIFIER_API_KEY={key}",
        f"GUARDRAIL_NEBIUS_API_KEY={key}",
    ]
    print("\n.environment config that enables this:")
    for line in env_lines:
        shown = line
        if "API_KEY=" in line:
            shown = line.split("=", 1)[0] + "=<your key>"
        print(f"  {shown}")

    if args.write_env:
        env_path = ROOT / ".env"
        existing = env_path.read_text() if env_path.exists() else ""
        keys_present = {ln.split("=", 1)[0].strip() for ln in existing.splitlines() if "=" in ln}
        additions = [ln for ln in env_lines if ln.split("=", 1)[0] not in keys_present]
        if not additions:
            print("\n.env already has these keys — nothing written.")
        else:
            if existing:
                backup = ROOT / ".env.bak"
                backup.write_text(existing)
                print(f"\nbackup written: {backup.name}")
            with open(env_path, "a", encoding="utf-8") as f:
                f.write("\n# added by harness/nebius_preflight.py\n")
                f.write("\n".join(additions) + "\n")
            os.chmod(env_path, 0o600)
            print(f"wrote {len(additions)} line(s) to .env (mode 600). Restart the server.")
    else:
        print("\nrun again with --write-env to append these to .env")

    print("\nnext: restart the server, then")
    print("  python3 harness/nemotron_probe.py --model " + model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
