# Hackathon submission checklist

Nebius × NVIDIA Global AI Hackathon. Submission closes **Fri 30 Oct 2026, 10:00 PT
(Sat 31 Oct, 01:00 CST)**. Judging 9–23 Dec. Track: **Coding & Agentic Engineering**.

Status is honest — anything not verified is marked as such.

## Required

- **Project runs on Nebius Token Factory / AI Cloud** — the rules define this as
  *"makes a runtime call to the Token Factory inference API"*.
  - Code path: `guardrail_classifier.py` → `POST https://api.tokenfactory.nebius.com/v1/chat/completions`.
  - Status: **wired and validated against a local mock; live call pending a Nebius key.**
  - Verify with `python3 harness/nemotron_probe.py --model <id>` and paste the output
    into the submission notes. Do not claim numbers that were not measured.
- **At least one NVIDIA open model** — `nvidia/Nemotron-3.5-Super-VL` (confirm the
  exact id with `GET /v1/models`; ids change).
- **Public repo with an open-source licence and README** — done: MIT, public,
  README documents the Nebius path.
- **Live demo URL** — *missing*. Localhost does not count. Options: a small VM, a
  tunnel for the demo window, or a hosted read-only instance. The guardrail binds
  loopback by default — expose it deliberately, behind auth, never with a default
  password.
- **Public YouTube video, ≤ 3 minutes** — *missing*. Suggested 150-second script:
  1. 0:00–0:20 the problem: an agent that can run tools needs an enforced boundary.
  2. 0:20–0:50 live block of a jailbreak in the console (real verdict, real rule name).
  3. 0:50–1:20 policy editor: rules are data, not prose.
  4. 1:20–1:50 Nemotron second opinion on Nebius doing the deciding (show the call).
  5. 1:50–2:20 the benchmark: deterministic vs +Nemotron, precision/recall/latency.
  6. 2:20–2:30 what it does not do.
- **Feedback on Nebius and NVIDIA tools** — *not written*. Only write what you
  actually experienced. Prompts that produce honest answers:
  - Which part of Token Factory onboarding cost you time, and what would have fixed it?
  - Did the OpenAI-compatible endpoint behave as documented? Any surprise in errors or limits?
  - Which Nemotron tier did you reach for, and was the latency acceptable for a per-request guard?
  - What would you change in the model docs to make this integration a one-hour job?

## Not required but scored

- **"What's new" note** — not needed: the submission period opened 26 Aug 2026 and
  this repository's first commit is 28 Oct 2026, so the project was created inside
  the window.
- **Builder credits** — Nebius Builder Program gives Token Factory credits; the
  promo code from the hackathon page was `NEBIUS-DEVPOST-GLOBAL26` (90-day expiry).
  Confirm the current amount before relying on it.

## Before submitting — the checks that matter

```
python3 harness/nemotron_probe.py --self-test        # wire format + verdict parsing
python3 harness/nemotron_probe.py --model <id>       # real numbers, saved to harness/results/
for t in tests/*.py; do python3 "$t" || echo "FAILED $t"; done
```

Do not submit a claim about the model layer that the benchmark file does not back up.
