# Security Policy

AI Guardrails is security software, so bypasses of its detectors count as
vulnerabilities.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately
through GitHub: **Security → Report a vulnerability** on this repository
(private vulnerability reporting).

Include:

- what is affected (module, endpoint, check, or policy),
- a minimal reproduction (input text, request, configuration),
- the impact (bypass, data exposure, privilege escalation, crash/DoS).

You can expect an acknowledgement within 3 business days and a status update
within 10. Fixes are released as a patch version with a GitHub Security
Advisory crediting the reporter (unless you prefer not to be named).

## What is in scope

- **Detection bypasses**: an input that a reasonable reader (or LLM) would
  understand as a prompt injection, jailbreak, exfiltration instruction or
  container-escape attempt, but that passes `validate_input` with the default
  policy. Bypasses become named regression cases in `tests/test_detection.py`
  and, where they generalize, benchmark mutators.
- Authentication, session, 2FA, API-key and role-permission flaws.
- Server-side request forgery, path traversal, injection, or unsafe
  deserialization in the server or CLI.
- Resource exhaustion (an input that makes a scan super-linear).
- Supply-chain problems in the release or CI pipeline.

## Out of scope

- False positives (please open a normal issue, they are welcome too).
- Attacks that require an already-compromised host or administrator account.
- Findings that only affect the `harness/` developer probes.

## Supported versions

Only the latest release on `main` receives security fixes.
