## What and why

<!-- What does this change, and why is it needed? Link issues. -->

## Security checklist

- [ ] No detection threshold in `benchmarks/thresholds.json` was lowered (if one was, explain why here)
- [ ] New detection rules have a named case in `tests/test_detection.py` and a false-positive trap
- [ ] External holdout (`python3 benchmarks/external_eval.py --gate`) still passes
- [ ] No secrets, keys or personal data in the diff
- [ ] New HTTP routes have an entry in `ROUTE_POLICY` (default deny) and a test
- [ ] New GitHub Actions are pinned to a commit SHA

## Testing

<!-- Commands run and results, e.g. `python3 tests/run_all.py`. -->
