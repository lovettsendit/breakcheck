# Contributing to Breakcheck

Breakcheck accepts narrowly scoped fixes, tests, documentation improvements, and reproducible compatibility cases.

## Development setup

```console
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m pytest -q
```

Run the test suite on Python 3.10 through 3.13 when changing runtime behavior. Linux and macOS are the supported platforms.

## Contribution requirements

- Add a regression test that fails for the defect before the production fix.
- Include a known-good counterexample when strengthening a refusal or confinement rule.
- Preserve deterministic ordering and canonical JSON behavior.
- Never turn malformed, missing, dynamic, or unstable evidence into an `IDENTICAL` verdict.
- Keep the local-wheelhouse and no-network defaults unchanged.
- Do not include private source, generated `.breakcheck/` evidence, credentials, or machine-specific paths.

## Pull requests

Describe the user-visible failure, the smallest correcting change, and the tests that prove both the failure and the preserved behavior. Keep unrelated refactoring out of the same pull request.

For security defects, follow [SECURITY.md](SECURITY.md) instead of opening a public pull request containing exploit details.
