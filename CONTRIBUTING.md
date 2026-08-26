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
- Preserve fixture authorship, source revision, argument provenance, and strict separation in every new replay path.
- Keep schema changes closed, versioned, canonical, and backward-readable where documented.
- Preserve detached-worktree cleanup and never mutate a user's checkout, index, or stash.
- Do not include private source, generated `.breakcheck/` evidence, credentials, or machine-specific paths.

## Product effort budget

Breakcheck is designed to add almost no manual work to an upgrade or review:

- a fresh repository reaches its first report with one command in under five minutes;
- CI integration is one workflow file with fewer than 20 non-comment lines;
- a rerun after a code change is one command with no new input;
- fixture suggestions require no manual authoring before a human reviews the diff.

A feature that cannot meet this default-path budget must remain explicitly optional.
Contributions must preserve noninteractive execution and zero runtime dependencies.

Fail-closed behavior is mechanical: every refusal code needs a producing test, broad
adapter exceptions cannot silently continue, fixed identical and changed cases must
retain their verdicts, and every exercised observation must carry declared provenance.

## Behavioral invariants

Changes must preserve all of these:

- `IDENTICAL` means both admitted observations were replayed and compared equal.
- `NOT_EXERCISED` and `CLAIM_UNVERIFIABLE` are never summarized as safe.
- Every new execution path runs twice and refuses nondeterministic observations.
- Scanning never imports or evaluates repository or dependency code.
- Fixture and claim inputs use closed, bounded formats and fail on stale or unmatched bindings.
- Machine-readable artifacts remain noninteractive, deterministically ordered, and free of hidden fallback behavior.
- Runtime package dependencies remain empty unless a reviewed design demonstrates that the benefit outweighs the embeddability and supply-chain cost.

Add or update the fixed identical, changed, refusal, provenance, artifact-verification, and installed-CLI tests when changing these behaviors.

## Pull requests

Describe the user-visible failure, the smallest correcting change, and the tests that prove both the failure and the preserved behavior. Keep unrelated refactoring out of the same pull request.

For security defects, follow [SECURITY.md](SECURITY.md) instead of opening a public pull request containing exploit details.
