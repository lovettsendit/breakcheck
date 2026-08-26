---
name: verifying-python-changes-with-breakcheck
description: Use when a Python dependency version changes or when a code change claims to preserve behavior.
---

# Verifying Python Changes with Breakcheck

## Purpose

Use Breakcheck as the deterministic measurement step after proposing a dependency upgrade or a behavior-preserving code change. A coding agent may propose inputs and interpret results; Breakcheck owns replay, comparison, refusal, and evidence.

## Dependency upgrades

Run from the repository root after preparing exact trusted wheels in a local wheelhouse:

```console
breakcheck PACKAGE@NEW_VERSION \
  --wheelhouse wheelhouse \
  --output .breakcheck/report.json \
  --evidence .breakcheck/evidence.json \
  --coverage-report .breakcheck/coverage.json \
  --json --ci
```

If coverage is limited by unresolved arguments, generate proposals with:

```console
breakcheck PACKAGE@NEW_VERSION --suggest-fixtures breakcheck.fixtures.toml
```

Fill only fixtures that can be justified from repository context, mark `fixture_authored_by = "agent"`, and present the fixture diff for human review before replay.

## Behavior-preserving code changes

Fixtures must be authored, reviewed, and committed against the base revision before the target code changes. Use this sequence:

1. Run `breakcheck freeze` for the affected symbols and retain the verified baseline.
2. Make the behavior-preserving code change without altering its fixtures or baseline.
3. Create a claim file listing every symbol the change is intended to preserve.
4. Run `breakcheck attest` against the changed revision.
5. Report every disposition verbatim to the human, including all unverifiable and out-of-scope counts.

An explicit comparison between committed revisions is also available:

```console
breakcheck diff \
  --base BASE_REVISION --head HEAD_REVISION \
  --fixtures breakcheck.fixtures.toml \
  --strict-separation \
  --output .breakcheck/revision-report.json \
  --evidence .breakcheck/revision-evidence.json
```

For an explicit preservation claim, create a reviewed `breakcheck.claim.toml` and run:

```console
breakcheck attest \
  --head HEAD_REVISION \
  --claim breakcheck.claim.toml \
  --fixtures breakcheck.fixtures.toml \
  --output .breakcheck/claim-report.json \
  --evidence .breakcheck/claim-evidence.json
```

## Result contract

- `IDENTICAL` or `CLAIM_VERIFIED`: exercised evidence matched within the stated scope.
- `CHANGED` or `CLAIM_REFUTED`: surface the finding to the human; do not silently resolve it.
- `NOT_EXERCISED` or `CLAIM_UNVERIFIABLE`: report the count and reason explicitly; never describe it as safe.
- `CLAIM_OUT_OF_SCOPE`: report the omitted changed symbols.

## Required separation

- Never edit `report.json`, `evidence.json`, or `baseline.json`.
- Never author or modify a fixture for a target after changing that target's code; fixtures used to verify preservation must predate the change.
- Never modify a fixture after seeing `CHANGED` for that binding in the same session.
- Never pass `--allow-empty`, lower `--min-coverage`, disable strict policy, or weaken fixture separation to obtain a passing result.
- Never modify verdict or verification logic as part of the change being verified.
- Inspect and sanitize artifacts before sending them to an external service; they may contain source locations, replay source, arguments, setup, projections, and observed values.

Report the exact Breakcheck command, exit code, verdict counts, and artifact paths alongside the ordinary project test results.
