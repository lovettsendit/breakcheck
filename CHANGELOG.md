# Changelog

All notable changes to Breakcheck are documented here.

## 2.0.0 - 2026-08-26

- Added PyPI-ready project metadata and trusted release automation.
- Added a one-command changed-behavior demonstration that verifies its report and evidence before success.
- Added structured GitHub issue and pull-request intake.
- Limited push CI to main while retaining pull-request coverage.
- Added bounded static folding, module-constant resolution, and safe nested calls.
- Added operator-reviewed fixtures, projections, coverage diagnostics, and fixture suggestions.
- Added behavioral baselines, cross-revision comparison, and behavior-preservation claims.
- Kept unchanged sibling functions out of the changed-symbol set when another definition shifts their source locations.
- Added closed schema-2 reports, replay witnesses, provenance, and machine-readable capabilities.

## 1.0.1 - 2026-08-26

- Preserve exact static submodule imports and aliases when replaying literal calls.
- Prevent false `IDENTICAL` findings caused by importing only a distribution's root package.

## 1.0.0 - 2026-08-25

- First standalone production release.
- Added offline deterministic upgrade replay and integrity verification.
- Refuse APIs absent from both environments instead of counting them as exercised.
- Bind complete replay environments, finding identities, witness identities, and observation hashes.
- Terminate descendant process groups on timeout and bound captured output in memory.
- Refuse malformed Python source, invalid UTF-8 observations, symlinked inventory roots, and escaping wheel inputs.
- Provide transactional environment rollback, clean wheel and source-distribution installation, public CI, and complete operator documentation.
