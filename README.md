# Breakcheck

Breakcheck is a deterministic behavioral compatibility checker for Python package upgrades. It finds statically discoverable calls your repository makes to a dependency, replays literal calls against exact current and proposed wheels in isolated environments, and reports whether the observed behavior changed.

Breakcheck does not update dependencies and does not guess whether a change is safe. It produces bounded evidence for a maintainer or CI system to judge.

## Quick start

Breakcheck evaluates one dependency upgrade in an existing Python repository. Start from the repository root, with the currently used dependency installed:

```console
python -m pip install /path/to/breakcheck-1.0.0-py3-none-any.whl
mkdir -p wheelhouse .breakcheck/results
python -m pip download --only-binary=:all: --dest wheelhouse \
  'attrs==23.2.0' 'attrs==24.2.0'
breakcheck attrs@24.2.0 \
  --wheelhouse wheelhouse \
  --runtime-root .breakcheck/runtime-001 \
  --output .breakcheck/results/report.json \
  --evidence .breakcheck/results/evidence.json \
  --json \
  --ci
```

Replace `attrs` and the versions with the dependency you are evaluating. Breakcheck expects the current version to be installed in the Python interpreter running the command and both exact wheels, plus their installation dependencies, to be present in `wheelhouse`.

## Why use it?

Version-update tools can tell you that a newer dependency exists. Breakcheck answers a different question: **does the newer version change behavior that this repository actually exercises?**

- Uses call sites found in your repository instead of a generic API inventory.
- Runs entirely from an explicit local wheelhouse with no network fallback.
- Produces deterministically ordered JSON, human output, and replay witnesses.
- Distinguishes changed behavior, identical behavior, and calls it could not exercise.
- Refuses malformed, dynamic, missing, or unstable evidence instead of treating it as success.

## Where Breakcheck fits

Breakcheck is a pre-merge check for a specific Python dependency update. It complements, rather than replaces, your existing tests:

1. A maintainer, dependency bot, or coding tool proposes a version change.
2. Breakcheck finds supported calls to that dependency in the repository.
3. It runs those calls against exact old and new wheels in separate environments.
4. It records identical, changed, and not-exercised results with replay evidence.
5. A maintainer reviews the changes together with the project's ordinary tests, security checks, and release process.

This is useful when reviewing automated dependency updates, preparing a framework migration, or investigating whether a version bump changes literal API calls already present in a codebase.

## Using Breakcheck with AI-assisted development

AI coding tools can propose dependency updates and help interpret a Breakcheck report, but Breakcheck remains the deterministic measurement step:

1. Let the coding tool propose the dependency change without merging it.
2. Run Breakcheck locally or in CI against trusted, exact wheels.
3. Inspect and sanitize the report before sharing it with an external AI service; reports may contain source locations, literal arguments, outputs, and local paths.
4. Ask the coding tool to address specific `CHANGED` or `NOT_EXERCISED` findings.
5. Rerun Breakcheck and the project's normal test suite.
6. Require human review before accepting the upgrade.

Breakcheck does not decide whether an upgrade should ship, and AI-generated explanations do not override its recorded observations.

## Supported scope

- Python 3.10 through 3.13.
- Linux and macOS.
- Python package calls discoverable through static imports.
- Calls whose positional and keyword arguments are Python literals.
- Trusted package wheels supplied by the operator.

Dynamic dispatch, runtime-computed arguments, setup-dependent object state, and calls hidden behind unsupported indirection are reported as not exercised. Breakcheck is not a security sandbox and must not execute untrusted package code on a sensitive host.

## What Breakcheck does not prove

An exit status of `0` means the supported calls Breakcheck exercised met the configured coverage threshold and produced no changed observations. It does not establish that every dependency API is compatible, that unexercised application paths are safe, or that a package is secure. Keep unit, integration, security, and platform tests in the release process.

## Install for development

From a source checkout:

```console
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
breakcheck --help
python -m pytest -q
```

To build and install the distributable wheel:

```console
python -m pip install 'build>=1.2,<2'
python -m build
python -m pip install dist/breakcheck-1.0.0-py3-none-any.whl
breakcheck --help
```

## Prepare an offline wheelhouse

Breakcheck requires:

1. The current distribution to be installed in the Python interpreter running `breakcheck`.
2. An exact wheel for the installed version.
3. An exact wheel for the proposed version.
4. Wheels for any dependencies that pip must install into either replay environment.

For example, if the repository currently uses `attrs==23.2.0` and you want to evaluate `attrs==24.2.0`:

```console
python -m pip install 'attrs==23.2.0'
mkdir -p wheelhouse
python -m pip download --only-binary=:all: --dest wheelhouse 'attrs==23.2.0' 'attrs==24.2.0'
```

Treat every wheel in the wheelhouse as executable input. Obtain wheels from a source you trust and preserve their hashes in your own supply-chain records.

## Run a comparison

Run Breakcheck from the root of the repository to analyze:

```console
mkdir -p .breakcheck/results
breakcheck attrs@24.2.0 \
  --wheelhouse wheelhouse \
  --runtime-root .breakcheck/runtime-001 \
  --output .breakcheck/results/report.json \
  --evidence .breakcheck/results/evidence.json \
  --json \
  --ci
```

The target grammar is `<distribution>@<new-version>`. Use a fresh, absent `--runtime-root` for every run. If `--runtime-root` is omitted, Breakcheck creates a temporary runtime directory and records its path in the evidence.

### CI exit statuses

| Exit | Meaning |
| ---: | --- |
| `0` | Coverage is at least 80 percent and no exercised behavior changed. |
| `2` | The request or its evidence was refused. |
| `3` | At least one exercised behavior changed. |
| `4` | Exercised coverage is below 80 percent. |

An exit of `0` is evidence about the supported, exercised calls only. It is not a claim that an entire dependency is universally compatible.

## Verify persisted evidence

Verification rechecks report integrity, finding and witness identities, observation hashes, and the recorded replay environments:

```console
breakcheck \
  --verify .breakcheck/results/report.json \
  --evidence .breakcheck/results/evidence.json
```

Successful verification prints `VERIFIED`. Verification requires both recorded environment roots to remain present and byte-identical. Once verification and retention obligations are complete, delete `.breakcheck/runtime-001` yourself to recover disk space.

The hashes provide integrity and self-consistency checks. They are not signatures and do not prove who created an evidence bundle. Anyone who can replace an entire report and evidence bundle can compute new hashes.

## Reading results

Each finding has one of three verdicts:

- `IDENTICAL`: the normalized observations matched.
- `CHANGED`: the normalized observations differed and should be reviewed.
- `NOT_EXERCISED`: Breakcheck could not lawfully replay the call; the reason code explains why.

Reports include deterministic finding IDs, call-site locations, normalized old and new observations, suggested maintainer actions, and replay witnesses for exercised findings.

## Security and privacy

Breakcheck launches package code with a scrubbed environment, no shell, bounded resources, a fresh working directory, and a Python socket audit guard. These are containment measures, not a security boundary. Native extensions, subprocesses, and code with the caller's operating-system permissions can still affect the host.

Generated reports and evidence can contain:

- repository-relative source locations and literal call snippets;
- literal arguments;
- normalized return values and exception messages;
- captured standard output and standard error;
- absolute replay-environment paths.

Inspect and sanitize generated artifacts before sharing them. Do not commit `.breakcheck/` output from private repositories. See [SECURITY.md](SECURITY.md) for the complete trust model and vulnerability-reporting process.

## Reproducibility evidence

The repository contains release evidence for a 20-package battery and a 16,002-call-site scale exercise under `release_evidence/`. Those records are release measurements, not substitutes for running Breakcheck against your own repository and wheels.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Breakcheck is licensed under the [MIT License](LICENSE).
