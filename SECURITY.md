# Security Policy for Breakcheck

## Supported versions

Security fixes are provided for the latest `2.x` release.

## Trust model

Breakcheck is designed for trusted Python repositories and trusted package wheels. It is not a security sandbox.

Replay processes receive a scrubbed environment, a fresh working directory, resource limits, no shell, and a Python socket audit guard. Package code still runs with the operating-system permissions of the user who launched Breakcheck. Native extensions or subprocesses may access the filesystem, host resources, or capabilities that a Python audit hook cannot block.

Do not use Breakcheck to execute an untrusted wheel on a sensitive machine. Use a disposable virtual machine or comparably isolated host when package provenance is uncertain.

## Repository code, fixtures, and revisions

Dependency wheels, imported repository modules, fixture expressions, fixture setup, and fixture projections are executable input. Review them before running Breakcheck.

Revision comparison materializes committed source into detached Git worktrees. It does not mutate the active checkout, index, or stash. Worktree confinement and cleanup reduce accidental interference; they do not make imported application code safe. Import-time code can read files, inspect permitted environment state, start subprocesses, or exercise native extensions with the invoking user's permissions.

Fixture files are read only from repository-relative paths. Expressions are parsed before replay, bounded in size, and executed only inside the replay process. A projection limits what is compared; it does not prevent the underlying call from executing.

Run Breakcheck only on repositories, revisions, wheels, fixtures, and claim files you trust. Use a disposable host for code whose provenance is uncertain.

## Wheelhouse integrity

- Breakcheck never falls back to a network package index.
- Exact current and proposed wheels must be present locally.
- Wheel paths must be regular files confined to the declared wheelhouse.
- Operators remain responsible for obtaining trusted wheels and recording their expected hashes or signatures.

## Reports and evidence

Generated artifacts may contain repository-relative paths, replay source, literal or fixture arguments, setup and projection expressions, returned values, exception messages, captured output, revision identities, and hashes derived from source or environments. Treat reports, baselines, claims, coverage records, and witnesses with the same confidentiality as the source repository being analyzed.

Breakcheck hashes reports, witnesses, finding identities, observations, replay source, fixtures, revisions, and environment artifacts to detect accidental or partial alteration. These hashes are integrity checks, not authenticated signatures, encryption, or remote connectivity. Creating or publishing a hash does not make a computer a server and does not expose the original content from the digest alone. A party able to replace the complete bundle can generate a new internally consistent bundle.

Inspect generated artifacts before sending them to an external service. Do not commit `.breakcheck/` output from a private repository.

## Reporting a vulnerability

For a public GitHub repository, open the repository's **Security** tab and select **Report a vulnerability**. This creates a private report visible to the maintainers when GitHub private vulnerability reporting is enabled.

If private reporting is unavailable, open a public issue containing no exploit details, credentials, private source, tokens, or personal information and request a private contact channel. Do not publish a proof of concept until maintainers provide one.
