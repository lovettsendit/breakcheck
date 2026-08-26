# Security Policy for Breakcheck

## Supported versions

Security fixes are provided for the latest `1.x` release.

## Trust model

Breakcheck is designed for trusted Python repositories and trusted package wheels. It is not a security sandbox.

Replay processes receive a scrubbed environment, a fresh working directory, resource limits, no shell, and a Python socket audit guard. Package code still runs with the operating-system permissions of the user who launched Breakcheck. Native extensions or subprocesses may access the filesystem, host resources, or capabilities that a Python audit hook cannot block.

Do not use Breakcheck to execute an untrusted wheel on a sensitive machine. Use a disposable virtual machine or comparably isolated host when package provenance is uncertain.

## Wheelhouse integrity

- Breakcheck never falls back to a network package index.
- Exact current and proposed wheels must be present locally.
- Wheel paths must be regular files confined to the declared wheelhouse.
- Operators remain responsible for obtaining trusted wheels and recording their expected hashes or signatures.

## Reports and evidence

Generated artifacts may contain source snippets, literal arguments, returned values, exception messages, stdout, stderr, usernames embedded in paths, and absolute replay-environment paths. Treat reports and witnesses with the same confidentiality as the source repository being analyzed.

Breakcheck hashes reports, witnesses, finding identities, observations, and replay-environment artifacts to detect accidental or partial alteration. These hashes are integrity checks, not authenticated signatures. A party able to replace the complete bundle can generate a new internally consistent bundle.

## Reporting a vulnerability

For a public GitHub repository, open the repository's **Security** tab and select **Report a vulnerability**. This creates a private report visible to the maintainers when GitHub private vulnerability reporting is enabled.

If private reporting is unavailable, open a public issue containing no exploit details, credentials, private source, tokens, or personal information and request a private contact channel. Do not publish a proof of concept until maintainers provide one.
