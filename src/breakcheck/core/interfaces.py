"""Frozen adapter boundary shared by every supported ecosystem."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .models import (
    Comparison,
    Environment,
    EnvironmentPair,
    Observation,
    ReplaySnippet,
    UsageManifest,
)


__all__ = (
    "UsageScanner",
    "EnvBuilder",
    "Executor",
    "EqualityRules",
    "ArtifactVerifier",
)


class UsageScanner(Protocol):
    """Locate package usage and produce deterministic replay candidates."""

    def scan(self, repo: Path, package: str) -> UsageManifest: ...


class EnvBuilder(Protocol):
    """Materialize isolated current-version and new-version environments."""

    def build(
        self,
        package: str,
        current_version: str,
        new_version: str,
        wheelhouse: Path | None,
    ) -> EnvironmentPair: ...


class Executor(Protocol):
    """Execute one replay candidate in one isolated environment."""

    def execute(self, snippet: ReplaySnippet, environment: Environment) -> Observation: ...


class EqualityRules(Protocol):
    """Compare two normalized observations using ecosystem semantics."""

    def compare(self, old: Observation, new: Observation) -> Comparison: ...


class ArtifactVerifier(Protocol):
    """Verify a versioned report and its separately persisted evidence."""

    def verify(self, report: dict, evidence: dict) -> str: ...
