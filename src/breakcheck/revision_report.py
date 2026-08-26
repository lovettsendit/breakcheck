"""Builders for revision-domain schema-2 artifacts."""

from __future__ import annotations

import copy
from typing import Mapping, Sequence

from .schema import artifact_digest, make_artifact, validate_artifact


_REVISION_ARTIFACT_KINDS = frozenset(
    ("baseline", "revision_report", "claim_report")
)


def make_revision_artifact(kind: str, payload: Mapping[str, object]) -> dict:
    if kind not in _REVISION_ARTIFACT_KINDS:
        raise ValueError("ARTIFACT_KIND_REFUSED")
    return make_artifact(kind, payload)


def make_evidence_artifact(
    report: Mapping[str, object],
    *,
    environment_artifacts: Sequence[Mapping[str, object]],
) -> dict:
    validated = validate_artifact(report)
    if validated["artifact_kind"] == "evidence":
        raise ValueError("ARTIFACT_KIND_REFUSED")
    payload = validated["payload"]
    witnesses = payload.get("witnesses", [])
    return make_artifact(
        "evidence",
        {
            "report_artifact_sha256": artifact_digest(validated),
            "report_payload_sha256": validated["payload_sha256"],
            "report_kind": validated["artifact_kind"],
            "witnesses": copy.deepcopy(witnesses),
            "environment_artifacts": copy.deepcopy(list(environment_artifacts)),
            "invocation": copy.deepcopy(payload["invocation"]),
        },
    )


__all__ = ("make_evidence_artifact", "make_revision_artifact")
