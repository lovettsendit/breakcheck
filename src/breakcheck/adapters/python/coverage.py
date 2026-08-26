"""Deterministic identities and terminal records for coverage accounting.

This module is intentionally independent of the command-line integration.  It
defines the closed vocabulary and canonical records that later pipeline stages
can consume without changing the legacy scanner call-site schema.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping


TERMINAL_BUCKETS = (
    "EXERCISED",
    "G1_NOT_DISCOVERABLE",
    "G2_NONLITERAL",
    "G3_UNNORMALIZABLE",
    "G4_IMPURE",
)

PROVENANCE_ORDER = (
    "SOURCE_LITERAL",
    "SOURCE_FOLDED",
    "SOURCE_MODULE_CONSTANT",
    "SOURCE_NESTED_CALL",
    "OPERATOR_FIXTURE",
    "RUNTIME_CAPTURE",
)

_PROVENANCE_POSITION = {
    value: position for position, value in enumerate(PROVENANCE_ORDER)
}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _nonempty_text(value: object, refusal: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(refusal)
    return value


def _location(*, api: object, file: object, line: object, column: object) -> dict:
    observed_api = _nonempty_text(api, "CANDIDATE_API_REFUSED")
    observed_file = _nonempty_text(file, "CANDIDATE_FILE_REFUSED")
    if type(line) is not int or line < 1:
        raise ValueError("CANDIDATE_LINE_REFUSED")
    if type(column) is not int or column < 0:
        raise ValueError("CANDIDATE_COLUMN_REFUSED")
    return {
        "api": observed_api,
        "file": observed_file,
        "line": line,
        "column": column,
    }


def candidate_id(*, api: object, file: object, line: object, column: object) -> str:
    """Return the stable identity of one statically attributable call site."""

    payload = {
        "kind": "python_dependency_call",
        "location": _location(api=api, file=file, line=line, column=column),
        "schema_version": 1,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def make_candidate(*, api: object, file: object, line: object, column: object) -> dict:
    location = _location(api=api, file=file, line=line, column=column)
    return {
        "candidate_id": candidate_id(**location),
        **location,
    }


def order_provenance(values: Iterable[str]) -> tuple[str, ...]:
    try:
        observed = set(values)
    except TypeError as exc:
        raise ValueError("PROVENANCE_REFUSED") from exc
    if not observed or any(value not in _PROVENANCE_POSITION for value in observed):
        raise ValueError("PROVENANCE_REFUSED")
    return tuple(sorted(observed, key=_PROVENANCE_POSITION.__getitem__))


def _validate_candidate(candidate: Mapping[str, object]) -> dict:
    if not isinstance(candidate, Mapping) or set(candidate) != {
        "candidate_id",
        "api",
        "file",
        "line",
        "column",
    }:
        raise ValueError("CANDIDATE_SCHEMA_REFUSED")
    location = _location(
        api=candidate["api"],
        file=candidate["file"],
        line=candidate["line"],
        column=candidate["column"],
    )
    expected = candidate_id(**location)
    if candidate["candidate_id"] != expected:
        raise ValueError("CANDIDATE_IDENTITY_REFUSED")
    return {"candidate_id": expected, **location}


def terminal_record(
    candidate: Mapping[str, object],
    bucket: str,
    *,
    reason_code: str | None = None,
    reason_detail: str | None = None,
    raw_type: str | None = None,
    environment: str | None = None,
    provenance: Iterable[str],
) -> dict:
    """Bind one candidate to exactly one terminal coverage disposition."""

    observed = _validate_candidate(candidate)
    if bucket not in TERMINAL_BUCKETS:
        raise ValueError("COVERAGE_BUCKET_REFUSED")
    if bucket == "EXERCISED":
        if any(value is not None for value in (reason_code, reason_detail, raw_type, environment)):
            raise ValueError("EXERCISED_DETAIL_REFUSED")
    elif reason_code is None:
        raise ValueError("COVERAGE_REASON_REQUIRED")
    row = {
        **observed,
        "bucket": bucket,
        "provenance": list(order_provenance(provenance)),
    }
    for name, value in (
        ("reason_code", reason_code),
        ("reason_detail", reason_detail),
        ("raw_type", raw_type),
        ("environment", environment),
    ):
        if value is not None:
            row[name] = _nonempty_text(value, "COVERAGE_DETAIL_REFUSED")
    return row


def finalize_terminal_records(records: Iterable[Mapping[str, object]]) -> list[dict]:
    """Validate uniqueness and return canonical candidate-id order."""

    observed = []
    identities = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("CANDIDATE_TERMINAL_SCHEMA_REFUSED")
        candidate = {
            key: record[key]
            for key in ("candidate_id", "api", "file", "line", "column")
            if key in record
        }
        validated = _validate_candidate(candidate)
        identity = validated["candidate_id"]
        if identity in identities:
            raise ValueError("CANDIDATE_TERMINAL_DUPLICATE")
        identities.add(identity)
        bucket = record.get("bucket")
        if bucket not in TERMINAL_BUCKETS:
            raise ValueError("COVERAGE_BUCKET_REFUSED")
        allowed = {
            "candidate_id",
            "api",
            "file",
            "line",
            "column",
            "bucket",
            "provenance",
            "reason_code",
            "reason_detail",
            "raw_type",
            "environment",
        }
        if not set(record).issubset(allowed):
            raise ValueError("CANDIDATE_TERMINAL_SCHEMA_REFUSED")
        rebuilt = terminal_record(
            validated,
            bucket,
            reason_code=record.get("reason_code"),
            reason_detail=record.get("reason_detail"),
            raw_type=record.get("raw_type"),
            environment=record.get("environment"),
            provenance=record.get("provenance", ()),
        )
        if rebuilt != dict(record):
            raise ValueError("CANDIDATE_TERMINAL_CANONICAL_REFUSED")
        observed.append(rebuilt)
    return sorted(observed, key=lambda row: row["candidate_id"])


def count_terminal_records(records: Iterable[Mapping[str, object]]) -> dict:
    finalized = finalize_terminal_records(records)
    counts = {bucket: 0 for bucket in TERMINAL_BUCKETS}
    for record in finalized:
        counts[record["bucket"]] += 1
    counts["total"] = len(finalized)
    return counts
