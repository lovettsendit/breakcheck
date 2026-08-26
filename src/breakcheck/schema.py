"""Closed, deterministic schema-2 artifacts.

Schema 1 remains owned by :mod:`breakcheck.verify`.  This module defines the
major-version boundary used by all new dependency, coverage, revision, claim,
baseline, and evidence artifacts.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
from typing import Mapping


SCHEMA_VERSION = 2

_ENVELOPE_FIELDS = frozenset(
    ("schema_version", "artifact_kind", "payload", "payload_sha256")
)
_PAYLOAD_FIELDS = {
    "dependency_report": frozenset(
        (
            "package",
            "current_version",
            "new_version",
            "coverage",
            "findings",
            "witnesses",
            "summary",
            "invocation",
        )
    ),
    "coverage_report": frozenset(
        (
            "package",
            "current_version",
            "new_version",
            "candidates",
            "counts",
            "invocation",
        )
    ),
    "baseline": frozenset(
        (
            "revision",
            "tree_sha256",
            "dirty",
            "allow_dirty",
            "environment",
            "fixture",
            "target_observations",
            "invocation",
        )
    ),
    "revision_report": frozenset(
        (
            "base_revision",
            "head_revision",
            "base_tree_sha256",
            "head_tree_sha256",
            "findings",
            "witnesses",
            "summary",
            "fixture",
            "fixtures_predate_change",
            "fixture_revision_events",
            "invocation",
        )
    ),
    "claim_report": frozenset(
        (
            "claim",
            "base_revision",
            "head_revision",
            "dispositions",
            "summary",
            "fixture",
            "fixtures_predate_change",
            "fixture_revision_events",
            "invocation",
        )
    ),
    "evidence": frozenset(
        (
            "report_artifact_sha256",
            "report_payload_sha256",
            "report_kind",
            "witnesses",
            "environment_artifacts",
            "invocation",
        )
    ),
}

_SUMMARY_FIELDS = frozenset(
    (
        "changed",
        "changed_under_projection",
        "identical",
        "identical_under_projection",
        "not_exercised",
    )
)
_VERDICTS = frozenset(
    (
        "IDENTICAL",
        "CHANGED",
        "IDENTICAL_UNDER_PROJECTION",
        "CHANGED_UNDER_PROJECTION",
        "NOT_EXERCISED",
    )
)
_EXERCISED_VERDICTS = _VERDICTS - {"NOT_EXERCISED"}
_PROJECTION_VERDICTS = frozenset(
    ("IDENTICAL_UNDER_PROJECTION", "CHANGED_UNDER_PROJECTION")
)
_PROVENANCE_ORDER = (
    "SOURCE_LITERAL",
    "SOURCE_FOLDED",
    "SOURCE_MODULE_CONSTANT",
    "SOURCE_NESTED_CALL",
    "OPERATOR_FIXTURE",
    "RUNTIME_CAPTURE",
)
_PROVENANCE_POSITION = {
    value: position for position, value in enumerate(_PROVENANCE_ORDER)
}
_COVERAGE_BUCKETS = (
    "EXERCISED",
    "G1_NOT_DISCOVERABLE",
    "G2_NONLITERAL",
    "G3_UNNORMALIZABLE",
    "G4_IMPURE",
)
_CLAIM_DISPOSITIONS = (
    "CLAIM_VERIFIED",
    "CLAIM_REFUTED",
    "CLAIM_UNVERIFIABLE",
    "CLAIM_OUT_OF_SCOPE",
)
_CLAIM_COUNTS = {
    "CLAIM_VERIFIED": "claim_verified",
    "CLAIM_REFUTED": "claim_refuted",
    "CLAIM_UNVERIFIABLE": "claim_unverifiable",
    "CLAIM_OUT_OF_SCOPE": "claim_out_of_scope",
}
_HEX = re.compile(r"[0-9a-f]+\Z")
_FLAG_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]*\Z")
_INVOCATION_FLAGS = {
    "dependency_report": frozenset(
        (
            "allow_empty",
            "ci",
            "coverage_report",
            "fixture_file",
            "fixture_policy",
            "json",
            "min_coverage",
            "suggest_fixtures",
        )
    ),
    "coverage_report": frozenset(
        (
            "allow_empty",
            "fixture_file",
            "fixture_policy",
            "min_coverage",
            "suggest_fixtures",
        )
    ),
    "baseline": frozenset(
        ("allow_dirty", "fixture_file", "fixture_policy", "target")
    ),
    "revision_report": frozenset(
        (
            "allow_empty",
            "fixture_file",
            "fixture_policy",
            "fixture_source",
            "min_coverage",
            "strict_separation",
            "target",
            "previous_report_sha256",
        )
    ),
    "claim_report": frozenset(
        (
            "allow_empty",
            "claim_file",
            "fixture_file",
            "fixture_source",
            "min_coverage",
            "strict",
            "strict_separation",
            "previous_report_sha256",
        )
    ),
}


def _refuse(code: str) -> None:
    raise ValueError(code)


def _plain_json(value, *, _depth=0, _budget=None):
    if _budget is None:
        _budget = [0]
    _budget[0] += 1
    if _depth > 64 or _budget[0] > 100_000:
        _refuse("ARTIFACT_ENCODING_REFUSED")
    if value is None or type(value) in (bool, int, str):
        if type(value) is str and len(value.encode("utf-8")) > 65_536:
            _refuse("ARTIFACT_ENCODING_REFUSED")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _refuse("ARTIFACT_ENCODING_REFUSED")
        return value
    if type(value) is list:
        if len(value) > 10_000:
            _refuse("ARTIFACT_ENCODING_REFUSED")
        return [
            _plain_json(item, _depth=_depth + 1, _budget=_budget)
            for item in value
        ]
    if isinstance(value, Mapping):
        if len(value) > 10_000:
            _refuse("ARTIFACT_ENCODING_REFUSED")
        result = {}
        for key, item in value.items():
            if (
                type(key) is not str
                or key in result
                or len(key.encode("utf-8")) > 65_536
            ):
                _refuse("ARTIFACT_ENCODING_REFUSED")
            result[key] = _plain_json(
                item, _depth=_depth + 1, _budget=_budget
            )
        return result
    _refuse("ARTIFACT_ENCODING_REFUSED")


def canonical_json(value) -> str:
    return json.dumps(
        _plain_json(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def artifact_digest(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def record_identity(value: Mapping[str, object], field: str) -> str:
    if not isinstance(value, Mapping) or field not in value:
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    payload = _plain_json(copy.deepcopy(value))
    payload[field] = ""
    return artifact_digest(payload)


def _closed(value, fields, *, code="ARTIFACT_SCHEMA_REFUSED") -> dict:
    if not isinstance(value, dict) or set(value) != set(fields):
        _refuse(code)
    return value


def _text(value, *, code="ARTIFACT_SCHEMA_REFUSED", allow_empty=False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        _refuse(code)
    if len(value.encode("utf-8")) > 65_536:
        _refuse(code)
    return value


def _sha256(value, *, code="ARTIFACT_HASH_REFUSED") -> str:
    if type(value) is not str or len(value) != 64 or not _HEX.fullmatch(value):
        _refuse(code)
    return value


def _revision(value) -> str:
    if (
        type(value) is not str
        or len(value) not in (40, 64)
        or not _HEX.fullmatch(value)
    ):
        _refuse("ARTIFACT_REVISION_REFUSED")
    return value


def _nonnegative_integer(value, *, code="ARTIFACT_COUNT_REFUSED") -> int:
    if type(value) is not int or value < 0:
        _refuse(code)
    return value


def _relative_path(value) -> str:
    _text(value, code="ARTIFACT_PATH_REFUSED")
    if "\\" in value:
        _refuse("ARTIFACT_PATH_REFUSED")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        _refuse("ARTIFACT_PATH_REFUSED")
    if path.as_posix() != value:
        _refuse("ARTIFACT_PATH_REFUSED")
    return value


def _validate_flag_value(name, value):
    if name in {
        "allow_dirty",
        "allow_empty",
        "ci",
        "coverage_report",
        "json",
        "strict",
        "strict_separation",
        "suggest_fixtures",
    }:
        if type(value) is not bool:
            _refuse("ARTIFACT_INVOCATION_REFUSED")
    elif name == "min_coverage":
        if type(value) not in (int, float) or not 0 < float(value) <= 100:
            _refuse("ARTIFACT_INVOCATION_REFUSED")
    elif name == "fixture_policy":
        if value not in ("forbid", "allow", "require"):
            _refuse("ARTIFACT_INVOCATION_REFUSED")
    elif name == "fixture_source":
        if value not in ("base", "head", "explicit"):
            _refuse("ARTIFACT_INVOCATION_REFUSED")
    elif name in ("fixture_file", "claim_file"):
        _relative_path(value)
    elif name == "previous_report_sha256":
        _sha256(value, code="ARTIFACT_INVOCATION_REFUSED")
    elif name == "target":
        if not isinstance(value, list) or not value:
            _refuse("ARTIFACT_INVOCATION_REFUSED")
        for item in value:
            _text(item, code="ARTIFACT_INVOCATION_REFUSED")
    else:
        _refuse("ARTIFACT_INVOCATION_REFUSED")
    return _plain_json(value)


def canonicalize_invocation(kind: str, flags: Mapping[str, object]) -> list[dict]:
    allowed = _INVOCATION_FLAGS.get(kind)
    if allowed is None or not isinstance(flags, Mapping):
        _refuse("ARTIFACT_INVOCATION_REFUSED")
    if set(flags) - allowed or any(not _FLAG_NAME.fullmatch(name) for name in flags):
        _refuse("ARTIFACT_INVOCATION_REFUSED")
    return [
        {"name": name, "value": _validate_flag_value(name, flags[name])}
        for name in sorted(flags)
    ]


def _validate_invocation(value, kind: str) -> list[dict]:
    if not isinstance(value, list):
        _refuse("ARTIFACT_INVOCATION_REFUSED")
    flags = {}
    observed_names = []
    for row in value:
        _closed(row, ("name", "value"), code="ARTIFACT_INVOCATION_REFUSED")
        name = row["name"]
        if type(name) is not str or name in flags:
            _refuse("ARTIFACT_INVOCATION_REFUSED")
        flags[name] = row["value"]
        observed_names.append(name)
    if observed_names != sorted(observed_names):
        _refuse("ARTIFACT_INVOCATION_REFUSED")
    if canonicalize_invocation(kind, flags) != value:
        _refuse("ARTIFACT_INVOCATION_REFUSED")
    return value


def _validate_provenance(value) -> list[str]:
    if not isinstance(value, list) or not value or len(set(value)) != len(value):
        _refuse("ARTIFACT_PROVENANCE_REFUSED")
    if any(item not in _PROVENANCE_POSITION for item in value):
        _refuse("ARTIFACT_PROVENANCE_REFUSED")
    if value != sorted(value, key=_PROVENANCE_POSITION.__getitem__):
        _refuse("ARTIFACT_PROVENANCE_REFUSED")
    return value


def _validate_observation(value) -> dict:
    _closed(value, ("kind", "payload", "exception_class", "provenance"))
    kind = value["kind"]
    if kind not in ("value", "exception"):
        _refuse("ARTIFACT_OBSERVATION_REFUSED")
    _validate_provenance(value["provenance"])
    _plain_json(value["payload"])
    if kind == "value":
        if value["exception_class"] is not None:
            _refuse("ARTIFACT_OBSERVATION_REFUSED")
    elif (
        type(value["exception_class"]) is not str
        or not _NAME.fullmatch(value["exception_class"])
        or not isinstance(value["payload"], list)
    ):
        _refuse("ARTIFACT_OBSERVATION_REFUSED")
    return value


def _validate_projection(value):
    if value is None:
        return None
    _closed(value, ("source", "sha256"))
    source = _text(value["source"], code="ARTIFACT_PROJECTION_REFUSED")
    if "outcome" not in source or _sha256(
        value["sha256"], code="ARTIFACT_PROJECTION_REFUSED"
    ) != artifact_digest(source):
        _refuse("ARTIFACT_PROJECTION_REFUSED")
    return value


def _validate_replay(value):
    _closed(value, ("source", "sha256"))
    source = _text(value["source"], code="ARTIFACT_REPLAY_REFUSED")
    if _sha256(
        value["sha256"], code="ARTIFACT_REPLAY_REFUSED"
    ) != artifact_digest(source):
        _refuse("ARTIFACT_REPLAY_REFUSED")
    return value


def _validate_call_site(value):
    _closed(value, ("file", "line", "column"))
    _relative_path(value["file"])
    if type(value["line"]) is not int or value["line"] < 1:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    if type(value["column"]) is not int or value["column"] < 0:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    return value


def _validate_comparison(value):
    if value is None:
        return None
    _closed(value, ("verdict", "detail"))
    if value["verdict"] not in ("IDENTICAL", "CHANGED"):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    detail = _closed(
        value["detail"],
        ("reason_code", "path", "old_summary", "new_summary", "policy"),
    )
    for field in ("reason_code", "old_summary", "new_summary", "policy"):
        _text(detail[field])
    if detail["path"] is not None and (
        type(detail["path"]) is not str
        or (detail["path"] and not detail["path"].startswith("/"))
    ):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    return value


def _validate_actions(value):
    if not isinstance(value, list) or len(value) > 3:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    for row in value:
        _closed(row, ("kind", "argument"))
        if row["kind"] not in ("adapt", "pin", "review"):
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        _plain_json(row["argument"])
    return value


def _validate_finding(value, *, revision=False):
    if revision:
        fields = (
            "finding_id",
            "target_id",
            "module",
            "symbol",
            "verdict",
            "base",
            "head",
            "reason_code",
            "projection",
            "fixture_binding_sha256",
        )
        old_name, new_name = "base", "head"
    else:
        fields = (
            "finding_id",
            "candidate_id",
            "api",
            "call_sites",
            "verdict",
            "old",
            "new",
            "reason_code",
            "reason_detail",
            "comparison",
            "projection",
            "fixture_binding_sha256",
            "suggested_action",
        )
        old_name, new_name = "old", "new"
    _closed(value, fields)
    _sha256(value["finding_id"], code="ARTIFACT_IDENTITY_REFUSED")
    if value["finding_id"] != record_identity(value, "finding_id"):
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    identity_field = "target_id" if revision else "candidate_id"
    _sha256(value[identity_field], code="ARTIFACT_IDENTITY_REFUSED")
    if revision:
        _text(value["module"])
        _text(value["symbol"])
    else:
        _text(value["api"])
        if not isinstance(value["call_sites"], list) or not value["call_sites"]:
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        for site in value["call_sites"]:
            _validate_call_site(site)
        _validate_comparison(value["comparison"])
        _validate_actions(value["suggested_action"])
        if value["reason_detail"] is not None:
            _text(value["reason_detail"])
    verdict = value["verdict"]
    if verdict not in _VERDICTS:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    projection = _validate_projection(value["projection"])
    if (verdict in _PROJECTION_VERDICTS) != (projection is not None):
        _refuse("ARTIFACT_PROJECTION_REFUSED")
    binding = value["fixture_binding_sha256"]
    if binding is not None:
        _sha256(binding)
    if verdict == "NOT_EXERCISED":
        if value[old_name] is not None or value[new_name] is not None:
            _refuse("ARTIFACT_OBSERVATION_REFUSED")
        _text(value["reason_code"], code="ARTIFACT_OBSERVATION_REFUSED")
    else:
        _validate_observation(value[old_name])
        _validate_observation(value[new_name])
        if value["reason_code"] is not None:
            _refuse("ARTIFACT_OBSERVATION_REFUSED")
    return value


def _validate_repeat_hashes(value, expected) -> None:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(_sha256(item, code="ARTIFACT_REPEAT_REFUSED") != expected for item in value)
    ):
        _refuse("ARTIFACT_REPEAT_REFUSED")


def _validate_dependency_witness(value, finding):
    _closed(
        value,
        (
            "witness_id",
            "finding_id",
            "candidate_id",
            "old_observation_sha256",
            "new_observation_sha256",
            "old_repeat_sha256",
            "new_repeat_sha256",
            "projection_sha256",
            "provenance",
            "replay",
        ),
    )
    if value["witness_id"] != record_identity(value, "witness_id"):
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    if (
        value["finding_id"] != finding["finding_id"]
        or value["candidate_id"] != finding["candidate_id"]
    ):
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    old_digest = artifact_digest(finding["old"])
    new_digest = artifact_digest(finding["new"])
    if (
        value["old_observation_sha256"] != old_digest
        or value["new_observation_sha256"] != new_digest
    ):
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    _validate_repeat_hashes(value["old_repeat_sha256"], old_digest)
    _validate_repeat_hashes(value["new_repeat_sha256"], new_digest)
    expected_projection = (
        None if finding["projection"] is None else finding["projection"]["sha256"]
    )
    if value["projection_sha256"] != expected_projection:
        _refuse("ARTIFACT_PROJECTION_REFUSED")
    _validate_provenance(value["provenance"])
    _validate_replay(value["replay"])
    expected_provenance = finding["old"]["provenance"]
    if (
        value["provenance"] != expected_provenance
        or finding["new"]["provenance"] != expected_provenance
    ):
        _refuse("ARTIFACT_PROVENANCE_REFUSED")


def _validate_summary(value, findings):
    _closed(value, _SUMMARY_FIELDS)
    expected = {name: 0 for name in _SUMMARY_FIELDS}
    mapping = {
        "IDENTICAL": "identical",
        "CHANGED": "changed",
        "IDENTICAL_UNDER_PROJECTION": "identical_under_projection",
        "CHANGED_UNDER_PROJECTION": "changed_under_projection",
        "NOT_EXERCISED": "not_exercised",
    }
    for finding in findings:
        expected[mapping[finding["verdict"]]] += 1
    for count in value.values():
        _nonnegative_integer(count)
    if value != expected:
        _refuse("ARTIFACT_COUNT_REFUSED")


def _validate_coverage(value, findings):
    _closed(value, ("exercised", "total", "percent"))
    exercised = _nonnegative_integer(value["exercised"])
    total = _nonnegative_integer(value["total"])
    if total != len(findings) or exercised != sum(
        finding["verdict"] in _EXERCISED_VERDICTS for finding in findings
    ):
        _refuse("ARTIFACT_COUNT_REFUSED")
    percent = value["percent"]
    if type(percent) not in (int, float) or not math.isfinite(float(percent)):
        _refuse("ARTIFACT_COUNT_REFUSED")
    expected = 100.0 * exercised / total if total else 0.0
    if float(percent) != expected:
        _refuse("ARTIFACT_COUNT_REFUSED")


def _validate_dependency(payload):
    for field in ("package", "current_version", "new_version"):
        _text(payload[field])
    if not isinstance(payload["findings"], list) or not isinstance(
        payload["witnesses"], list
    ):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    findings = []
    by_id = {}
    for finding in payload["findings"]:
        _validate_finding(finding)
        if finding["finding_id"] in by_id:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        by_id[finding["finding_id"]] = finding
        findings.append(finding)
    if findings != sorted(findings, key=lambda item: item["finding_id"]):
        _refuse("ARTIFACT_ORDER_REFUSED")
    witnessed = set()
    for witness in payload["witnesses"]:
        finding = by_id.get(witness.get("finding_id") if isinstance(witness, dict) else None)
        if finding is None or finding["verdict"] == "NOT_EXERCISED":
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        _validate_dependency_witness(witness, finding)
        if finding["finding_id"] in witnessed:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        witnessed.add(finding["finding_id"])
    if payload["witnesses"] != sorted(
        payload["witnesses"], key=lambda item: item["witness_id"]
    ):
        _refuse("ARTIFACT_ORDER_REFUSED")
    if witnessed != {
        finding["finding_id"]
        for finding in findings
        if finding["verdict"] in _EXERCISED_VERDICTS
    }:
        _refuse("ARTIFACT_REPEAT_REFUSED")
    _validate_coverage(payload["coverage"], findings)
    _validate_summary(payload["summary"], findings)
    _validate_invocation(payload["invocation"], "dependency_report")


def _validate_coverage_report(payload):
    for field in ("package", "current_version", "new_version"):
        _text(payload[field])
    candidates = payload["candidates"]
    if not isinstance(candidates, list):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    identities = set()
    for row in candidates:
        required = {"candidate_id", "api", "file", "line", "column", "bucket", "provenance"}
        optional = {"reason_code", "reason_detail", "raw_type", "environment"}
        if not isinstance(row, dict) or not required.issubset(row) or set(row) - required - optional:
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        _sha256(row["candidate_id"], code="ARTIFACT_IDENTITY_REFUSED")
        if row["candidate_id"] in identities:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        identities.add(row["candidate_id"])
        _text(row["api"])
        _relative_path(row["file"])
        if type(row["line"]) is not int or row["line"] < 1 or type(row["column"]) is not int or row["column"] < 0:
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        if row["bucket"] not in _COVERAGE_BUCKETS:
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        _validate_provenance(row["provenance"])
        if row["bucket"] == "EXERCISED" and set(row) != required:
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        if row["bucket"] != "EXERCISED" and not row.get("reason_code"):
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        for name in optional & set(row):
            _text(row[name])
    if candidates != sorted(candidates, key=lambda item: item["candidate_id"]):
        _refuse("ARTIFACT_ORDER_REFUSED")
    counts = _closed(payload["counts"], (*_COVERAGE_BUCKETS, "total"))
    expected = {bucket: 0 for bucket in _COVERAGE_BUCKETS}
    for row in candidates:
        expected[row["bucket"]] += 1
    expected["total"] = len(candidates)
    for value in counts.values():
        _nonnegative_integer(value)
    if counts != expected:
        _refuse("ARTIFACT_COUNT_REFUSED")
    _validate_invocation(payload["invocation"], "coverage_report")


def _validate_environment(value):
    _closed(value, ("implementation", "machine", "platform", "python"))
    for item in value.values():
        _text(item)


def _validate_fixture(value):
    _closed(value, ("authored_by", "sha256", "source_revision"))
    if value["authored_by"] not in ("human", "agent", "unknown"):
        _refuse("ARTIFACT_PROVENANCE_REFUSED")
    _sha256(value["sha256"])
    _revision(value["source_revision"])


def _validate_baseline(payload):
    _revision(payload["revision"])
    _sha256(payload["tree_sha256"])
    if type(payload["dirty"]) is not bool or type(payload["allow_dirty"]) is not bool:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    if payload["dirty"] and not payload["allow_dirty"]:
        _refuse("ARTIFACT_DIRTY_REFUSED")
    _validate_environment(payload["environment"])
    _validate_fixture(payload["fixture"])
    targets = payload["target_observations"]
    if not isinstance(targets, list) or not targets:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    identities = set()
    for target in targets:
        _closed(
            target,
            (
                "target_id",
                "module",
                "symbol",
                "definition_sha256",
                "signature_sha256",
                "observation",
                "repeat_sha256",
                "projection_sha256",
            ),
        )
        if target["target_id"] != record_identity(target, "target_id") or target["target_id"] in identities:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        identities.add(target["target_id"])
        _text(target["module"])
        _text(target["symbol"])
        _sha256(target["definition_sha256"])
        _sha256(target["signature_sha256"])
        _validate_observation(target["observation"])
        _validate_repeat_hashes(
            target["repeat_sha256"], artifact_digest(target["observation"])
        )
        if target["projection_sha256"] is not None:
            _sha256(target["projection_sha256"])
    if targets != sorted(targets, key=lambda item: item["target_id"]):
        _refuse("ARTIFACT_ORDER_REFUSED")
    _validate_invocation(payload["invocation"], "baseline")


def _validate_revision_witness(value, finding):
    _closed(
        value,
        (
            "witness_id",
            "finding_id",
            "target_id",
            "base_observation_sha256",
            "head_observation_sha256",
            "base_repeat_sha256",
            "head_repeat_sha256",
            "projection_sha256",
            "provenance",
            "replay",
        ),
    )
    if value["witness_id"] != record_identity(value, "witness_id"):
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    if value["finding_id"] != finding["finding_id"] or value["target_id"] != finding["target_id"]:
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    base_digest = artifact_digest(finding["base"])
    head_digest = artifact_digest(finding["head"])
    if value["base_observation_sha256"] != base_digest or value["head_observation_sha256"] != head_digest:
        _refuse("ARTIFACT_IDENTITY_REFUSED")
    _validate_repeat_hashes(value["base_repeat_sha256"], base_digest)
    _validate_repeat_hashes(value["head_repeat_sha256"], head_digest)
    expected_projection = None if finding["projection"] is None else finding["projection"]["sha256"]
    if value["projection_sha256"] != expected_projection:
        _refuse("ARTIFACT_PROJECTION_REFUSED")
    _validate_provenance(value["provenance"])
    _validate_replay(value["replay"])
    if value["provenance"] != finding["base"]["provenance"] or value["provenance"] != finding["head"]["provenance"]:
        _refuse("ARTIFACT_PROVENANCE_REFUSED")


def _validate_fixture_revision_events(value, *, findings=None):
    if not isinstance(value, list):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    current_by_id = (
        None if findings is None else {row["finding_id"]: row for row in findings}
    )
    event_ids = set()
    targets = set()
    for row in value:
        _closed(
            row,
            (
                "event_id",
                "target_id",
                "prior_finding_id",
                "current_finding_id",
                "prior_fixture_binding_sha256",
                "current_fixture_binding_sha256",
                "prior_verdict",
                "current_verdict",
                "reason_code",
            ),
        )
        if (
            row["event_id"] != record_identity(row, "event_id")
            or row["event_id"] in event_ids
            or row["target_id"] in targets
        ):
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        event_ids.add(row["event_id"])
        targets.add(row["target_id"])
        for name in (
            "target_id",
            "prior_finding_id",
            "current_finding_id",
            "prior_fixture_binding_sha256",
            "current_fixture_binding_sha256",
        ):
            _sha256(row[name], code="ARTIFACT_IDENTITY_REFUSED")
        if row["prior_fixture_binding_sha256"] == row["current_fixture_binding_sha256"]:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        if row["prior_verdict"] not in (
            "CHANGED",
            "CHANGED_UNDER_PROJECTION",
        ) or row["current_verdict"] not in (
            "IDENTICAL",
            "IDENTICAL_UNDER_PROJECTION",
        ):
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        if row["reason_code"] != "FIXTURE_REVISED_AFTER_FAILURE":
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        if current_by_id is not None:
            current = current_by_id.get(row["current_finding_id"])
            if (
                current is None
                or current["target_id"] != row["target_id"]
                or current["fixture_binding_sha256"]
                != row["current_fixture_binding_sha256"]
                or current["verdict"] != row["current_verdict"]
            ):
                _refuse("ARTIFACT_IDENTITY_REFUSED")
    if value != sorted(value, key=lambda row: row["event_id"]):
        _refuse("ARTIFACT_ORDER_REFUSED")
    return value


def _validate_revision_report(payload):
    for field in ("base_revision", "head_revision"):
        _revision(payload[field])
    for field in ("base_tree_sha256", "head_tree_sha256"):
        _sha256(payload[field])
    if type(payload["fixtures_predate_change"]) is not bool:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    _validate_fixture(payload["fixture"])
    findings = payload["findings"]
    witnesses = payload["witnesses"]
    if not isinstance(findings, list) or not isinstance(witnesses, list):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    by_id = {}
    for finding in findings:
        _validate_finding(finding, revision=True)
        if finding["finding_id"] in by_id:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        by_id[finding["finding_id"]] = finding
    if findings != sorted(findings, key=lambda item: item["finding_id"]):
        _refuse("ARTIFACT_ORDER_REFUSED")
    witnessed = set()
    for witness in witnesses:
        finding = by_id.get(witness.get("finding_id") if isinstance(witness, dict) else None)
        if finding is None or finding["verdict"] == "NOT_EXERCISED":
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        _validate_revision_witness(witness, finding)
        if finding["finding_id"] in witnessed:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        witnessed.add(finding["finding_id"])
    if witnessed != {row["finding_id"] for row in findings if row["verdict"] in _EXERCISED_VERDICTS}:
        _refuse("ARTIFACT_REPEAT_REFUSED")
    if witnesses != sorted(witnesses, key=lambda item: item["witness_id"]):
        _refuse("ARTIFACT_ORDER_REFUSED")
    _validate_fixture_revision_events(
        payload["fixture_revision_events"], findings=findings
    )
    _validate_summary(payload["summary"], findings)
    _validate_invocation(payload["invocation"], "revision_report")


def _invocation_mapping(value) -> dict:
    return {row["name"]: row["value"] for row in value}


def _validate_claim_report(payload):
    if payload["claim"] != "behavior_preserved":
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    _revision(payload["base_revision"])
    _revision(payload["head_revision"])
    if type(payload["fixtures_predate_change"]) is not bool:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    _validate_fixture(payload["fixture"])
    dispositions = payload["dispositions"]
    if not isinstance(dispositions, list) or not dispositions:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    identities = set()
    counts = {name: 0 for name in _CLAIM_COUNTS.values()}
    for row in dispositions:
        _closed(
            row,
            (
                "disposition_id",
                "target_id",
                "symbol",
                "disposition",
                "reason_code",
                "projection_scope",
            ),
        )
        if row["disposition_id"] != record_identity(row, "disposition_id") or row["disposition_id"] in identities:
            _refuse("ARTIFACT_IDENTITY_REFUSED")
        identities.add(row["disposition_id"])
        _sha256(row["target_id"], code="ARTIFACT_IDENTITY_REFUSED")
        _text(row["symbol"])
        if row["disposition"] not in _CLAIM_DISPOSITIONS:
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        counts[_CLAIM_COUNTS[row["disposition"]]] += 1
        if row["disposition"] == "CLAIM_VERIFIED":
            if row["reason_code"] is not None:
                _refuse("ARTIFACT_SCHEMA_REFUSED")
        else:
            _text(row["reason_code"])
        if row["projection_scope"] is not None:
            _text(row["projection_scope"], code="ARTIFACT_PROJECTION_REFUSED")
    if dispositions != sorted(dispositions, key=lambda item: item["disposition_id"]):
        _refuse("ARTIFACT_ORDER_REFUSED")
    summary = _closed(payload["summary"], (*counts, "total"))
    expected = {**counts, "total": len(dispositions)}
    for value in summary.values():
        _nonnegative_integer(value)
    if summary != expected:
        _refuse("ARTIFACT_COUNT_REFUSED")
    _validate_fixture_revision_events(payload["fixture_revision_events"])
    _validate_invocation(payload["invocation"], "claim_report")
    flags = _invocation_mapping(payload["invocation"])
    if flags.get("strict_separation") is True:
        if (
            not payload["fixtures_predate_change"]
            or payload["fixture"]["authored_by"] == "unknown"
        ):
            _refuse("ARTIFACT_SEPARATION_REFUSED")


def _validate_evidence(payload):
    _sha256(payload["report_artifact_sha256"])
    _sha256(payload["report_payload_sha256"])
    report_kind = payload["report_kind"]
    if report_kind not in _PAYLOAD_FIELDS or report_kind == "evidence":
        _refuse("ARTIFACT_KIND_REFUSED")
    if not isinstance(payload["witnesses"], list):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    _plain_json(payload["witnesses"])
    rows = payload["environment_artifacts"]
    if not isinstance(rows, list):
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    names = []
    for row in rows:
        _closed(row, ("name", "sha256"))
        if type(row["name"]) is not str or not _NAME.fullmatch(row["name"]):
            _refuse("ARTIFACT_SCHEMA_REFUSED")
        _sha256(row["sha256"])
        names.append(row["name"])
    if names != sorted(set(names)):
        _refuse("ARTIFACT_ORDER_REFUSED")
    _validate_invocation(payload["invocation"], report_kind)


_VALIDATORS = {
    "dependency_report": _validate_dependency,
    "coverage_report": _validate_coverage_report,
    "baseline": _validate_baseline,
    "revision_report": _validate_revision_report,
    "claim_report": _validate_claim_report,
    "evidence": _validate_evidence,
}


def validate_artifact(value):
    if not isinstance(value, Mapping) or set(value) != _ENVELOPE_FIELDS:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    artifact = _plain_json(copy.deepcopy(value))
    if artifact["schema_version"] != SCHEMA_VERSION:
        _refuse("ARTIFACT_SCHEMA_VERSION_REFUSED")
    kind = artifact["artifact_kind"]
    expected = _PAYLOAD_FIELDS.get(kind)
    if expected is None:
        _refuse("ARTIFACT_KIND_REFUSED")
    payload = artifact["payload"]
    if not isinstance(payload, dict) or set(payload) != expected:
        _refuse("ARTIFACT_SCHEMA_REFUSED")
    _sha256(artifact["payload_sha256"])
    _VALIDATORS[kind](payload)
    return artifact


def make_artifact(kind: str, payload: Mapping[str, object]):
    if kind not in _PAYLOAD_FIELDS:
        _refuse("ARTIFACT_KIND_REFUSED")
    plain_payload = _plain_json(copy.deepcopy(payload))
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": kind,
        "payload": plain_payload,
        "payload_sha256": artifact_digest(plain_payload),
    }
    return validate_artifact(artifact)


def verify_artifact(value) -> str:
    artifact = validate_artifact(value)
    if artifact["payload_sha256"] != artifact_digest(artifact["payload"]):
        _refuse("ARTIFACT_HASH_REFUSED")
    return "VERIFIED"


__all__ = (
    "SCHEMA_VERSION",
    "artifact_digest",
    "canonical_json",
    "canonicalize_invocation",
    "make_artifact",
    "record_identity",
    "validate_artifact",
    "verify_artifact",
)
