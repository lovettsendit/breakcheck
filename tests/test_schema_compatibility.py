from __future__ import annotations

import copy
import hashlib
import json

import pytest

from breakcheck.core.models import ArtifactEnvelope
from breakcheck.report import render_human
from breakcheck.schema import (
    artifact_digest,
    canonicalize_invocation,
    make_artifact,
    record_identity,
    validate_artifact,
    verify_artifact,
)
from breakcheck.verify import verify_report


def _sha(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _observation(value: object = False, *, provenance: str = "SOURCE_LITERAL"):
    return {
        "kind": "value",
        "payload": value,
        "exception_class": None,
        "provenance": [provenance],
    }


def _dependency_payload(*, projected: bool = False):
    old = _observation()
    new = _observation()
    projection = None
    verdict = "IDENTICAL"
    if projected:
        projection = {
            "source": "outcome.value",
            "sha256": _sha("outcome.value"),
        }
        verdict = "IDENTICAL_UNDER_PROJECTION"
    finding = {
        "finding_id": "",
        "candidate_id": "a" * 64,
        "api": "sample.has",
        "call_sites": [{"file": "app.py", "line": 3, "column": 4}],
        "verdict": verdict,
        "old": old,
        "new": new,
        "reason_code": None,
        "reason_detail": None,
        "comparison": {
            "verdict": "IDENTICAL",
            "detail": {
                "reason_code": "EQUAL",
                "path": None,
                "old_summary": "value:bool:false",
                "new_summary": "value:bool:false",
                "policy": "canonical_json_strict",
            },
        },
        "projection": projection,
        "fixture_binding_sha256": None,
        "suggested_action": [],
    }
    finding["finding_id"] = record_identity(finding, "finding_id")
    witness = {
        "witness_id": "",
        "finding_id": finding["finding_id"],
        "candidate_id": finding["candidate_id"],
        "old_observation_sha256": _sha(old),
        "new_observation_sha256": _sha(new),
        "old_repeat_sha256": [_sha(old), _sha(old)],
        "new_repeat_sha256": [_sha(new), _sha(new)],
        "projection_sha256": None if projection is None else projection["sha256"],
        "provenance": ["SOURCE_LITERAL"],
        "replay": {
            "source": "import sample\n\noutcome = sample.has(1)\n",
            "sha256": _sha("import sample\n\noutcome = sample.has(1)\n"),
        },
    }
    witness["witness_id"] = record_identity(witness, "witness_id")
    summary = {
        "changed": 0,
        "changed_under_projection": 0,
        "identical": 0 if projected else 1,
        "identical_under_projection": 1 if projected else 0,
        "not_exercised": 0,
    }
    return {
        "package": "sample",
        "current_version": "1.0",
        "new_version": "2.0",
        "coverage": {"exercised": 1, "total": 1, "percent": 100.0},
        "findings": [finding],
        "witnesses": [witness],
        "summary": summary,
        "invocation": canonicalize_invocation(
            "dependency_report",
            {
                "allow_empty": False,
                "fixture_policy": "forbid",
                "min_coverage": 80.0,
            },
        ),
    }


def _evidence_for(report):
    payload = report["payload"]
    return make_artifact(
        "evidence",
        {
            "report_artifact_sha256": artifact_digest(report),
            "report_payload_sha256": report["payload_sha256"],
            "report_kind": report["artifact_kind"],
            "witnesses": copy.deepcopy(payload["witnesses"]),
            "environment_artifacts": [
                {"name": "current", "sha256": "c" * 64},
                {"name": "new", "sha256": "d" * 64},
            ],
            "invocation": copy.deepcopy(payload["invocation"]),
        },
    )


def test_schema_two_dependency_artifact_is_closed_and_self_verifying():
    artifact = make_artifact("dependency_report", _dependency_payload())
    assert artifact["schema_version"] == 2
    assert artifact["artifact_kind"] == "dependency_report"
    assert verify_artifact(artifact) == "VERIFIED"


def test_artifact_envelope_model_validates_and_does_not_alias_mutable_input():
    artifact = make_artifact("dependency_report", _dependency_payload())
    model = ArtifactEnvelope.from_mapping(artifact)
    artifact["payload"]["package"] = "mutated"
    assert model.to_dict()["payload"]["package"] == "sample"
    assert model.to_dict()["payload_sha256"] == model.payload_sha256


def test_schema_two_dependency_bundle_verifies_report_and_evidence_identity():
    report = make_artifact("dependency_report", _dependency_payload())
    evidence = _evidence_for(report)
    assert verify_report(report, evidence) == "VERIFIED"


def test_schema_two_rejects_unknown_envelope_payload_and_nested_fields():
    artifact = make_artifact("dependency_report", _dependency_payload())
    unknown_envelope = copy.deepcopy(artifact)
    unknown_envelope["extra"] = True
    unknown_payload = copy.deepcopy(artifact)
    unknown_payload["payload"]["extra"] = True
    unknown_nested = copy.deepcopy(artifact)
    unknown_nested["payload"]["coverage"]["extra"] = True
    for mutated in (unknown_envelope, unknown_payload, unknown_nested):
        with pytest.raises(ValueError, match="ARTIFACT_SCHEMA_REFUSED"):
            validate_artifact(mutated)


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("count", "ARTIFACT_COUNT_REFUSED"),
        ("finding_identity", "ARTIFACT_IDENTITY_REFUSED"),
        ("missing_provenance", "ARTIFACT_PROVENANCE_REFUSED"),
        ("repeat_mismatch", "ARTIFACT_REPEAT_REFUSED"),
        ("projection_scope", "ARTIFACT_PROJECTION_REFUSED"),
    ],
)
def test_schema_two_rejects_semantically_invalid_dependency_artifacts(mutation, code):
    payload = _dependency_payload(projected=mutation == "projection_scope")
    if mutation == "count":
        payload["summary"]["identical"] = 0
    elif mutation == "finding_identity":
        payload["findings"][0]["finding_id"] = "0" * 64
    elif mutation == "missing_provenance":
        payload["findings"][0]["old"]["provenance"] = []
        payload["findings"][0]["finding_id"] = record_identity(
            payload["findings"][0], "finding_id"
        )
        payload["witnesses"][0]["finding_id"] = payload["findings"][0]["finding_id"]
        payload["witnesses"][0]["witness_id"] = record_identity(
            payload["witnesses"][0], "witness_id"
        )
    elif mutation == "repeat_mismatch":
        payload["witnesses"][0]["old_repeat_sha256"][1] = "0" * 64
        payload["witnesses"][0]["witness_id"] = record_identity(
            payload["witnesses"][0], "witness_id"
        )
    else:
        payload["findings"][0]["verdict"] = "IDENTICAL"
        payload["findings"][0]["finding_id"] = record_identity(
            payload["findings"][0], "finding_id"
        )
    with pytest.raises(ValueError, match=code):
        make_artifact("dependency_report", payload)


def test_schema_two_rejects_tampering_and_non_json_values():
    artifact = make_artifact("dependency_report", _dependency_payload())
    artifact["payload"]["package"] = "changed"
    with pytest.raises(ValueError, match="ARTIFACT_HASH_REFUSED"):
        verify_artifact(artifact)
    payload = _dependency_payload()
    payload["package"] = object()
    with pytest.raises(ValueError, match="ARTIFACT_ENCODING_REFUSED"):
        make_artifact("dependency_report", payload)
    payload = _dependency_payload()
    nested = None
    for _ in range(70):
        nested = [nested]
    payload["findings"][0]["old"]["payload"] = nested
    with pytest.raises(ValueError, match="ARTIFACT_ENCODING_REFUSED"):
        make_artifact("dependency_report", payload)


def test_coverage_artifact_enforces_one_terminal_bucket_per_candidate_and_counts():
    candidate = {
        "candidate_id": "a" * 64,
        "api": "sample.has",
        "file": "app.py",
        "line": 3,
        "column": 4,
        "bucket": "EXERCISED",
        "provenance": ["SOURCE_LITERAL"],
    }
    payload = {
        "package": "sample",
        "current_version": "1.0",
        "new_version": "2.0",
        "candidates": [candidate],
        "counts": {
            "EXERCISED": 1,
            "G1_NOT_DISCOVERABLE": 0,
            "G2_NONLITERAL": 0,
            "G3_UNNORMALIZABLE": 0,
            "G4_IMPURE": 0,
            "total": 1,
        },
        "invocation": canonicalize_invocation(
            "coverage_report",
            {
                "allow_empty": False,
                "fixture_policy": "forbid",
                "min_coverage": 80.0,
            },
        ),
    }
    assert verify_artifact(make_artifact("coverage_report", payload)) == "VERIFIED"
    payload["counts"]["EXERCISED"] = 0
    with pytest.raises(ValueError, match="ARTIFACT_COUNT_REFUSED"):
        make_artifact("coverage_report", payload)


def test_invocation_flags_are_sorted_closed_and_reject_unsanitized_paths():
    observed = canonicalize_invocation(
        "dependency_report",
        {"min_coverage": 80.0, "allow_empty": False, "fixture_policy": "forbid"},
    )
    assert [row["name"] for row in observed] == [
        "allow_empty",
        "fixture_policy",
        "min_coverage",
    ]
    with pytest.raises(ValueError, match="ARTIFACT_INVOCATION_REFUSED"):
        canonicalize_invocation("dependency_report", {"unknown": True})
    with pytest.raises(ValueError, match="ARTIFACT_PATH_REFUSED"):
        canonicalize_invocation(
            "dependency_report", {"fixture_file": "/private/location/fixtures.toml"}
        )


def test_human_output_puts_not_exercised_count_on_summary_line_and_names_projection():
    artifact = make_artifact("dependency_report", _dependency_payload(projected=True))
    rendered = render_human(artifact)
    assert "NOT_EXERCISED=0" in rendered.splitlines()[0]
    assert "IDENTICAL_UNDER_PROJECTION" in rendered
    assert "projection=outcome.value" in rendered


def test_historical_schema_one_bundle_still_verifies_with_unchanged_contract():
    observation = {
        "kind": "value",
        "payload": False,
        "exception_class": None,
        "duration_ms": None,
    }
    finding = {
        "finding_id": "",
        "api": "sample.has",
        "call_sites": [{"file": "app.py", "line": 3, "column": 4}],
        "verdict": "IDENTICAL",
        "old": observation,
        "new": observation,
        "repro": {
            "snippet_id": "a" * 64,
            "api": "sample.has",
            "call_sites": [{"file": "app.py", "line": 3, "column": 4}],
            "code": "import sample\noutcome = sample.has(1)\n",
            "args_source": "literal",
            "reason_code": None,
        },
        "suggested_action": [],
        "reason_code": None,
        "comparison": {
            "verdict": "IDENTICAL",
            "detail": {
                "reason_code": "EQUAL",
                "path": None,
                "old_summary": "value:bool:false",
                "new_summary": "value:bool:false",
                "policy": "canonical_json_strict",
            },
        },
    }
    finding["finding_id"] = _sha(
        {key: value for key, value in finding.items() if key != "finding_id"}
    )
    witness = {
        "witness_id": "",
        "finding_id": finding["finding_id"],
        "snippet_id": "a" * 64,
        "api": "sample.has",
        "code": "import sample\noutcome = sample.has(1)\n",
        "current_version": "1.0",
        "new_version": "2.0",
        "old_observation_sha256": _sha(observation),
        "new_observation_sha256": _sha(observation),
    }
    witness["witness_id"] = _sha(witness)
    report = {
        "schema_version": 1,
        "package": "sample",
        "current_version": "1.0",
        "new_version": "2.0",
        "coverage": {"exercised": 1, "total": 1, "percent": 100.0},
        "findings": [finding],
        "witnesses": [witness],
        "summary": {"changed": 0, "identical": 1, "not_exercised": 0},
    }
    evidence = {
        "report": copy.deepcopy(report),
        "report_sha256": _sha(report),
        "witnesses": copy.deepcopy(report["witnesses"]),
        "environment_artifacts": {},
    }
    evidence["witness_sha256"] = _sha(evidence)
    assert verify_report(report, evidence) == "VERIFIED"
