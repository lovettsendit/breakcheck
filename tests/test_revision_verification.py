from __future__ import annotations

import copy

import pytest

from breakcheck.report import ci_exit_code, render_human
from breakcheck.revision_report import make_evidence_artifact, make_revision_artifact
from breakcheck.schema import (
    artifact_digest,
    canonicalize_invocation,
    record_identity,
    verify_artifact,
)
from breakcheck.verify import verify_report


def _environment():
    return {
        "implementation": "cpython",
        "machine": "x86_64",
        "platform": "linux",
        "python": "3.12.0",
    }


def _fixture():
    return {
        "authored_by": "human",
        "sha256": "f" * 64,
        "source_revision": "a" * 40,
    }


def _observation():
    return {
        "kind": "value",
        "payload": 3,
        "exception_class": None,
        "provenance": ["OPERATOR_FIXTURE"],
    }


def _baseline_payload():
    observation = _observation()
    target = {
        "target_id": "",
        "module": "sample.pricing",
        "symbol": "compute_total",
        "definition_sha256": "d" * 64,
        "signature_sha256": "e" * 64,
        "observation": observation,
        "repeat_sha256": [artifact_digest(observation), artifact_digest(observation)],
        "projection_sha256": None,
    }
    target["target_id"] = record_identity(target, "target_id")
    return {
        "revision": "a" * 40,
        "tree_sha256": "b" * 64,
        "dirty": False,
        "allow_dirty": False,
        "environment": _environment(),
        "fixture": _fixture(),
        "target_observations": [target],
        "invocation": canonicalize_invocation(
            "baseline", {"allow_dirty": False, "fixture_policy": "require"}
        ),
    }


def _revision_payload():
    base = _observation()
    head = _observation()
    finding = {
        "finding_id": "",
        "target_id": "1" * 64,
        "module": "sample.pricing",
        "symbol": "compute_total",
        "verdict": "IDENTICAL",
        "base": base,
        "head": head,
        "reason_code": None,
        "projection": None,
        "fixture_binding_sha256": "2" * 64,
    }
    finding["finding_id"] = record_identity(finding, "finding_id")
    witness = {
        "witness_id": "",
        "finding_id": finding["finding_id"],
        "target_id": finding["target_id"],
        "base_observation_sha256": artifact_digest(base),
        "head_observation_sha256": artifact_digest(head),
        "base_repeat_sha256": [artifact_digest(base), artifact_digest(base)],
        "head_repeat_sha256": [artifact_digest(head), artifact_digest(head)],
        "projection_sha256": None,
        "provenance": ["OPERATOR_FIXTURE"],
        "replay": {
            "source": "import sample.pricing\n\noutcome = sample.pricing.compute_total(1)\n",
            "sha256": artifact_digest(
                "import sample.pricing\n\noutcome = sample.pricing.compute_total(1)\n"
            ),
        },
    }
    witness["witness_id"] = record_identity(witness, "witness_id")
    return {
        "base_revision": "a" * 40,
        "head_revision": "b" * 40,
        "base_tree_sha256": "c" * 64,
        "head_tree_sha256": "d" * 64,
        "findings": [finding],
        "witnesses": [witness],
        "summary": {
            "changed": 0,
            "changed_under_projection": 0,
            "identical": 1,
            "identical_under_projection": 0,
            "not_exercised": 0,
        },
        "fixture": _fixture(),
        "fixtures_predate_change": True,
        "fixture_revision_events": [],
        "invocation": canonicalize_invocation(
            "revision_report",
            {
                "fixture_policy": "require",
                "fixture_source": "base",
                "strict_separation": True,
            },
        ),
    }


def _claim_payload():
    disposition = {
        "disposition_id": "",
        "target_id": "1" * 64,
        "symbol": "sample.pricing:compute_total",
        "disposition": "CLAIM_VERIFIED",
        "reason_code": None,
        "projection_scope": None,
    }
    disposition["disposition_id"] = record_identity(
        disposition, "disposition_id"
    )
    return {
        "claim": "behavior_preserved",
        "base_revision": "a" * 40,
        "head_revision": "b" * 40,
        "dispositions": [disposition],
        "summary": {
            "claim_out_of_scope": 0,
            "claim_refuted": 0,
            "claim_unverifiable": 0,
            "claim_verified": 1,
            "total": 1,
        },
        "fixture": _fixture(),
        "fixtures_predate_change": True,
        "fixture_revision_events": [],
        "invocation": canonicalize_invocation(
            "claim_report",
            {
                "fixture_source": "base",
                "strict": True,
                "strict_separation": True,
            },
        ),
    }


@pytest.mark.parametrize(
    "kind,payload",
    [
        ("baseline", _baseline_payload()),
        ("revision_report", _revision_payload()),
        ("claim_report", _claim_payload()),
    ],
)
def test_revision_artifact_kinds_are_closed_self_verifying_and_bundle_bound(kind, payload):
    report = make_revision_artifact(kind, payload)
    evidence = make_evidence_artifact(
        report,
        environment_artifacts=[{"name": "revision", "sha256": "9" * 64}],
    )
    assert verify_artifact(report) == "VERIFIED"
    assert verify_report(report, evidence) == "VERIFIED"


def test_claim_summary_count_mismatch_and_out_of_scope_omission_are_refused():
    payload = _claim_payload()
    payload["summary"]["claim_verified"] = 0
    with pytest.raises(ValueError, match="ARTIFACT_COUNT_REFUSED"):
        make_revision_artifact("claim_report", payload)


def test_claim_human_output_states_projection_scope_explicitly():
    payload = _claim_payload()
    payload["dispositions"][0]["projection_scope"] = "outcome.total"
    payload["dispositions"][0]["disposition_id"] = record_identity(
        payload["dispositions"][0], "disposition_id"
    )
    rendered = render_human(make_revision_artifact("claim_report", payload))
    assert "CLAIM_UNVERIFIABLE=0" in rendered.splitlines()[0]
    assert "projection=outcome.total" in rendered


def test_schema_two_claim_exit_policy_honors_the_recorded_strict_flag():
    payload = _claim_payload()
    payload["dispositions"][0]["disposition"] = "CLAIM_UNVERIFIABLE"
    payload["dispositions"][0]["reason_code"] = "IMPORT_FAILED"
    payload["dispositions"][0]["disposition_id"] = record_identity(
        payload["dispositions"][0], "disposition_id"
    )
    payload["summary"] = {
        "claim_out_of_scope": 0,
        "claim_refuted": 0,
        "claim_unverifiable": 1,
        "claim_verified": 0,
        "total": 1,
    }

    strict = make_revision_artifact("claim_report", payload)
    assert ci_exit_code(strict) == 2

    payload["invocation"] = canonicalize_invocation(
        "claim_report",
        {
            "fixture_source": "base",
            "strict": False,
            "strict_separation": True,
        },
    )
    advisory = make_revision_artifact("claim_report", payload)
    assert ci_exit_code(advisory) == 0


def test_strict_claim_cannot_verify_unknown_or_post_change_fixture_authorship():
    payload = _claim_payload()
    payload["fixtures_predate_change"] = False
    with pytest.raises(ValueError, match="ARTIFACT_SEPARATION_REFUSED"):
        make_revision_artifact("claim_report", payload)
    payload = _claim_payload()
    payload["fixture"]["authored_by"] = "unknown"
    with pytest.raises(ValueError, match="ARTIFACT_SEPARATION_REFUSED"):
        make_revision_artifact("claim_report", payload)


def test_evidence_cannot_be_reused_for_another_report():
    report = make_revision_artifact("revision_report", _revision_payload())
    evidence = make_evidence_artifact(report, environment_artifacts=[])
    other = copy.deepcopy(report)
    other["payload"]["head_tree_sha256"] = "e" * 64
    other["payload_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="ARTIFACT_HASH_REFUSED"):
        verify_report(other, evidence)


def test_unknown_artifact_kind_version_and_environment_row_are_refused():
    payload = _baseline_payload()
    with pytest.raises(ValueError, match="ARTIFACT_KIND_REFUSED"):
        make_revision_artifact("other", payload)
    artifact = make_revision_artifact("baseline", payload)
    artifact["schema_version"] = 3
    with pytest.raises(ValueError, match="ARTIFACT_SCHEMA_VERSION_REFUSED"):
        verify_artifact(artifact)
    with pytest.raises(ValueError, match="ARTIFACT_SCHEMA_VERSION_REFUSED"):
        verify_report(artifact, {})
    clean = make_revision_artifact("baseline", _baseline_payload())
    with pytest.raises(ValueError, match="ARTIFACT_SCHEMA_REFUSED"):
        make_evidence_artifact(
            clean,
            environment_artifacts=[
                {"name": "revision", "sha256": "9" * 64, "path": "/tmp/private"}
            ],
        )
