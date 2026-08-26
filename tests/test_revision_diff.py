from __future__ import annotations

import copy

import pytest

from breakcheck.core.baselines import (
    BaselineRefusal,
    compare_frozen_baseline,
    detect_fixture_revision_after_failure,
    freeze_baseline,
)


BASE_REVISION = "1" * 40
HEAD_REVISION = "2" * 40
BASE_TREE = "3" * 64
HEAD_TREE = "4" * 64
FIXTURE_SHA256 = "5" * 64
BINDING_SHA256 = "6" * 64
TARGET_SHA256 = "7" * 64
HEAD_TARGET_SHA256 = "8" * 64
SIGNATURE_SHA256 = "9" * 64


def _environment() -> dict[str, str]:
    return {
        "implementation": "CPython",
        "python_version": "3.12.5",
        "platform": "linux-x86_64",
    }


def _fixture(sha256: str = FIXTURE_SHA256) -> dict[str, str]:
    return {
        "sha256": sha256,
        "source_revision": BASE_REVISION,
        "source": "base",
        "authored_by": "human",
    }


def _outcome(payload: object = 7) -> dict[str, object]:
    return {
        "status": "VALUE",
        "observation": {
            "kind": "value",
            "payload": payload,
            "exception_class": None,
            "duration_ms": None,
        },
        "reason_code": None,
        "repeatable": True,
    }


def _target(
    *,
    symbol: str = "sample.math:value",
    payload: object = 7,
    target_sha256: str = TARGET_SHA256,
    signature_sha256: str = SIGNATURE_SHA256,
    projection: str | None = None,
) -> dict[str, object]:
    return {
        "symbol": symbol,
        "target_sha256": target_sha256,
        "signature_sha256": signature_sha256,
        "fixture_binding_sha256": BINDING_SHA256,
        "provenance": "OPERATOR_FIXTURE",
        "projection": projection,
        "outcome": _outcome(payload),
    }


def _baseline(*targets: dict[str, object]) -> dict[str, object]:
    return freeze_baseline(
        revision=BASE_REVISION,
        tree_sha256=BASE_TREE,
        dirty=False,
        allow_dirty=False,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=list(targets or (_target(),)),
        invocation={"fixture_source": "base"},
    )


def test_revision_diff_reports_identical_changed_added_and_removed_without_guessing() -> None:
    """A wrong target census must not disappear additions, removals, or changes."""
    baseline = _baseline(
        _target(symbol="sample.math:changed", payload=1),
        _target(symbol="sample.math:identical", payload=2),
        _target(symbol="sample.math:removed", payload=3),
    )
    head = [
        _target(
            symbol="sample.math:changed",
            payload=4,
            target_sha256=HEAD_TARGET_SHA256,
        ),
        _target(
            symbol="sample.math:identical",
            payload=2,
            target_sha256=HEAD_TARGET_SHA256,
        ),
        _target(
            symbol="sample.math:added",
            payload=5,
            target_sha256=HEAD_TARGET_SHA256,
        ),
    ]

    report = compare_frozen_baseline(
        baseline,
        head_revision=HEAD_REVISION,
        head_tree_sha256=HEAD_TREE,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=head,
        fixtures_predate_change=True,
        invocation={"fixture_source": "base"},
    )

    assert [(row["symbol"], row["verdict"], row["reason_code"]) for row in report["findings"]] == [
        ("sample.math:added", "NOT_EXERCISED", "NO_BASELINE_REVISION"),
        ("sample.math:changed", "CHANGED", None),
        ("sample.math:identical", "IDENTICAL", None),
        ("sample.math:removed", "NOT_EXERCISED", "SYMBOL_REMOVED"),
    ]
    assert report["summary"] == {
        "changed": 1,
        "identical": 1,
        "not_exercised": 2,
        "total": 4,
    }
    assert report["base_revision"] == BASE_REVISION
    assert report["head_revision"] == HEAD_REVISION


def test_signature_drift_projection_scope_and_unrepeatable_head_are_explicit() -> None:
    """A changed signature, projection, or unstable run must not become IDENTICAL."""
    projected = _target(
        symbol="sample.math:projected",
        projection="outcome.value",
    )
    baseline = _baseline(
        projected,
        _target(symbol="sample.math:signature"),
        _target(symbol="sample.math:unstable"),
    )
    projected_head = copy.deepcopy(projected)
    projected_head["target_sha256"] = HEAD_TARGET_SHA256
    signature_head = _target(
        symbol="sample.math:signature",
        target_sha256=HEAD_TARGET_SHA256,
        signature_sha256="a" * 64,
    )
    unstable_head = _target(
        symbol="sample.math:unstable", target_sha256=HEAD_TARGET_SHA256
    )
    unstable_head["outcome"] = {
        "status": "PROTOCOL_REFUSED",
        "observation": None,
        "reason_code": "NONDETERMINISTIC_OBSERVATION",
        "repeatable": False,
    }

    report = compare_frozen_baseline(
        baseline,
        head_revision=HEAD_REVISION,
        head_tree_sha256=HEAD_TREE,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=[projected_head, signature_head, unstable_head],
        fixtures_predate_change=True,
        invocation={},
    )
    findings = {row["symbol"]: row for row in report["findings"]}

    assert findings["sample.math:projected"]["verdict"] == "IDENTICAL_UNDER_PROJECTION"
    assert findings["sample.math:projected"]["projection_scope"] == "outcome.value"
    assert findings["sample.math:signature"]["verdict"] == "NOT_EXERCISED"
    assert findings["sample.math:signature"]["reason_code"] == "FIXTURE_SIGNATURE_DRIFT"
    assert findings["sample.math:unstable"]["verdict"] == "NOT_EXERCISED"
    assert findings["sample.math:unstable"]["reason_code"] == "NONDETERMINISTIC_OBSERVATION"


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("missing", "NO_BASELINE_REVISION"),
        ("revision", "IDENTICAL_REVISIONS_REFUSED"),
        ("tree", "IDENTICAL_REVISIONS_REFUSED"),
        ("environment", "BASELINE_ENVIRONMENT_MISMATCH"),
        ("fixture", "BASELINE_FIXTURE_MISMATCH"),
        ("zero", "VACUOUS_REVISION_COMPARISON_REFUSED"),
    ],
)
def test_revision_diff_refuses_missing_vacuous_or_incomparable_inputs(
    mutation: str, code: str
) -> None:
    """No comparison may succeed without two distinct, comparable sides."""
    baseline = None if mutation == "missing" else _baseline()
    head_revision = BASE_REVISION if mutation == "revision" else HEAD_REVISION
    head_tree = BASE_TREE if mutation == "tree" else HEAD_TREE
    environment = _environment()
    fixture = _fixture()
    targets = [_target(target_sha256=HEAD_TARGET_SHA256)]
    if mutation == "environment":
        environment["platform"] = "different"
    elif mutation == "fixture":
        fixture["sha256"] = "a" * 64
    elif mutation == "zero":
        baseline = _baseline(_target(symbol="sample.math:only"))
        targets = []

    with pytest.raises(BaselineRefusal, match=f"^{code}$"):
        compare_frozen_baseline(
            baseline,
            head_revision=head_revision,
            head_tree_sha256=head_tree,
            environment=environment,
            fixture=fixture,
            target_observations=targets,
            fixtures_predate_change=True,
            invocation={},
        )


def test_custom_comparator_is_used_instead_of_a_second_equality_engine() -> None:
    """Integration must be able to delegate equality to the shared comparison rules."""
    calls: list[tuple[object, object]] = []

    def comparator(old: object, new: object) -> str:
        calls.append((old, new))
        return "IDENTICAL"

    report = compare_frozen_baseline(
        _baseline(),
        head_revision=HEAD_REVISION,
        head_tree_sha256=HEAD_TREE,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=[_target(payload=999, target_sha256=HEAD_TARGET_SHA256)],
        fixtures_predate_change=True,
        invocation={},
        comparator=comparator,
    )

    assert len(calls) == 1
    assert report["findings"][0]["verdict"] == "IDENTICAL"


def test_fixture_revision_after_changed_result_is_disclosed_deterministically() -> None:
    """Changing a fixture after a failure must remain visible to reviewers."""
    previous = {
        "base_revision": BASE_REVISION,
        "fixture_sha256": FIXTURE_SHA256,
        "findings": [
            {"symbol": "sample.math:value", "verdict": "CHANGED"},
            {"symbol": "sample.math:stable", "verdict": "IDENTICAL"},
        ],
    }
    current = {
        "base_revision": BASE_REVISION,
        "fixture_sha256": "a" * 64,
        "findings": [
            {"symbol": "sample.math:value", "verdict": "IDENTICAL"},
            {"symbol": "sample.math:stable", "verdict": "IDENTICAL"},
        ],
    }

    assert detect_fixture_revision_after_failure(previous, current) == (
        "sample.math:value",
    )
    assert detect_fixture_revision_after_failure(previous, previous) == ()


def test_fixture_revision_disclosure_accepts_full_revision_findings() -> None:
    """The disclosure helper must consume the real revision finding shape."""
    changed = compare_frozen_baseline(
        _baseline(),
        head_revision=HEAD_REVISION,
        head_tree_sha256=HEAD_TREE,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=[_target(payload=8, target_sha256=HEAD_TARGET_SHA256)],
        fixtures_predate_change=True,
        invocation={},
    )
    identical = copy.deepcopy(changed)
    identical["findings"][0]["verdict"] = "IDENTICAL"
    previous = {
        "base_revision": BASE_REVISION,
        "fixture_sha256": FIXTURE_SHA256,
        "findings": changed["findings"],
    }
    current = {
        "base_revision": BASE_REVISION,
        "fixture_sha256": "a" * 64,
        "findings": identical["findings"],
    }

    assert detect_fixture_revision_after_failure(previous, current) == (
        "sample.math:value",
    )
