from __future__ import annotations

import copy

import pytest

from breakcheck.core.baselines import BaselineRefusal, freeze_baseline, validate_baseline


BASE_REVISION = "1" * 40
TREE_SHA256 = "2" * 64
FIXTURE_SHA256 = "3" * 64
BINDING_SHA256 = "4" * 64
TARGET_SHA256 = "5" * 64
SIGNATURE_SHA256 = "6" * 64


def _environment() -> dict[str, str]:
    return {
        "implementation": "CPython",
        "python_version": "3.12.5",
        "platform": "darwin-arm64",
    }


def _fixture() -> dict[str, str]:
    return {
        "sha256": FIXTURE_SHA256,
        "source_revision": BASE_REVISION,
        "source": "base",
        "authored_by": "human",
    }


def _target(symbol: str = "sample.math:value") -> dict[str, object]:
    return {
        "symbol": symbol,
        "target_sha256": TARGET_SHA256,
        "signature_sha256": SIGNATURE_SHA256,
        "fixture_binding_sha256": BINDING_SHA256,
        "provenance": "OPERATOR_FIXTURE",
        "projection": None,
        "outcome": {
            "status": "VALUE",
            "observation": {
                "kind": "value",
                "payload": 7,
                "exception_class": None,
                "duration_ms": None,
            },
            "reason_code": None,
            "repeatable": True,
        },
    }


def test_freeze_binds_revision_environment_fixture_target_and_invocation() -> None:
    """Removing any identity field would make a baseline mutable or ambiguous."""
    baseline = freeze_baseline(
        revision=BASE_REVISION,
        tree_sha256=TREE_SHA256,
        dirty=False,
        allow_dirty=False,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=[_target()],
        invocation={"allow_dirty": False, "fixture_source": "base"},
    )

    assert baseline == {
        "revision": BASE_REVISION,
        "tree_sha256": TREE_SHA256,
        "dirty": False,
        "allow_dirty": False,
        "environment": _environment(),
        "fixture": _fixture(),
        "target_observations": [_target()],
        "invocation": {"allow_dirty": False, "fixture_source": "base"},
    }
    assert validate_baseline(copy.deepcopy(baseline)) == baseline


def test_dirty_tree_is_refused_by_default_and_explicitly_recorded_when_allowed() -> None:
    """A dirty checkout must never be silently represented as a committed revision."""
    with pytest.raises(BaselineRefusal, match="^DIRTY_TREE_REFUSED$"):
        freeze_baseline(
            revision=BASE_REVISION,
            tree_sha256=TREE_SHA256,
            dirty=True,
            allow_dirty=False,
            environment=_environment(),
            fixture=_fixture(),
            target_observations=[_target()],
            invocation={"allow_dirty": False},
        )

    baseline = freeze_baseline(
        revision=BASE_REVISION,
        tree_sha256=TREE_SHA256,
        dirty=True,
        allow_dirty=True,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=[_target()],
        invocation={"allow_dirty": True},
    )
    assert baseline["dirty"] is True
    assert baseline["allow_dirty"] is True
    assert baseline["invocation"]["allow_dirty"] is True


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("environment", "BASELINE_ENVIRONMENT_REFUSED"),
        ("fixture", "BASELINE_FIXTURE_REFUSED"),
        ("target_hash", "BASELINE_TARGET_REFUSED"),
        ("signature_hash", "BASELINE_TARGET_REFUSED"),
        ("binding_hash", "BASELINE_TARGET_REFUSED"),
        ("repeatability", "BASELINE_OBSERVATION_REFUSED"),
        ("status", "BASELINE_OBSERVATION_REFUSED"),
        ("duplicate", "BASELINE_DUPLICATE_TARGET_REFUSED"),
        ("empty", "VACUOUS_BASELINE_REFUSED"),
        ("path", "BASELINE_PATH_REFUSED"),
    ],
)
def test_freeze_fails_closed_when_required_evidence_is_missing_or_unsafe(
    mutation: str, code: str
) -> None:
    """Malformed evidence must refuse instead of producing a partial baseline."""
    environment = _environment()
    fixture = _fixture()
    targets = [_target()]
    if mutation == "environment":
        environment.pop("platform")
    elif mutation == "fixture":
        fixture["unknown"] = "value"
    elif mutation == "target_hash":
        targets[0]["target_sha256"] = "bad"
    elif mutation == "signature_hash":
        targets[0]["signature_sha256"] = "bad"
    elif mutation == "binding_hash":
        targets[0]["fixture_binding_sha256"] = "bad"
    elif mutation == "repeatability":
        targets[0]["outcome"]["repeatable"] = False  # type: ignore[index]
    elif mutation == "status":
        targets[0]["outcome"]["status"] = "NETWORK_REFUSED"  # type: ignore[index]
    elif mutation == "duplicate":
        targets.append(_target())
    elif mutation == "empty":
        targets = []

    invocation: dict[str, object] = {"allow_dirty": False}
    if mutation == "path":
        invocation["runtime_root"] = "/private/location"

    with pytest.raises(BaselineRefusal, match=f"^{code}$"):
        freeze_baseline(
            revision=BASE_REVISION,
            tree_sha256=TREE_SHA256,
            dirty=False,
            allow_dirty=False,
            environment=environment,
            fixture=fixture,
            target_observations=targets,
            invocation=invocation,
        )


def test_freeze_is_deterministic_and_does_not_mutate_inputs() -> None:
    """Input ordering and caller mutation must not alter persisted baseline bytes."""
    first_target = _target("sample.math:zeta")
    second_target = _target("sample.math:alpha")
    targets = [first_target, second_target]
    original = copy.deepcopy(targets)

    first = freeze_baseline(
        revision=BASE_REVISION,
        tree_sha256=TREE_SHA256,
        dirty=False,
        allow_dirty=False,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=targets,
        invocation={"fixture_source": "base", "allow_dirty": False},
    )
    second = freeze_baseline(
        revision=BASE_REVISION,
        tree_sha256=TREE_SHA256,
        dirty=False,
        allow_dirty=False,
        environment=_environment(),
        fixture=_fixture(),
        target_observations=list(reversed(targets)),
        invocation={"allow_dirty": False, "fixture_source": "base"},
    )

    assert first == second
    assert [row["symbol"] for row in first["target_observations"]] == [
        "sample.math:alpha",
        "sample.math:zeta",
    ]
    assert targets == original
