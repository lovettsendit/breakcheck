from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from breakcheck.revision_cli import (
    RevisionModeRefusal,
    attest_revision,
    diff_revisions,
)
from breakcheck.revision_report import make_revision_artifact
from breakcheck.revision_cli import freeze_revision
from breakcheck.report import ci_exit_code
from breakcheck.schema import artifact_digest, verify_artifact

from test_revision_executor import _commit, _git, _write, revision_repository


def _src_revision_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "src-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _write(
        repository,
        "src/sample.py",
        "def compute_total(value):\n    return value + 1\n",
    )
    _write(
        repository,
        "breakcheck.fixtures.toml",
        "\n".join(
            (
                "schema_version = 1",
                "",
                "[[binding]]",
                'file = "src/sample.py"',
                "line = 1",
                "column = 0",
                'api = "sample.compute_total"',
                'args = ["2"]',
                "kwargs = {}",
                'fixture_authored_by = "human"',
                "",
            )
        ),
    )
    base = _commit(
        repository,
        "src base",
        ("src/sample.py", "breakcheck.fixtures.toml"),
    )
    _write(
        repository,
        "src/sample.py",
        "def compute_total(value):\n    return value + 2\n",
    )
    head = _commit(repository, "src head", ("src/sample.py",))
    return repository, base, head


def test_src_layout_freeze_diff_and_attest_use_confined_import_roots(
    tmp_path: Path,
) -> None:
    repository, base, head = _src_revision_repository(tmp_path)

    frozen = freeze_revision(
        repository,
        revision=base,
        runtime_root=tmp_path / "freeze-runtime",
    )
    assert frozen.report["payload"]["target_observations"][0]["observation"][
        "payload"
    ] == 3
    assert {
        row["name"]
        for row in frozen.evidence["payload"]["environment_artifacts"]
    } >= {"revision_import_roots", "revision_tree"}

    compared = diff_revisions(
        repository,
        base_revision=base,
        head_revision=head,
        runtime_root=tmp_path / "diff-runtime",
    )
    assert compared.exit_code == 3
    assert compared.report["payload"]["findings"][0]["verdict"] == "CHANGED"
    assert {
        row["name"]
        for row in compared.evidence["payload"]["environment_artifacts"]
    } >= {"base_import_roots", "head_import_roots"}

    _write(
        repository,
        "claim.toml",
        "\n".join(
            (
                "schema_version = 1",
                'claim = "behavior_preserved"',
                f'base_revision = "{base}"',
                "",
                "[[target]]",
                'symbol = "sample:compute_total"',
                "",
            )
        ),
    )
    claim_head = _commit(repository, "src claim", ("claim.toml",))
    attested = attest_revision(
        repository,
        head_revision=claim_head,
        claim_path="claim.toml",
        runtime_root=tmp_path / "attest-runtime",
    )
    assert attested.exit_code == 1
    assert attested.report["payload"]["dispositions"][0][
        "disposition"
    ] == "CLAIM_REFUTED"
    assert {
        row["name"]
        for row in attested.evidence["payload"]["environment_artifacts"]
    } >= {"base_import_roots", "head_import_roots"}

    for result in (frozen, compared, attested):
        encoded = json.dumps(result.evidence, sort_keys=True)
        assert str(tmp_path) not in encoded
        assert verify_artifact(result.report) == "VERIFIED"
        assert verify_artifact(result.evidence) == "VERIFIED"


def test_diff_catches_a_real_behavior_change_and_emits_a_verified_witness(
    tmp_path: Path,
) -> None:
    repository, base, head = revision_repository(tmp_path)

    result = diff_revisions(
        repository,
        base_revision=base,
        head_revision=head,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "runtime",
    )

    assert result.exit_code == 3
    assert ci_exit_code(result.report) == result.exit_code
    assert verify_artifact(result.report) == "VERIFIED"
    assert verify_artifact(result.evidence) == "VERIFIED"
    payload = result.report["payload"]
    assert payload["summary"] == {
        "changed": 1,
        "changed_under_projection": 0,
        "identical": 0,
        "identical_under_projection": 0,
        "not_exercised": 0,
    }
    finding = payload["findings"][0]
    assert finding["symbol"] == "compute_total"
    assert finding["verdict"] == "CHANGED"
    assert finding["base"]["payload"] == 3
    assert finding["head"]["payload"] == 4
    assert len(payload["witnesses"]) == 1
    replay = payload["witnesses"][0]["replay"]
    assert "importlib.import_module('sample')" in replay["source"]
    assert replay["sha256"] == artifact_digest(replay["source"])
    assert str(tmp_path) not in replay["source"]
    assert not (tmp_path / "runtime").exists()


def test_diff_reports_import_asymmetry_without_a_witness(tmp_path: Path) -> None:
    repository, base, _ = revision_repository(tmp_path)
    _write(
        repository,
        "sample.py",
        "import dependency_that_is_not_installed\n\ndef compute_total(value):\n    return value + 1\n",
    )
    head = _commit(repository, "import failure", ("sample.py",))

    result = diff_revisions(
        repository,
        base_revision=base,
        head_revision=head,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "runtime",
        targets=("sample:compute_total",),
    )

    assert result.exit_code == 4
    assert ci_exit_code(result.report) == result.exit_code
    finding = result.report["payload"]["findings"][0]
    assert finding["verdict"] == "NOT_EXERCISED"
    assert finding["reason_code"] == "IMPORT_ASYMMETRY"
    assert finding["base"] is None
    assert finding["head"] is None
    assert result.report["payload"]["witnesses"] == []


def test_default_target_selection_ignores_unchanged_symbols_but_explicit_targets_do_not(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    _write(
        repository,
        "sample.py",
        "def compute_total(value):\n    return value + 1\n",
    )
    _write(repository, "stable.py", "def untouched(value):\n    return value\n")
    _write(
        repository,
        "breakcheck.fixtures.toml",
        "\n".join(
            (
                "schema_version = 1",
                "",
                "[[binding]]",
                'file = "sample.py"',
                "line = 1",
                "column = 0",
                'api = "sample.compute_total"',
                'args = ["2"]',
                "kwargs = {}",
                'fixture_authored_by = "human"',
                "",
                "[[binding]]",
                'file = "stable.py"',
                "line = 1",
                "column = 0",
                'api = "stable.untouched"',
                'args = ["2"]',
                "kwargs = {}",
                'fixture_authored_by = "human"',
                "",
            )
        ),
    )
    base = _commit(
        repository,
        "fixture coverage",
        ("sample.py", "stable.py", "breakcheck.fixtures.toml"),
    )
    _write(
        repository,
        "sample.py",
        "def compute_total(value):\n    return value + 2\n",
    )
    head = _commit(repository, "one changed", ("sample.py",))

    default = diff_revisions(
        repository,
        base_revision=base,
        head_revision=head,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "default-runtime",
    )
    explicit = diff_revisions(
        repository,
        base_revision=base,
        head_revision=head,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "explicit-runtime",
        targets=("stable:untouched",),
    )

    assert [row["symbol"] for row in default.report["payload"]["findings"]] == [
        "compute_total"
    ]
    assert explicit.report["payload"]["findings"][0]["verdict"] == "IDENTICAL"
    assert explicit.exit_code == 0


def test_attest_adjudicates_an_independent_claim_and_detects_omitted_changes(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    _write(
        repository,
        "sample.py",
        "def compute_total(value):\n    added = value + 1\n    return added\n\ndef omitted(value):\n    return value * 2\n",
    )
    _write(
        repository,
        "breakcheck.fixtures.toml",
        "\n".join(
            (
                "schema_version = 1",
                "",
                "[[binding]]",
                'file = "sample.py"',
                "line = 1",
                "column = 0",
                'api = "sample.compute_total"',
                'args = ["2"]',
                "kwargs = {}",
                'fixture_authored_by = "human"',
                "",
            )
        ),
    )
    _write(
        repository,
        "claim.toml",
        "\n".join(
            (
                "schema_version = 1",
                'claim = "behavior_preserved"',
                f'base_revision = "{base}"',
                "",
                "[[target]]",
                'symbol = "sample:compute_total"',
                "",
            )
        ),
    )
    head = _commit(
        repository,
        "refactor and extra change",
        ("sample.py", "claim.toml"),
    )

    result = attest_revision(
        repository,
        head_revision=head,
        claim_path="claim.toml",
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "runtime",
    )

    assert result.exit_code == 3
    assert verify_artifact(result.report) == "VERIFIED"
    assert verify_artifact(result.evidence) == "VERIFIED"
    dispositions = {
        row["symbol"]: row["disposition"]
        for row in result.report["payload"]["dispositions"]
    }
    assert dispositions["sample:compute_total"] == "CLAIM_VERIFIED"
    assert dispositions["sample:omitted"] == "CLAIM_OUT_OF_SCOPE"


def test_diff_rejects_an_existing_runtime_root_before_touching_it(tmp_path: Path) -> None:
    repository, base, head = revision_repository(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    sentinel = runtime / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="^REVISION_RUNTIME_ROOT_REFUSED$"):
        diff_revisions(
            repository,
            base_revision=base,
            head_revision=head,
            fixture_path="breakcheck.fixtures.toml",
            runtime_root=runtime,
        )

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_diff_from_verified_baseline_rechecks_environment_fixture_and_base_observation(
    tmp_path: Path,
) -> None:
    repository, base, head = revision_repository(tmp_path)
    baseline = freeze_revision(
        repository,
        revision=base,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "freeze-runtime",
    ).report

    result = diff_revisions(
        repository,
        baseline=baseline,
        head_revision=head,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "diff-runtime",
    )
    assert result.exit_code == 3

    payload = copy.deepcopy(baseline["payload"])
    payload["environment"]["platform"] = "different-platform"
    incompatible = make_revision_artifact("baseline", payload)
    with pytest.raises(ValueError, match="^BASELINE_ENVIRONMENT_MISMATCH$"):
        diff_revisions(
            repository,
            baseline=incompatible,
            head_revision=head,
            fixture_path="breakcheck.fixtures.toml",
            runtime_root=tmp_path / "incompatible-runtime",
        )


def test_projection_verdict_and_non_strict_claim_scope_remain_explicit(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    _write(
        repository,
        "sample.py",
        "def compute_total(value):\n    return value + 1\n",
    )
    _write(
        repository,
        "breakcheck.fixtures.toml",
        "\n".join(
            (
                "schema_version = 1",
                "",
                "[[binding]]",
                'file = "sample.py"',
                "line = 1",
                "column = 0",
                'api = "sample.compute_total"',
                'args = ["2"]',
                "kwargs = {}",
                'projection = "outcome % 2"',
                'fixture_authored_by = "human"',
                "",
            )
        ),
    )
    base = _commit(
        repository, "projection", ("sample.py", "breakcheck.fixtures.toml")
    )
    _write(
        repository,
        "sample.py",
        "def compute_total(value):\n    changed_structure = value + 3\n    return changed_structure\n",
    )
    _write(
        repository,
        "claim.toml",
        "\n".join(
            (
                "schema_version = 1",
                'claim = "behavior_preserved"',
                f'base_revision = "{base}"',
                "",
                "[[target]]",
                'symbol = "sample:compute_total"',
                "",
            )
        ),
    )
    head = _commit(repository, "projected refactor", ("sample.py", "claim.toml"))

    compared = diff_revisions(
        repository,
        base_revision=base,
        head_revision=head,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "diff-runtime",
    )
    finding = compared.report["payload"]["findings"][0]
    assert finding["verdict"] == "IDENTICAL_UNDER_PROJECTION"
    assert finding["projection"]["source"] == "outcome % 2"

    attested = attest_revision(
        repository,
        head_revision=head,
        claim_path="claim.toml",
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "attest-runtime",
        strict_separation=False,
    )
    disposition = attested.report["payload"]["dispositions"][0]
    assert disposition["disposition"] == "CLAIM_UNVERIFIABLE"
    assert disposition["reason_code"] == "STRICT_SEPARATION_REQUIRED"
    assert attested.exit_code == 2


def test_attest_strict_policy_controls_only_unverifiable_exit_status(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    _write(
        repository,
        "sample.py",
        "import dependency_that_is_not_installed\n\ndef compute_total(value):\n    return value + 1\n",
    )
    _write(
        repository,
        "claim.toml",
        "\n".join(
            (
                "schema_version = 1",
                'claim = "behavior_preserved"',
                f'base_revision = "{base}"',
                "",
                "[[target]]",
                'symbol = "sample:compute_total"',
                "",
            )
        ),
    )
    head = _commit(repository, "unverifiable import", ("sample.py", "claim.toml"))

    strict_result = attest_revision(
        repository,
        head_revision=head,
        claim_path="claim.toml",
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "strict-runtime",
        strict=True,
    )
    advisory_result = attest_revision(
        repository,
        head_revision=head,
        claim_path="claim.toml",
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "advisory-runtime",
        strict=False,
    )

    for result in (strict_result, advisory_result):
        disposition = result.report["payload"]["dispositions"][0]
        assert disposition["disposition"] == "CLAIM_UNVERIFIABLE"
        assert disposition["reason_code"] == "IMPORT_ASYMMETRY"
        assert result.report["payload"]["summary"]["claim_verified"] == 0
    assert strict_result.exit_code == 2
    assert advisory_result.exit_code == 0
    assert ci_exit_code(strict_result.report) == strict_result.exit_code
    assert ci_exit_code(advisory_result.report) == advisory_result.exit_code


def test_diff_surfaces_fixture_revision_after_failure_without_changing_exit(
    tmp_path: Path,
) -> None:
    repository, base, head = revision_repository(tmp_path)
    prior = diff_revisions(
        repository,
        base_revision=base,
        head_revision=head,
        fixture_path="breakcheck.fixtures.toml",
        fixture_source="head",
        runtime_root=tmp_path / "prior-runtime",
    )
    assert prior.exit_code == 3

    fixture = (repository / "breakcheck.fixtures.toml").read_text(
        encoding="utf-8"
    )
    _write(
        repository,
        "breakcheck.fixtures.toml",
        fixture.replace(
            'fixture_authored_by = "human"',
            'projection = "outcome * 0"\nfixture_authored_by = "human"',
        ),
    )
    tuned_head = _commit(
        repository,
        "fixture revision",
        ("breakcheck.fixtures.toml",),
    )

    current = diff_revisions(
        repository,
        base_revision=base,
        head_revision=tuned_head,
        fixture_path="breakcheck.fixtures.toml",
        fixture_source="head",
        previous_report=prior.report,
        runtime_root=tmp_path / "current-runtime",
    )

    assert current.exit_code == 0
    payload = current.report["payload"]
    assert payload["findings"][0]["verdict"] == "IDENTICAL_UNDER_PROJECTION"
    assert len(payload["fixture_revision_events"]) == 1
    event = payload["fixture_revision_events"][0]
    assert event["target_id"] == payload["findings"][0]["target_id"]
    assert event["prior_verdict"] == "CHANGED"
    assert event["current_verdict"] == "IDENTICAL_UNDER_PROJECTION"
    assert event["reason_code"] == "FIXTURE_REVISED_AFTER_FAILURE"
    assert (
        event["prior_fixture_binding_sha256"]
        != event["current_fixture_binding_sha256"]
    )
    assert verify_artifact(current.report) == "VERIFIED"

    mismatched_payload = copy.deepcopy(prior.report["payload"])
    mismatched_payload["base_revision"] = head
    mismatched = make_revision_artifact(
        "revision_report", mismatched_payload
    )
    mismatch_runtime = tmp_path / "mismatch-runtime"
    with pytest.raises(
        ValueError, match="^PREVIOUS_REPORT_BASE_MISMATCH$"
    ):
        diff_revisions(
            repository,
            base_revision=base,
            head_revision=tuned_head,
            fixture_path="breakcheck.fixtures.toml",
            fixture_source="head",
            previous_report=mismatched,
            runtime_root=mismatch_runtime,
        )
    assert not mismatch_runtime.exists()

    _write(
        repository,
        "claim.toml",
        "\n".join(
            (
                "schema_version = 1",
                'claim = "behavior_preserved"',
                f'base_revision = "{base}"',
                "",
                "[[target]]",
                'symbol = "sample:compute_total"',
                "",
            )
        ),
    )
    claim_head = _commit(repository, "claim", ("claim.toml",))
    attested = attest_revision(
        repository,
        head_revision=claim_head,
        claim_path="claim.toml",
        fixture_path="breakcheck.fixtures.toml",
        fixture_source="head",
        previous_report=prior.report,
        runtime_root=tmp_path / "attest-runtime",
        strict_separation=False,
    )
    assert (
        attested.report["payload"]["fixture_revision_events"]
        == payload["fixture_revision_events"]
    )
    assert verify_artifact(attested.report) == "VERIFIED"


@pytest.mark.parametrize("fixture_state", ("untracked", "edited"))
def test_strict_separation_refuses_explicit_checkout_fixtures(
    tmp_path: Path, fixture_state: str
) -> None:
    repository, base, head = revision_repository(tmp_path)
    fixture_path = "breakcheck.fixtures.toml"
    if fixture_state == "untracked":
        fixture_path = "untracked-fixtures.toml"
        _write(
            repository,
            fixture_path,
            (repository / "breakcheck.fixtures.toml").read_text(
                encoding="utf-8"
            ),
        )
    else:
        with (repository / fixture_path).open("a", encoding="utf-8") as stream:
            stream.write("\n# edited after the recorded revision\n")

    runtime = tmp_path / (fixture_state + "-runtime")
    with pytest.raises(
        RevisionModeRefusal, match="^FIXTURE_EXPLICIT_STRICT_REFUSED$"
    ):
        diff_revisions(
            repository,
            base_revision=base,
            head_revision=head,
            fixture_path=fixture_path,
            fixture_source="explicit",
            runtime_root=runtime,
            strict_separation=True,
        )
    assert not runtime.exists()
