from __future__ import annotations

import copy
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from breakcheck import cli
from breakcheck import revision_cli
from breakcheck.adapters.python import envs
from breakcheck.adapters.python.fixtures import FixtureRefusal
from breakcheck.adapters.python.literals import synthesize_snippet
from breakcheck.report import finding_id
from breakcheck.verify import verify_report


def _fake_pipeline(source: Path, runtime: Path, executions: list[tuple[str, str]]):
    class Inventory:
        def __call__(self, _root, excluded_paths=()):
            return [source]

    class Scanner:
        def __init__(self, _package):
            pass

        def scan(self, **_kwargs):
            return {
                "imports": [],
                "call_sites": [
                    {"api": "sample.api", "file": "app.py", "line": 2, "column": 0}
                ],
                "unsupported": [],
                "candidates": [],
            }

    class EnvironmentBuilder:
        def __init__(self, **_kwargs):
            pass

        def build(self):
            return {"current": str(runtime / "current"), "new": str(runtime / "new")}

    def execute(*, snippet_source, environment):
        if "_rows" in snippet_source:
            return {
                "returncode": 0,
                "stdout": repr({"sample.api": True}).encode(),
                "stderr": b"",
                "timed_out": False,
            }
        executions.append((str(environment), snippet_source))
        return {
            "returncode": 0,
            "stdout": b"'stable'\n",
            "stderr": b"",
            "timed_out": False,
        }

    def compare(old, new):
        assert old == new
        return {
            "verdict": "IDENTICAL",
            "detail": {
                "reason_code": "EQUAL",
                "path": None,
                "old_summary": "stable",
                "new_summary": "stable",
                "policy": "canonical_json_strict",
            },
        }

    return (
        Inventory(),
        Scanner,
        lambda _expression, import_statement=None: "outcome = 'stable'\n",
        EnvironmentBuilder,
        execute,
        lambda value: copy.deepcopy(value),
        compare,
        finding_id,
        lambda report: json.dumps(report, sort_keys=True),
        lambda report: json.dumps(report, sort_keys=True),
        lambda report: 0,
        verify_report,
    )


def test_dependency_replay_runs_twice_in_each_environment(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api()\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    executions: list[tuple[str, str]] = []
    monkeypatch.setattr(cli, "_load_pipeline", lambda: _fake_pipeline(source, runtime, executions))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.chdir(tmp_path)

    args = SimpleNamespace(
        target="sample@2.0",
        wheelhouse=str(tmp_path / "wheelhouse"),
        runtime_root=str(runtime),
        output=None,
        evidence=None,
        coverage_report=None,
        fixtures=None,
        fixture_policy="forbid",
        suggest_fixtures=None,
        min_coverage=80.0,
        allow_empty=False,
        json=True,
        ci=False,
    )

    assert cli._build(args) == 0
    assert [environment for environment, _ in executions].count(str(runtime / "current")) == 2
    assert [environment for environment, _ in executions].count(str(runtime / "new")) == 2


def test_implicit_dependency_runtime_is_removed_after_the_run(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api()\n", encoding="utf-8")
    generated_runtime = tmp_path / "generated-runtime"
    executions: list[tuple[str, str]] = []

    def make_runtime(*, prefix):
        assert prefix == "breakcheck-runtime-"
        generated_runtime.mkdir()
        return str(generated_runtime)

    monkeypatch.setattr(cli.tempfile, "mkdtemp", make_runtime)
    monkeypatch.setattr(
        cli,
        "_load_pipeline",
        lambda: _fake_pipeline(source, generated_runtime, executions),
    )
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.chdir(tmp_path)

    result = cli._build(
        SimpleNamespace(
            target="sample@2.0",
            wheelhouse=str(tmp_path / "wheelhouse"),
            runtime_root=None,
            output=None,
            evidence=None,
            coverage_report=None,
            fixtures=None,
            fixture_policy="forbid",
            suggest_fixtures=None,
            min_coverage=80.0,
            allow_empty=False,
            json=True,
            ci=False,
        )
    )

    assert result == 0
    assert not generated_runtime.exists()


def test_implicit_dependency_runtime_is_removed_after_failure(monkeypatch, tmp_path):
    generated_runtime = tmp_path / "generated-runtime"

    def make_runtime(*, prefix):
        assert prefix == "breakcheck-runtime-"
        generated_runtime.mkdir()
        return str(generated_runtime)

    monkeypatch.setattr(cli.tempfile, "mkdtemp", make_runtime)
    monkeypatch.setattr(
        cli,
        "_load_pipeline",
        lambda: (_ for _ in ()).throw(RuntimeError("unexpected failure")),
    )

    with pytest.raises(RuntimeError, match="unexpected failure"):
        cli._build(
            SimpleNamespace(
                target="sample@2.0",
                wheelhouse=str(tmp_path / "wheelhouse"),
                runtime_root=None,
                output=None,
                evidence=None,
                coverage_report=None,
                suggest_fixtures=None,
            )
        )

    assert not generated_runtime.exists()


def test_dependency_replay_uses_static_context_and_records_provenance(
    monkeypatch, tmp_path
):
    source = tmp_path / "app.py"
    source.write_text("ARG = 1 + 1\nsample.api(ARG)\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    executions: list[tuple[str, str]] = []
    pipeline = list(_fake_pipeline(source, runtime, executions))
    pipeline[2] = synthesize_snippet
    monkeypatch.setattr(cli, "_load_pipeline", lambda: tuple(pipeline))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "report.json"

    result = cli._build(
        SimpleNamespace(
            target="sample@2.0",
            wheelhouse=str(tmp_path / "wheelhouse"),
            runtime_root=str(runtime),
            output=str(report_path),
            evidence=None,
            coverage_report=None,
            fixtures=None,
            fixture_policy="forbid",
            suggest_fixtures=None,
            min_coverage=80.0,
            allow_empty=False,
            json=True,
            ci=False,
        )
    )

    assert result == 0
    assert all("outcome = sample.api(2)" in snippet for _, snippet in executions)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    finding = report["payload"]["findings"][0]
    expected = ["SOURCE_FOLDED", "SOURCE_MODULE_CONSTANT"]
    assert finding["old"]["provenance"] == expected
    assert finding["new"]["provenance"] == expected


def test_unexpected_synthesis_failure_is_not_hidden_as_unexercised(
    monkeypatch, tmp_path
):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api(1)\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    pipeline = list(_fake_pipeline(source, runtime, []))

    def broken_synthesizer(_expression, _import_statement=None):
        raise RuntimeError("boom")

    pipeline[2] = broken_synthesizer
    monkeypatch.setattr(cli, "_load_pipeline", lambda: tuple(pipeline))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(RuntimeError, match="boom"):
        cli._build(
            SimpleNamespace(
                target="sample@2.0",
                wheelhouse=str(tmp_path / "wheelhouse"),
                runtime_root=str(runtime),
                output=None,
                evidence=None,
                coverage_report=None,
                fixtures=None,
                fixture_policy="forbid",
                suggest_fixtures=None,
                min_coverage=80.0,
                allow_empty=False,
                json=True,
                ci=False,
            )
        )


def test_artifact_write_uses_private_atomic_file_and_ignores_predictable_temp(
    tmp_path,
):
    destination = tmp_path / "report.json"
    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged", encoding="utf-8")
    (tmp_path / "report.json.tmp").symlink_to(victim)

    cli._write(destination, "verified\n")

    assert destination.read_text(encoding="utf-8") == "verified\n"
    assert victim.read_text(encoding="utf-8") == "unchanged"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_artifact_write_refuses_a_symlinked_parent(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="OUTPUT_PATH_REFUSED"):
        cli._write(linked_parent / "report.json", "sensitive\n")


def test_output_artifact_destinations_must_be_distinct(tmp_path):
    destination = tmp_path / "same.json"
    args = SimpleNamespace(
        output=str(destination),
        evidence=str(destination),
        coverage_report=None,
        suggest_fixtures=None,
    )

    with pytest.raises(ValueError, match="OUTPUT_PATH_COLLISION_REFUSED"):
        cli._validate_output_paths(args)

    destination.touch()
    alias = tmp_path / "alias.json"
    alias.symlink_to(destination)
    args.evidence = str(alias)
    with pytest.raises(ValueError, match="OUTPUT_PATH_COLLISION_REFUSED"):
        cli._validate_output_paths(args)


def test_suggest_fixtures_needs_no_wheelhouse(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api(object())\n", encoding="utf-8")
    destination = tmp_path / "suggested.toml"
    monkeypatch.chdir(tmp_path)

    result = cli.main(
        ["sample@2.0", "--suggest-fixtures", str(destination)]
    )

    assert result == 0
    rendered = destination.read_text(encoding="utf-8")
    assert 'api = "sample.api"' in rendered
    assert 'fixture_authored_by = "unknown"' in rendered
    assert "sample.api(object())" in rendered


def test_collocated_chained_call_selects_the_scanned_dependency_api(
    monkeypatch, tmp_path
):
    source = tmp_path / "app.py"
    source.write_text(
        "import click\n\n"
        "def decorate(function):\n"
        "    return click.option('--flag', callback=function)(function)\n",
        encoding="utf-8",
    )
    scan = {
        "call_sites": [
            {"api": "click.option", "file": "app.py", "line": 4, "column": 11}
        ]
    }
    monkeypatch.setattr(cli, "_synthesize", synthesize_snippet, raising=False)

    candidates = cli._fixture_suggestion_candidates(
        tmp_path, scan, {source.resolve()}
    )

    assert len(candidates) == 1
    assert candidates[0]["api"] == "click.option"
    assert candidates[0]["nearby_source"] == "click.option('--flag', callback=function)"


def test_dependency_refusal_prints_canonical_fixture_detail(monkeypatch, capsys):
    detail = {
        "binding": {"file": "app.py", "line": 8, "column": 9, "api": "sample.api"},
        "inventory_candidates": [
            {
                "file": "app.py",
                "line": 7,
                "column": 0,
                "api": "sample.api",
                "mismatched_fields": ["line", "column"],
            }
        ],
    }
    monkeypatch.setattr(
        cli,
        "_build",
        lambda _args: (_ for _ in ()).throw(
            FixtureRefusal("FIXTURE_STALE_REFUSED", detail=detail)
        ),
    )

    result = cli.main(["sample@2.0", "--wheelhouse", "wheelhouse"])

    assert result == 2
    assert capsys.readouterr().err.splitlines() == [
        "BUILD_REFUSED:FIXTURE_STALE_REFUSED",
        "REFUSAL_DETAIL:" + json.dumps(detail, sort_keys=True, separators=(",", ":")),
    ]


def test_environment_install_detail_survives_the_build_boundary(
    monkeypatch, tmp_path, capsys
):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api()\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    pipeline = list(_fake_pipeline(source, runtime, []))

    class RefusingEnvironmentBuilder:
        def __init__(self, **_kwargs):
            pass

        def build(self):
            raise envs.EnvironmentRefusal(
                "ENVIRONMENT_INSTALL_REFUSED",
                detail={
                    "requirement": "sample==1.0",
                    "wheelhouse_requirement": "complete_dependency_closure",
                },
            )

    pipeline[3] = RefusingEnvironmentBuilder
    monkeypatch.setattr(cli, "_load_pipeline", lambda: tuple(pipeline))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.chdir(tmp_path)

    result = cli.main(
        ["sample@2.0", "--wheelhouse", str(tmp_path / "wheelhouse")]
    )

    assert result == 2
    assert capsys.readouterr().err.splitlines() == [
        "BUILD_REFUSED:ENVIRONMENT_INSTALL_REFUSED",
        'REFUSAL_DETAIL:{"requirement":"sample==1.0",'
        '"wheelhouse_requirement":"complete_dependency_closure"}',
    ]


def test_replay_backed_suggestions_include_repeatable_rich_results(
    monkeypatch, tmp_path, capsys
):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api()\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    destination = tmp_path / "suggested.toml"
    executions: list[tuple[str, str]] = []
    monkeypatch.setattr(cli, "_load_pipeline", lambda: _fake_pipeline(source, runtime, executions))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.setattr(
        cli,
        "_repeat_observation",
        lambda _snippet, _environment: {
            "runs": [{"raw_type": "SampleResult"}, {"raw_type": "SampleResult"}],
            "repeatable": True,
            "status": "UNNORMALIZABLE",
            "reason_code": "UNSTABLE_OBSERVATION_REFUSED",
            "observation": None,
        },
    )
    monkeypatch.chdir(tmp_path)

    result = cli.main(
        [
            "sample@2.0",
            "--wheelhouse",
            str(tmp_path / "wheelhouse"),
            "--suggest-fixtures",
            str(destination),
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["fixture_suggestions"] == 1
    rendered = destination.read_text(encoding="utf-8")
    assert "# coverage_bucket: G3_UNNORMALIZABLE" in rendered
    assert "# raw_type: SampleResult" in rendered
    assert 'projection = ""' in rendered


def test_replay_backed_suggestions_exclude_impure_or_nondeterministic_calls(
    monkeypatch, tmp_path, capsys
):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api()\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    destination = tmp_path / "suggested.toml"
    executions: list[tuple[str, str]] = []
    monkeypatch.setattr(cli, "_load_pipeline", lambda: _fake_pipeline(source, runtime, executions))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.setattr(
        cli,
        "_repeat_observation",
        lambda _snippet, _environment: {
            "runs": [],
            "repeatable": False,
            "status": "PROTOCOL_REFUSED",
            "reason_code": "NONDETERMINISTIC_OBSERVATION",
            "observation": None,
        },
    )
    monkeypatch.chdir(tmp_path)

    result = cli.main(
        [
            "sample@2.0",
            "--wheelhouse",
            str(tmp_path / "wheelhouse"),
            "--suggest-fixtures",
            str(destination),
        ]
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out)["fixture_suggestions"] == 0
    assert "[[binding]]" not in destination.read_text(encoding="utf-8")


def test_operator_fixture_replays_a_nonliteral_call(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api(object())\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    fixture = tmp_path / "breakcheck.fixtures.toml"
    fixture.write_text(
        "\n".join(
            (
                "schema_version = 1",
                "",
                "[[binding]]",
                'fixture_authored_by = "agent"',
                'file = "app.py"',
                "line = 2",
                "column = 0",
                'api = "sample.api"',
                'args = ["7"]',
                "kwargs = {}",
                "",
            )
        ),
        encoding="utf-8",
    )
    executions: list[tuple[str, str]] = []
    pipeline = list(_fake_pipeline(source, runtime, executions))

    def refuse_nonliteral(_expression, import_statement=None):
        raise ValueError("NONLITERAL_ARGS")

    pipeline[2] = refuse_nonliteral
    monkeypatch.setattr(cli, "_load_pipeline", lambda: tuple(pipeline))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "report.json"

    result = cli._build(
        SimpleNamespace(
            target="sample@2.0",
            wheelhouse=str(tmp_path / "wheelhouse"),
            runtime_root=str(runtime),
            output=str(report_path),
            evidence=None,
            coverage_report=None,
            fixtures=str(fixture),
            fixture_policy="allow",
            suggest_fixtures=None,
            min_coverage=80.0,
            allow_empty=False,
            json=True,
            ci=False,
        )
    )

    assert result == 0
    assert len(executions) == 4
    assert all("outcome = sample.api(7)" in source for _, source in executions)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == 2
    finding = report["payload"]["findings"][0]
    assert finding["verdict"] == "IDENTICAL"
    assert finding["old"]["provenance"] == ["OPERATOR_FIXTURE"]
    assert finding["new"]["provenance"] == ["OPERATOR_FIXTURE"]


def test_nondeterministic_replay_is_g4_without_a_witness(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api()\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    executions = []
    pipeline = list(_fake_pipeline(source, runtime, executions))
    counter = {"value": 0}

    def execute(*, snippet_source, environment):
        if "_rows" in snippet_source:
            return {
                "returncode": 0,
                "stdout": repr({"sample.api": True}).encode(),
                "stderr": b"",
                "timed_out": False,
            }
        counter["value"] += 1
        return {
            "returncode": 0,
            "stdout": repr(counter["value"]).encode(),
            "stderr": b"",
            "timed_out": False,
        }

    pipeline[4] = execute
    monkeypatch.setattr(cli, "_load_pipeline", lambda: tuple(pipeline))
    monkeypatch.setattr(cli._metadata, "version", lambda _package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda _package: "sample")
    monkeypatch.chdir(tmp_path)
    report_path = tmp_path / "report.json"
    coverage_path = tmp_path / "coverage.json"

    result = cli._build(
        SimpleNamespace(
            target="sample@2.0",
            wheelhouse=str(tmp_path / "wheelhouse"),
            runtime_root=str(runtime),
            output=str(report_path),
            evidence=None,
            coverage_report=str(coverage_path),
            fixtures=None,
            fixture_policy="forbid",
            suggest_fixtures=None,
            min_coverage=80.0,
            allow_empty=False,
            json=True,
            ci=False,
        )
    )

    assert result == 4
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["payload"]["witnesses"] == []
    assert report["payload"]["findings"][0]["reason_code"] == "NONDETERMINISTIC_OBSERVATION"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert coverage["payload"]["counts"]["G4_IMPURE"] == 1
    assert coverage["payload"]["counts"]["EXERCISED"] == 0


def test_freeze_command_routes_to_revision_engine(monkeypatch, tmp_path):
    observed = {}
    sentinel = SimpleNamespace(report={}, evidence={}, exit_code=0)

    def freeze(repository, **kwargs):
        observed["repository"] = repository
        observed.update(kwargs)
        assert not Path(kwargs["runtime_root"]).exists()
        return sentinel

    monkeypatch.setattr(revision_cli, "freeze_revision", freeze)
    monkeypatch.setattr(cli, "_emit_revision_result", lambda result, _args: result.exit_code)
    monkeypatch.chdir(tmp_path)

    result = cli.main(
        [
            "freeze",
            "--revision",
            "HEAD",
            "--fixtures",
            "breakcheck.fixtures.toml",
            "--target",
            "app.pricing:total",
            "--output",
            "baseline.json",
        ]
    )

    assert result == 0
    assert observed["repository"] == tmp_path
    assert observed["targets"] == ["app.pricing:total"]


def test_diff_command_loads_baseline_and_preserves_strict_options(
    monkeypatch, tmp_path
):
    baseline = {"schema_version": 2, "artifact_kind": "baseline"}
    (tmp_path / "baseline.json").write_text(json.dumps(baseline), encoding="utf-8")
    observed = {}
    sentinel = SimpleNamespace(report={}, evidence={}, exit_code=3)

    def diff(repository, **kwargs):
        observed["repository"] = repository
        observed.update(kwargs)
        return sentinel

    monkeypatch.setattr(revision_cli, "diff_revisions", diff)
    monkeypatch.setattr(cli, "_emit_revision_result", lambda result, _args: result.exit_code)
    monkeypatch.chdir(tmp_path)

    result = cli.main(
        [
            "diff",
            "--baseline",
            "baseline.json",
            "--head",
            "HEAD",
            "--strict-separation",
        ]
    )

    assert result == 3
    assert observed["baseline"] == baseline
    assert observed["strict_separation"] is True


def test_attest_command_is_strict_by_default(monkeypatch, tmp_path):
    observed = {}
    sentinel = SimpleNamespace(report={}, evidence={}, exit_code=0)

    def attest(repository, **kwargs):
        observed["repository"] = repository
        observed.update(kwargs)
        return sentinel

    monkeypatch.setattr(revision_cli, "attest_revision", attest)
    monkeypatch.setattr(cli, "_emit_revision_result", lambda result, _args: result.exit_code)
    monkeypatch.chdir(tmp_path)

    result = cli.main(
        ["attest", "--head", "HEAD", "--claim", "breakcheck.claim.toml"]
    )

    assert result == 0
    assert observed["strict"] is True
    assert observed["strict_separation"] is True
