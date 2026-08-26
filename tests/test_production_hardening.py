from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.10 CI jobs
    import tomli as tomllib

from breakcheck import cli
from breakcheck.adapters.python import envs, executor, files, scanner
from breakcheck.report import finding_id
from breakcheck.verify import verify_report


def _canonical_digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _report_and_evidence(current_root: Path, new_root: Path):
    observation = {
        "kind": "value",
        "payload": "stable",
        "exception_class": None,
        "duration_ms": None,
    }
    comparison = {
        "verdict": "IDENTICAL",
        "detail": {
            "reason_code": "EQUAL",
            "path": None,
            "old_summary": "stable",
            "new_summary": "stable",
            "policy": "canonical_json_strict",
        },
    }
    snippet_id = _canonical_digest(
        {"api": "sample.api", "code": "sample.api()", "call_sites": []}
    )
    finding = {
        "finding_id": "",
        "api": "sample.api",
        "call_sites": [{"file": "app.py", "line": 1, "column": 0}],
        "verdict": "IDENTICAL",
        "old": copy.deepcopy(observation),
        "new": copy.deepcopy(observation),
        "repro": {
            "snippet_id": snippet_id,
            "api": "sample.api",
            "call_sites": [{"file": "app.py", "line": 1, "column": 0}],
            "code": "sample.api()",
            "args_source": "literal",
            "reason_code": None,
        },
        "suggested_action": [],
        "reason_code": None,
        "comparison": comparison,
    }
    finding["finding_id"] = finding_id(finding)
    witness = {
        "witness_id": "",
        "finding_id": finding["finding_id"],
        "snippet_id": snippet_id,
        "api": "sample.api",
        "code": "sample.api()",
        "current_version": "1.0",
        "new_version": "2.0",
        "old_observation_sha256": _canonical_digest(observation),
        "new_observation_sha256": _canonical_digest(observation),
    }
    witness["witness_id"] = _canonical_digest(witness)
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
        "report_sha256": _canonical_digest(report),
        "witnesses": copy.deepcopy(report["witnesses"]),
        "environment_artifacts": {
            "current": cli._artifact_digest(current_root),
            "new": cli._artifact_digest(new_root),
        },
    }
    evidence["witness_sha256"] = _canonical_digest(evidence)
    return report, evidence


def _fake_build(monkeypatch, tmp_path, *, present):
    source = tmp_path / "app.py"
    source.write_text("import sample\nsample.api()\n", encoding="utf-8")
    runtime = tmp_path / "runtime"
    captured = {}

    class Inventory:
        def __call__(self, root, excluded_paths=()):
            return [source]

    class Scanner:
        def __init__(self, package):
            self.package = package

        def scan(self, **_kwargs):
            return {
                "imports": [],
                "call_sites": [
                    {"api": "sample.api", "file": "app.py", "line": 2, "column": 0}
                ],
                "unsupported": [],
            }

    class EnvironmentBuilder:
        def __init__(self, **_kwargs):
            pass

        def build(self):
            return {"current": str(runtime / "current"), "new": str(runtime / "new")}

    def execute(*, snippet_source, environment):
        if "_rows" in snippet_source:
            payload = {"sample.api": bool(present)}
            return {
                "returncode": 0,
                "stdout": repr(payload).encode("utf-8"),
                "stderr": b"",
                "timed_out": False,
            }
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

    def render_json(report):
        captured["report"] = copy.deepcopy(report)
        return json.dumps(report, sort_keys=True)

    pipeline = (
        Inventory(),
        Scanner,
        lambda expression: "print('stable')",
        EnvironmentBuilder,
        execute,
        lambda value: copy.deepcopy(value),
        compare,
        finding_id,
        render_json,
        lambda report: json.dumps(report, sort_keys=True),
        lambda report: 0,
        verify_report,
    )
    monkeypatch.setattr(cli, "_load_pipeline", lambda: pipeline)
    monkeypatch.setattr(cli._metadata, "version", lambda package: "1.0")
    monkeypatch.setattr(cli, "_import_root", lambda package: "sample")
    monkeypatch.chdir(tmp_path)
    args = SimpleNamespace(
        target="sample@2.0",
        wheelhouse=str(tmp_path / "wheelhouse"),
        runtime_root=str(runtime),
        output=None,
        evidence=None,
        json=True,
        ci=False,
    )
    assert cli._build(args) == 0
    return captured["report"]


def test_present_api_remains_exercised(monkeypatch, tmp_path):
    report = _fake_build(monkeypatch, tmp_path, present=True)
    assert report["coverage"] == {"exercised": 1, "total": 1, "percent": 100.0}
    assert [row["verdict"] for row in report["findings"]] == ["IDENTICAL"]


def test_api_absent_in_both_environments_is_not_exercised(monkeypatch, tmp_path):
    report = _fake_build(monkeypatch, tmp_path, present=False)
    assert report["coverage"] == {"exercised": 0, "total": 1, "percent": 0.0}
    assert [row["verdict"] for row in report["findings"]] == ["NOT_EXERCISED"]
    assert [row["reason_code"] for row in report["findings"]] == [
        "API_ABSENT_BOTH_ENVIRONMENTS"
    ]


def test_syntax_error_becomes_explicit_not_exercised_input():
    usage_scanner = scanner.PythonUsageScanner("sample")
    observed = usage_scanner.scan(
        source="def broken(", path="broken.py", package="sample"
    )
    assert observed["imports"] == []
    assert observed["call_sites"] == []
    assert observed["unsupported"] == [
        {
            "api": "source:broken.py",
            "line": 1,
            "file": "broken.py",
            "column": 10,
            "reason_code": "SOURCE_SYNTAX_REFUSED",
        }
    ]


def test_build_backend_policy_does_not_exclude_newer_compatible_tools():
    project_root = Path(__file__).resolve().parents[1]
    document = tomllib.loads(
        (project_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    requirements = document["build-system"]["requires"]
    assert requirements == ["setuptools>=77", "wheel>=0.43"]


def test_public_release_roots_exclude_private_identity_and_internal_provenance():
    project_root = Path(__file__).resolve().parents[1]
    private_term_fingerprints = {
        3: {"8b850164b5a2e503567a6779b9a31a4f9bf202fb3f5d1327c789cdc948ebb794"},
        6: {
            "147e78b1e6476d75bf35a0b85796f18369fb025928d6963a8eeeefb6c8330e64",
            "6a487b4fd1d59b9a6d73b542978c4d03778842385b603085f2d4880476509bf3",
            "b6f4bf975b93ad705f194752a5119dfeb93d1c8a20cf3c3aeff372fcf94d4e71",
        },
        7: {"3e44fb009899c0f900c1e74cd803b171d70a5d799d2cc933898d78e8d5fc17ca"},
        9: {"6592078a7321c458cd4586c3945ef79b7fd3b13947eba1faa78568364918178d"},
        11: {
            "06ae6b52ed986ed5349967715ae18b67f83e52e67984ab7e0b2b5404a7ef8cf2",
            "a3626979818075a734058bdf0847410e2bf597ce85eac770ae2dd6285fe1bc62",
        },
    }
    paths = sorted(
        path
        for path in project_root.rglob("*")
        if path.is_file()
        and path.resolve() != Path(__file__).resolve()
        and not path.name.startswith("._")
        and not {".benchmarks", ".pytest_cache", "__pycache__"}.intersection(path.parts)
        and path.suffix.lower() in {".in", ".md", ".py", ".toml", ".yml"}
    )
    matches = []
    for path in paths:
        text = path.read_text(encoding="utf-8").lower()
        if re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", text):
            matches.append(path.relative_to(project_root).as_posix())
            continue
        for length, forbidden in private_term_fingerprints.items():
            if any(
                hashlib.sha256(text[index : index + length].encode("utf-8")).hexdigest()
                in forbidden
                for index in range(max(0, len(text) - length + 1))
            ):
                matches.append(path.relative_to(project_root).as_posix())
                break
    assert matches == []


def test_public_documentation_explains_practical_and_ai_assisted_use():
    project_root = Path(__file__).resolve().parents[1]
    readme = (project_root / "README.md").read_text(encoding="utf-8")
    metadata = tomllib.loads(
        (project_root / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]

    for heading in (
        "## Quick start",
        "## Where Breakcheck fits",
        "## Using Breakcheck with AI-assisted development",
        "## What Breakcheck does not prove",
    ):
        assert heading in readme
    for phrase in (
        "sanitize the report",
        "human review",
        "does not decide whether an upgrade should ship",
    ):
        assert phrase in readme
    assert {
        "behavioral-compatibility",
        "dependency-management",
        "regression-testing",
        "python",
    }.issubset(set(metadata["keywords"]))
    assert not re.search(
        r"revolutionary|breakthrough|unprecedented|never[- ]before|world[- ]class",
        readme,
        re.IGNORECASE,
    )


@pytest.mark.parametrize(
    "result",
    [
        {"returncode": 0, "stdout": b"\xff", "stderr": b"", "timed_out": False},
        {"returncode": 1, "stdout": b"", "stderr": b"\xff", "timed_out": False},
    ],
)
def test_invalid_utf8_observation_refuses(monkeypatch, result):
    monkeypatch.setattr(cli, "_normalize", lambda value: value)
    with pytest.raises(ValueError, match="OBSERVATION_ENCODING_REFUSED"):
        cli._process_observation(result)


def test_environment_digest_binds_non_python_files(tmp_path):
    root = tmp_path / "environment"
    root.mkdir()
    artifact = root / "native-extension.bin"
    artifact.write_bytes(b"version-one")
    before = cli._artifact_digest(root)
    artifact.write_bytes(b"version-two")
    after = cli._artifact_digest(root)
    assert before["sha256"] != after["sha256"]


def test_valid_report_and_live_environment_roots_verify(tmp_path, capsys):
    current = tmp_path / "current"
    new = tmp_path / "new"
    current.mkdir()
    new.mkdir()
    (current / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (new / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    report, evidence = _report_and_evidence(current, new)
    report_path = tmp_path / "report.json"
    evidence_path = tmp_path / "evidence.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    result = cli._verify(SimpleNamespace(verify=str(report_path), evidence=str(evidence_path)))
    assert result == 0
    assert capsys.readouterr().out.strip() == "VERIFIED"


def test_missing_environment_root_refuses_verification(tmp_path, capsys):
    current = tmp_path / "current"
    new = tmp_path / "new"
    current.mkdir()
    new.mkdir()
    (current / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (new / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    report, evidence = _report_and_evidence(current, new)
    report_path = tmp_path / "report.json"
    evidence_path = tmp_path / "evidence.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    shutil.rmtree(new)
    result = cli._verify(SimpleNamespace(verify=str(report_path), evidence=str(evidence_path)))
    assert result == 2
    assert "VERIFY_REFUSED" in capsys.readouterr().err


def test_missing_witness_hash_refuses(tmp_path):
    current = tmp_path / "current"
    new = tmp_path / "new"
    current.mkdir()
    new.mkdir()
    report, evidence = _report_and_evidence(current, new)
    evidence.pop("witness_sha256")
    with pytest.raises(ValueError, match="witness hash missing"):
        verify_report(report, evidence)


def test_recomputed_evidence_cannot_hide_stale_finding_identity(tmp_path):
    current = tmp_path / "current"
    new = tmp_path / "new"
    current.mkdir()
    new.mkdir()
    report, evidence = _report_and_evidence(current, new)
    report["findings"][0]["api"] = "sample.changed"
    evidence["report"] = copy.deepcopy(report)
    evidence["report_sha256"] = _canonical_digest(report)
    evidence["witness_sha256"] = _canonical_digest(
        {key: value for key, value in evidence.items() if key != "witness_sha256"}
    )
    with pytest.raises(ValueError, match="finding identity mismatch"):
        verify_report(report, evidence)


def test_recomputed_evidence_cannot_hide_stale_witness_identity(tmp_path):
    current = tmp_path / "current"
    new = tmp_path / "new"
    current.mkdir()
    new.mkdir()
    report, evidence = _report_and_evidence(current, new)
    report["witnesses"][0]["api"] = "sample.changed"
    evidence["report"] = copy.deepcopy(report)
    evidence["witnesses"] = copy.deepcopy(report["witnesses"])
    evidence["report_sha256"] = _canonical_digest(report)
    evidence["witness_sha256"] = _canonical_digest(
        {key: value for key, value in evidence.items() if key != "witness_sha256"}
    )
    with pytest.raises(ValueError, match="witness identity mismatch"):
        verify_report(report, evidence)


def _pid_exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_timeout_terminates_descendant_process_group(tmp_path):
    pid_path = tmp_path / "descendant.pid"
    child = (
        "import subprocess,sys,time\n"
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        f"open({str(pid_path)!r},'w').write(str(p.pid))\n"
        "time.sleep(60)\n"
    )
    descendant_pid = None
    try:
        result = executor.run_snippet_isolated(
            snippet_source=child, timeout_seconds=0.5, max_output_bytes=1024
        )
        assert result["timed_out"] is True
        descendant_pid = int(pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2.0
        while _pid_exists(descendant_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _pid_exists(descendant_pid)
    finally:
        if descendant_pid is not None and _pid_exists(descendant_pid):
            os.kill(descendant_pid, signal.SIGKILL)


def test_executor_preserves_normal_output_and_bounds_large_output():
    ordinary = executor.run_snippet_isolated(snippet_source="print('hello')")
    assert ordinary["returncode"] == 0
    assert ordinary["stdout"] == b"hello\n"
    assert ordinary["output_limited"] is False
    large = executor.run_snippet_isolated(
        snippet_source="print('x' * 200000)", max_output_bytes=1024
    )
    assert len(large["stdout"]) == 1024
    assert large["output_limited"] is True


def test_symlink_repository_root_refuses(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="INVENTORY_ROOT_SYMLINK_REFUSED"):
        files.iter_python_files(alias)


def test_regular_repository_root_remains_supported(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    expected = root / "app.py"
    expected.write_text("VALUE = 1\n", encoding="utf-8")
    assert files.iter_python_files(root) == [expected]


def test_symlinked_wheel_refuses(tmp_path):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    outside = tmp_path / "outside.whl"
    outside.write_bytes(b"not-a-real-wheel")
    (wheelhouse / "sample-1.0-py3-none-any.whl").symlink_to(outside)
    with pytest.raises(RuntimeError, match="WHEELHOUSE_REFUSED"):
        envs._local_wheel(wheelhouse, "sample", "1.0")


def test_build_venv_rolls_back_both_environments_on_second_install_failure(
    monkeypatch, tmp_path
):
    created = []

    def make_environment(destination):
        path = Path(destination)
        path.mkdir(parents=True)
        created.append(path)
        return str(path)

    def install(_wheelhouse, _package, version, _network, _runner, _environment):
        if version == "2.0":
            raise RuntimeError("INSTALL_FAILED")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(envs, "_make_environment", make_environment)
    monkeypatch.setattr(envs, "_install", install)
    destination = tmp_path / "current"
    with pytest.raises(RuntimeError, match="INSTALL_FAILED"):
        envs.build_venv(
            package="sample",
            current_version="1.0",
            new_version="2.0",
            wheelhouse=tmp_path / "wheelhouse",
            destination=destination,
        )
    assert created == [destination, tmp_path / "current-new"]
    assert not destination.exists()
    assert not (tmp_path / "current-new").exists()
