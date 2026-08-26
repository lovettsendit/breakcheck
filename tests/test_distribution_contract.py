from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 CI
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_distribution_metadata_exposes_the_current_public_contract() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "breakcheck"
    assert project["version"] == "2.0.0"
    assert project["authors"] == [{"name": "ViDale Lovett"}]
    assert project["dependencies"] == []
    assert project["scripts"] == {"breakcheck": "breakcheck.cli:main"}
    assert project["urls"]["Repository"] == "https://github.com/lovettsendit/breakcheck"

    package = importlib.import_module("breakcheck")
    assert package.__version__ == project["version"]


def test_source_manifest_includes_public_operational_material() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for contract in (
        "include SKILL.md",
        "graft docs",
        "graft examples",
        "graft scripts",
        "recursive-include src/breakcheck *.py",
        "recursive-include tests *.py",
        "global-exclude ._*",
        "global-exclude .DS_Store",
        "prune .breakcheck",
        "prune build",
        "prune dist",
    ):
        assert contract in manifest


def test_github_action_example_is_small_and_uses_the_public_package() -> None:
    example = (ROOT / "examples" / "github-actions.yml").read_text(encoding="utf-8")
    effective_lines = [
        line
        for line in example.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert len(effective_lines) <= 20
    assert 'python -m pip install "breakcheck==2.0.0"' in example
    assert "--ci" in example
    for line in example.splitlines():
        if "uses:" in line:
            revision = line.split("@", 1)[1].split()[0]
            assert len(revision) == 40
            int(revision, 16)


def test_github_action_example_quotes_colons_in_run_scalars() -> None:
    example = (ROOT / "examples" / "github-actions.yml").read_text(encoding="utf-8")
    for line in example.splitlines():
        if "- run:" not in line:
            continue
        scalar = line.split("- run:", 1)[1].strip()
        if ":" in scalar:
            assert scalar.startswith(("'", '"', "|", ">")), line


def test_release_scanner_accepts_the_public_working_tree() -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "scan_artifacts.sh"), str(ROOT)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_module_and_installed_command_report_one_version(tmp_path: Path) -> None:
    output = subprocess.run(
        [sys.executable, "-c", "import breakcheck; print(breakcheck.__version__)"],
        cwd=tmp_path,
        env=os.environ | {"PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=True,
    )
    assert output.stdout.strip() == "2.0.0"
