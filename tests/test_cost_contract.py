from __future__ import annotations

import json
import time
from pathlib import Path

from breakcheck import cli


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dependency_inventory_remains_empty():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    compact = "".join(project.split())
    assert "dependencies=[]" in compact


def test_capabilities_are_one_noninteractive_machine_readable_command(capsys):
    started = time.monotonic()
    assert cli.main(["--capabilities", "--json"]) == 0
    elapsed = time.monotonic() - started
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] >= 1
    assert payload["python"] == ["3.10", "3.11", "3.12", "3.13"]
    assert payload["platforms"] == ["linux", "macos"]
    assert "dependency_comparison" in payload["features"]
    assert "fixture_suggestions" in payload["features"]
    assert "projection_suggestions" in payload["features"]
    assert "revision_comparison" in payload["features"]
    assert "claim_attestation" in payload["features"]
    assert elapsed < 5.0


def test_demo_is_one_command_and_reaches_a_report_within_five_minutes(
    tmp_path, capsys
):
    started = time.monotonic()
    assert cli.main(["demo", "--output-root", str(tmp_path / "demo")]) == 0
    elapsed = time.monotonic() - started
    output = capsys.readouterr().out
    assert "CHANGED" in output
    assert (tmp_path / "demo" / "report.json").is_file()
    assert (tmp_path / "demo" / "evidence.json").is_file()
    assert elapsed < 300.0


def test_documented_ci_example_is_one_file_under_twenty_lines():
    example = ROOT / "examples" / "github-actions.yml"
    lines = [
        line
        for line in example.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert len(lines) < 20
