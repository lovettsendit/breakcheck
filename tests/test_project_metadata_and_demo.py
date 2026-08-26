from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

from breakcheck.demo import run_demo

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "run_demo.sh"
APP = ROOT / "examples" / "packaging-change" / "app.py"


def _wheel_record(files: dict[str, bytes]) -> bytes:
    rows = []
    for name, content in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        rows.append((name, f"sha256={digest}", str(len(content))))
    rows.append(("packaging-PLACEHOLDER.dist-info/RECORD", "", ""))
    output = io.StringIO()
    writer = csv.writer(output)
    for row in rows:
        writer.writerow(row)
    return output.getvalue().encode()


def _write_packaging_wheel(wheelhouse: Path, version: str, utils_source: str) -> None:
    dist_info = f"packaging-{version}.dist-info"
    files = {
        "packaging/__init__.py": f"__version__ = {version!r}\n".encode(),
        "packaging/utils.py": utils_source.encode(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            "Name: packaging\n"
            f"Version: {version}\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: breakcheck-test-suite\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
    }
    record = _wheel_record(files).replace(
        b"packaging-PLACEHOLDER.dist-info/RECORD",
        f"{dist_info}/RECORD".encode(),
    )
    files[f"{dist_info}/RECORD"] = record
    wheel = wheelhouse / f"packaging-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def _offline_wheelhouse(tmp_path: Path) -> Path:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _write_packaging_wheel(
        wheelhouse,
        "21.3",
        "def canonicalize_version(version, strip_trailing_zero=True):\n"
        "    return version.rstrip('.0') if strip_trailing_zero else version\n",
    )
    _write_packaging_wheel(
        wheelhouse,
        "22.0",
        "def canonicalize_version(version):\n"
        "    return version.rstrip('.0')\n",
    )
    return wheelhouse


def _line_value(output: str, name: str) -> Path:
    prefix = f"{name}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return Path(line.removeprefix(prefix))
    raise AssertionError(f"missing {prefix!r} in demo output:\n{output}")


def test_current_project_metadata_and_public_artifacts_are_declared():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["version"] == "2.0.0"
    assert project["project"]["authors"] == [{"name": "ViDale Lovett"}]
    assert project["project"]["urls"] == {
        "Homepage": "https://github.com/lovettsendit/breakcheck",
        "Repository": "https://github.com/lovettsendit/breakcheck",
        "Issues": "https://github.com/lovettsendit/breakcheck/issues",
        "Changelog": "https://github.com/lovettsendit/breakcheck/blob/main/CHANGELOG.md",
    }
    assert "Copyright (c) 2026 ViDale Lovett and contributors" in (ROOT / "LICENSE").read_text()
    assert "## 2.0.0 - 2026-08-26" in (ROOT / "CHANGELOG.md").read_text()
    manifest = (ROOT / "MANIFEST.in").read_text()
    assert "include SKILL.md" in manifest
    assert "graft examples" in manifest
    assert "graft docs" in manifest
    readme = (ROOT / "README.md").read_text()
    assert "Dependabot tells you a new version exists." in readme
    assert "python -m pip install breakcheck" in readme
    assert "docs/assets/breakcheck-social-preview.png" in readme


def test_demo_runs_real_changed_case_from_offline_synthetic_wheels(tmp_path: Path):
    wheelhouse = _offline_wheelhouse(tmp_path)
    environment = os.environ | {
        "BREAKCHECK_DEMO_WHEELHOUSE": str(wheelhouse),
        "BREAKCHECK_DEMO_KEEP": "1",
        "PYTHON": sys.executable,
    }
    result = subprocess.run(
        ["sh", str(DEMO)],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BREAKCHECK_EXIT=3" in result.stdout
    assert "VERIFIED" in result.stdout
    assert "DEMO_VERDICT=PASS" in result.stdout
    assert APP.read_text() == (
        "from packaging.utils import canonicalize_version\n\n"
        "canonicalize_version('1.0.0', strip_trailing_zero=False)\n"
    )
    root = _line_value(result.stdout, "DEMO_ROOT")
    report_path = _line_value(result.stdout, "REPORT_PATH")
    evidence_path = _line_value(result.stdout, "EVIDENCE_PATH")
    try:
        assert root.is_dir()
        assert report_path.is_file()
        assert evidence_path.is_file()
        report = json.loads(report_path.read_text())
        assert report["schema_version"] == 2
        assert report["payload"]["summary"]["changed"] == 1
        assert len(report["payload"]["findings"]) == 1
        assert report["payload"]["findings"][0]["verdict"] == "CHANGED"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_builtin_demo_refuses_an_unverified_artifact_bundle(tmp_path: Path) -> None:
    """The one-command demo must verify its output before reporting success."""

    def write_unverified_bundle(arguments) -> int:
        Path(arguments.output).write_text('{"schema_version": 2}', encoding="utf-8")
        Path(arguments.evidence).write_text("{}", encoding="utf-8")
        return 0

    with pytest.raises(ValueError, match="^DEMO_VERIFICATION_REFUSED$"):
        run_demo(tmp_path / "demo", write_unverified_bundle)
