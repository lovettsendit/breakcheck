from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace


_DISTRIBUTION = "breakcheck-demo-dependency"
_IMPORT_ROOT = "breakcheck_demo_dependency"
_CURRENT = "1.0.0"
_PROPOSED = "2.0.0"


def _record_digest(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
    return "sha256=" + encoded.rstrip(b"=").decode("ascii")


def _package_source(version: str) -> bytes:
    increment = "0" if version == _CURRENT else "1"
    return (
        f'__version__ = "{version}"\n\n'
        "def behavior(value):\n"
        f"    return value + {increment}\n"
    ).encode("utf-8")


def _wheel_files(version: str) -> dict[str, bytes]:
    dist_info = f"breakcheck_demo_dependency-{version}.dist-info"
    return {
        f"{_IMPORT_ROOT}/__init__.py": _package_source(version),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {_DISTRIBUTION}\n"
            f"Version: {version}\n"
            "Summary: Offline Breakcheck demonstration dependency\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: breakcheck-demo\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("utf-8"),
        f"{dist_info}/top_level.txt": f"{_IMPORT_ROOT}\n".encode("utf-8"),
    }


def _write_wheel(wheelhouse: Path, version: str) -> Path:
    wheel = wheelhouse / (
        f"breakcheck_demo_dependency-{version}-py3-none-any.whl"
    )
    files = _wheel_files(version)
    dist_info = f"breakcheck_demo_dependency-{version}.dist-info"
    record_path = f"{dist_info}/RECORD"
    rows = [
        (name, _record_digest(data), str(len(data)))
        for name, data in sorted(files.items())
    ]
    rows.append((record_path, "", ""))
    record_stream = io.StringIO(newline="")
    csv.writer(record_stream, lineterminator="\n").writerows(rows)
    files[record_path] = record_stream.getvalue().encode("utf-8")
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return wheel


def _install_metadata_view(root: Path) -> None:
    package = root / _IMPORT_ROOT
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(_package_source(_CURRENT))
    dist_info = root / f"breakcheck_demo_dependency-{_CURRENT}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        f"Name: {_DISTRIBUTION}\n"
        f"Version: {_CURRENT}\n",
        encoding="utf-8",
    )
    (dist_info / "top_level.txt").write_text(
        _IMPORT_ROOT + "\n", encoding="utf-8"
    )


def run_demo(output_root: str | os.PathLike[str], build) -> int:
    root = Path(output_root).resolve()
    if root.exists() or root.is_symlink():
        raise ValueError("DEMO_OUTPUT_EXISTS_REFUSED")
    root.mkdir(parents=True)
    repository = root / "repository"
    wheelhouse = root / "wheelhouse"
    installed = root / "installed-current"
    repository.mkdir()
    wheelhouse.mkdir()
    installed.mkdir()
    (repository / "app.py").write_text(
        "import breakcheck_demo_dependency\n\n"
        "outcome = breakcheck_demo_dependency.behavior(1)\n",
        encoding="utf-8",
    )
    _write_wheel(wheelhouse, _CURRENT)
    _write_wheel(wheelhouse, _PROPOSED)
    _install_metadata_view(installed)

    report = root / "report.json"
    evidence = root / "evidence.json"
    runtime = root / "runtime"
    args = SimpleNamespace(
        target=f"{_DISTRIBUTION}@{_PROPOSED}",
        wheelhouse=str(wheelhouse),
        runtime_root=str(runtime),
        output=str(report),
        evidence=str(evidence),
        json=False,
        ci=False,
    )
    previous_cwd = Path.cwd()
    sys.path.insert(0, str(installed))
    try:
        os.chdir(repository)
        result = build(args)
    finally:
        os.chdir(previous_cwd)
        if sys.path and sys.path[0] == str(installed):
            sys.path.pop(0)
    if result != 0 or not report.is_file() or not evidence.is_file():
        raise ValueError("DEMO_EXECUTION_REFUSED")
    try:
        from breakcheck.verify import verify_report

        report_payload = json.loads(report.read_text(encoding="utf-8"))
        evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))
        verify_report(report_payload, evidence_payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("DEMO_VERIFICATION_REFUSED") from exc
    return 0
