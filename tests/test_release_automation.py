from __future__ import annotations

import subprocess
import tarfile
import warnings
import zipfile
from io import BytesIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
SCANNER = ROOT / "scripts" / "scan_artifacts.sh"
PUBLISH_ACTION = "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ACTION = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_ci_keeps_full_eight_job_matrix_and_runs_one_acceptance_job() -> None:
    ci = _read(CI)
    assert "branches: [main]" in ci
    assert "pull_request:" in ci
    assert 'os: ["ubuntu-latest", "macos-latest"]' in ci
    assert 'python-version: ["3.10", "3.11", "3.12", "3.13"]' in ci
    assert ci.count("runs-on: ${{ matrix.os }}") == 1
    assert "acceptance:" in ci
    assert "needs: test" in ci
    assert "breakcheck demo --output-root" in ci
    assert "breakcheck --capabilities --json" in ci
    assert "matrix.os == 'ubuntu-latest'" not in ci
    assert "matrix.python-version == '3.13'" not in ci
    for action in ("actions/checkout@", "actions/setup-python@"):
        line = next(line for line in ci.splitlines() if action in line)
        assert len(line.split("@", 1)[1].split()[0]) == 40


def test_release_workflow_fails_closed_before_trusted_publishing() -> None:
    release = _read(RELEASE)
    assert "types: [published]" in release
    assert "permissions: {}" in release
    assert "validate:" in release
    assert "publish:" in release
    assert "needs: validate" in release
    assert "name: pypi" in release
    assert "url: https://pypi.org/p/breakcheck" in release
    assert "contents: read" in release
    assert "id-token: write" in release
    assert "attestations: true" in release
    assert PUBLISH_ACTION in release
    assert UPLOAD_ACTION in release
    assert DOWNLOAD_ACTION in release
    assert "packages-dir: dist/" in release
    assert "print-hash: true" in release
    assert "actions/checkout@" in release
    assert "secrets." not in release
    assignment_marker = "token" + ":"
    id_token_permission = "id-token" + ":"
    assert assignment_marker not in release.replace(id_token_permission, "")
    assert "draft" in release and "prerelease" in release
    assert "breakcheck-2.0.0-py3-none-any.whl" in release
    assert "breakcheck-2.0.0.tar.gz" in release
    assert "sha256sum" in release
    assert "test -z" not in release
    assert release.count("id-token: write") == 1
    validate_block, publish_block = release.split("  publish:", 1)
    assert "id-token: write" not in validate_block
    assert "python -m build --outdir dist ." in validate_block
    assert "SOURCE_DATE_EPOCH" in validate_block
    assert "python -m twine check --strict" in validate_block
    assert "scripts/scan_artifacts.sh" in validate_block
    assert "gh api" not in validate_block
    assert "github.event.release.id" not in validate_block
    assert "releases/assets" not in validate_block
    assert "id-token: write" in publish_block
    assert "pip install" not in publish_block
    assert "python -m build" not in publish_block
    assert "skip-existing: false" in publish_block
    assert "verify-metadata: true" in publish_block
    assert "outputs.wheel-sha256" not in release
    assert "outputs.sdist-sha256" not in release
    assert "wheel_sha256:" in release
    assert "sdist_sha256:" in release
    for line in release.splitlines():
        if "uses:" in line:
            assert "@" in line
            assert len(line.split("@", 1)[1].split()[0]) == 40


def test_release_provenance_is_the_exact_tag_not_uploaded_release_assets() -> None:
    release = _read(RELEASE)
    validate_block, publish_block = release.split("  publish:", 1)

    assert "ref: ${{ github.event.release.tag_name }}" in validate_block
    assert "persist-credentials: false" in validate_block
    assert "git describe --exact-match --tags HEAD" in validate_block
    assert "git status --porcelain" in validate_block
    assert validate_block.index("git describe --exact-match --tags HEAD") < validate_block.index(
        "python -m build --outdir dist ."
    )
    assert "release_json" not in release
    assert "RELEASE_ID" not in release
    assert "GH_TOKEN" not in release
    assert "releases/assets" not in release
    assert "python -m build --outdir dist ." not in publish_block
    assert "actions/upload-artifact@" in validate_block
    assert "actions/download-artifact@" in publish_block


def test_artifact_scanner_rejects_personal_and_macos_payloads(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "public.txt").write_text("public release artifact\n", encoding="utf-8")
    clean_result = subprocess.run(["bash", str(SCANNER), str(clean)], text=True, capture_output=True)
    assert clean_result.returncode == 0, clean_result.stderr

    dirty = tmp_path / "dirty"
    dirty.mkdir()
    (dirty / "._metadata").write_text("AppleDouble", encoding="utf-8")
    personal_email = "person" + "@" + "example" + ".com"
    (dirty / "metadata.json").write_text('{"email":"' + personal_email + '"}', encoding="utf-8")
    dirty_result = subprocess.run(["bash", str(SCANNER), str(dirty)], text=True, capture_output=True)
    assert dirty_result.returncode != 0
    assert "FORBIDDEN" in dirty_result.stdout

    wheel = tmp_path / "dirty.whl"
    local_path = "/" + "Users/example/work/project"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("breakcheck-2.0.0.dist-info/build-path.txt", local_path)
    wheel_result = subprocess.run(["bash", str(SCANNER), str(wheel)], text=True, capture_output=True)
    assert wheel_result.returncode != 0

    sdist = tmp_path / "dirty.tar.gz"
    payload = tmp_path / "payload.txt"
    credential_name = "api" + "_key"
    payload.write_text(credential_name + "=not-a-release-secret", encoding="utf-8")
    with tarfile.open(sdist, "w:gz") as archive:
        archive.add(payload, arcname="breakcheck-2.0.0/.git/config")
    sdist_result = subprocess.run(["bash", str(SCANNER), str(sdist)], text=True, capture_output=True)
    assert sdist_result.returncode != 0


def test_artifact_scanner_allows_clean_checkout_and_id_token(tmp_path: Path) -> None:
    checkout_result = subprocess.run(["bash", str(SCANNER), str(ROOT)], text=True, capture_output=True)
    assert checkout_result.returncode == 0, checkout_result.stdout + checkout_result.stderr

    artifact = tmp_path / "workflow.yml"
    artifact.write_text("permissions:\n  id-token: write\n", encoding="utf-8")
    result = subprocess.run(["bash", str(SCANNER), str(artifact.parent)], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_artifact_scanner_refuses_local_path_without_self_triggering(
    tmp_path: Path,
) -> None:
    local_root = "/" + "Volumes/external-work/project"
    artifact = tmp_path / "local-path.txt"
    artifact.write_text(local_root + "\n", encoding="utf-8")

    result = subprocess.run(
        ["bash", str(SCANNER), str(tmp_path)],
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "local filesystem path" in result.stdout

    scanner_only = tmp_path / "scanner-only"
    scanner_only.mkdir()
    (scanner_only / SCANNER.name).write_bytes(SCANNER.read_bytes())
    result = subprocess.run(
        ["bash", str(SCANNER), str(scanner_only)],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_artifact_scanner_refuses_real_email_local_path_and_credential(tmp_path: Path) -> None:
    email = "release" + "@" + "example" + ".com"
    local_root = "/" + "home/example/work/project"
    credential_name = "api" + "_key"
    artifact = tmp_path / "private.txt"
    artifact.write_text(
        "\n".join((email, local_root, credential_name + "=not-a-secret")),
        encoding="utf-8",
    )
    result = subprocess.run(["bash", str(SCANNER), str(artifact.parent)], text=True, capture_output=True)
    assert result.returncode != 0
    assert "FORBIDDEN" in result.stdout


def test_artifact_scanner_checks_git_patch_content_without_author_headers(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Release Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "release" + "@" + "example" + ".com"],
        check=True,
    )
    tracked = repository / "tracked.txt"
    tracked.write_text("safe content\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "safe"], check=True)
    historical_value = "token" + ": historical-secret"
    tracked.write_text(historical_value + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "commit", "-am", "add secret"], check=True)
    tracked.write_text("safe again\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "commit", "-am", "remove secret"], check=True)

    result = subprocess.run(["bash", str(SCANNER), str(repository)], text=True, capture_output=True)
    assert result.returncode != 0
    assert "git history" in result.stdout


def test_artifact_scanner_checks_commit_email_metadata(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Release Test"], check=True)
    personal_email = "release" + "@" + "example" + ".com"
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", personal_email],
        check=True,
    )
    (repository / "tracked.txt").write_text("safe content\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "safe"], check=True)

    result = subprocess.run(
        ["bash", str(SCANNER), str(repository)],
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "personal email in git metadata" in result.stdout


def test_artifact_scanner_allows_github_noreply_merge_metadata(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "GitHub"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "noreply@github.com"],
        check=True,
    )
    (repository / "tracked.txt").write_text("safe content\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "commit",
            "-qm",
            "Merge pull request",
            "--author",
            "Contributor <12345+contributor@users.noreply.github.com>",
        ],
        check=True,
    )

    result = subprocess.run(
        ["bash", str(SCANNER), str(repository)],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_artifact_scanner_refuses_archive_traversal_and_links(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.whl"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../outside.txt", "public")
    result = subprocess.run(
        ["bash", str(SCANNER), str(traversal)],
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "unsafe archive path" in result.stdout

    linked = tmp_path / "linked.tar.gz"
    with tarfile.open(linked, "w:gz") as archive:
        info = tarfile.TarInfo("breakcheck-2.0.0/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside"
        archive.addfile(info, BytesIO())
    result = subprocess.run(
        ["bash", str(SCANNER), str(linked)],
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "archive link or special file" in result.stdout


def test_artifact_scanner_refuses_duplicate_archive_members(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("breakcheck/module.py", "first")
            archive.writestr("breakcheck/module.py", "second")
    result = subprocess.run(
        ["bash", str(SCANNER), str(duplicate)],
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "duplicate archive path" in result.stdout
