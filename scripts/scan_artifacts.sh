#!/usr/bin/env bash
# Read-only release hygiene scan for a checkout, wheel, or source distribution.
set -u

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <directory|wheel|source-distribution>" >&2
  exit 2
fi

python_bin=${PYTHON:-python3}
exec "$python_bin" - "$1" <<'PY'
from __future__ import annotations

import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
findings: list[str] = []


def forbidden(message: str) -> None:
    findings.append(message)


local_path_patterns = (
    re.compile(
        rb"(?m)(?:^|[\s\"'=:(])/(?:Users|home|Volumes)/[^\s\"'<>]+"
    ),
    re.compile(
        rb"(?mi)(?:^|[\s\"'=:(])[A-Z]:\\Users\\[^\s\"'<>]+"
    ),
)
email_pattern = re.compile(
    rb"(?<!\\)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
noreply_pattern = re.compile(
    rb"(?:[A-Za-z0-9._%+-]+@(users\.)?noreply\.github\.com|noreply@github\.com)$",
    re.IGNORECASE,
)
credential_patterns = (
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(rb"sk-[A-Za-z0-9]{20,}"),
    re.compile(rb"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"),
    re.compile(
        rb"(?<![A-Za-z0-9_-])(?:api[_-]?key|access[_-]?key|secret|password|token)\s*[:=]",
        re.IGNORECASE,
    ),
)


def checked_relative(name: str) -> str | None:
    if not name or "\x00" in name or "\\" in name:
        forbidden(f"unsafe archive path: {name!r}")
        return None
    raw_parts = name.rstrip("/").split("/")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in raw_parts):
        forbidden(f"unsafe archive path: {name}")
        return None
    return str(path)


def scan_name(relative: str) -> None:
    parts = PurePosixPath(relative).parts
    lowered = [part.casefold() for part in parts]
    if any(
        part == ".git"
        or part == ".ds_store"
        or part.startswith("._")
        for part in lowered
    ):
        forbidden(f"local or macOS path: {relative}")
        return


def scan_content(data: bytes, relative: str) -> None:
    if not data or b"\x00" in data[:4096]:
        return
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return
    for pattern in local_path_patterns:
        if pattern.search(data):
            forbidden(f"local filesystem path: {relative}")
            break
    for match in email_pattern.finditer(data):
        if not noreply_pattern.fullmatch(match.group(0)):
            forbidden(f"personal email content: {relative}")
            break
    for pattern in credential_patterns:
        if pattern.search(data):
            forbidden(f"credential-shaped content: {relative}")
            break


def scan_zip(path: Path) -> None:
    total = 0
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                relative = checked_relative(info.filename)
                if relative is None:
                    continue
                if relative in seen:
                    forbidden(f"duplicate archive path: {relative}")
                    continue
                seen.add(relative)
                scan_name(relative)
                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFLNK or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    forbidden(f"archive link or special file: {relative}")
                    continue
                if info.is_dir():
                    continue
                total += info.file_size
                if info.file_size > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
                    forbidden(f"archive size limit exceeded: {relative}")
                    continue
                scan_content(archive.read(info), relative)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        forbidden(f"unreadable zip archive: {exc}")


def scan_tar(path: Path) -> None:
    total = 0
    seen: set[str] = set()
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive:
                relative = checked_relative(member.name)
                if relative is None:
                    continue
                if relative in seen:
                    forbidden(f"duplicate archive path: {relative}")
                    continue
                seen.add(relative)
                scan_name(relative)
                if member.isdir():
                    continue
                if not member.isfile():
                    forbidden(f"archive link or special file: {relative}")
                    continue
                total += member.size
                if member.size > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
                    forbidden(f"archive size limit exceeded: {relative}")
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    forbidden(f"unreadable archive member: {relative}")
                    continue
                scan_content(stream.read(MAX_MEMBER_BYTES + 1), relative)
    except (OSError, tarfile.TarError) as exc:
        forbidden(f"unreadable tar archive: {exc}")


def git_output(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def scan_directory(path: Path) -> None:
    try:
        repository = Path(
            git_output(path, "rev-parse", "--show-toplevel").decode().strip()
        )
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        repository = None

    if repository is None:
        candidates = sorted(
            item for item in path.rglob("*") if ".git" not in item.parts
        )
        base = path
    else:
        tracked = git_output(repository, "ls-files", "-z").split(b"\0")
        untracked = git_output(
            repository, "ls-files", "--others", "--exclude-standard", "-z"
        ).split(b"\0")
        names = sorted({name.decode() for name in tracked + untracked if name})
        candidates = [repository / name for name in names]
        base = repository

    for item in candidates:
        try:
            relative = item.relative_to(base).as_posix()
        except ValueError:
            forbidden(f"path escaped scan root: {item}")
            continue
        scan_name(relative)
        if item.is_symlink():
            forbidden(f"symlink in release tree: {relative}")
        elif item.is_file():
            try:
                size = item.stat().st_size
                if size > MAX_MEMBER_BYTES:
                    forbidden(f"file size limit exceeded: {relative}")
                else:
                    scan_content(item.read_bytes(), relative)
            except OSError as exc:
                forbidden(f"unreadable file: {relative}: {exc}")

    if repository is not None:
        try:
            metadata_emails = git_output(
                repository, "log", "--all", "--format=%ae%n%ce"
            ).splitlines()
        except (OSError, subprocess.CalledProcessError) as exc:
            forbidden(f"unable to inspect git metadata: {exc}")
        else:
            for address in metadata_emails:
                if address and not noreply_pattern.fullmatch(address):
                    forbidden("personal email in git metadata")
                    break
        try:
            patch = git_output(repository, "log", "--format=", "--all", "-p", "--no-ext-diff")
        except (OSError, subprocess.CalledProcessError) as exc:
            forbidden(f"unable to inspect git history: {exc}")
        else:
            changed = b"\n".join(
                line[1:]
                for line in patch.splitlines()
                if line[:1] in (b"+", b"-")
                and not line.startswith((b"+++", b"---"))
            )
            before = len(findings)
            scan_content(changed, "git history")
            if len(findings) > before:
                findings[before:] = ["sensitive content in git history"]


def main() -> int:
    if len(sys.argv) != 2:
        print("scanner argument error", file=sys.stderr)
        return 2
    input_path = Path(sys.argv[1])
    if not input_path.exists() and not input_path.is_symlink():
        print(f"artifact not found: {input_path}", file=sys.stderr)
        return 2
    if input_path.is_symlink():
        forbidden(f"symlink input refused: {input_path}")
    elif input_path.is_dir():
        scan_directory(input_path)
    elif input_path.name.endswith((".whl", ".zip")):
        scan_zip(input_path)
    elif input_path.name.endswith((".tar.gz", ".tgz")):
        scan_tar(input_path)
    elif input_path.is_file():
        scan_name(input_path.name)
        scan_content(input_path.read_bytes(), input_path.name)
    else:
        forbidden(f"unsupported input: {input_path}")

    for finding in dict.fromkeys(findings):
        print(f"FORBIDDEN: {finding}")
    if findings:
        return 1
    print(f"artifact scan clean: {input_path}")
    return 0


raise SystemExit(main())
PY
