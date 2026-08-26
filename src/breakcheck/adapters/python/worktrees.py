from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from typing import Iterator


_GIT_CONFIG = (
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "filter.lfs.required=false",
    "filter.lfs.smudge=",
    "filter.lfs.process=",
    "advice.detachedHead=false",
    "protocol.file.allow=never",
)


class WorktreeRefusal(ValueError):
    """A safe revision pair could not be materialized."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _git_environment() -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
        if key in os.environ
    }
    environment.update(
        {
            "GIT_ASKPASS": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_SSH_COMMAND": "ssh -oBatchMode=yes",
            "GIT_TERMINAL_PROMPT": "0",
            "SSH_ASKPASS": os.devnull,
        }
    )
    return environment


def _git_command(repository: Path, *arguments: str) -> list[str]:
    command = ["git", "-C", str(repository)]
    for value in _GIT_CONFIG:
        command.extend(("-c", value))
    command.extend(arguments)
    return command


def _run_git(
    repository: Path,
    *arguments: str,
    refusal: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            _git_command(repository, *arguments),
            check=False,
            capture_output=True,
            env=_git_environment(),
            shell=False,
        )
    except OSError as exc:
        raise WorktreeRefusal(refusal) from exc
    if check and result.returncode != 0:
        raise WorktreeRefusal(refusal)
    return result


def _decoded_line(result: subprocess.CompletedProcess[bytes], refusal: str) -> str:
    try:
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise WorktreeRefusal(refusal) from exc
    if not value or "\n" in value or "\r" in value:
        raise WorktreeRefusal(refusal)
    return value


def _repository_paths(repository: Path) -> tuple[Path, Path]:
    requested = Path(repository)
    if requested.is_symlink() or not requested.is_dir():
        raise WorktreeRefusal("REPOSITORY_REFUSED")
    top = Path(
        _decoded_line(
            _run_git(requested, "rev-parse", "--show-toplevel", refusal="REPOSITORY_REFUSED"),
            "REPOSITORY_REFUSED",
        )
    ).resolve()
    common = Path(
        _decoded_line(
            _run_git(top, "rev-parse", "--path-format=absolute", "--git-common-dir", refusal="REPOSITORY_REFUSED"),
            "REPOSITORY_REFUSED",
        )
    ).resolve()
    return top, common


def _validate_ref_text(reference: str) -> str:
    if not isinstance(reference, str) or not reference or reference.startswith("-"):
        raise WorktreeRefusal("REVISION_REF_REFUSED")
    if any(ord(character) < 32 or ord(character) == 127 for character in reference):
        raise WorktreeRefusal("REVISION_REF_REFUSED")
    return reference


def resolve_commit(repository: Path | str, reference: str) -> str:
    top, _ = _repository_paths(Path(repository))
    requested = _validate_ref_text(reference)
    result = _run_git(
        top,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{requested}^{{commit}}",
        refusal="REVISION_REF_REFUSED",
    )
    commit = _decoded_line(result, "REVISION_REF_REFUSED")
    if len(commit) not in (40, 64) or any(character not in "0123456789abcdef" for character in commit):
        raise WorktreeRefusal("REVISION_REF_REFUSED")
    return commit


def _validate_checkout_filters(repository: Path) -> None:
    result = _run_git(
        repository,
        "config",
        "--null",
        "--get-regexp",
        r"^filter\..*\.(clean|smudge|process|required)$",
        refusal="REVISION_FILTER_REFUSED",
        check=False,
    )
    if result.returncode not in (0, 1):
        raise WorktreeRefusal("REVISION_FILTER_REFUSED")
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        key = record.split(b"\n", 1)[0].decode("utf-8", errors="replace").lower()
        if not key.startswith("filter.lfs."):
            raise WorktreeRefusal("REVISION_FILTER_REFUSED")


def _tree_entries(repository: Path, commit: str) -> tuple[tuple[bytes, bytes, bytes], ...]:
    result = _run_git(
        repository,
        "ls-tree",
        "-r",
        "-z",
        commit,
        refusal="REVISION_TREE_REFUSED",
    )
    entries = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path = record.split(b"\t", 1)
            mode, kind, _ = metadata.split(b" ", 2)
        except ValueError as exc:
            raise WorktreeRefusal("REVISION_TREE_REFUSED") from exc
        entries.append((mode, kind, path))
    return tuple(entries)


def _validate_no_submodules(repository: Path, *commits: str) -> None:
    for commit in commits:
        if any(mode == b"160000" or kind == b"commit" for mode, kind, _ in _tree_entries(repository, commit)):
            raise WorktreeRefusal("REVISION_SUBMODULE_REFUSED")


def _relative_path(raw: bytes) -> Path:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WorktreeRefusal("REVISION_PATH_ENCODING_REFUSED") from exc
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise WorktreeRefusal("REVISION_TREE_REFUSED")
    return relative


def _validate_symlinks(repository: Path, worktree: Path, commit: str) -> None:
    root = worktree.resolve(strict=True)
    for mode, _, raw_path in _tree_entries(repository, commit):
        if mode != b"120000":
            continue
        relative = _relative_path(raw_path)
        link = root / relative
        if not link.is_symlink():
            raise WorktreeRefusal("REVISION_TREE_REFUSED")
        try:
            target = Path(os.readlink(link))
            resolved = link.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise WorktreeRefusal("REVISION_SYMLINK_ESCAPE_REFUSED") from exc
        if target.is_absolute() or not _is_within(resolved, root):
            raise WorktreeRefusal("REVISION_SYMLINK_ESCAPE_REFUSED")


def _is_within(candidate: Path, container: Path) -> bool:
    return candidate == container or container in candidate.parents


def _prepare_runtime_root(runtime_root: Path, repository: Path, common_git: Path) -> Path:
    requested = Path(runtime_root)
    if requested.exists() or requested.is_symlink():
        raise WorktreeRefusal("REVISION_RUNTIME_ROOT_REFUSED")
    parent = requested.parent
    if parent.is_symlink() or not parent.is_dir():
        raise WorktreeRefusal("REVISION_RUNTIME_ROOT_REFUSED")
    resolved = parent.resolve(strict=True) / requested.name
    if _is_within(resolved, repository) or _is_within(resolved, common_git):
        raise WorktreeRefusal("REVISION_RUNTIME_ROOT_REFUSED")
    try:
        resolved.mkdir(mode=0o700)
    except OSError as exc:
        raise WorktreeRefusal("REVISION_RUNTIME_ROOT_REFUSED") from exc
    return resolved


@dataclass
class RevisionWorktreePair:
    repository: Path
    runtime_root: Path
    base_commit: str
    head_commit: str
    base_root: Path
    head_root: Path
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        errors = []
        for worktree in (self.head_root, self.base_root):
            result = _run_git(
                self.repository,
                "worktree",
                "remove",
                "--force",
                str(worktree),
                refusal="REVISION_WORKTREE_CLEANUP_REFUSED",
                check=False,
            )
            if result.returncode != 0 and (worktree.exists() or worktree.is_symlink()):
                errors.append(worktree.name)
        if not errors:
            try:
                self.runtime_root.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                errors.append(self.runtime_root.name)
        self._closed = not errors
        if errors:
            raise WorktreeRefusal("REVISION_WORKTREE_CLEANUP_REFUSED")

    def __enter__(self) -> "RevisionWorktreePair":
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        try:
            self.close()
        except WorktreeRefusal:
            if exc is None:
                raise
        return False


def _add_worktree(repository: Path, destination: Path, commit: str) -> None:
    _run_git(
        repository,
        "worktree",
        "add",
        "--detach",
        "--no-checkout",
        str(destination),
        commit,
        refusal="REVISION_WORKTREE_CREATE_REFUSED",
    )
    _run_git(
        destination,
        "checkout",
        "--detach",
        "--force",
        commit,
        refusal="REVISION_WORKTREE_CHECKOUT_REFUSED",
    )


def create_revision_worktrees(
    repository: Path | str,
    base_ref: str,
    head_ref: str,
    runtime_root: Path | str,
) -> RevisionWorktreePair:
    top, common = _repository_paths(Path(repository))
    base_commit = resolve_commit(top, base_ref)
    head_commit = resolve_commit(top, head_ref)
    _validate_checkout_filters(top)
    _validate_no_submodules(top, base_commit, head_commit)
    root = _prepare_runtime_root(Path(runtime_root), top, common)
    pair = RevisionWorktreePair(
        repository=top,
        runtime_root=root,
        base_commit=base_commit,
        head_commit=head_commit,
        base_root=root / "base",
        head_root=root / "head",
    )
    try:
        _add_worktree(top, pair.base_root, base_commit)
        _add_worktree(top, pair.head_root, head_commit)
        _validate_symlinks(top, pair.base_root, base_commit)
        _validate_symlinks(top, pair.head_root, head_commit)
    except BaseException:
        try:
            pair.close()
        except WorktreeRefusal:
            pass
        raise
    return pair


@contextmanager
def revision_worktrees(
    repository: Path | str,
    base_ref: str,
    head_ref: str,
    runtime_root: Path | str,
) -> Iterator[RevisionWorktreePair]:
    pair = create_revision_worktrees(repository, base_ref, head_ref, runtime_root)
    try:
        yield pair
    finally:
        pair.close()
