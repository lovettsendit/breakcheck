from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

import breakcheck.adapters.python.worktrees as worktree_module
from breakcheck.adapters.python.worktrees import WorktreeRefusal, revision_worktrees


def _git(repository: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=check,
        capture_output=True,
        text=True,
        env=environment,
    )


def _commit(repository: Path, message: str, content: str) -> str:
    (repository / "module.py").write_text(content, encoding="utf-8")
    _git(repository, "add", "--", "module.py")
    _git(
        repository,
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@invalid",
        "commit",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD").stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    base = _commit(repository, "base", "def value():\n    return 1\n")
    head = _commit(repository, "head", "def value():\n    return 2\n")
    return repository, base, head


def _index_sha256(repository: Path) -> str:
    index = Path(_git(repository, "rev-parse", "--git-path", "index").stdout.strip())
    if not index.is_absolute():
        index = repository / index
    return hashlib.sha256(index.read_bytes()).hexdigest()


def test_revision_worktrees_are_detached_owned_and_leave_checkout_unchanged(tmp_path: Path) -> None:
    """A revision comparison must not move HEAD, alter the index, or leave worktrees."""
    repository, base, head = _repository(tmp_path)
    runtime_root = tmp_path / "runtime"
    original_head = _git(repository, "rev-parse", "HEAD").stdout.strip()
    original_index = _index_sha256(repository)
    original_worktrees = _git(repository, "worktree", "list", "--porcelain").stdout

    with revision_worktrees(repository, base, head, runtime_root) as pair:
        assert pair.base_commit == base
        assert pair.head_commit == head
        assert pair.base_root.parent == runtime_root
        assert pair.head_root.parent == runtime_root
        assert _git(pair.base_root, "rev-parse", "HEAD").stdout.strip() == base
        assert _git(pair.head_root, "rev-parse", "HEAD").stdout.strip() == head
        assert _git(pair.base_root, "symbolic-ref", "-q", "HEAD", check=False).returncode != 0
        assert _git(pair.head_root, "symbolic-ref", "-q", "HEAD", check=False).returncode != 0

    assert not runtime_root.exists()
    assert _git(repository, "rev-parse", "HEAD").stdout.strip() == original_head
    assert _index_sha256(repository) == original_index
    assert _git(repository, "worktree", "list", "--porcelain").stdout == original_worktrees


@pytest.mark.parametrize("reference", ["", "--help", "HEAD\n--help", "HEAD\x00suffix"])
def test_revision_ref_metacharacters_are_refused_without_creating_runtime(
    tmp_path: Path, reference: str
) -> None:
    """Option-like or control-bearing refs must never reach Git as arguments."""
    repository, base, _ = _repository(tmp_path)
    runtime_root = tmp_path / "runtime"

    with pytest.raises(WorktreeRefusal, match="^REVISION_REF_REFUSED$"):
        with revision_worktrees(repository, reference, base, runtime_root):
            pass

    assert not runtime_root.exists()


def test_runtime_root_must_be_absent_and_outside_repository_and_git_data(tmp_path: Path) -> None:
    """A caller must not make checkout cleanup capable of deleting existing data."""
    repository, base, head = _repository(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()
    sentinel = existing / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    for runtime_root in (existing, repository / "runtime", repository / ".git" / "runtime"):
        with pytest.raises(WorktreeRefusal, match="^REVISION_RUNTIME_ROOT_REFUSED$"):
            with revision_worktrees(repository, base, head, runtime_root):
                pass

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert not (repository / "runtime").exists()
    assert not (repository / ".git" / "runtime").exists()


def test_cleanup_runs_for_base_exception_and_is_idempotent(tmp_path: Path) -> None:
    """Catchable termination must not leave owned worktrees registered or on disk."""
    repository, base, head = _repository(tmp_path)
    runtime_root = tmp_path / "runtime"
    original_worktrees = _git(repository, "worktree", "list", "--porcelain").stdout

    with pytest.raises(KeyboardInterrupt):
        with revision_worktrees(repository, base, head, runtime_root) as pair:
            raise KeyboardInterrupt

    pair.close()
    assert not runtime_root.exists()
    assert _git(repository, "worktree", "list", "--porcelain").stdout == original_worktrees


def test_checkout_hooks_and_lfs_smudge_are_disabled(tmp_path: Path) -> None:
    """Repository-controlled checkout helpers must not execute during materialization."""
    repository, base, _ = _repository(tmp_path)
    marker = tmp_path / "executed"
    hooks = repository / "hooks"
    hooks.mkdir()
    post_checkout = hooks / "post-checkout"
    post_checkout.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    post_checkout.chmod(0o755)
    _git(repository, "config", "core.hooksPath", str(hooks))
    (repository / ".gitattributes").write_text("payload.txt filter=lfs\n", encoding="utf-8")
    (repository / "payload.txt").write_text("payload\n", encoding="utf-8")
    _git(repository, "config", "filter.lfs.clean", "cat")
    _git(repository, "config", "filter.lfs.smudge", f"touch '{marker}'; cat")
    _git(repository, "config", "filter.lfs.required", "true")
    _git(repository, "add", "--", ".gitattributes", "payload.txt")
    _git(
        repository,
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@invalid",
        "commit",
        "-m",
        "filtered",
    )
    head = _git(repository, "rev-parse", "HEAD").stdout.strip()

    with revision_worktrees(repository, base, head, tmp_path / "runtime") as pair:
        assert (pair.head_root / "payload.txt").read_text(encoding="utf-8") == "payload\n"

    assert not marker.exists()


def test_non_lfs_checkout_filter_is_refused_before_materialization(tmp_path: Path) -> None:
    """An unknown smudge/process filter could execute arbitrary repository configuration."""
    repository, base, head = _repository(tmp_path)
    _git(repository, "config", "filter.unsafe.smudge", "cat")
    runtime_root = tmp_path / "runtime"

    with pytest.raises(WorktreeRefusal, match="^REVISION_FILTER_REFUSED$"):
        with revision_worktrees(repository, base, head, runtime_root):
            pass

    assert not runtime_root.exists()


def test_gitlink_is_refused_before_materialization(tmp_path: Path) -> None:
    """Submodule gitlinks must never trigger nested repository behavior."""
    repository, base, _ = _repository(tmp_path)
    _git(repository, "update-index", "--add", "--cacheinfo", f"160000,{base},vendor/sub")
    _git(
        repository,
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@invalid",
        "commit",
        "-m",
        "gitlink",
    )
    head = _git(repository, "rev-parse", "HEAD").stdout.strip()
    runtime_root = tmp_path / "runtime"

    with pytest.raises(WorktreeRefusal, match="^REVISION_SUBMODULE_REFUSED$"):
        with revision_worktrees(repository, base, head, runtime_root):
            pass

    assert not runtime_root.exists()


def test_symlink_escape_is_refused_and_owned_worktrees_are_cleaned(tmp_path: Path) -> None:
    """A tracked symlink may not make revision execution escape its owned tree."""
    repository, base, _ = _repository(tmp_path)
    (repository / "escape").symlink_to("../outside")
    _git(repository, "add", "--", "escape")
    _git(
        repository,
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@invalid",
        "commit",
        "-m",
        "escape",
    )
    head = _git(repository, "rev-parse", "HEAD").stdout.strip()
    runtime_root = tmp_path / "runtime"
    original_worktrees = _git(repository, "worktree", "list", "--porcelain").stdout

    with pytest.raises(WorktreeRefusal, match="^REVISION_SYMLINK_ESCAPE_REFUSED$"):
        with revision_worktrees(repository, base, head, runtime_root):
            pass

    assert not runtime_root.exists()
    assert _git(repository, "worktree", "list", "--porcelain").stdout == original_worktrees


def test_partial_creation_failure_does_not_delete_foreign_runtime_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failure cleanup may remove owned worktrees but never a later foreign sibling."""
    repository, base, head = _repository(tmp_path)
    runtime_root = tmp_path / "runtime"
    real_add = worktree_module._add_worktree
    calls = 0

    def fail_second_add(repository_path: Path, destination: Path, commit: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            (runtime_root / "foreign.txt").write_text("keep", encoding="utf-8")
            raise WorktreeRefusal("REVISION_WORKTREE_CREATE_REFUSED")
        real_add(repository_path, destination, commit)

    monkeypatch.setattr(worktree_module, "_add_worktree", fail_second_add)

    with pytest.raises(WorktreeRefusal, match="^REVISION_WORKTREE_CREATE_REFUSED$"):
        with revision_worktrees(repository, base, head, runtime_root):
            pass

    assert (runtime_root / "foreign.txt").read_text(encoding="utf-8") == "keep"
    assert not (runtime_root / "base").exists()
