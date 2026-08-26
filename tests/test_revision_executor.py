from __future__ import annotations

import copy
import os
from pathlib import Path
import subprocess

import pytest

from breakcheck.adapters.python.symbols import SymbolDefinition
from breakcheck.revision_cli import (
    RevisionModeRefusal,
    _import_roots,
    freeze_revision,
)
from breakcheck.schema import verify_artifact


def _git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=check,
        capture_output=True,
        text=True,
        env=environment,
    )


def _write(repository: Path, relative: str, content: str) -> None:
    path = repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _commit(repository: Path, message: str, paths: tuple[str, ...]) -> str:
    _git(repository, "add", "--", *paths)
    _git(
        repository,
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD").stdout.strip()


def revision_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _write(repository, "sample.py", "def compute_total(value):\n    return value + 1\n")
    _write(
        repository,
        "breakcheck.fixtures.toml",
        "\n".join(
            (
                "schema_version = 1",
                "",
                "[[binding]]",
                'file = "sample.py"',
                "line = 1",
                "column = 0",
                'api = "sample.compute_total"',
                'args = ["2"]',
                "kwargs = {}",
                'fixture_authored_by = "human"',
                "",
            )
        ),
    )
    base = _commit(
        repository,
        "base",
        ("sample.py", "breakcheck.fixtures.toml"),
    )
    _write(repository, "sample.py", "def compute_total(value):\n    return value + 2\n")
    head = _commit(repository, "head", ("sample.py",))
    return repository, base, head


def test_freeze_uses_a_detached_tree_repeats_exactly_twice_and_cleans_up(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    original_head = _git(repository, "rev-parse", "HEAD").stdout.strip()
    original_status = _git(repository, "status", "--porcelain=v1").stdout
    original_worktrees = _git(repository, "worktree", "list", "--porcelain").stdout

    result = freeze_revision(
        repository,
        revision=base,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "runtime",
    )

    assert result.exit_code == 0
    assert result.report["artifact_kind"] == "baseline"
    assert verify_artifact(result.report) == "VERIFIED"
    assert verify_artifact(result.evidence) == "VERIFIED"
    target = result.report["payload"]["target_observations"][0]
    assert target["module"] == "sample"
    assert target["symbol"] == "compute_total"
    assert target["observation"]["payload"] == 3
    assert len(target["repeat_sha256"]) == 2
    assert target["repeat_sha256"][0] == target["repeat_sha256"][1]
    assert not (tmp_path / "runtime").exists()
    assert _git(repository, "rev-parse", "HEAD").stdout.strip() == original_head
    assert _git(repository, "status", "--porcelain=v1").stdout == original_status
    assert _git(repository, "worktree", "list", "--porcelain").stdout == original_worktrees


def test_freeze_refuses_dirty_checkout_even_when_relaxation_is_requested(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    _write(repository, "untracked.txt", "not part of the committed revision\n")

    with pytest.raises(RevisionModeRefusal, match="^DIRTY_TREE_REFUSED$"):
        freeze_revision(
            repository,
            revision=base,
            fixture_path="breakcheck.fixtures.toml",
            runtime_root=tmp_path / "refused-runtime",
        )

    with pytest.raises(
        RevisionModeRefusal, match="^DIRTY_TREE_CAPTURE_UNSUPPORTED$"
    ):
        freeze_revision(
            repository,
            revision=base,
            fixture_path="breakcheck.fixtures.toml",
            runtime_root=tmp_path / "allowed-runtime",
            allow_dirty=True,
        )

    assert not (tmp_path / "allowed-runtime").exists()


def test_freeze_refuses_an_unrepeatable_or_unexercised_baseline(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    _write(repository, "sample.py", "def compute_total(value):\n    return object()\n")
    refused = _commit(repository, "rich result", ("sample.py",))

    with pytest.raises(
        RevisionModeRefusal, match="^BASELINE_TARGET_NOT_EXERCISED$"
    ):
        freeze_revision(
            repository,
            revision=refused,
            fixture_path="breakcheck.fixtures.toml",
            runtime_root=tmp_path / "runtime",
        )


def test_freeze_result_is_detached_from_caller_mutation(tmp_path: Path) -> None:
    repository, base, _ = revision_repository(tmp_path)
    result = freeze_revision(
        repository,
        revision=base,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "runtime",
    )
    report = copy.deepcopy(result.report)
    report["payload"]["target_observations"][0]["observation"]["payload"] = 99
    assert result.report["payload"]["target_observations"][0]["observation"]["payload"] == 3


def test_revision_executor_contract_requests_exactly_two_runs_and_an_explicit_tree(
    tmp_path: Path,
) -> None:
    repository, base, _ = revision_repository(tmp_path)
    calls: list[dict[str, object]] = []

    def executor(**kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs))
        return {
            "runs": [{}, {}],
            "repeatable": True,
            "status": "VALUE",
            "reason_code": None,
            "observation": {
                "kind": "value",
                "payload": 3,
                "exception_class": None,
                "duration_ms": None,
            },
        }

    freeze_revision(
        repository,
        revision=base,
        fixture_path="breakcheck.fixtures.toml",
        runtime_root=tmp_path / "runtime",
        executor=executor,
    )

    assert len(calls) == 1
    assert calls[0]["runs"] == 2
    prefixes = calls[0]["sys_path_prefixes"]
    assert isinstance(prefixes, tuple) and len(prefixes) == 1
    assert Path(prefixes[0]).name == "base"


def test_revision_cleanup_runs_when_execution_is_interrupted(tmp_path: Path) -> None:
    repository, base, _ = revision_repository(tmp_path)
    original_worktrees = _git(repository, "worktree", "list", "--porcelain").stdout

    def interrupted(**kwargs: object) -> dict[str, object]:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        freeze_revision(
            repository,
            revision=base,
            fixture_path="breakcheck.fixtures.toml",
            runtime_root=tmp_path / "runtime",
            executor=interrupted,
        )

    assert not (tmp_path / "runtime").exists()
    assert _git(repository, "worktree", "list", "--porcelain").stdout == original_worktrees


def test_src_import_root_refuses_a_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "src").symlink_to(outside, target_is_directory=True)
    definition = SymbolDefinition(
        target="sample:compute_total",
        module="sample",
        symbol="compute_total",
        kind="function",
        relative_path="src/sample.py",
        line=1,
        column=0,
        signature_sha256="0" * 64,
        behavior_sha256="1" * 64,
        context_sha256="2" * 64,
        definition_sha256="3" * 64,
    )

    with pytest.raises(
        RevisionModeRefusal, match="^REVISION_IMPORT_ROOT_REFUSED$"
    ):
        _import_roots(root, definition)
