from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from breakcheck.adapters.python.symbols import (
    SymbolAnalysisRefusal,
    compare_symbol_trees,
    inventory_symbols,
    tracked_tree_identity,
)


def _write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def test_location_only_source_changes_do_not_change_symbol_fingerprints(tmp_path: Path) -> None:
    """Blank lines and source locations must not create behavioral targets."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    _write(
        base,
        "pricing.py",
        "def total(value: int) -> int:\n    return value + 1\n\n"
        "class Calculator:\n    def apply(self, value):\n        return value * 2\n",
    )
    _write(
        head,
        "pricing.py",
        "\n\n\ndef total(value: int) -> int:\n\n    return value + 1\n\n\n"
        "class Calculator:\n\n    def apply(self, value):\n        return value * 2\n",
    )

    changes = {change.target: change for change in compare_symbol_trees(base, head)}

    assert changes["pricing:total"].status == "UNCHANGED"
    assert changes["pricing:Calculator.apply"].status == "UNCHANGED"


def test_changed_sibling_does_not_mark_an_unchanged_function_as_context_changed(
    tmp_path: Path,
) -> None:
    """A changed function must not make every sibling an out-of-scope target."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    _write(
        base,
        "sample.py",
        "def compute_total(value):\n    return value + 1\n\n"
        "def auxiliary(value):\n    return value * 2\n",
    )
    _write(
        head,
        "sample.py",
        "def compute_total(value):\n    result = value + 1\n    return result\n\n"
        "def auxiliary(value):\n    return value * 2\n",
    )

    changes = {change.target: change for change in compare_symbol_trees(base, head)}

    assert changes["sample:compute_total"].status == "CHANGED"
    assert changes["sample:auxiliary"].status == "UNCHANGED"


def test_symbol_changes_classify_body_signature_addition_and_removal(tmp_path: Path) -> None:
    """Each structural transition must retain its distinct fail-closed disposition."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    _write(
        base,
        "service.py",
        "def changed(value):\n    return value + 1\n\n"
        "def signature(value):\n    return value\n\n"
        "def removed():\n    return 'old'\n",
    )
    _write(
        head,
        "service.py",
        "def changed(value):\n    return value + 2\n\n"
        "def signature(value, scale=1):\n    return value\n\n"
        "def added():\n    return 'new'\n",
    )

    changes = {change.target: change for change in compare_symbol_trees(base, head)}

    assert changes["service:changed"].status == "CHANGED"
    assert changes["service:signature"].status == "FIXTURE_SIGNATURE_DRIFT"
    assert changes["service:removed"].status == "SYMBOL_REMOVED"
    assert changes["service:added"].status == "NO_BASELINE_REVISION"


def test_module_and_class_context_changes_are_not_silently_ignored(tmp_path: Path) -> None:
    """Globals, imports, bases, and class attributes can change unchanged method bodies."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    _write(
        base,
        "context.py",
        "OFFSET = 1\n"
        "def total(value):\n    return value + OFFSET\n\n"
        "class Base:\n    pass\n\n"
        "class Calculator(Base):\n    scale = 2\n    def apply(self, value):\n        return value * self.scale\n",
    )
    _write(
        head,
        "context.py",
        "OFFSET = 2\n"
        "def total(value):\n    return value + OFFSET\n\n"
        "class Base:\n    pass\n\n"
        "class Calculator(Base):\n    scale = 3\n    def apply(self, value):\n        return value * self.scale\n",
    )

    changes = {change.target: change for change in compare_symbol_trees(base, head)}

    assert changes["context:total"].status == "CONTEXT_CHANGED"
    assert changes["context:Calculator.apply"].status == "CONTEXT_CHANGED"


def test_inventory_includes_only_top_level_functions_and_direct_methods(tmp_path: Path) -> None:
    """Nested functions and nested-class methods are outside the declared symbol surface."""
    root = tmp_path / "root"
    root.mkdir()
    _write(
        root,
        "workers.py",
        "async def fetch():\n    return 1\n\n"
        "def outer():\n    def nested():\n        return 2\n    return nested()\n\n"
        "class Direct:\n    async def run(self):\n        return 3\n"
        "    class Nested:\n        def hidden(self):\n            return 4\n",
    )

    definitions = {item.target: item for item in inventory_symbols(root).definitions}

    assert set(definitions) == {"workers:fetch", "workers:outer", "workers:Direct.run"}
    assert definitions["workers:fetch"].kind == "async_function"
    assert definitions["workers:Direct.run"].kind == "async_method"


def test_duplicate_targets_and_module_path_collisions_are_ambiguous(tmp_path: Path) -> None:
    """Python's last-definition-wins behavior must not choose a comparison target silently."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root in (base, head):
        root.mkdir()
        _write(root, "duplicate.py", "def value():\n    return 1\ndef value():\n    return 2\n")
        _write(root, "pkg.py", "def run():\n    return 1\n")
        _write(root, "pkg/__init__.py", "def run():\n    return 1\n")

    changes = {change.target: change for change in compare_symbol_trees(base, head)}

    assert changes["duplicate:value"].status == "SYMBOL_AMBIGUOUS"
    assert changes["pkg:run"].status == "SYMBOL_AMBIGUOUS"


def test_ambiguity_takes_precedence_over_added_or_removed_dispositions(tmp_path: Path) -> None:
    """A duplicated one-sided target must not be represented as a single new or removed symbol."""
    empty = tmp_path / "empty"
    duplicate = tmp_path / "duplicate"
    empty.mkdir()
    duplicate.mkdir()
    _write(duplicate, "module.py", "def value():\n    return 1\ndef value():\n    return 2\n")

    added = compare_symbol_trees(empty, duplicate)
    removed = compare_symbol_trees(duplicate, empty)

    assert added[0].status == "SYMBOL_AMBIGUOUS"
    assert removed[0].status == "SYMBOL_AMBIGUOUS"


def test_syntax_failure_refuses_the_whole_inventory(tmp_path: Path) -> None:
    """A partial inventory could make a claim look narrower than the changed tree."""
    root = tmp_path / "root"
    root.mkdir()
    _write(root, "broken.py", "def broken(:\n")

    with pytest.raises(SymbolAnalysisRefusal, match="^SYMBOL_SOURCE_SYNTAX_REFUSED$"):
        inventory_symbols(root)


def test_missing_or_symlinked_symbol_root_is_refused_with_a_stable_code(tmp_path: Path) -> None:
    """Root resolution errors must not leak host paths or escape the selected tree."""
    real = tmp_path / "real"
    real.mkdir()
    symlink = tmp_path / "linked"
    symlink.symlink_to(real, target_is_directory=True)

    for root in (tmp_path / "missing", symlink):
        with pytest.raises(SymbolAnalysisRefusal, match="^SYMBOL_ROOT_REFUSED$") as caught:
            inventory_symbols(root)
        assert str(tmp_path) not in str(caught.value)


def _git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        },
    )


def _commit_all(repository: Path, message: str) -> None:
    _git(repository, "add", "--", "module.py", "data.txt")
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


def test_tracked_tree_identity_binds_every_tracked_regular_file_and_ignores_untracked(
    tmp_path: Path,
) -> None:
    """The tree identity must cover tracked content without leaking an absolute path."""
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _write(repository, "module.py", "def value():\n    return 1\n")
    _write(repository, "data.txt", "first\n")
    _commit_all(repository, "base")

    first = tracked_tree_identity(repository)
    (repository / "untracked.txt").write_text("ignored\n", encoding="utf-8")
    second = tracked_tree_identity(repository)
    (repository / "module.py").chmod(0o755)
    executable = tracked_tree_identity(repository)
    (repository / "data.txt").write_text("second\n", encoding="utf-8")
    third = tracked_tree_identity(repository)

    assert first.sha256 == second.sha256
    assert first.sha256 != executable.sha256
    assert first.sha256 != third.sha256
    assert first.regular_files == 2
    assert [entry.path for entry in first.entries] == ["data.txt", "module.py"]
    assert all(not Path(entry.path).is_absolute() for entry in first.entries)
    assert all(str(tmp_path) not in repr(entry) for entry in first.entries)


def test_tracked_tree_identity_binds_internal_symlinks_and_refuses_missing_files(
    tmp_path: Path,
) -> None:
    """Non-regular tracked entries and missing checkout content cannot disappear from identity."""
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _write(repository, "module.py", "def value():\n    return 1\n")
    _write(repository, "data.txt", "payload\n")
    (repository / "alias.txt").symlink_to("data.txt")
    _git(repository, "add", "--", "module.py", "data.txt", "alias.txt")
    _git(
        repository,
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@invalid",
        "commit",
        "-m",
        "symlink",
    )

    identity = tracked_tree_identity(repository)
    assert identity.regular_files == 2
    assert identity.symlinks == 1
    assert next(entry for entry in identity.entries if entry.path == "alias.txt").kind == "symlink"

    (repository / "data.txt").unlink()
    with pytest.raises(SymbolAnalysisRefusal, match="^TRACKED_TREE_REFUSED$"):
        tracked_tree_identity(repository)


def test_tracked_tree_identity_refuses_gitlinks(tmp_path: Path) -> None:
    """A submodule commit cannot be represented as a complete local file-tree hash."""
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _write(repository, "module.py", "def value():\n    return 1\n")
    _write(repository, "data.txt", "payload\n")
    _commit_all(repository, "base")
    commit = _git(repository, "rev-parse", "HEAD").stdout.strip()
    _git(repository, "update-index", "--add", "--cacheinfo", f"160000,{commit},vendor/sub")

    with pytest.raises(SymbolAnalysisRefusal, match="^TRACKED_TREE_SUBMODULE_REFUSED$"):
        tracked_tree_identity(repository)
