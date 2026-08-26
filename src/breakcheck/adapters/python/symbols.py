from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Iterable


class SymbolAnalysisRefusal(ValueError):
    """A source tree could not be analyzed without guessing."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sha256(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ast_value(value: object) -> object:
    if isinstance(value, ast.AST):
        return ast.dump(value, annotate_fields=True, include_attributes=False)
    if isinstance(value, list):
        return [_ast_value(item) for item in value]
    if isinstance(value, tuple):
        return [_ast_value(item) for item in value]
    return value


def _module_name(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return "__init__"
    return ".".join(parts)


def _iter_python_files(root: Path) -> Iterable[Path]:
    requested = Path(root)
    if requested.is_symlink() or not requested.is_dir():
        raise SymbolAnalysisRefusal("SYMBOL_ROOT_REFUSED")
    resolved = requested.resolve(strict=True)
    for path in sorted(resolved.rglob("*.py"), key=lambda item: item.relative_to(resolved).as_posix()):
        relative = path.relative_to(resolved)
        if any(part.startswith(".") or part in {"site-packages", "venv"} for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            raise SymbolAnalysisRefusal("SYMBOL_SOURCE_SYMLINK_REFUSED")
        yield path


def _signature_payload(node: ast.FunctionDef | ast.AsyncFunctionDef) -> object:
    return {
        "arguments": _ast_value(node.args),
        "returns": _ast_value(node.returns),
        "type_comment": node.type_comment,
        "type_params": _ast_value(getattr(node, "type_params", [])),
    }


def _behavior_payload(node: ast.FunctionDef | ast.AsyncFunctionDef) -> object:
    return {
        "async": isinstance(node, ast.AsyncFunctionDef),
        "decorators": _ast_value(node.decorator_list),
        "body": _ast_value(node.body),
    }


def _context_payload(
    module: ast.Module,
    top_level: ast.stmt,
    target: ast.FunctionDef | ast.AsyncFunctionDef,
) -> object:
    callable_declarations = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    module_context = [
        _ast_value(statement)
        for statement in module.body
        if statement is not top_level
        and not isinstance(statement, callable_declarations)
    ]
    class_context: object = None
    if isinstance(top_level, ast.ClassDef):
        class_context = {
            "bases": _ast_value(top_level.bases),
            "keywords": _ast_value(top_level.keywords),
            "decorators": _ast_value(top_level.decorator_list),
            "type_params": _ast_value(getattr(top_level, "type_params", [])),
            "body": [
                _ast_value(statement)
                for statement in top_level.body
                if statement is not target
                and not isinstance(statement, callable_declarations)
            ],
        }
    return {"module": module_context, "class": class_context}


@dataclass(frozen=True)
class SymbolDefinition:
    target: str
    module: str
    symbol: str
    kind: str
    relative_path: str
    line: int
    column: int
    signature_sha256: str
    behavior_sha256: str
    context_sha256: str
    definition_sha256: str


@dataclass(frozen=True)
class SymbolInventory:
    definitions: tuple[SymbolDefinition, ...]

    def by_target(self) -> dict[str, tuple[SymbolDefinition, ...]]:
        grouped: dict[str, list[SymbolDefinition]] = {}
        for definition in self.definitions:
            grouped.setdefault(definition.target, []).append(definition)
        return {
            target: tuple(sorted(values, key=lambda value: (value.relative_path, value.line, value.column)))
            for target, values in sorted(grouped.items())
        }


@dataclass(frozen=True)
class SymbolChange:
    target: str
    status: str
    base: SymbolDefinition | None
    head: SymbolDefinition | None


@dataclass(frozen=True)
class TrackedTreeEntry:
    path: str
    mode: str
    kind: str
    sha256: str
    size: int


@dataclass(frozen=True)
class TrackedTreeIdentity:
    sha256: str
    entries: tuple[TrackedTreeEntry, ...]
    regular_files: int
    symlinks: int


def _git_output(root: Path, *arguments: str) -> bytes:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
        if key in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            env=environment,
            shell=False,
        )
    except OSError as exc:
        raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED") from exc
    if result.returncode != 0:
        raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED")
    return result.stdout


def tracked_tree_identity(root: Path | str) -> TrackedTreeIdentity:
    requested = Path(root)
    if requested.is_symlink() or not requested.is_dir():
        raise SymbolAnalysisRefusal("TRACKED_TREE_ROOT_REFUSED")
    resolved = requested.resolve(strict=True)
    try:
        top = Path(_git_output(resolved, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    except (UnicodeDecodeError, OSError) as exc:
        raise SymbolAnalysisRefusal("TRACKED_TREE_ROOT_REFUSED") from exc
    if top != resolved:
        raise SymbolAnalysisRefusal("TRACKED_TREE_ROOT_REFUSED")
    entries = []
    for record in _git_output(top, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, _, stage = metadata.split(b" ", 2)
            relative_text = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED") from exc
        relative = Path(relative_text)
        if stage != b"0" or relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED")
        if mode == b"160000":
            raise SymbolAnalysisRefusal("TRACKED_TREE_SUBMODULE_REFUSED")
        path = top / relative
        try:
            metadata_stat = path.lstat()
        except OSError as exc:
            raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED") from exc
        mode_text = mode.decode("ascii", errors="strict")
        if mode in (b"100644", b"100755"):
            if not stat.S_ISREG(metadata_stat.st_mode) or path.is_symlink():
                raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED")
            mode_text = "100755" if metadata_stat.st_mode & 0o111 else "100644"
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED") from exc
            kind = "regular"
        elif mode == b"120000":
            if not stat.S_ISLNK(metadata_stat.st_mode):
                raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED")
            try:
                content = os.fsencode(os.readlink(path))
            except OSError as exc:
                raise SymbolAnalysisRefusal("TRACKED_TREE_REFUSED") from exc
            kind = "symlink"
        else:
            raise SymbolAnalysisRefusal("TRACKED_TREE_MODE_REFUSED")
        entries.append(
            TrackedTreeEntry(
                path=relative.as_posix(),
                mode=mode_text,
                kind=kind,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
            )
        )
    ordered = tuple(sorted(entries, key=lambda entry: entry.path))
    digest_rows = [
        {
            "kind": entry.kind,
            "mode": entry.mode,
            "path": entry.path,
            "sha256": entry.sha256,
            "size": entry.size,
        }
        for entry in ordered
    ]
    return TrackedTreeIdentity(
        sha256=_sha256(digest_rows),
        entries=ordered,
        regular_files=sum(entry.kind == "regular" for entry in ordered),
        symlinks=sum(entry.kind == "symlink" for entry in ordered),
    )


def inventory_symbols(root: Path | str) -> SymbolInventory:
    requested = Path(root)
    if requested.is_symlink() or not requested.is_dir():
        raise SymbolAnalysisRefusal("SYMBOL_ROOT_REFUSED")
    resolved = requested.resolve(strict=True)
    definitions = []
    for path in _iter_python_files(resolved):
        relative = path.relative_to(resolved)
        try:
            source = path.read_text(encoding="utf-8", errors="strict")
            module_ast = ast.parse(source, filename=relative.as_posix(), type_comments=True)
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise SymbolAnalysisRefusal("SYMBOL_SOURCE_SYNTAX_REFUSED") from exc
        module_name = _module_name(relative)
        for statement in module_ast.body:
            candidates: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                candidates.append((statement.name, statement))
            elif isinstance(statement, ast.ClassDef):
                for member in statement.body:
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        candidates.append((f"{statement.name}.{member.name}", member))
            for symbol, node in candidates:
                signature = _signature_payload(node)
                behavior = _behavior_payload(node)
                context = _context_payload(module_ast, statement, node)
                signature_sha256 = _sha256(signature)
                behavior_sha256 = _sha256(behavior)
                definition_sha256 = _sha256(
                    {"signature": signature_sha256, "behavior": behavior_sha256}
                )
                kind_prefix = "async_" if isinstance(node, ast.AsyncFunctionDef) else ""
                kind = kind_prefix + ("method" if isinstance(statement, ast.ClassDef) else "function")
                definitions.append(
                    SymbolDefinition(
                        target=f"{module_name}:{symbol}",
                        module=module_name,
                        symbol=symbol,
                        kind=kind,
                        relative_path=relative.as_posix(),
                        line=node.lineno,
                        column=node.col_offset,
                        signature_sha256=signature_sha256,
                        behavior_sha256=behavior_sha256,
                        context_sha256=_sha256(context),
                        definition_sha256=definition_sha256,
                    )
                )
    return SymbolInventory(
        definitions=tuple(
            sorted(definitions, key=lambda value: (value.target, value.relative_path, value.line, value.column))
        )
    )


def compare_symbol_trees(base_root: Path | str, head_root: Path | str) -> tuple[SymbolChange, ...]:
    base = inventory_symbols(base_root).by_target()
    head = inventory_symbols(head_root).by_target()
    changes = []
    for target in sorted(set(base) | set(head)):
        base_values = base.get(target, ())
        head_values = head.get(target, ())
        if len(base_values) > 1 or len(head_values) > 1:
            changes.append(SymbolChange(target, "SYMBOL_AMBIGUOUS", None, None))
            continue
        if not base_values:
            changes.append(SymbolChange(target, "NO_BASELINE_REVISION", None, head_values[0] if len(head_values) == 1 else None))
            continue
        if not head_values:
            changes.append(SymbolChange(target, "SYMBOL_REMOVED", base_values[0] if len(base_values) == 1 else None, None))
            continue
        base_definition = base_values[0]
        head_definition = head_values[0]
        if base_definition.signature_sha256 != head_definition.signature_sha256:
            status = "FIXTURE_SIGNATURE_DRIFT"
        elif base_definition.behavior_sha256 != head_definition.behavior_sha256:
            status = "CHANGED"
        elif base_definition.context_sha256 != head_definition.context_sha256:
            status = "CONTEXT_CHANGED"
        else:
            status = "UNCHANGED"
        changes.append(SymbolChange(target, status, base_definition, head_definition))
    return tuple(changes)
