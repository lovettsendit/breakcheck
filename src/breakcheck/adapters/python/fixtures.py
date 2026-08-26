from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Iterable, Mapping, Sequence


__all__ = (
    "FixtureBinding",
    "FixtureFile",
    "FixtureRefusal",
    "REFUSAL_CODES",
    "coverage_delta",
    "deterministic",
    "executable",
    "fixture_yield",
    "human_minutes",
    "load_fixture_file",
    "render_fixture_source",
    "resolve_fixture_policy",
    "suggest_fixtures",
    "valid",
)


REFUSAL_CODES = frozenset(
    {
        "FIXTURE_AMBIGUOUS_REFUSED",
        "FIXTURE_ARGUMENT_CAP_REFUSED",
        "FIXTURE_AUTHOR_REFUSED",
        "FIXTURE_BINDING_CAP_REFUSED",
        "FIXTURE_BINDING_PATH_REFUSED",
        "FIXTURE_DUPLICATE_BINDING_REFUSED",
        "FIXTURE_DUPLICATE_FIELD_REFUSED",
        "FIXTURE_ENCODING_REFUSED",
        "FIXTURE_EXPRESSION_REFUSED",
        "FIXTURE_FILE_CAP_REFUSED",
        "FIXTURE_INVENTORY_REFUSED",
        "FIXTURE_METRIC_REFUSED",
        "FIXTURE_PATH_REFUSED",
        "FIXTURE_POLICY_FORBID",
        "FIXTURE_POLICY_REFUSED",
        "FIXTURE_PROJECTION_REFUSED",
        "FIXTURE_RENDER_REFUSED",
        "FIXTURE_REQUIRED",
        "FIXTURE_SCHEMA_REFUSED",
        "FIXTURE_SCHEMA_VERSION_REFUSED",
        "FIXTURE_SOURCE_CAP_REFUSED",
        "FIXTURE_STALE_REFUSED",
        "FIXTURE_SUGGESTION_EXISTS",
        "FIXTURE_SUGGESTION_WRITE_REFUSED",
        "FIXTURE_SYMLINK_REFUSED",
        "FIXTURE_SYNTAX_REFUSED",
        "FIXTURE_UNMATCHED_REFUSED",
    }
)


_AUTHOR_VALUES = frozenset(("human", "agent", "unknown"))
_POLICY_VALUES = frozenset(("forbid", "allow", "require"))
_TOP_LEVEL_FIELDS = frozenset(("schema_version",))
_BINDING_REQUIRED_FIELDS = frozenset(
    ("file", "line", "column", "api", "args", "kwargs", "fixture_authored_by")
)
_BINDING_OPTIONAL_FIELDS = frozenset(("setup", "projection"))
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_API = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_MAX_FILE_BYTES = 262_144
_MAX_BINDINGS = 256
_MAX_ARGS = 64
_MAX_KWARGS = 64
_MAX_EXPRESSION_BYTES = 65_536
_MAX_SETUP_BYTES = 65_536
_MAX_EXPRESSION_NODES = 256
_MAX_SETUP_NODES = 1_024
_MAX_CONTEXT_BYTES = 512


class FixtureRefusal(ValueError):
    """A stable fail-closed fixture refusal."""

    def __init__(
        self,
        code: str,
        *,
        line: int | None = None,
        detail: Mapping[str, object] | None = None,
    ):
        self.code = code
        self.line = line
        self.detail = (
            {"line": line}
            if detail is None and line is not None
            else None if detail is None else dict(detail)
        )
        message = code if line is None else f"{code}:line={line}"
        super().__init__(message)


@dataclass(frozen=True)
class FixtureBinding:
    file: str
    line: int
    column: int
    api: str
    args: tuple[str, ...]
    kwargs: tuple[tuple[str, str], ...]
    setup: str
    projection: str | None
    fixture_authored_by: str
    binding_sha256: str

    @property
    def key(self) -> tuple[str, int, int, str]:
        return (self.file, self.line, self.column, self.api)


@dataclass(frozen=True)
class FixtureFile:
    path: str
    bindings: tuple[FixtureBinding, ...]
    file_sha256: str
    canonical_sha256: str


def _refuse(
    code: str,
    *,
    line: int | None = None,
    detail: Mapping[str, object] | None = None,
) -> None:
    if code not in REFUSAL_CODES:
        raise RuntimeError("FIXTURE_REFUSAL_UNDECLARED")
    raise FixtureRefusal(code, line=line, detail=detail)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in ('"', "'"):
            quote = character
            continue
        if character == "#":
            return line[:index]
    if quote is not None or escaped:
        _refuse("FIXTURE_SYNTAX_REFUSED")
    return line


def _split_unquoted(value: str, delimiter: str) -> list[str]:
    pieces: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    nesting = 0
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in ('"', "'"):
            quote = character
            continue
        if character in "[{(":
            nesting += 1
        elif character in "]})":
            nesting -= 1
            if nesting < 0:
                _refuse("FIXTURE_SYNTAX_REFUSED")
        elif character == delimiter and nesting == 0:
            pieces.append(value[start:index])
            start = index + 1
    if quote is not None or escaped or nesting != 0:
        _refuse("FIXTURE_SYNTAX_REFUSED")
    pieces.append(value[start:])
    return pieces


def _decode_basic_string(value: str, *, multiline: bool) -> str:
    decoded: list[str] = []
    index = 0
    escapes = {
        "b": "\b",
        "t": "\t",
        "n": "\n",
        "f": "\f",
        "r": "\r",
        '"': '"',
        "\\": "\\",
    }
    while index < len(value):
        character = value[index]
        if character != "\\":
            if character == '"' and not multiline:
                _refuse("FIXTURE_SYNTAX_REFUSED")
            if ord(character) < 0x20 and character not in ("\t", "\n"):
                _refuse("FIXTURE_SYNTAX_REFUSED")
            if character == "\n" and not multiline:
                _refuse("FIXTURE_SYNTAX_REFUSED")
            decoded.append(character)
            index += 1
            continue
        index += 1
        if index >= len(value):
            _refuse("FIXTURE_SYNTAX_REFUSED")
        escaped = value[index]
        if multiline and escaped == "\n":
            index += 1
            while index < len(value) and value[index] in (" ", "\t", "\n"):
                index += 1
            continue
        if escaped in escapes:
            decoded.append(escapes[escaped])
            index += 1
            continue
        if escaped in ("u", "U"):
            width = 4 if escaped == "u" else 8
            digits = value[index + 1 : index + 1 + width]
            if len(digits) != width or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
                _refuse("FIXTURE_SYNTAX_REFUSED")
            codepoint = int(digits, 16)
            if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                _refuse("FIXTURE_SYNTAX_REFUSED")
            decoded.append(chr(codepoint))
            index += width + 1
            continue
        _refuse("FIXTURE_SYNTAX_REFUSED")
    return "".join(decoded)


def _parse_string(value: str) -> str:
    if value.startswith('"""') and value.endswith('"""') and len(value) >= 6:
        content = value[3:-3]
        if content.startswith("\n"):
            content = content[1:]
        return _decode_basic_string(content, multiline=True)
    if value.startswith("'''") and value.endswith("'''") and len(value) >= 6:
        content = value[3:-3]
        return content[1:] if content.startswith("\n") else content
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return _decode_basic_string(value[1:-1], multiline=False)
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        content = value[1:-1]
        if "'" in content or "\n" in content or "\r" in content:
            _refuse("FIXTURE_SYNTAX_REFUSED")
        if any(ord(character) < 0x20 and character != "\t" for character in content):
            _refuse("FIXTURE_SYNTAX_REFUSED")
        return content
    _refuse("FIXTURE_SYNTAX_REFUSED")


def _parse_string_array(value: str) -> list[str]:
    if not value.startswith("[") or not value.endswith("]"):
        _refuse("FIXTURE_SYNTAX_REFUSED")
    body = value[1:-1].strip()
    if not body:
        return []
    parsed = []
    for item in _split_unquoted(body, ","):
        item = item.strip()
        if not item:
            _refuse("FIXTURE_SYNTAX_REFUSED")
        parsed.append(_parse_string(item))
    return parsed


def _parse_inline_string_table(value: str) -> dict[str, str]:
    if not value.startswith("{") or not value.endswith("}"):
        _refuse("FIXTURE_SYNTAX_REFUSED")
    body = value[1:-1].strip()
    if not body:
        return {}
    result: dict[str, str] = {}
    for item in _split_unquoted(body, ","):
        if "=" not in item:
            _refuse("FIXTURE_SYNTAX_REFUSED")
        key, raw = item.split("=", 1)
        key = key.strip()
        if not _KEY.fullmatch(key):
            _refuse("FIXTURE_SYNTAX_REFUSED")
        if key in result:
            _refuse("FIXTURE_DUPLICATE_FIELD_REFUSED")
        result[key] = _parse_string(raw.strip())
    return result


def _parse_value(field: str, raw: str) -> object:
    if field in ("schema_version", "line", "column"):
        if not _INTEGER.fullmatch(raw):
            _refuse("FIXTURE_SYNTAX_REFUSED")
        return int(raw)
    if field == "args":
        return _parse_string_array(raw)
    if field == "kwargs":
        return _parse_inline_string_table(raw)
    return _parse_string(raw)


def _triple_string_end(value: str, delimiter: str) -> int | None:
    position = 3
    while True:
        found = value.find(delimiter, position)
        if found < 0:
            return None
        if delimiter == "'''":
            return found
        backslashes = 0
        cursor = found - 1
        while cursor >= 0 and value[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return found
        position = found + 1


def _collect_multiline_string(
    lines: Sequence[str], start: int, raw_value: str
) -> tuple[str, int]:
    delimiter = raw_value[:3]
    combined = raw_value
    end = start
    while True:
        closing = _triple_string_end(combined, delimiter)
        if closing is not None:
            trailing = combined[closing + 3 :].strip()
            if trailing and not trailing.startswith("#"):
                _refuse("FIXTURE_SYNTAX_REFUSED")
            return combined[: closing + 3], end
        end += 1
        if end >= len(lines):
            _refuse("FIXTURE_SYNTAX_REFUSED")
        combined += "\n" + lines[end]


def _parse_document(text: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    top: dict[str, object] = {}
    bindings: list[dict[str, object]] = []
    current: dict[str, object] = top
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line_number = index + 1
        try:
            raw_line = lines[index]
            probe = raw_line.strip()
            triple_assignment = False
            if "=" in probe:
                _, probe_value = probe.split("=", 1)
                triple_assignment = probe_value.strip().startswith(('"""', "'''"))
            line = probe if triple_assignment else _strip_comment(raw_line).strip()
            if not line:
                index += 1
                continue
            if line == "[[binding]]":
                if len(bindings) >= _MAX_BINDINGS:
                    _refuse("FIXTURE_BINDING_CAP_REFUSED")
                current = {}
                bindings.append(current)
                index += 1
                continue
            if line.startswith("["):
                _refuse("FIXTURE_SCHEMA_REFUSED")
            if "=" not in line:
                _refuse("FIXTURE_SYNTAX_REFUSED")
            key, raw_value = line.split("=", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            if raw_value.startswith(('"""', "'''")):
                raw_value, index = _collect_multiline_string(
                    lines, index, raw_value
                )
            allowed = (
                _TOP_LEVEL_FIELDS
                if current is top
                else _BINDING_REQUIRED_FIELDS | _BINDING_OPTIONAL_FIELDS
            )
            if key not in allowed:
                _refuse("FIXTURE_SCHEMA_REFUSED")
            if key in current:
                _refuse("FIXTURE_DUPLICATE_FIELD_REFUSED")
            current[key] = _parse_value(key, raw_value)
            index += 1
        except FixtureRefusal as exc:
            if exc.code == "FIXTURE_SYNTAX_REFUSED" and exc.line is None:
                raise FixtureRefusal(exc.code, line=line_number) from None
            raise
    if set(top) != _TOP_LEVEL_FIELDS:
        _refuse("FIXTURE_SCHEMA_REFUSED")
    return top, bindings


def _repository_root(value: os.PathLike[str] | str) -> Path:
    root = Path(value)
    if root.is_symlink() or not root.is_dir():
        _refuse("FIXTURE_PATH_REFUSED")
    return Path(os.path.abspath(root))


def _path_under_root(
    value: os.PathLike[str] | str, root: Path, *, must_exist: bool
) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        _refuse("FIXTURE_PATH_REFUSED")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            _refuse("FIXTURE_SYMLINK_REFUSED")
    if must_exist:
        try:
            metadata = candidate.stat()
        except OSError:
            _refuse("FIXTURE_PATH_REFUSED")
        if not stat.S_ISREG(metadata.st_mode):
            _refuse("FIXTURE_PATH_REFUSED")
    return candidate


def _binding_file(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        _refuse("FIXTURE_BINDING_PATH_REFUSED")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        _refuse("FIXTURE_BINDING_PATH_REFUSED")
    normalized = path.as_posix()
    if normalized != value:
        _refuse("FIXTURE_BINDING_PATH_REFUSED")
    return normalized


def _validate_source(source: str, *, setup: bool = False) -> ast.AST:
    cap = _MAX_SETUP_BYTES if setup else _MAX_EXPRESSION_BYTES
    if len(source.encode("utf-8")) > cap:
        _refuse("FIXTURE_SOURCE_CAP_REFUSED")
    try:
        tree = ast.parse(source, mode="exec" if setup else "eval")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        _refuse("FIXTURE_EXPRESSION_REFUSED")
    node_cap = _MAX_SETUP_NODES if setup else _MAX_EXPRESSION_NODES
    if sum(1 for _ in ast.walk(tree)) > node_cap:
        _refuse("FIXTURE_SOURCE_CAP_REFUSED")
    return tree


def _binding_payload(row: Mapping[str, object]) -> dict[str, object]:
    if set(row) - (_BINDING_REQUIRED_FIELDS | _BINDING_OPTIONAL_FIELDS):
        _refuse("FIXTURE_SCHEMA_REFUSED")
    if "fixture_authored_by" not in row:
        _refuse("FIXTURE_AUTHOR_REFUSED")
    if not _BINDING_REQUIRED_FIELDS.issubset(row):
        _refuse("FIXTURE_SCHEMA_REFUSED")
    file_name = _binding_file(row["file"])
    line = row["line"]
    column = row["column"]
    api = row["api"]
    args = row["args"]
    kwargs = row["kwargs"]
    setup = row.get("setup", "")
    projection = row.get("projection")
    fixture_authored_by = row["fixture_authored_by"]
    if (
        type(line) is not int
        or line < 1
        or type(column) is not int
        or column < 0
        or not isinstance(api, str)
        or not _API.fullmatch(api)
        or not isinstance(args, list)
        or not isinstance(kwargs, dict)
        or not isinstance(setup, str)
        or (projection is not None and not isinstance(projection, str))
    ):
        _refuse("FIXTURE_SCHEMA_REFUSED")
    if fixture_authored_by not in _AUTHOR_VALUES:
        _refuse("FIXTURE_AUTHOR_REFUSED")
    if len(args) > _MAX_ARGS or len(kwargs) > _MAX_KWARGS:
        _refuse("FIXTURE_ARGUMENT_CAP_REFUSED")
    for source in args:
        if not isinstance(source, str):
            _refuse("FIXTURE_SCHEMA_REFUSED")
        _validate_source(source)
    ordered_kwargs = []
    for name in sorted(kwargs):
        source = kwargs[name]
        if not _KEY.fullmatch(name) or not isinstance(source, str):
            _refuse("FIXTURE_SCHEMA_REFUSED")
        _validate_source(source)
        ordered_kwargs.append((name, source))
    if setup:
        _validate_source(setup, setup=True)
    if projection is not None:
        tree = _validate_source(projection)
        if not any(isinstance(node, ast.Name) and node.id == "outcome" for node in ast.walk(tree)):
            _refuse("FIXTURE_PROJECTION_REFUSED")
    return {
        "file": file_name,
        "line": line,
        "column": column,
        "api": api,
        "args": list(args),
        "kwargs": ordered_kwargs,
        "setup": setup,
        "projection": projection,
        "fixture_authored_by": fixture_authored_by,
    }


def _inventory_keys(
    inventory: Iterable[Mapping[str, object]],
) -> tuple[
    dict[tuple[str, int, int, str], int],
    dict[tuple[str, str], list[tuple[str, int, int, str]]],
]:
    counts: dict[tuple[str, int, int, str], int] = {}
    nearby: dict[tuple[str, str], list[tuple[str, int, int, str]]] = {}
    try:
        rows = list(inventory)
    except TypeError:
        _refuse("FIXTURE_INVENTORY_REFUSED")
    for row in rows:
        if not isinstance(row, Mapping):
            _refuse("FIXTURE_INVENTORY_REFUSED")
        try:
            file_name = _binding_file(row["file"])
            line = row["line"]
            column = row["column"]
            api = row["api"]
        except (KeyError, TypeError):
            _refuse("FIXTURE_INVENTORY_REFUSED")
        if (
            type(line) is not int
            or line < 1
            or type(column) is not int
            or column < 0
            or not isinstance(api, str)
            or not _API.fullmatch(api)
        ):
            _refuse("FIXTURE_INVENTORY_REFUSED")
        key = (file_name, line, column, api)
        counts[key] = counts.get(key, 0) + 1
        nearby.setdefault((file_name, api), []).append(key)
    for values in nearby.values():
        values.sort(key=lambda item: (item[1], item[2], item[0], item[3]))
    return counts, nearby


def load_fixture_file(
    path: os.PathLike[str] | str,
    *,
    repository_root: os.PathLike[str] | str,
    inventory: Iterable[Mapping[str, object]],
) -> FixtureFile:
    """Parse and exactly bind a closed fixture file without executing its source."""

    root = _repository_root(repository_root)
    source_path = _path_under_root(path, root, must_exist=True)
    if source_path.stat().st_size > _MAX_FILE_BYTES:
        _refuse("FIXTURE_FILE_CAP_REFUSED")
    try:
        raw = source_path.read_bytes()
        text = raw.decode("utf-8", "strict")
    except (OSError, UnicodeError):
        _refuse("FIXTURE_ENCODING_REFUSED")
    top, rows = _parse_document(text)
    if top["schema_version"] != 1:
        _refuse("FIXTURE_SCHEMA_VERSION_REFUSED")
    inventory_counts, nearby = _inventory_keys(inventory)
    bindings: list[FixtureBinding] = []
    seen: set[tuple[str, int, int, str]] = set()
    payloads: list[dict[str, object]] = []
    for row in rows:
        payload = _binding_payload(row)
        key = (
            str(payload["file"]),
            int(payload["line"]),
            int(payload["column"]),
            str(payload["api"]),
        )
        if key in seen:
            _refuse("FIXTURE_DUPLICATE_BINDING_REFUSED")
        seen.add(key)
        matches = inventory_counts.get(key, 0)
        if matches > 1:
            _refuse("FIXTURE_AMBIGUOUS_REFUSED")
        if matches == 0:
            candidates = nearby.get((key[0], key[3]), [])
            if candidates:
                binding = {
                    "file": key[0], "line": key[1], "column": key[2], "api": key[3]
                }
                inventory_candidates = []
                for candidate_key in candidates:
                    mismatched_fields = []
                    if candidate_key[1] != key[1]:
                        mismatched_fields.append("line")
                    if candidate_key[2] != key[2]:
                        mismatched_fields.append("column")
                    inventory_candidates.append(
                        {
                            "file": candidate_key[0],
                            "line": candidate_key[1],
                            "column": candidate_key[2],
                            "api": candidate_key[3],
                            "mismatched_fields": mismatched_fields,
                        }
                    )
                _refuse(
                    "FIXTURE_STALE_REFUSED",
                    detail={
                        "binding": binding,
                        "inventory_candidates": inventory_candidates,
                    },
                )
            _refuse("FIXTURE_UNMATCHED_REFUSED")
        binding_sha256 = _digest(payload)
        payloads.append(payload)
        bindings.append(
            FixtureBinding(
                file=key[0],
                line=key[1],
                column=key[2],
                api=key[3],
                args=tuple(str(value) for value in payload["args"]),
                kwargs=tuple((str(name), str(value)) for name, value in payload["kwargs"]),
                setup=str(payload["setup"]),
                projection=(
                    None if payload["projection"] is None else str(payload["projection"])
                ),
                fixture_authored_by=str(payload["fixture_authored_by"]),
                binding_sha256=binding_sha256,
            )
        )
    bindings.sort(key=lambda binding: binding.key)
    payloads.sort(
        key=lambda payload: (
            str(payload["file"]),
            int(payload["line"]),
            int(payload["column"]),
            str(payload["api"]),
        )
    )
    canonical_sha256 = _digest(
        {
            "schema_version": 1,
            "bindings": payloads,
        }
    )
    return FixtureFile(
        path=source_path.relative_to(root).as_posix(),
        bindings=tuple(bindings),
        file_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_sha256=canonical_sha256,
    )


def resolve_fixture_policy(
    policy: str = "forbid",
    *,
    fixture_path: os.PathLike[str] | str | None,
    repository_root: os.PathLike[str] | str,
    inventory: Iterable[Mapping[str, object]],
) -> FixtureFile | None:
    """Apply the pure forbid/allow/require policy and parse only when admitted."""

    if policy not in _POLICY_VALUES:
        _refuse("FIXTURE_POLICY_REFUSED")
    root = _repository_root(repository_root)
    selected: os.PathLike[str] | str | None = fixture_path
    if selected is None:
        default = root / "breakcheck.fixtures.toml"
        if default.exists() or default.is_symlink():
            selected = default
    if policy == "forbid":
        if selected is not None:
            _refuse("FIXTURE_POLICY_FORBID")
        return None
    if selected is None:
        if policy == "require":
            _refuse("FIXTURE_REQUIRED")
        return None
    return load_fixture_file(selected, repository_root=root, inventory=inventory)


def render_fixture_source(binding: FixtureBinding, callable_source: str) -> str:
    """Render admitted source for later isolated execution; this function never runs it."""

    if not isinstance(binding, FixtureBinding) or not _API.fullmatch(callable_source):
        _refuse("FIXTURE_RENDER_REFUSED")
    arguments = list(binding.args)
    arguments.extend(name + "=" + source for name, source in binding.kwargs)
    pieces = []
    if binding.setup:
        pieces.append(binding.setup.rstrip("\n") + "\n")
    pieces.append("outcome = " + callable_source + "(" + ", ".join(arguments) + ")\n")
    if binding.projection is not None:
        pieces.append("outcome = " + binding.projection + "\n")
    return "".join(pieces)


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _context(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    encoded = text.encode("utf-8")
    if len(encoded) > _MAX_CONTEXT_BYTES:
        encoded = encoded[:_MAX_CONTEXT_BYTES]
        text = encoded.decode("utf-8", "ignore") + "..."
    return "".join(character if character >= " " else "?" for character in text)


def suggest_fixtures(
    destination: os.PathLike[str] | str,
    candidates: Iterable[Mapping[str, object]],
    *,
    repository_root: os.PathLike[str] | str,
) -> str:
    """Write deterministic fixture skeletons once, refusing overwrite races."""

    root = _repository_root(repository_root)
    output = _path_under_root(destination, root, must_exist=False)
    if output.exists() or output.is_symlink():
        _refuse("FIXTURE_SUGGESTION_EXISTS")
    if not output.parent.is_dir() or output.parent.is_symlink():
        _refuse("FIXTURE_PATH_REFUSED")
    normalized = []
    seen = set()
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            _refuse("FIXTURE_INVENTORY_REFUSED")
        counts, _ = _inventory_keys([candidate])
        key = next(iter(counts))
        if key in seen:
            _refuse("FIXTURE_AMBIGUOUS_REFUSED")
        seen.add(key)
        projection_required = candidate.get("projection_required", False)
        if type(projection_required) is not bool:
            _refuse("FIXTURE_INVENTORY_REFUSED")
        coverage_bucket = _context(candidate.get("coverage_bucket"))
        reason_code = _context(candidate.get("reason_code"))
        raw_type = _context(candidate.get("raw_type"))
        if projection_required and coverage_bucket != "G3_UNNORMALIZABLE":
            _refuse("FIXTURE_INVENTORY_REFUSED")
        normalized.append(
            {
                "key": key,
                "signature": _context(candidate.get("signature")),
                "type_hints": _context(candidate.get("type_hints")),
                "nearby_source": _context(candidate.get("nearby_source")),
                "coverage_bucket": coverage_bucket,
                "reason_code": reason_code,
                "raw_type": raw_type,
                "projection_required": projection_required,
            }
        )
    normalized.sort(key=lambda item: item["key"])
    lines = [
        "# CONFIDENTIALITY WARNING: review source context and fixture values before sharing.",
        "# Fixture expressions are executable source and must be human-reviewed.",
        "schema_version = 1",
    ]
    for item in normalized:
        file_name, line, column, api = item["key"]
        lines.append("")
        for label in (
            "signature",
            "type_hints",
            "nearby_source",
            "coverage_bucket",
            "reason_code",
            "raw_type",
        ):
            if item[label] is not None:
                lines.append("# " + label + ": " + str(item[label]))
        lines.extend(
            [
                "[[binding]]",
                'fixture_authored_by = "unknown"',
                "file = " + _toml_string(file_name),
                "line = " + str(line),
                "column = " + str(column),
                "api = " + _toml_string(api),
                "args = []",
                "kwargs = {}",
            ]
        )
        if item["projection_required"]:
            lines.extend(
                [
                    "# Projection must reference outcome and reduce it to stable, normalizable data.",
                    'projection = ""',
                ]
            )
    data = ("\n".join(lines) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    created = False
    try:
        descriptor = os.open(output, flags, 0o644)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        _refuse("FIXTURE_SUGGESTION_EXISTS")
    except OSError:
        if created:
            try:
                output.unlink()
            except OSError:
                pass
        _refuse("FIXTURE_SUGGESTION_WRITE_REFUSED")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return hashlib.sha256(data).hexdigest()


def _percentage(numerator: object, denominator: object) -> float:
    if (
        isinstance(numerator, bool)
        or isinstance(denominator, bool)
        or not isinstance(numerator, (int, float))
        or not isinstance(denominator, (int, float))
        or not math.isfinite(float(numerator))
        or not math.isfinite(float(denominator))
        or denominator <= 0
        or numerator < 0
        or numerator > denominator
    ):
        _refuse("FIXTURE_METRIC_REFUSED")
    return 100.0 * float(numerator) / float(denominator)


def fixture_yield(matched: object, candidates: object) -> float:
    return _percentage(matched, candidates)


def valid(valid_fixtures: object, proposed_fixtures: object) -> float:
    return _percentage(valid_fixtures, proposed_fixtures)


def executable(executable_fixtures: object, valid_fixtures: object) -> float:
    return _percentage(executable_fixtures, valid_fixtures)


def deterministic(deterministic_fixtures: object, executable_fixtures: object) -> float:
    return _percentage(deterministic_fixtures, executable_fixtures)


def coverage_delta(exercised_without: object, exercised_with: object) -> float:
    """Return the measured fixture coverage multiplier.

    A zero non-fixture baseline has no finite multiplier, so it is refused rather
    than represented with an invented sentinel or infinity.
    """
    if (
        isinstance(exercised_without, bool)
        or isinstance(exercised_with, bool)
        or not isinstance(exercised_without, (int, float))
        or not isinstance(exercised_with, (int, float))
        or not math.isfinite(float(exercised_without))
        or not math.isfinite(float(exercised_with))
        or float(exercised_without) <= 0
        or float(exercised_with) < 0
    ):
        _refuse("FIXTURE_METRIC_REFUSED")
    return float(exercised_with) / float(exercised_without)


def human_minutes(observed_minutes: object) -> float:
    if (
        isinstance(observed_minutes, bool)
        or not isinstance(observed_minutes, (int, float))
        or not math.isfinite(float(observed_minutes))
        or observed_minutes < 0
    ):
        _refuse("FIXTURE_METRIC_REFUSED")
    return float(observed_minutes)
