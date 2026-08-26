from __future__ import annotations

import ast
import keyword
import math
import operator
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .coverage import order_provenance


_REFUSAL_CODE = "NONLITERAL_ARGS"
_NODE_BUDGET = 256
_SEQUENCE_LENGTH_CAP = 10_000
_TEXT_LENGTH_CAP = 65_536
_INTEGER_BIT_CAP = 65_536
_NESTED_CALL_DEPTH_CAP = 3
_RENDERED_SOURCE_BYTES_CAP = 1_048_576
_VALUE_DEPTH_CAP = 64

_SAFE_NESTED_MODULES = frozenset(
    {
        "base64",
        "binascii",
        "decimal",
        "fractions",
        "hashlib",
        "json",
        "math",
        "re",
        "struct",
        "textwrap",
        "urllib.parse",
    }
)

_REFUSAL_DETAILS = frozenset(
    {
        "ATTRIBUTE_ACCESS",
        "COMPREHENSION",
        "FOLDABLE_EXPR",
        "FOLD_REFUSED",
        "LOCAL_NAME",
        "MODULE_CONSTANT",
        "MODULE_CONSTANT_CROSS_MODULE",
        "NESTED_CALL",
        "NESTED_CALL_DEPTH_EXCEEDED",
        "OTHER",
        "STARRED",
    }
)


class LiteralRefusal(ValueError):
    """Backward-compatible literal refusal with bounded diagnostics."""

    family = _REFUSAL_CODE

    def __init__(self, reason_detail: str = "OTHER") -> None:
        if reason_detail not in _REFUSAL_DETAILS:
            raise ValueError("LITERAL_REFUSAL_DETAIL_REFUSED")
        self.reason_detail = reason_detail
        super().__init__(self.family)

    def as_dict(self) -> dict[str, str]:
        return {
            "reason_code": self.family,
            "reason_detail": self.reason_detail,
        }


@dataclass(frozen=True)
class LiftedLiteral:
    value: object
    provenance: tuple[str, ...]


@dataclass(frozen=True)
class SynthesizedSnippet:
    source: str
    provenance: tuple[str, ...]


@dataclass
class _LiftContext:
    module_constants: Mapping[str, LiftedLiteral]
    imported_names: frozenset[str]
    visited: int = 0
    rendered_bytes: list[int] = field(default_factory=lambda: [0])

    def consume(self) -> None:
        self.visited += 1
        if self.visited > _NODE_BUDGET:
            _refuse("FOLD_REFUSED")


def _refuse(reason_detail: str = "OTHER") -> None:
    raise LiteralRefusal(reason_detail)


def _reason_detail(node: ast.AST) -> str:
    if isinstance(node, (ast.BinOp, ast.JoinedStr)):
        return "FOLDABLE_EXPR"
    if isinstance(node, ast.Name):
        return "LOCAL_NAME"
    if isinstance(node, ast.Call):
        return "NESTED_CALL"
    if isinstance(node, ast.Attribute):
        return "ATTRIBUTE_ACCESS"
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        return "COMPREHENSION"
    if isinstance(node, ast.Starred):
        return "STARRED"
    return "OTHER"


def _provenance(values: Iterable[str]) -> tuple[str, ...]:
    observed = tuple(values)
    return order_provenance(observed or ("SOURCE_LITERAL",))


def _bounded_literal_value(value: object) -> None:
    if type(value) is int and value.bit_length() > _INTEGER_BIT_CAP:
        _refuse("FOLD_REFUSED")
    if type(value) is float and not math.isfinite(value):
        _refuse("FOLD_REFUSED")
    if isinstance(value, (str, bytes)) and len(value) > _TEXT_LENGTH_CAP:
        _refuse("FOLD_REFUSED")
    if isinstance(value, (list, tuple)) and len(value) > _SEQUENCE_LENGTH_CAP:
        _refuse("FOLD_REFUSED")


def _sequence_multiplication_length(left: object, right: object) -> int | None:
    if isinstance(left, (str, bytes, list, tuple)) and type(right) is int:
        return len(left) * max(right, 0)
    if isinstance(right, (str, bytes, list, tuple)) and type(left) is int:
        return len(right) * max(left, 0)
    return None


def _fold_binop(node: ast.BinOp, context: _LiftContext) -> LiftedLiteral:
    left = _lift_result(node.left, context)
    right = _lift_result(node.right, context)
    op_type = type(node.op)
    operations = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }
    operation = operations.get(op_type)
    if operation is None:
        _refuse("FOLD_REFUSED")
    if op_type is ast.Pow and (
        type(left.value) is not int
        or type(right.value) is not int
        or abs(right.value) > 64
    ):
        _refuse("FOLD_REFUSED")
    if op_type is ast.Mult:
        result_length = _sequence_multiplication_length(left.value, right.value)
        if result_length is not None:
            cap = (
                _TEXT_LENGTH_CAP
                if isinstance(left.value, (str, bytes))
                or isinstance(right.value, (str, bytes))
                else _SEQUENCE_LENGTH_CAP
            )
            if result_length > cap:
                _refuse("FOLD_REFUSED")
    if op_type is ast.Add:
        if isinstance(left.value, (str, bytes)) and isinstance(
            right.value, type(left.value)
        ):
            if len(left.value) + len(right.value) > _TEXT_LENGTH_CAP:
                _refuse("FOLD_REFUSED")
        if isinstance(left.value, (list, tuple)) and isinstance(
            right.value, type(left.value)
        ):
            if len(left.value) + len(right.value) > _SEQUENCE_LENGTH_CAP:
                _refuse("FOLD_REFUSED")
    if op_type is ast.Mod and isinstance(left.value, (str, bytes)):
        _refuse("FOLD_REFUSED")
    try:
        value = operation(left.value, right.value)
    except (ArithmeticError, OverflowError, TypeError, ValueError):
        _refuse("FOLD_REFUSED")
    if not isinstance(value, (type(None), bool, int, float, str, bytes, list, tuple)):
        _refuse("FOLD_REFUSED")
    _bounded_literal_value(value)
    inherited = set(left.provenance) | set(right.provenance)
    inherited.discard("SOURCE_LITERAL")
    inherited.add("SOURCE_FOLDED")
    return LiftedLiteral(value, _provenance(inherited))


def _fold_joined_string(node: ast.JoinedStr, context: _LiftContext) -> LiftedLiteral:
    pieces: list[str] = []
    inherited: set[str] = set()
    for item in node.values:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            pieces.append(item.value)
            continue
        if not isinstance(item, ast.FormattedValue) or item.conversion != -1:
            _refuse("FOLD_REFUSED")
        if item.format_spec is not None and not (
            isinstance(item.format_spec, ast.JoinedStr) and not item.format_spec.values
        ):
            _refuse("FOLD_REFUSED")
        try:
            lifted = _lift_result(item.value, context)
        except LiteralRefusal as exc:
            if exc.reason_detail == "FOLD_REFUSED":
                raise
            _refuse("FOLDABLE_EXPR")
        if type(lifted.value) not in (str, int, float, bool):
            _refuse("FOLD_REFUSED")
        pieces.append(str(lifted.value))
        inherited.update(lifted.provenance)
    value = "".join(pieces)
    _bounded_literal_value(value)
    inherited.discard("SOURCE_LITERAL")
    inherited.add("SOURCE_FOLDED")
    return LiftedLiteral(value, _provenance(inherited))


def _lift_result(node: ast.AST, context: _LiftContext) -> LiftedLiteral:
    context.consume()
    if isinstance(node, ast.Constant) and isinstance(
        node.value, (type(None), bool, int, float, str, bytes)
    ):
        return LiftedLiteral(node.value, ("SOURCE_LITERAL",))
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
        and isinstance(node.operand, ast.Constant)
        and type(node.operand.value) in (int, float)
    ):
        value = node.operand.value if isinstance(node.op, ast.UAdd) else -node.operand.value
        _bounded_literal_value(value)
        return LiftedLiteral(value, ("SOURCE_LITERAL",))
    if isinstance(node, ast.BinOp):
        return _fold_binop(node, context)
    if isinstance(node, ast.JoinedStr):
        return _fold_joined_string(node, context)
    if isinstance(node, ast.Name):
        if node.id in context.module_constants:
            resolved = context.module_constants[node.id]
            if not isinstance(resolved, LiftedLiteral):
                _refuse("MODULE_CONSTANT")
            return LiftedLiteral(
                resolved.value,
                _provenance((*resolved.provenance, "SOURCE_MODULE_CONSTANT")),
            )
        if node.id in context.imported_names:
            _refuse("MODULE_CONSTANT_CROSS_MODULE")
        _refuse("LOCAL_NAME")
    if isinstance(node, ast.Attribute):
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in context.imported_names:
            _refuse("MODULE_CONSTANT_CROSS_MODULE")
        _refuse("ATTRIBUTE_ACCESS")
    if isinstance(node, ast.List):
        values = [_lift_result(item, context) for item in node.elts]
        provenance = _provenance(value for item in values for value in item.provenance)
        return LiftedLiteral([item.value for item in values], provenance)
    if isinstance(node, ast.Tuple):
        values = [_lift_result(item, context) for item in node.elts]
        provenance = _provenance(value for item in values for value in item.provenance)
        return LiftedLiteral(tuple(item.value for item in values), provenance)
    if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
        keys = [_lift_result(key, context) for key in node.keys]
        values = [_lift_result(value, context) for value in node.values]
        try:
            observed = {
                key.value: value.value for key, value in zip(keys, values, strict=True)
            }
        except TypeError:
            _refuse()
        provenance = _provenance(
            value for item in (*keys, *values) for value in item.provenance
        )
        return LiftedLiteral(observed, provenance)
    _refuse(_reason_detail(node))


def _context(
    module_constants: Mapping[str, LiftedLiteral] | None = None,
    imported_names: Iterable[str] = (),
) -> _LiftContext:
    constants = {} if module_constants is None else module_constants
    if not isinstance(constants, Mapping):
        raise ValueError("MODULE_CONSTANT_TABLE_REFUSED")
    names = frozenset(imported_names)
    if any(not isinstance(name, str) or not name.isidentifier() for name in names):
        raise ValueError("IMPORTED_NAME_TABLE_REFUSED")
    return _LiftContext(constants, names)


def _lift(
    node: ast.AST,
    *,
    module_constants: Mapping[str, LiftedLiteral] | None = None,
    imported_names: Iterable[str] = (),
) -> object:
    return _lift_result(node, _context(module_constants, imported_names)).value


def _call_node(source_text: str) -> ast.Call:
    if not isinstance(source_text, str):
        _refuse()
    try:
        node = ast.parse(source_text, mode="eval").body
    except (SyntaxError, ValueError, TypeError):
        _refuse()
    if not isinstance(node, ast.Call):
        _refuse()
    if any(keyword_item.arg is None for keyword_item in node.keywords):
        _refuse("STARRED")
    if any(isinstance(argument, ast.Starred) for argument in node.args):
        _refuse("STARRED")
    return node


def lift_literal_args(
    node: ast.AST | str,
    *,
    module_constants: Mapping[str, LiftedLiteral] | None = None,
    imported_names: Iterable[str] = (),
) -> object:
    context = _context(module_constants, imported_names)
    if isinstance(node, str):
        call = _call_node(node)
        return [_lift_result(item, context).value for item in call.args]
    return _lift_result(node, context).value


def lift_with_provenance(
    node: ast.AST,
    *,
    module_constants: Mapping[str, LiftedLiteral] | None = None,
    imported_names: Iterable[str] = (),
) -> LiftedLiteral:
    return _lift_result(node, _context(module_constants, imported_names))


def _reserve_rendered_bytes(budget: list[int], amount: int) -> None:
    budget[0] += amount
    if budget[0] > _RENDERED_SOURCE_BYTES_CAP:
        _refuse("FOLD_REFUSED")


def _literal_source(
    value: object,
    budget: list[int] | None = None,
    depth: int = 0,
) -> str:
    if budget is None:
        budget = [0]
    if depth > _VALUE_DEPTH_CAP:
        _refuse("FOLD_REFUSED")
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        source = repr(value)
        _reserve_rendered_bytes(budget, len(source.encode("utf-8")))
        return source
    if isinstance(value, list):
        _reserve_rendered_bytes(budget, 2 + max(0, len(value) - 1) * 2)
        return "[" + ", ".join(
            _literal_source(item, budget, depth + 1) for item in value
        ) + "]"
    if isinstance(value, tuple):
        _reserve_rendered_bytes(
            budget,
            2 + max(0, len(value) - 1) * 2 + (1 if len(value) == 1 else 0),
        )
        body = ", ".join(
            _literal_source(item, budget, depth + 1) for item in value
        )
        if len(value) == 1:
            body += ","
        return "(" + body + ")"
    if isinstance(value, dict):
        _reserve_rendered_bytes(
            budget,
            2 + max(0, len(value) - 1) * 2 + len(value) * 2,
        )
        return "{" + ", ".join(
            _literal_source(key, budget, depth + 1)
            + ": "
            + _literal_source(item, budget, depth + 1)
            for key, item in value.items()
        ) + "}"
    _refuse()


def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        _refuse("NESTED_CALL")
    parts.append(current.id)
    parts.reverse()
    if not all(part.isidentifier() and not keyword.iskeyword(part) for part in parts):
        _refuse("NESTED_CALL")
    return ".".join(parts)


def _import_source(source: str) -> str:
    if not isinstance(source, str):
        _refuse()
    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError, TypeError):
        _refuse()
    if len(tree.body) != 1 or not isinstance(tree.body[0], (ast.Import, ast.ImportFrom)):
        _refuse()
    node = tree.body[0]
    if len(node.names) != 1 or node.names[0].name == "*":
        _refuse()
    alias = node.names[0]
    if alias.asname is not None and (
        not alias.asname.isidentifier() or keyword.iskeyword(alias.asname)
    ):
        _refuse()
    if isinstance(node, ast.Import):
        parts = alias.name.split(".")
        if not all(part.isidentifier() and not keyword.iskeyword(part) for part in parts):
            _refuse()
    else:
        if node.level != 0 or not node.module:
            _refuse()
        module_parts = node.module.split(".")
        if not all(part.isidentifier() and not keyword.iskeyword(part) for part in module_parts):
            _refuse()
        if not alias.name.isidentifier() or keyword.iskeyword(alias.name):
            _refuse()
    return ast.unparse(node)


def _import_binding(import_statement: str) -> str:
    node = ast.parse(import_statement).body[0]
    alias = node.names[0]
    if alias.asname:
        return alias.asname
    if isinstance(node, ast.Import):
        return alias.name.split(".", 1)[0]
    return alias.name


def _safe_nested_module(api: str) -> str | None:
    matches = [
        module
        for module in _SAFE_NESTED_MODULES
        if api == module or api.startswith(module + ".")
    ]
    return max(matches, key=len) if matches else None


def _render_nested_call(
    call: ast.Call,
    context: _LiftContext,
    *,
    depth: int,
    target_roots: frozenset[str],
) -> tuple[str, tuple[str, ...], set[str]]:
    if depth > _NESTED_CALL_DEPTH_CAP:
        _refuse("NESTED_CALL_DEPTH_EXCEEDED")
    if any(keyword_item.arg is None for keyword_item in call.keywords) or any(
        isinstance(argument, ast.Starred) for argument in call.args
    ):
        _refuse("STARRED")
    api = _call_name(call.func)
    root = api.split(".", 1)[0]
    module = _safe_nested_module(api)
    if root not in target_roots and module is None:
        _refuse("NESTED_CALL")
    imports = set()
    if root not in target_roots and module is not None:
        imports.add("import " + module)
    rendered: list[str] = []
    provenance: set[str] = {"SOURCE_NESTED_CALL"}
    for argument in call.args:
        source, observed_provenance, observed_imports = _render_argument(
            argument, context, depth=depth + 1, target_roots=target_roots
        )
        rendered.append(source)
        provenance.update(observed_provenance)
        imports.update(observed_imports)
    for item in call.keywords:
        source, observed_provenance, observed_imports = _render_argument(
            item.value, context, depth=depth + 1, target_roots=target_roots
        )
        rendered.append(item.arg + "=" + source)
        provenance.update(observed_provenance)
        imports.update(observed_imports)
    return (
        api + "(" + ", ".join(rendered) + ")",
        _provenance(provenance),
        imports,
    )


def _render_argument(
    node: ast.AST,
    context: _LiftContext,
    *,
    depth: int,
    target_roots: frozenset[str],
) -> tuple[str, tuple[str, ...], set[str]]:
    if isinstance(node, ast.Call):
        return _render_nested_call(node, context, depth=depth, target_roots=target_roots)
    lifted = _lift_result(node, context)
    return (
        _literal_source(lifted.value, context.rendered_bytes),
        lifted.provenance,
        set(),
    )


def _snippet_result(
    call: ast.Call,
    import_statement: str,
    *,
    module_constants: Mapping[str, LiftedLiteral] | None,
    imported_names: Iterable[str],
) -> SynthesizedSnippet:
    api = _call_name(call.func)
    target_import = _import_source(import_statement)
    target_roots = frozenset({_import_binding(target_import), api.split(".", 1)[0]})
    context = _context(module_constants, imported_names)
    imports = {target_import}
    rendered: list[str] = []
    provenance: set[str] = set()
    for argument in call.args:
        source, observed_provenance, observed_imports = _render_argument(
            argument, context, depth=1, target_roots=target_roots
        )
        rendered.append(source)
        provenance.update(observed_provenance)
        imports.update(observed_imports)
    for item in call.keywords:
        source, observed_provenance, observed_imports = _render_argument(
            item.value, context, depth=1, target_roots=target_roots
        )
        rendered.append(item.arg + "=" + source)
        provenance.update(observed_provenance)
        imports.update(observed_imports)
    source = (
        "\n".join(sorted(imports))
        + "\n\noutcome = "
        + api
        + "("
        + ", ".join(rendered)
        + ")\nprint(repr(outcome))\n"
    )
    return SynthesizedSnippet(source, _provenance(provenance))


def synthesize_with_provenance(
    *arguments: object,
    module_constants: Mapping[str, LiftedLiteral] | None = None,
    imported_names: Iterable[str] = (),
) -> SynthesizedSnippet:
    if len(arguments) == 1 and isinstance(arguments[0], str):
        call = _call_node(arguments[0])
        api = _call_name(call.func)
        return _snippet_result(
            call,
            "import " + api.split(".", 1)[0],
            module_constants=module_constants,
            imported_names=imported_names,
        )
    if (
        len(arguments) == 2
        and isinstance(arguments[0], str)
        and isinstance(arguments[1], str)
    ):
        return _snippet_result(
            _call_node(arguments[0]),
            arguments[1],
            module_constants=module_constants,
            imported_names=imported_names,
        )
    if len(arguments) != 2:
        _refuse()
    function_name, node = arguments
    if (
        not isinstance(function_name, str)
        or not function_name.isidentifier()
        or keyword.iskeyword(function_name)
        or not isinstance(node, ast.AST)
    ):
        _refuse()
    context = _context(module_constants, imported_names)
    lifted = _lift_result(node, context)
    return SynthesizedSnippet(
        function_name
        + "("
        + _literal_source(lifted.value, context.rendered_bytes)
        + ")",
        lifted.provenance,
    )


def synthesize_snippet(
    *arguments: object,
    module_constants: Mapping[str, LiftedLiteral] | None = None,
    imported_names: Iterable[str] = (),
) -> str:
    return synthesize_with_provenance(
        *arguments,
        module_constants=module_constants,
        imported_names=imported_names,
    ).source
