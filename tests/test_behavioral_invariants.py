from __future__ import annotations

import ast
from pathlib import Path

import pytest

from breakcheck import cli
from breakcheck.adapters.python import literals
from breakcheck.adapters.python.equality import compare_observations
from breakcheck.adapters.python.normalization import normalize_outcome


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_ROOT = ROOT / "src" / "breakcheck" / "adapters"


def _catches_broadly(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name):
        return handler.type.id in {"Exception", "BaseException"}
    if isinstance(handler.type, ast.Tuple):
        return any(
            isinstance(item, ast.Name)
            and item.id in {"Exception", "BaseException"}
            for item in handler.type.elts
        )
    return False


def _terminates_explicitly(handler: ast.ExceptHandler) -> bool:
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Return):
            value = node.value
            if isinstance(value, ast.Constant) and value.value is None:
                continue
            return True
    return False


def test_adapter_broad_exceptions_cannot_silently_continue():
    violations = []
    for path in sorted(ADAPTER_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or not _catches_broadly(node):
                continue
            if not _terminates_explicitly(node):
                violations.append(
                    f"{path.relative_to(ROOT).as_posix()}:{node.lineno}"
                )
    assert violations == []


@pytest.mark.parametrize("code", sorted(cli._DECLARED_REFUSAL_CODES))
def test_every_declared_refusal_is_bounded_and_machine_recognizable(code):
    assert cli._bounded_refusal(ValueError(code)) == code
    assert code in cli._HELP


def test_runtime_source_never_waits_for_interactive_input():
    violations = []
    source_root = ROOT / "src" / "breakcheck"
    for path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"input", "breakpoint"}:
                    violations.append(
                        f"{path.relative_to(ROOT).as_posix()}:{node.lineno}"
                    )
    assert violations == []


def test_fixture_refusal_registry_is_complete():
    from breakcheck.adapters.python import fixtures

    tree = ast.parse(
        (ADAPTER_ROOT / "python" / "fixtures.py").read_text(encoding="utf-8")
    )
    emitted = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_refuse"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    assert emitted == fixtures.REFUSAL_CODES


def _normalized_value(payload):
    return normalize_outcome(
        {
            "kind": "value",
            "payload": payload,
            "exception_class": None,
        }
    )


@pytest.mark.parametrize(
    ("old_payload", "new_payload"),
    [
        (b"a", "61"),
        ({1, 2}, [1, 2]),
        ((1, 2), [1, 2]),
        ({1, 2}, frozenset({1, 2})),
    ],
)
def test_normalization_preserves_python_type_changes(old_payload, new_payload):
    result = compare_observations(
        _normalized_value(old_payload),
        _normalized_value(new_payload),
    )

    assert result["verdict"] == "CHANGED"
    assert result["detail"]["reason_code"] == "KIND_MISMATCH"


@pytest.mark.parametrize(
    "payload",
    [b"a", {1, 2}, (1, 2), frozenset({1, 2})],
)
def test_tagged_normalization_remains_identical_for_the_same_value(payload):
    observation = _normalized_value(payload)

    assert compare_observations(observation, observation)["verdict"] == "IDENTICAL"


def test_user_mapping_cannot_collide_with_a_normalized_type_tag():
    tag_shaped_mapping = {
        "$breakcheck_type": "bytes",
        "$breakcheck_value": "61",
    }

    result = compare_observations(
        _normalized_value(b"a"),
        _normalized_value(tag_shaped_mapping),
    )

    assert result["verdict"] == "CHANGED"
    assert result["detail"]["reason_code"] == "KIND_MISMATCH"


def test_folded_values_have_a_cumulative_render_budget():
    expression = "json.dumps(['x' * 65536] * 20)"

    with pytest.raises(literals.LiteralRefusal) as caught:
        literals.synthesize_snippet(expression)

    assert caught.value.reason_detail == "FOLD_REFUSED"
