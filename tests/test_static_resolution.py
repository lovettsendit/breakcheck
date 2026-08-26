from __future__ import annotations

import ast
import subprocess
import sys

import pytest

from breakcheck.adapters.python import coverage, literals, scanner


def _refusal(expression: str) -> literals.LiteralRefusal:
    with pytest.raises(literals.LiteralRefusal) as caught:
        literals.synthesize_snippet(expression)
    return caught.value


def test_literal_refusal_remains_backward_compatible_and_is_diagnostic():
    refusal = _refusal("json.dumps(cfg)")

    assert isinstance(refusal, ValueError)
    assert str(refusal) == "NONLITERAL_ARGS"
    assert refusal.family == "NONLITERAL_ARGS"
    assert refusal.reason_detail == "LOCAL_NAME"
    assert refusal.as_dict() == {
        "reason_code": "NONLITERAL_ARGS",
        "reason_detail": "LOCAL_NAME",
    }


@pytest.mark.parametrize(
    ("expression", "detail"),
    [
        ("json.dumps({'x': f'{url}'})", "FOLDABLE_EXPR"),
        ("json.dumps(obj.value)", "ATTRIBUTE_ACCESS"),
        ("json.dumps([x for x in values])", "COMPREHENSION"),
        ("json.dumps(*values)", "STARRED"),
        ("json.dumps(**values)", "STARRED"),
        ("json.dumps(lambda: None)", "OTHER"),
    ],
)
def test_nonliteral_taxonomy_is_stable(expression: str, detail: str):
    assert _refusal(expression).reason_detail == detail


def test_eight_call_golden_preserves_lift_split_and_adds_diagnostics():
    cases = [
        ("json.dumps({'x': 1})", "LIFTED"),
        ("json.dumps(cfg)", "LOCAL_NAME"),
        ("json.dumps({'x': 1 + 1})", "LIFTED"),
        ("json.dumps({'x': f'{url}'})", "FOLDABLE_EXPR"),
        ("json.dumps({'x': 1}, indent=cfg)", "LOCAL_NAME"),
        ("json.dumps(json.loads('{}'))", "LIFTED"),
        ("json.loads('{}')", "LIFTED"),
        ("cfg.keys()", "LIFTED"),
    ]

    observed = []
    for expression, _expected in cases:
        try:
            literals.synthesize_snippet(expression)
        except literals.LiteralRefusal as exc:
            observed.append(exc.reason_detail)
        else:
            observed.append("LIFTED")

    assert observed == [expected for _expression, expected in cases]


def _run_snippet(snippet: str) -> object:
    completed = subprocess.run(
        [sys.executable, "-I", "-c", snippet],
        check=True,
        capture_output=True,
        text=True,
    )
    return ast.literal_eval(completed.stdout.strip())


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("json.dumps(1 + 2)", "3"),
        ("json.dumps(8 - 3)", "5"),
        ("json.dumps(3 * 4)", "12"),
        ("json.dumps(7 / 2)", "3.5"),
        ("json.dumps(7 // 2)", "3"),
        ("json.dumps(7 % 3)", "1"),
        ("json.dumps(2 ** 8)", "256"),
        ("json.dumps(f'value={1 + 1}')", '"value=2"'),
    ],
)
def test_constant_folding_is_replayed_as_a_bounded_literal(expression, expected):
    synthesized = literals.synthesize_with_provenance(expression)

    assert _run_snippet(synthesized.source) == expected
    assert synthesized.provenance == ("SOURCE_FOLDED",)


@pytest.mark.parametrize(
    "expression",
    [
        "json.dumps(2 ** 65)",
        "json.dumps(2.0 ** 2)",
        "json.dumps([0] * 10001)",
        "json.dumps('x' * 65537)",
        "json.dumps(1 / 0)",
        "json.dumps(1 + 'x')",
        "json.dumps(1e308 * 1e308)",
        "json.dumps(f'{1!r}')",
        "json.dumps(f'{1:02d}')",
    ],
)
def test_constant_folding_guards_refuse_without_leaking_exceptions(expression):
    assert _refusal(expression).reason_detail == "FOLD_REFUSED"


def test_constant_folding_has_one_shared_256_node_budget_per_call_site():
    expression = "json.dumps([" + ",".join("1" for _ in range(257)) + "])"

    assert _refusal(expression).reason_detail == "FOLD_REFUSED"


def test_module_constant_table_resolves_only_a_single_stable_module_binding():
    source = "LIMIT = 1 + 1\nimport json\njson.dumps(LIMIT)\n"
    context = scanner.build_static_context(source)
    call = ast.parse(source).body[-1].value
    synthesized = literals.synthesize_with_provenance(
        ast.unparse(call),
        module_constants=context.module_constants,
        imported_names=context.imported_names,
    )

    assert context.module_constants["LIMIT"].value == 2
    assert _run_snippet(synthesized.source) == "2"
    assert synthesized.provenance == (
        "SOURCE_FOLDED",
        "SOURCE_MODULE_CONSTANT",
    )
    assert scanner.PythonUsageScanner.build_static_context(source) == context


@pytest.mark.parametrize(
    ("source", "constant_name"),
    [
        (
            "VALUES = [1]\nVALUES.append(2)\nimport json\njson.dumps(VALUES)\n",
            "VALUES",
        ),
        (
            (
                "OPTIONS = {'mode': 'safe'}\n"
                "OPTIONS['mode'] = 'unsafe'\n"
                "import json\njson.dumps(OPTIONS)\n"
            ),
            "OPTIONS",
        ),
        (
            "MEMBERS = {1}\nMEMBERS.add(2)\nimport json\njson.dumps(MEMBERS)\n",
            "MEMBERS",
        ),
        (
            (
                "NESTED = ([1],)\n"
                "ALIAS = NESTED[0]\n"
                "ALIAS.append(2)\n"
                "import json\njson.dumps(NESTED)\n"
            ),
            "NESTED",
        ),
        (
            "ALIASED = [1]\nCOPY = ALIASED\nimport json\njson.dumps(ALIASED)\n",
            "ALIASED",
        ),
    ],
)
def test_mutable_module_bindings_are_refused_instead_of_replayed_from_stale_ast(
    source, constant_name
):
    context = scanner.build_static_context(source)
    call = ast.parse(source).body[-1].value

    assert constant_name not in context.module_constants
    with pytest.raises(literals.LiteralRefusal) as caught:
        literals.synthesize_with_provenance(
            ast.unparse(call),
            module_constants=context.module_constants,
            imported_names=context.imported_names,
        )
    assert caught.value.reason_detail == "LOCAL_NAME"


def test_deeply_immutable_module_tuple_is_still_replayed_with_provenance():
    source = (
        "COORDINATES = ('origin', (1, 2), None, True, 1.5, b'x')\n"
        "import json\njson.dumps(COORDINATES)\n"
    )
    context = scanner.build_static_context(source)
    call = ast.parse(source).body[-1].value
    synthesized = literals.synthesize_with_provenance(
        ast.unparse(call),
        module_constants=context.module_constants,
        imported_names=context.imported_names,
    )

    assert context.module_constants["COORDINATES"].value == (
        "origin",
        (1, 2),
        None,
        True,
        1.5,
        b"x",
    )
    assert "SOURCE_MODULE_CONSTANT" in synthesized.provenance


def test_nonfinite_float_is_not_admitted_as_an_immutable_module_constant():
    context = scanner.build_static_context("LIMIT = 1e309\n")

    assert "LIMIT" not in context.module_constants


def test_mutable_literals_remain_supported_when_passed_directly_to_a_call():
    synthesized = literals.synthesize_with_provenance(
        "json.dumps([1, {'mode': 'safe'}])"
    )

    assert _run_snippet(synthesized.source) == '[1, {"mode": "safe"}]'
    assert synthesized.provenance == ("SOURCE_LITERAL",)


@pytest.mark.parametrize(
    "source",
    [
        "LIMIT = 1\ndef f():\n    LIMIT = 2\n",
        "LIMIT = 1\ndef f(LIMIT):\n    return LIMIT\n",
        "LIMIT = 1\nfor LIMIT in []:\n    pass\n",
        "LIMIT = 1\nwith open('x') as LIMIT:\n    pass\n",
        "LIMIT = 1\ntry:\n    pass\nexcept Exception as LIMIT:\n    pass\n",
        "LIMIT = 1\nvalues = [LIMIT for LIMIT in []]\n",
        "LIMIT = 1\n(LIMIT := 2)\n",
        "LIMIT = 1\nLIMIT += 1\n",
        "LIMIT = 1\ndel LIMIT\n",
        "LIMIT = 1\ndef f():\n    global LIMIT\n",
    ],
)
def test_module_constant_is_refused_for_every_shadow_or_rebind_form(source):
    assert "LIMIT" not in scanner.build_static_context(source).module_constants


def test_globals_call_refuses_the_whole_module_constant_table():
    context = scanner.build_static_context("A = 1\nB = 2\nglobals()\n")

    assert context.module_constants == {}


def test_multi_target_nested_and_unpack_assignments_are_not_module_constants():
    source = "A = B = 1\n(C, D) = (2, 3)\nif True:\n    E = 4\nF = 5; G = 6\n"

    assert set(scanner.build_static_context(source).module_constants) == {"F"}


@pytest.mark.parametrize(
    ("source", "expression"),
    [
        ("from .config import TIMEOUT\n", "json.dumps(TIMEOUT)"),
        ("import config\n", "json.dumps(config.TIMEOUT)"),
    ],
)
def test_cross_module_constants_have_a_distinct_fail_closed_detail(source, expression):
    context = scanner.build_static_context(source)

    with pytest.raises(literals.LiteralRefusal) as caught:
        literals.synthesize_with_provenance(
            expression,
            module_constants=context.module_constants,
            imported_names=context.imported_names,
        )

    assert caught.value.reason_detail == "MODULE_CONSTANT_CROSS_MODULE"


def test_nested_call_is_emitted_not_evaluated_at_scan_time_with_sorted_imports():
    synthesized = literals.synthesize_with_provenance(
        "json.dumps(json.loads('{}'), default=base64.b64encode(b'x'))"
    )

    assert synthesized.source.splitlines()[:2] == ["import base64", "import json"]
    assert "json.loads('{}')" in synthesized.source
    assert synthesized.provenance == (
        "SOURCE_LITERAL",
        "SOURCE_NESTED_CALL",
    )


def test_nested_call_replays_a_real_composition():
    synthesized = literals.synthesize_with_provenance(
        "json.dumps(json.loads('{\"x\": 1}'))"
    )

    assert _run_snippet(synthesized.source) == '{"x": 1}'


@pytest.mark.parametrize(
    ("expression", "required_import"),
    [
        ("json.dumps(base64.b64encode(b'x'))", "import base64"),
        ("json.dumps(binascii.hexlify(b'x'))", "import binascii"),
        ("json.dumps(decimal.Decimal('1'))", "import decimal"),
        ("json.dumps(fractions.Fraction(1, 2))", "import fractions"),
        ("json.dumps(hashlib.sha256(b'x'))", "import hashlib"),
        ("json.dumps(math.floor(1.5))", "import math"),
        ("json.dumps(re.escape('x'))", "import re"),
        ("json.dumps(struct.pack('B', 1))", "import struct"),
        ("json.dumps(textwrap.dedent('x'))", "import textwrap"),
        ("json.dumps(urllib.parse.quote('x'))", "import urllib.parse"),
    ],
)
def test_nested_call_stdlib_allowlist_is_exact_and_deterministic(
    expression, required_import
):
    source = literals.synthesize_snippet(expression)

    assert required_import in source.splitlines()


@pytest.mark.parametrize(
    ("expression", "detail"),
    [
        ("json.dumps(os.getcwd())", "NESTED_CALL"),
        ("json.dumps(open('x'))", "NESTED_CALL"),
        (
            "json.dumps(json.loads(json.dumps(json.loads(json.dumps('{}')))))",
            "NESTED_CALL_DEPTH_EXCEEDED",
        ),
        ("json.dumps(json.loads(cfg))", "LOCAL_NAME"),
        ("json.dumps(json.loads(*values))", "STARRED"),
    ],
)
def test_nested_call_allowlist_depth_and_arguments_fail_closed(expression, detail):
    assert _refusal(expression).reason_detail == detail


def test_nested_target_package_alias_is_allowed_without_an_extra_import():
    synthesized = literals.synthesize_with_provenance(
        "tools.changed(tools.normalize(1 + 1))",
        "import samplepkg.tools as tools",
    )

    assert synthesized.source.startswith("import samplepkg.tools as tools\n\n")
    assert "tools.normalize(2)" in synthesized.source
    assert synthesized.provenance == (
        "SOURCE_FOLDED",
        "SOURCE_NESTED_CALL",
    )


def test_static_expansion_is_deterministic_across_repeated_runs():
    context = scanner.build_static_context("VALUE = 1 + 1\n")
    observed = [
        literals.synthesize_with_provenance(
            "json.dumps(json.loads(json.dumps(VALUE)))",
            module_constants=context.module_constants,
            imported_names=context.imported_names,
        )
        for _ in range(2)
    ]

    assert observed[0] == observed[1]


def test_provenance_scaffold_is_closed_ordered_and_immutable():
    lifted = literals.lift_with_provenance(ast.parse("{'x': [1, 2]}", mode="eval").body)

    assert lifted.value == {"x": [1, 2]}
    assert lifted.provenance == ("SOURCE_LITERAL",)
    assert literals.order_provenance(
        ["SOURCE_NESTED_CALL", "SOURCE_LITERAL", "SOURCE_FOLDED", "SOURCE_LITERAL"]
    ) == ("SOURCE_LITERAL", "SOURCE_FOLDED", "SOURCE_NESTED_CALL")
    with pytest.raises(ValueError, match="PROVENANCE_REFUSED"):
        literals.order_provenance(["UNKNOWN"])


def test_candidate_identity_is_canonical_stable_and_location_attributable():
    first = coverage.make_candidate(
        api="json.dumps", file="src/app.py", line=7, column=4
    )
    second = coverage.make_candidate(
        column=4, line=7, file="src/app.py", api="json.dumps"
    )

    assert first == second
    assert len(first["candidate_id"]) == 64
    assert set(first) == {"candidate_id", "api", "file", "line", "column"}
    assert coverage.make_candidate(
        api="json.dumps", file="src/app.py", line=8, column=4
    )["candidate_id"] != first["candidate_id"]


def test_terminal_records_are_closed_sorted_and_one_per_candidate():
    first = coverage.make_candidate(
        api="json.dumps", file="b.py", line=2, column=0
    )
    second = coverage.make_candidate(
        api="json.loads", file="a.py", line=1, column=0
    )
    records = coverage.finalize_terminal_records(
        [
            coverage.terminal_record(
                first,
                "G2_NONLITERAL",
                reason_code="NONLITERAL_ARGS",
                reason_detail="LOCAL_NAME",
                provenance=("SOURCE_LITERAL",),
            ),
            coverage.terminal_record(
                second,
                "EXERCISED",
                provenance=("SOURCE_LITERAL",),
            ),
        ]
    )

    assert [row["candidate_id"] for row in records] == sorted(
        [first["candidate_id"], second["candidate_id"]]
    )
    assert coverage.count_terminal_records(records) == {
        "EXERCISED": 1,
        "G1_NOT_DISCOVERABLE": 0,
        "G2_NONLITERAL": 1,
        "G3_UNNORMALIZABLE": 0,
        "G4_IMPURE": 0,
        "total": 2,
    }
    with pytest.raises(ValueError, match="CANDIDATE_TERMINAL_DUPLICATE"):
        coverage.finalize_terminal_records([records[0], records[0]])


def test_scanner_exposes_candidates_separately_without_changing_legacy_calls():
    observed = scanner.PythonUsageScanner("json").scan(
        source=(
            "import json\n"
            "json.dumps({'x': 1})\n"
            "getattr(json, 'loads')('{}')\n"
        ),
        path="app.py",
        package="json",
    )

    assert observed["call_sites"] == [
        {"api": "json.dumps", "line": 2, "file": "app.py", "column": 0}
    ]
    assert len(observed["candidates"]) == 2
    assert len({row["candidate_id"] for row in observed["candidates"]}) == 2
    assert [row["reason_code"] for row in observed["candidates"]] == [
        None,
        "DYNAMIC_USAGE_UNSUPPORTED",
    ]


@pytest.mark.parametrize(
    "source",
    [
        "import attrs\ndef check(attrs):\n    return attrs.has(1)\n",
        (
            "import attrs\ndef check(manager):\n"
            "    with manager as attrs:\n        return attrs.has(1)\n"
        ),
        (
            "import attrs\ndef check():\n    try:\n        raise RuntimeError\n"
            "    except RuntimeError as attrs:\n        return attrs.has(1)\n"
        ),
        "import attrs\ndef check():\n    attrs += 1\n    return attrs.has(1)\n",
        "import attrs\ndef check():\n    del attrs\n    return attrs.has(1)\n",
    ],
)
def test_scanner_refuses_calls_when_the_import_alias_is_shadowed(source):
    observed = scanner.PythonUsageScanner("attrs").scan(
        source=source,
        path="app.py",
        package="attrs",
    )

    assert observed["call_sites"] == []
    assert [row["reason_code"] for row in observed["unsupported"]] == [
        "DYNAMIC_USAGE_UNSUPPORTED"
    ]
