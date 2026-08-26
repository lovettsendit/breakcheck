from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

from breakcheck.adapters.python.fixtures import (
    FixtureRefusal,
    coverage_delta,
    deterministic,
    executable,
    fixture_yield,
    human_minutes,
    load_fixture_file,
    render_fixture_source,
    resolve_fixture_policy,
    suggest_fixtures,
    valid,
)


INVENTORY = [
    {"file": "src/app.py", "line": 7, "column": 4, "api": "attrs.has"},
]


def _fixture_text(*, author: str = "human", extra: str = "") -> str:
    return (
        'schema_version = 1\n'
        "\n"
        "[[binding]]\n"
        f'fixture_authored_by = "{author}"\n'
        'file = "src/app.py"\n'
        "line = 7\n"
        "column = 4\n"
        'api = "attrs.has"\n'
        'args = ["Point(1, 2)"]\n'
        'kwargs = { strict = "True" }\n'
        'setup = "class Point:\\n    pass"\n'
        'projection = "(outcome, type(outcome).__name__)"\n'
        + extra
    )


def _write_fixture(root: Path, text: str) -> Path:
    destination = root / "breakcheck.fixtures.toml"
    destination.write_text(text, encoding="utf-8")
    return destination


def test_valid_fixture_is_closed_matched_and_hash_stable(tmp_path: Path) -> None:
    path = _write_fixture(tmp_path, _fixture_text())

    first = load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)
    second = load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)

    assert first.file_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert first.canonical_sha256 == second.canonical_sha256
    assert len(first.bindings) == 1
    binding = first.bindings[0]
    assert binding.fixture_authored_by == "human"
    assert binding.key == ("src/app.py", 7, 4, "attrs.has")
    assert binding.args == ("Point(1, 2)",)
    assert binding.kwargs == (("strict", "True"),)
    assert binding.setup == "class Point:\n    pass"
    assert binding.projection == "(outcome, type(outcome).__name__)"
    assert binding.binding_sha256 == second.bindings[0].binding_sha256


def test_fixture_rendering_preserves_reviewed_source_without_executing_it(
    tmp_path: Path,
) -> None:
    path = _write_fixture(
        tmp_path,
        _fixture_text().replace(
            'setup = "class Point:\\n    pass"',
            'setup = "raise RuntimeError(\\\"must not run while loading\\\")"',
        ),
    )
    fixture = load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)

    rendered = render_fixture_source(fixture.bindings[0], "attrs.has")

    assert rendered == (
        'raise RuntimeError("must not run while loading")\n'
        "outcome = attrs.has(Point(1, 2), strict=True)\n"
        "outcome = (outcome, type(outcome).__name__)\n"
    )


@pytest.mark.parametrize("author", ["", "model", "Human", "operator"])
def test_fixture_author_is_required_and_closed(tmp_path: Path, author: str) -> None:
    text = _fixture_text(author=author) if author else _fixture_text().replace(
        'fixture_authored_by = "human"\n', "", 1
    )
    path = _write_fixture(tmp_path, text)

    with pytest.raises(FixtureRefusal, match="FIXTURE_AUTHOR_REFUSED"):
        load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("schema_version = 2", "FIXTURE_SCHEMA_VERSION_REFUSED"),
        ('unknown = "value"', "FIXTURE_SCHEMA_REFUSED"),
        ('api = "attrs.has"\napi = "attrs.has"', "FIXTURE_DUPLICATE_FIELD_REFUSED"),
        ('args = ["unterminated]', "FIXTURE_SYNTAX_REFUSED"),
    ],
)
def test_closed_schema_refuses_unknown_duplicate_and_malformed_values(
    tmp_path: Path, mutation: str, code: str
) -> None:
    text = _fixture_text()
    if mutation.startswith("schema_version"):
        text = text.replace("schema_version = 1", mutation)
    elif mutation.startswith("unknown"):
        text = text.replace("[[binding]]", mutation + "\n\n[[binding]]")
    elif mutation.startswith("api ="):
        text = text.replace('api = "attrs.has"', mutation)
    else:
        text = text.replace('args = ["Point(1, 2)"]', mutation)
    path = _write_fixture(tmp_path, text)

    with pytest.raises(FixtureRefusal, match=code):
        load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)


def test_fixture_file_must_be_confined_regular_and_nonsymlink(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = _write_fixture(tmp_path, _fixture_text())

    with pytest.raises(FixtureRefusal, match="FIXTURE_PATH_REFUSED"):
        load_fixture_file(outside, repository_root=repository, inventory=INVENTORY)

    link = repository / "breakcheck.fixtures.toml"
    link.symlink_to(outside)
    with pytest.raises(FixtureRefusal, match="FIXTURE_SYMLINK_REFUSED"):
        load_fixture_file(link, repository_root=repository, inventory=INVENTORY)


@pytest.mark.parametrize(
    ("inventory", "mutation", "code"),
    [
        (INVENTORY, "duplicate", "FIXTURE_DUPLICATE_BINDING_REFUSED"),
        (INVENTORY, "line", "FIXTURE_STALE_REFUSED"),
        ([], "none", "FIXTURE_UNMATCHED_REFUSED"),
        (INVENTORY + INVENTORY, "none", "FIXTURE_AMBIGUOUS_REFUSED"),
    ],
)
def test_inventory_matching_refuses_duplicate_stale_unmatched_and_ambiguous(
    tmp_path: Path, inventory: list[dict[str, object]], mutation: str, code: str
) -> None:
    text = _fixture_text()
    if mutation == "duplicate":
        text += text[text.index("[[binding]]") :]
    elif mutation == "line":
        text = text.replace("line = 7", "line = 8")
    path = _write_fixture(tmp_path, text)

    with pytest.raises(FixtureRefusal, match=code):
        load_fixture_file(path, repository_root=tmp_path, inventory=inventory)


def test_source_and_projection_caps_fail_closed(tmp_path: Path) -> None:
    too_many_args = ", ".join('"1"' for _ in range(65))
    path = _write_fixture(
        tmp_path,
        _fixture_text().replace('args = ["Point(1, 2)"]', f"args = [{too_many_args}]"),
    )
    with pytest.raises(FixtureRefusal, match="FIXTURE_ARGUMENT_CAP_REFUSED"):
        load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)

    path.write_text(
        _fixture_text().replace(
            'projection = "(outcome, type(outcome).__name__)"',
            'projection = "42"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(FixtureRefusal, match="FIXTURE_PROJECTION_REFUSED"):
        load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)

    path.write_text(
        _fixture_text().replace('args = ["Point(1, 2)"]', 'args = ["("]'),
        encoding="utf-8",
    )
    with pytest.raises(FixtureRefusal, match="FIXTURE_EXPRESSION_REFUSED"):
        load_fixture_file(path, repository_root=tmp_path, inventory=INVENTORY)


def test_fixture_policy_defaults_forbid_and_allow_require_are_explicit(tmp_path: Path) -> None:
    path = _write_fixture(tmp_path, _fixture_text())

    with pytest.raises(FixtureRefusal, match="FIXTURE_POLICY_FORBID"):
        resolve_fixture_policy(
            fixture_path=path, repository_root=tmp_path, inventory=INVENTORY
        )
    allowed = resolve_fixture_policy(
        "allow", fixture_path=path, repository_root=tmp_path, inventory=INVENTORY
    )
    assert len(allowed.bindings) == 1
    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    absent = resolve_fixture_policy(
        "allow", fixture_path=None, repository_root=empty_root, inventory=INVENTORY
    )
    assert absent is None
    with pytest.raises(FixtureRefusal, match="FIXTURE_REQUIRED"):
        resolve_fixture_policy(
            "require", fixture_path=None, repository_root=empty_root, inventory=INVENTORY
        )
    with pytest.raises(FixtureRefusal, match="FIXTURE_POLICY_REFUSED"):
        resolve_fixture_policy(
            "sometimes", fixture_path=path, repository_root=tmp_path, inventory=INVENTORY
        )


def test_suggestions_are_deterministic_contextual_warn_and_never_overwrite(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "breakcheck.fixtures.toml"
    candidates = [
        {
            "file": "src/b.py",
            "line": 9,
            "column": 2,
            "api": "attrs.asdict",
            "signature": "attrs.asdict(inst, *, recurse=True)",
            "type_hints": "inst: object -> dict[str, object]",
            "nearby_source": "result = attrs.asdict(value)",
        },
        {
            "file": "src/a.py",
            "line": 3,
            "column": 1,
            "api": "attrs.has",
        },
    ]

    first = suggest_fixtures(
        destination, candidates, repository_root=tmp_path
    )
    text = destination.read_text(encoding="utf-8")
    assert first == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert "CONFIDENTIALITY WARNING" in text
    assert text.index('file = "src/a.py"') < text.index('file = "src/b.py"')
    assert "# signature: attrs.asdict(inst, *, recurse=True)" in text
    assert "# type_hints: inst: object -> dict[str, object]" in text
    assert "# nearby_source: result = attrs.asdict(value)" in text
    assert text.count('fixture_authored_by = "unknown"') == 2

    with pytest.raises(FixtureRefusal, match="FIXTURE_SUGGESTION_EXISTS"):
        suggest_fixtures(destination, candidates, repository_root=tmp_path)
    assert destination.read_text(encoding="utf-8") == text

    second_destination = tmp_path / "second.toml"
    suggest_fixtures(second_destination, list(reversed(candidates)), repository_root=tmp_path)
    assert second_destination.read_text(encoding="utf-8") == text


def test_metrics_require_observed_inputs_and_do_not_invent_values() -> None:
    assert fixture_yield(3, 4) == 75.0
    assert valid(2, 3) == pytest.approx(66.66666666666667)
    assert executable(1, 2) == 50.0
    assert deterministic(1, 1) == 100.0
    assert coverage_delta(40, 80) == 2.0
    assert human_minutes(12.25) == 12.25

    with pytest.raises(TypeError):
        fixture_yield()  # type: ignore[call-arg]
    with pytest.raises(FixtureRefusal, match="FIXTURE_METRIC_REFUSED"):
        valid(4, 3)
    with pytest.raises(FixtureRefusal, match="FIXTURE_METRIC_REFUSED"):
        human_minutes(-1)
    with pytest.raises(FixtureRefusal, match="FIXTURE_METRIC_REFUSED"):
        coverage_delta(0, 1)


def test_fixture_module_imports_with_stdlib_only() -> None:
    source_root = Path(__file__).parents[1] / "src"
    code = (
        "import sys; "
        f"sys.path.insert(0, {str(source_root)!r}); "
        "import breakcheck.adapters.python.fixtures as fixtures; "
        "print(fixtures.__name__)"
    )
    result = subprocess.run(
        [sys.executable, "-S", "-c", code],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "breakcheck.adapters.python.fixtures"
