from __future__ import annotations

import ast
from pathlib import Path

REQUIRED_CATEGORIES = ['functional', 'environment_rollback', 'bounded_failures', 'unstable_observations', 'platform_refusal', 'report_tamper', 'artifact_installation']
MINIMUM_COLLECTED_TESTS = 10
SOURCE_COMMAND = 'python -m pytest -q tests'
INSTALLED_COMMAND = 'python -m pytest -q tests'

def test_native_release_category_coverage():
    names = set()
    here = Path(__file__).resolve()
    for path in sorted(here.parent.glob('test_*.py')):
        if path.resolve() == here:
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'))
        names.update(node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'))
    required = {'test_' + value for value in REQUIRED_CATEGORIES}
    assert required <= names
    assert len(names) >= MINIMUM_COLLECTED_TESTS
