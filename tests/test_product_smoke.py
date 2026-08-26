import importlib

import pytest


def test_package_imports():
    assert importlib.import_module('breakcheck') is not None


def test_cli_help_exits_cleanly():
    main = getattr(importlib.import_module('breakcheck.cli'), 'main')
    try:
        result = main(['--help'])
    except SystemExit as exc:
        result = int(exc.code or 0)
    assert int(result or 0) == 0


@pytest.mark.parametrize(
    "arguments",
    [
        ["--capabilities", "--json", "--wheelhouse", "/unused"],
        ["demo", "--output-root", "/unused", "--allow-empty"],
        ["--verify", "/unused/report.json", "--ci"],
        ["sample@2.0", "--wheelhouse", "/unused", "--output-root", "/unused"],
    ],
)
def test_cli_modes_refuse_irrelevant_options(arguments):
    main = getattr(importlib.import_module("breakcheck.cli"), "main")
    with pytest.raises(SystemExit) as refused:
        main(arguments)
    assert refused.value.code == 2
