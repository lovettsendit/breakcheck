import importlib


def test_package_imports():
    assert importlib.import_module('breakcheck') is not None


def test_cli_help_exits_cleanly():
    main = getattr(importlib.import_module('breakcheck.cli'), 'main')
    try:
        result = main(['--help'])
    except SystemExit as exc:
        result = int(exc.code or 0)
    assert int(result or 0) == 0
