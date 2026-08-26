from __future__ import annotations

import importlib
from pathlib import Path

import pytest

PACKAGE_MODULE = 'breakcheck'
CLI_MODULE = 'breakcheck.cli'
CLI_FUNCTION = 'main'
ENVIRONMENT_MODULE = 'breakcheck.adapters.python.envs'
ENVIRONMENT_BUILDER = 'PythonEnvBuilder'
NORMALIZATION_MODULE = 'breakcheck.adapters.python.normalization'
NORMALIZATION_FUNCTION = 'normalize_outcome'
VERIFIER_MODULE = 'breakcheck.verify'
VERIFIER_FUNCTION = 'verify_report'
MISSING_WHEEL_REFUSAL = 'MISSING_WHEEL_REFUSED'
PLATFORM_REFUSAL = 'PLATFORM_REFUSED'
UNSTABLE_OBSERVATION_REFUSAL = 'UNSTABLE_OBSERVATION_REFUSED'

def _error_text(exc):
    return str(exc.value)

def test_functional():
    assert importlib.import_module(PACKAGE_MODULE) is not None
    main = getattr(importlib.import_module(CLI_MODULE), CLI_FUNCTION)
    with pytest.raises(SystemExit) as exc:
        main(['--help'])
    assert int(exc.value.code or 0) == 0

def test_help_lists_every_declared_refusal_code(capsys):
    module = importlib.import_module(CLI_MODULE)
    with pytest.raises(SystemExit) as exc:
        module.main(['--help'])
    assert int(exc.value.code or 0) == 0
    help_text = capsys.readouterr().out
    for code in module._DECLARED_REFUSAL_CODES:
        assert code in help_text

def test_environment_rollback(tmp_path):
    builder_type = getattr(importlib.import_module(ENVIRONMENT_MODULE), ENVIRONMENT_BUILDER)
    wheelhouse = tmp_path / 'wheelhouse'
    wheelhouse.mkdir()
    destination = tmp_path / 'pair'
    builder = builder_type(package='missing-release-probe', current_version='1.0', new_version='2.0', wheelhouse=wheelhouse, destination=destination)
    with pytest.raises(Exception) as exc:
        builder.build()
    assert MISSING_WHEEL_REFUSAL in _error_text(exc)
    assert not destination.exists()

def test_bounded_failures():
    main = getattr(importlib.import_module(CLI_MODULE), CLI_FUNCTION)
    with pytest.raises(SystemExit) as exc:
        main([])
    assert int(exc.value.code or 0) == 2

def test_unstable_observations():
    normalize = getattr(importlib.import_module(NORMALIZATION_MODULE), NORMALIZATION_FUNCTION)
    class Explosive:
        def __repr__(self):
            raise AssertionError('arbitrary repr consulted')
    with pytest.raises(ValueError) as exc:
        normalize({'kind': 'value', 'payload': Explosive()})
    assert UNSTABLE_OBSERVATION_REFUSAL in _error_text(exc)

def test_platform_refusal(monkeypatch, tmp_path, capsys):
    module = importlib.import_module(CLI_MODULE)
    monkeypatch.setattr(module.sys, 'platform', 'unsupported-release-platform')
    result = getattr(module, CLI_FUNCTION)(['release-platform-probe@1.0', '--wheelhouse', str(tmp_path)])
    assert result == 2
    assert 'BUILD_REFUSED:' + PLATFORM_REFUSAL in capsys.readouterr().err


@pytest.mark.parametrize("value", ("0", "-1", "100.1", "nan"))
def test_min_coverage_is_rejected_before_execution_without_a_traceback(
    value, capsys
):
    module = importlib.import_module(CLI_MODULE)

    with pytest.raises(SystemExit) as exc:
        module.main(["coverage-probe@1.0", "--min-coverage", value])

    assert int(exc.value.code or 0) == 2
    error = capsys.readouterr().err
    assert "MIN_COVERAGE_REFUSED" in error
    assert "Traceback" not in error


@pytest.mark.parametrize(
    ("distribution", "import_root"),
    [
        ("PyYAML", "yaml"),
        ("beautifulsoup4", "bs4"),
        ("Pillow", "PIL"),
        ("python-dateutil", "dateutil"),
    ],
)
def test_known_distribution_names_resolve_to_their_public_import_roots(
    monkeypatch, distribution, import_root
):
    module = importlib.import_module(CLI_MODULE)
    monkeypatch.setattr(
        module._metadata,
        "distribution",
        lambda _name: (_ for _ in ()).throw(module._metadata.PackageNotFoundError()),
    )

    assert module._import_root(distribution) == import_root


def test_duplicate_exact_wheels_are_a_bounded_cli_refusal(monkeypatch, capsys):
    module = importlib.import_module(CLI_MODULE)
    monkeypatch.setattr(
        module,
        "_build",
        lambda _args: (_ for _ in ()).throw(
            RuntimeError("AMBIGUOUS_WHEEL_REFUSED:sample==1.0")
        ),
    )

    assert module.main(["sample@2.0", "--wheelhouse", "wheelhouse"]) == 2
    error = capsys.readouterr().err
    assert error.strip() == "BUILD_REFUSED:AMBIGUOUS_WHEEL_REFUSED"
    assert "Traceback" not in error

def test_report_tamper():
    verify = getattr(importlib.import_module(VERIFIER_MODULE), VERIFIER_FUNCTION)
    with pytest.raises(ValueError):
        verify({}, {'report': {}, 'report_sha256': '0' * 64})

def test_artifact_installation():
    package = importlib.import_module(PACKAGE_MODULE)
    location = Path(package.__file__).resolve()
    assert location.is_file() and location.name == '__init__.py'
