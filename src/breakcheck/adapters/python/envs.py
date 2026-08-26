from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


_KEYWORDS = ("allow_network", "current_version", "destination", "environment",
             "new_version", "package", "version", "wheelhouse")


def _normalized_distribution(value):
    return re.sub(r"[-_.]+", "-", str(value)).lower()


def _local_wheel(wheelhouse, package, version):
    if not wheelhouse:
        return None
    root = Path(wheelhouse)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("WHEELHOUSE_REFUSED")
    root = root.resolve()
    wanted = (_normalized_distribution(package), _normalized_distribution(version))
    matches = []
    for candidate in sorted(root.glob("*.whl")):
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError("WHEELHOUSE_REFUSED")
        try:
            candidate.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise RuntimeError("WHEELHOUSE_REFUSED") from exc
        parts = candidate.name[:-4].split("-")
        if len(parts) >= 2 and (_normalized_distribution(parts[0]), _normalized_distribution(parts[1])) == wanted:
            matches.append(candidate)
    if len(matches) > 1:
        raise RuntimeError(
            "AMBIGUOUS_WHEEL_REFUSED:%s==%s" %
            (_normalized_distribution(package), version)
        )
    return matches[0] if matches else None


def _environment_python(environment):
    if environment is not None:
        root = Path(environment)
        for relative in (("bin", "python"), ("Scripts", "python.exe")):
            candidate = root.joinpath(*relative)
            if candidate.exists():
                return str(candidate)
    return sys.executable


def _install(wheelhouse, package, version, allow_network, runner=None, environment=None):
    if not package or not version:
        return None
    executable = _environment_python(environment)
    requirement = f"{package}=={version}"
    argv = [executable, "-m", "pip", "install"]
    local_wheel = _local_wheel(wheelhouse, package, version)
    if local_wheel is not None:
        argv.extend(["--no-index", "--find-links", str(Path(wheelhouse)), str(local_wheel)])
    elif not allow_network:
        raise RuntimeError(
            "MISSING_WHEEL_REFUSED:%s==%s" %
            (_normalized_distribution(package), version)
        )
    else:
        argv.append(requirement)
    execute = runner or subprocess.run
    try:
        result = execute(argv, check=False, capture_output=True, text=True, shell=False)
    except Exception as exc:
        raise RuntimeError('INSTALL_FAILED') from exc
    if getattr(result, "returncode", 1) != 0:
        raise RuntimeError('INSTALL_FAILED')
    return result


def _make_environment(destination):
    if destination is None:
        destination = tempfile.mkdtemp(prefix="runtime-environment-")
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    venv.EnvBuilder(with_pip=True, clear=False).create(path)
    return str(path)


class PythonEnvBuilder:
    def __init__(self, package=None, current_version=None, new_version=None,
                 wheelhouse=None, destination=None, allow_network=False, runner=None):
        self.package = package
        self.current_version = current_version
        self.new_version = new_version
        self.wheelhouse = wheelhouse
        self.destination = destination
        self.allow_network = bool(allow_network)
        self.runner = runner

    def build(self, package=None, current_version=None, new_version=None,
              wheelhouse=None, *, destination=None, allow_network=None):
        selected_package = package if package is not None else self.package
        selected_current = current_version if current_version is not None else self.current_version
        selected_new = new_version if new_version is not None else self.new_version
        selected_wheelhouse = wheelhouse if wheelhouse is not None else self.wheelhouse
        selected_network = self.allow_network if allow_network is None else bool(allow_network)
        selected_destination = destination if destination is not None else self.destination
        implicit_root = selected_destination is None
        destination_preexisted = (
            selected_destination is not None and Path(selected_destination).exists()
        )
        if selected_destination is None:
            root = Path(tempfile.mkdtemp(prefix="runtime-pair-"))
        else:
            root = Path(selected_destination)
            if (root.is_symlink() or
                    (root.exists() and (not root.is_dir() or any(root.iterdir())))):
                raise ValueError("RUNTIME_DESTINATION_REFUSED")
        current_root = root / "current"
        new_root = root / "new"
        try:
            current = _make_environment(current_root)
            _install(selected_wheelhouse, selected_package, selected_current,
                     selected_network, self.runner, current)
            new = _make_environment(new_root)
            _install(selected_wheelhouse, selected_package, selected_new,
                     selected_network, self.runner, new)
        except BaseException:
            for created_root in (current_root, new_root):
                if created_root.exists() or created_root.is_symlink():
                    shutil.rmtree(created_root, ignore_errors=True)
            if (implicit_root or not destination_preexisted) and (root.exists() or root.is_symlink()):
                shutil.rmtree(root, ignore_errors=True)
            raise
        return {"current": current, "new": new}

    def install(self, wheelhouse=None, package=None, version=None, allow_network=None):
        return _install(
            wheelhouse if wheelhouse is not None else self.wheelhouse,
            package if package is not None else self.package,
            version if version is not None else self.current_version,
            self.allow_network if allow_network is None else bool(allow_network),
            self.runner,
        )


def build_venv(*, allow_network=False, current_version=None, destination=None,
                 environment=None, new_version=None, package=None, version=None,
                 wheelhouse=None, runner=None):
    requested = destination or environment
    if requested is not None:
        requested_path = Path(requested)
        if requested_path.exists() or requested_path.is_symlink():
            raise ValueError("RUNTIME_DESTINATION_REFUSED")
    path = None
    new_path = None
    try:
        path = _make_environment(requested)
        selected = version if version is not None else current_version
        _install(wheelhouse, package, selected, bool(allow_network), runner, path)
        if new_version:
            new_destination = str(Path(path).with_name(Path(path).name + "-new"))
            if Path(new_destination).exists() or Path(new_destination).is_symlink():
                raise ValueError("RUNTIME_DESTINATION_REFUSED")
            new_path = _make_environment(new_destination)
            _install(wheelhouse, package, new_version, bool(allow_network), runner, new_path)
        return path
    except BaseException:
        for created in (path, new_path):
            if created is not None:
                created_path = Path(created)
                if created_path.exists() or created_path.is_symlink():
                    shutil.rmtree(created_path, ignore_errors=True)
        raise


def env_fingerprint(*, environment=None):
    root = Path(environment) if environment is not None else None
    rows = []
    if root is not None and root.exists():
        paths = {str(root)}
        for marker in root.rglob("*.dist-info"):
            if marker.is_dir():
                paths.add(str(marker.parent))
        try:
            for distribution in importlib.metadata.distributions(path=sorted(paths)):
                rows.append((str(distribution.metadata.get("Name", "")),
                             str(distribution.version)))
        except Exception as exc:
            raise ValueError("ENVIRONMENT_FINGERPRINT_REFUSED") from exc
    rows = sorted(rows)
    payload = "\n".join("%s==%s" % row for row in rows).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
