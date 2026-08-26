from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time

try:
    import resource
except ImportError:
    resource = None


_SCRUB_KEYS = {
    "http_proxy", "https_proxy", "all_proxy",
    "no_proxy", "http_proxy_user", "http_proxy_password",
    "api_key", "access_token", "auth_token", "secret", "token",
}
_INHERITED_ENVIRONMENT_KEYS = {"PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP"}
_NETWORK_GUARD = (
    "import sys as _guard_sys\n"
    "def _guard_audit(event, args):\n"
    "    if event.startswith('socket.'):\n"
    "        raise RuntimeError('NETWORK_ACCESS_REFUSED')\n"
    "_guard_sys.addaudithook(_guard_audit)\n"
)


def _scrubbed_environment():
    return {
        key: value
        for key, value in os.environ.items()
        if key.lower() not in _SCRUB_KEYS
    }


def _resource_hook():
    if resource is None:
        return None
    def apply_limits():
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (AttributeError, OSError, ValueError):
            pass
        try:
            limit = 512 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        except (AttributeError, OSError, ValueError):
            pass
    return apply_limits


def _safe_environment(extra):
    result = {key: os.environ[key] for key in _INHERITED_ENVIRONMENT_KEYS if key in os.environ}
    result["PYTHONHASHSEED"] = "0"
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    if isinstance(extra, dict):
        for key, value in extra.items():
            low = str(key).lower()
            if low in _SCRUB_KEYS or any(token in low for token in ("proxy", "secret", "token")):
                continue
            result[str(key)] = str(value)
    return result


def _environment_runtime(environment):
    root = environment if isinstance(environment, (str, os.PathLike)) else None
    extra = environment if isinstance(environment, dict) else None
    if isinstance(environment, dict):
        candidate_root = environment.get("root") or environment.get("path")
        if isinstance(candidate_root, (str, os.PathLike)):
            root = candidate_root
    if root is not None:
        root = os.fspath(root)
        for relative in (("bin", "python"), ("Scripts", "python.exe")):
            candidate = os.path.join(root, *relative)
            if os.path.isfile(candidate):
                return candidate, extra, os.path.realpath(root)
        raise ValueError("environment interpreter missing")
    return sys.executable, extra, None


def _scrub_environment_root(data, environment_root):
    value = bytes(data or b"")
    if environment_root is None:
        return value
    encoded = os.fsencode(environment_root)
    return value.replace(encoded, b"<ENVIRONMENT_ROOT>")


def _source(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


class _BoundedStream:
    def __init__(self, stream, limit):
        self.stream = stream
        self.limit = limit
        self.data = bytearray()
        self.limited = False

    def drain(self):
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    return
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.limited = True
        except (OSError, ValueError):
            return


def _kill_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        try:
            process.wait(timeout=2.0)
        except (subprocess.TimeoutExpired, ProcessLookupError):
            process.kill()
            process.wait()


def _run_in_process_group(command, *, cwd, env, timeout_seconds,
                          max_output_bytes, preexec_fn):
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        preexec_fn=preexec_fn,
        start_new_session=True,
    )
    stdout = _BoundedStream(process.stdout, max_output_bytes)
    stderr = _BoundedStream(process.stderr, max_output_bytes)
    threads = [
        threading.Thread(target=stdout.drain, daemon=True),
        threading.Thread(target=stderr.drain, daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
    finally:
        for thread in threads:
            thread.join(timeout=2.0)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        for thread in threads:
            thread.join(timeout=0.2)
    return {
        "returncode": None if timed_out else process.returncode,
        "stdout": bytes(stdout.data),
        "stderr": bytes(stderr.data),
        "timed_out": timed_out,
        "output_limited": stdout.limited or stderr.limited,
    }


def _run_with_injected_runner(runner, command, *, cwd, env, timeout_seconds,
                              max_output_bytes, preexec_fn):
    try:
        result = runner(
            command,
            cwd=cwd,
            env=env,
            timeout=timeout_seconds,
            capture_output=True,
            shell=False,
            preexec_fn=preexec_fn,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = bytes(exc.stdout or b"")
        stderr = bytes(exc.stderr or b"")
        return {
            "returncode": None,
            "stdout": stdout[:max_output_bytes],
            "stderr": stderr[:max_output_bytes],
            "timed_out": True,
            "output_limited": (
                len(stdout) > max_output_bytes or len(stderr) > max_output_bytes
            ),
        }
    stdout = bytes(getattr(result, "stdout", b"") or b"")
    stderr = bytes(getattr(result, "stderr", b"") or b"")
    return {
        "returncode": int(getattr(result, "returncode", 1)),
        "stdout": stdout[:max_output_bytes],
        "stderr": stderr[:max_output_bytes],
        "timed_out": False,
        "output_limited": (
            len(stdout) > max_output_bytes or len(stderr) > max_output_bytes
        ),
    }


def run_snippet_isolated(*, snippet=None, snippet_source=None, code=None, environment=None,
               timeout_seconds=30.0, max_output_bytes=1048576, runner=None):
    if sys.platform not in ("darwin", "linux"):
        raise RuntimeError("PLATFORM_REFUSED")
    source = _source(snippet_source if snippet_source is not None else
                     code if code is not None else snippet)
    if not source:
        raise ValueError("snippet_source")
    if timeout_seconds <= 0 or max_output_bytes < 1:
        raise ValueError("limits")
    executable, environment_extra, environment_root = _environment_runtime(environment)
    command = [executable, "-I", "-c", _NETWORK_GUARD + source]
    with tempfile.TemporaryDirectory(prefix="isolated-runtime-") as fresh_cwd:
        started = time.monotonic()
        kwargs = {
            "cwd": fresh_cwd,
            "env": _safe_environment(environment_extra),
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "preexec_fn": _resource_hook(),
        }
        if runner is None:
            result = _run_in_process_group(command, **kwargs)
        else:
            result = _run_with_injected_runner(runner, command, **kwargs)
        stdout = _scrub_environment_root(
            result.get("stdout", b""), environment_root
        )
        stderr = _scrub_environment_root(
            result.get("stderr", b""), environment_root
        )
        return {
            "returncode": result.get("returncode"),
            "stdout": stdout[:max_output_bytes],
            "stderr": stderr[:max_output_bytes],
            "timed_out": bool(result.get("timed_out")),
            "output_limited": bool(result.get("output_limited")),
            "elapsed_ms": (
                None if result.get("timed_out")
                else int((time.monotonic() - started) * 1000)
            ),
        }


class PythonExecutor:
    def __init__(self, runner=None):
        self.runner = runner

    def run(self, *, snippet=None, snippet_source=None, code=None, environment=None,
            timeout_seconds=30.0, max_output_bytes=1048576):
        return run_snippet_isolated(
            snippet=snippet, snippet_source=snippet_source, code=code,
            environment=environment, timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes, runner=self.runner,
        )

    def execute(self, *, snippet=None, snippet_source=None, code=None, environment=None,
                timeout_seconds=30.0, max_output_bytes=1048576):
        return self.run(
            snippet=snippet, snippet_source=snippet_source, code=code,
            environment=environment, timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
