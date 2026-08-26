from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time

from breakcheck.adapters.python import protocol
from breakcheck.adapters.python.normalization import (
    normalize_protocol_packet,
    observation_identity,
)

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
    "import socket as _guard_socket\n"
    "def _guard_audit(event, args):\n"
    "    if not event.startswith('socket.'):\n"
    "        return\n"
    "    if event == 'socket.__new__' and len(args) >= 4:\n"
    "        if args[1] in (_guard_socket.AF_INET, _guard_socket.AF_INET6) and args[2] in (_guard_socket.SOCK_STREAM, _guard_socket.SOCK_DGRAM) and args[3] == 0:\n"
    "            return\n"
    "    raise RuntimeError('NETWORK_ACCESS_REFUSED')\n"
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
    replacements = () if environment_root is None else (
        (environment_root, "<ENVIRONMENT_ROOT>"),
    )
    return _scrub_roots_bytes(data, replacements)


def _scrub_roots_bytes(data, replacements):
    value = bytes(data or b"")
    encoded = []
    for root, marker in replacements:
        if root is None:
            continue
        raw = os.path.abspath(os.fspath(root))
        real = os.path.realpath(raw)
        for candidate in (raw, real):
            pair = (os.fsencode(candidate), str(marker).encode("ascii"))
            if pair[0] and pair not in encoded:
                encoded.append(pair)
    for needle, marker in sorted(encoded, key=lambda row: len(row[0]), reverse=True):
        value = value.replace(needle, marker)
    return value


def _scrub_packet(packet, replacements):
    encoded_replacements = []
    for root, marker in replacements:
        if root is None:
            continue
        raw = os.path.abspath(os.fspath(root))
        real = os.path.realpath(raw)
        for candidate in (raw, real):
            pair = (candidate, str(marker))
            if pair[0] and pair not in encoded_replacements:
                encoded_replacements.append(pair)
    encoded_replacements.sort(key=lambda row: len(row[0]), reverse=True)

    def scrub(value):
        if type(value) is str:
            for needle, marker in encoded_replacements:
                value = value.replace(needle, marker)
            return value
        if type(value) is list:
            return [scrub(item) for item in value]
        if type(value) is dict:
            return {key: scrub(item) for key, item in value.items()}
        return value

    return scrub(packet)


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
                          max_output_bytes, preexec_fn, pass_fds=(),
                          parent_close_fds=(), protocol_read_fd=None,
                          max_protocol_bytes=1048576):
    try:
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
            pass_fds=tuple(pass_fds),
        )
    except BaseException:
        for descriptor in parent_close_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if protocol_read_fd is not None:
            try:
                os.close(protocol_read_fd)
            except OSError:
                pass
        raise
    for descriptor in parent_close_fds:
        try:
            os.close(descriptor)
        except OSError:
            pass
    stdout = _BoundedStream(process.stdout, max_output_bytes)
    stderr = _BoundedStream(process.stderr, max_output_bytes)
    protocol_stream = (
        os.fdopen(protocol_read_fd, "rb", buffering=0)
        if protocol_read_fd is not None else None
    )
    protocol_output = (
        _BoundedStream(protocol_stream, max_protocol_bytes)
        if protocol_stream is not None else None
    )
    threads = [
        threading.Thread(target=stdout.drain, daemon=True),
        threading.Thread(target=stderr.drain, daemon=True),
    ]
    if protocol_output is not None:
        threads.append(threading.Thread(target=protocol_output.drain, daemon=True))
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
        for stream in (process.stdout, process.stderr, protocol_stream):
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
        "protocol": (
            bytes(protocol_output.data) if protocol_output is not None else b""
        ),
        "protocol_limited": (
            bool(protocol_output.limited) if protocol_output is not None else False
        ),
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
        "protocol": bytes(getattr(result, "protocol", b"") or b""),
        "protocol_limited": False,
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


def _validated_sys_path_prefixes(values):
    if values is None:
        return ()
    if isinstance(values, (str, bytes, os.PathLike)):
        raise ValueError("SYS_PATH_PREFIX_REFUSED")
    result = []
    for value in values:
        path = os.path.abspath(os.fspath(value))
        if (
            path != os.fspath(value)
            or not os.path.isdir(path)
            or os.path.islink(path)
        ):
            raise ValueError("SYS_PATH_PREFIX_REFUSED")
        real = os.path.realpath(path)
        if real != path or path in result:
            raise ValueError("SYS_PATH_PREFIX_REFUSED")
        result.append(path)
    return tuple(result)


def _path_replacements(environment_root, sys_path_prefixes):
    rows = []
    if environment_root is not None:
        rows.append((environment_root, "<ENVIRONMENT_ROOT>"))
    for index, root in enumerate(sys_path_prefixes, start=1):
        marker = "<WORKTREE_ROOT>" if index == 1 else f"<WORKTREE_ROOT_{index}>"
        rows.append((root, marker))
    return tuple(rows)


def _typed_result(packet, *, result, stdout, stderr, elapsed_ms):
    observation = normalize_protocol_packet(packet)
    return {
        "status": packet["status"],
        "observation": observation,
        "reason_code": packet["reason_code"],
        "raw_type": packet["raw_type"],
        "stdout": stdout,
        "stderr": stderr,
        "returncode": result.get("returncode"),
        "elapsed_ms": elapsed_ms,
    }


def _typed_refusal(status, reason_code, *, result, stdout, stderr, elapsed_ms):
    packet = protocol.status_packet(status, reason_code)
    return _typed_result(
        packet,
        result=result,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=elapsed_ms,
    )


def run_typed_snippet_isolated(
    *,
    snippet=None,
    snippet_source=None,
    code=None,
    environment=None,
    timeout_seconds=30.0,
    max_output_bytes=1048576,
    max_protocol_bytes=1048576,
    sys_path_prefixes=(),
    runner=None,
):
    """Execute a snippet with a separate, framed observation channel.

    Normal stdout and stderr remain diagnostics.  Only the private inherited pipe
    can carry the typed result, so printed package output cannot be mistaken for an
    observation.
    """
    if sys.platform not in ("darwin", "linux"):
        raise RuntimeError("PLATFORM_REFUSED")
    source = _source(
        snippet_source if snippet_source is not None else
        code if code is not None else snippet
    )
    if not source:
        raise ValueError("snippet_source")
    if (
        timeout_seconds <= 0
        or max_output_bytes < 1
        or type(max_protocol_bytes) is not int
        or max_protocol_bytes < 256
    ):
        raise ValueError("limits")
    prefixes = _validated_sys_path_prefixes(sys_path_prefixes)
    executable, environment_extra, environment_root = _environment_runtime(environment)
    replacements = _path_replacements(environment_root, prefixes)

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
            protocol_read_fd, protocol_write_fd = os.pipe()
            child = protocol.child_source(
                source,
                protocol_fd=protocol_write_fd,
                sys_path_prefixes=prefixes,
                max_protocol_bytes=max_protocol_bytes,
            )
            command = [executable, "-I", "-c", child]
            result = _run_in_process_group(
                command,
                pass_fds=(protocol_write_fd,),
                parent_close_fds=(protocol_write_fd,),
                protocol_read_fd=protocol_read_fd,
                max_protocol_bytes=max_protocol_bytes,
                **kwargs,
            )
        else:
            child = protocol.child_source(
                source,
                protocol_fd=3,
                sys_path_prefixes=prefixes,
                max_protocol_bytes=max_protocol_bytes,
            )
            command = [executable, "-I", "-c", child]
            result = _run_with_injected_runner(
                runner,
                command,
                max_output_bytes=max_output_bytes,
                **{key: value for key, value in kwargs.items()
                   if key != "max_output_bytes"},
            )

        stdout = _scrub_roots_bytes(result.get("stdout", b""), replacements)
        stderr = _scrub_roots_bytes(result.get("stderr", b""), replacements)
        elapsed_ms = (
            None if result.get("timed_out")
            else int((time.monotonic() - started) * 1000)
        )
        if result.get("timed_out"):
            return _typed_refusal(
                protocol.TIMEOUT,
                "EXECUTION_TIMEOUT",
                result=result,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=None,
            )
        if result.get("output_limited"):
            return _typed_refusal(
                protocol.OUTPUT_LIMIT_REFUSED,
                "OUTPUT_LIMIT_REFUSED",
                result=result,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=elapsed_ms,
            )
        if result.get("protocol_limited"):
            return _typed_refusal(
                protocol.PROTOCOL_REFUSED,
                "PROTOCOL_SIZE_REFUSED",
                result=result,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=elapsed_ms,
            )
        if result.get("returncode") != 0:
            return _typed_refusal(
                protocol.PROTOCOL_REFUSED,
                "PROTOCOL_REFUSED",
                result=result,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=elapsed_ms,
            )
        try:
            packet = protocol.decode_packet(
                result.get("protocol", b""), max_bytes=max_protocol_bytes
            )
        except ValueError:
            return _typed_refusal(
                protocol.PROTOCOL_REFUSED,
                "PROTOCOL_REFUSED",
                result=result,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=elapsed_ms,
            )
        packet = _scrub_packet(packet, replacements)
        return _typed_result(
            packet,
            result=result,
            stdout=stdout,
            stderr=stderr,
            elapsed_ms=elapsed_ms,
        )


def _repeat_identity(result):
    return (
        result["status"],
        result["reason_code"],
        result["raw_type"],
        observation_identity(result["observation"]),
    )


def run_repeated_typed_snippet_isolated(*, runs=2, **kwargs):
    """Repeat a typed execution and admit only byte-identical observations."""
    if type(runs) is not int or runs != 2:
        raise ValueError("REPEAT_COUNT_REFUSED")
    observed = [run_typed_snippet_isolated(**kwargs) for _ in range(runs)]
    repeatable = _repeat_identity(observed[0]) == _repeat_identity(observed[1])
    if not repeatable:
        return {
            "runs": observed,
            "repeatable": False,
            "status": protocol.PROTOCOL_REFUSED,
            "reason_code": "NONDETERMINISTIC_OBSERVATION",
            "observation": None,
        }
    first = observed[0]
    return {
        "runs": observed,
        "repeatable": True,
        "status": first["status"],
        "reason_code": first["reason_code"],
        "observation": first["observation"],
    }


run_typed_snippet_repeated = run_repeated_typed_snippet_isolated


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

    def run_typed(
        self,
        *,
        snippet=None,
        snippet_source=None,
        code=None,
        environment=None,
        timeout_seconds=30.0,
        max_output_bytes=1048576,
        max_protocol_bytes=1048576,
        sys_path_prefixes=(),
    ):
        return run_typed_snippet_isolated(
            snippet=snippet,
            snippet_source=snippet_source,
            code=code,
            environment=environment,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            max_protocol_bytes=max_protocol_bytes,
            sys_path_prefixes=sys_path_prefixes,
            runner=self.runner,
        )

    def run_repeated_typed(self, **kwargs):
        return run_repeated_typed_snippet_isolated(runner=self.runner, **kwargs)
