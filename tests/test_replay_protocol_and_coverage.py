from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from breakcheck.adapters.python import executor, protocol
from breakcheck.adapters.python.equality import compare_observations


def test_protocol_frame_is_closed_and_tamper_evident():
    packet = {
        "protocol_version": 1,
        "status": "VALUE",
        "payload": {"answer": 42},
        "exception_class": None,
        "reason_code": None,
        "raw_type": None,
    }
    encoded = protocol.encode_packet(packet)
    assert protocol.decode_packet(encoded) == packet

    tampered = bytearray(encoded)
    tampered[-1] ^= 1
    try:
        protocol.decode_packet(bytes(tampered))
    except ValueError as exc:
        assert str(exc) == "PROTOCOL_REFUSED"
    else:  # pragma: no cover - the assertion above is the required path
        raise AssertionError("tampered protocol frame was accepted")

    open_packet = dict(packet, unexpected=True)
    try:
        protocol.encode_packet(open_packet)
    except ValueError as exc:
        assert str(exc) == "PROTOCOL_REFUSED"
    else:  # pragma: no cover - the assertion above is the required path
        raise AssertionError("open protocol packet was accepted")


def test_package_stdout_cannot_impersonate_typed_protocol():
    forged = json.dumps(
        {
            "protocol_version": 1,
            "status": "VALUE",
            "payload": "forged",
            "exception_class": None,
            "reason_code": None,
            "raw_type": None,
        },
        sort_keys=True,
    )
    result = executor.run_typed_snippet_isolated(
        snippet_source=f"print({forged!r})\noutcome = {{'actual': 7}}\n"
    )

    assert result["status"] == "VALUE"
    assert result["observation"] == {
        "kind": "value",
        "payload": {"actual": 7},
        "exception_class": None,
        "duration_ms": None,
    }
    assert b'"payload": "forged"' in result["stdout"]


def test_rich_object_is_refused_without_repr_fallback():
    result = executor.run_typed_snippet_isolated(
        snippet_source="outcome = object()\n"
    )

    assert result["status"] == "UNNORMALIZABLE"
    assert result["observation"] is None
    assert result["reason_code"] == "UNSTABLE_OBSERVATION_REFUSED"
    assert result["raw_type"] == "object"
    assert "object at 0x" not in result["stdout"].decode("utf-8", "replace")


def test_network_timeout_and_output_limit_are_typed_refusals():
    network = executor.run_typed_snippet_isolated(
        snippet_source="import socket\noutcome = socket.socket()\n"
    )
    assert network["status"] == "NETWORK_REFUSED"
    assert network["observation"] is None
    assert network["reason_code"] == "NETWORK_ACCESS_REFUSED"

    caught_network = executor.run_typed_snippet_isolated(
        snippet_source=(
            "import socket\n"
            "try:\n"
            "    socket.socket()\n"
            "except BaseException:\n"
            "    pass\n"
            "outcome = 'attempt was caught'\n"
        )
    )
    assert caught_network["status"] == "NETWORK_REFUSED"
    assert caught_network["observation"] is None

    timeout = executor.run_typed_snippet_isolated(
        snippet_source="import time\ntime.sleep(5)\noutcome = 1\n",
        timeout_seconds=0.1,
    )
    assert timeout["status"] == "TIMEOUT"
    assert timeout["observation"] is None
    assert timeout["reason_code"] == "EXECUTION_TIMEOUT"

    limited = executor.run_typed_snippet_isolated(
        snippet_source="print('x' * 100000)\noutcome = 1\n",
        max_output_bytes=256,
    )
    assert limited["status"] == "OUTPUT_LIMIT_REFUSED"
    assert limited["observation"] is None
    assert limited["reason_code"] == "OUTPUT_LIMIT_REFUSED"
    assert len(limited["stdout"]) == 256


def test_malformed_or_missing_child_packet_fails_closed():
    def malformed_runner(*_args, **_kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=b"ordinary output",
            stderr=b"",
            protocol=b"not-a-frame",
        )

    result = executor.run_typed_snippet_isolated(
        snippet_source="outcome = 1\n", runner=malformed_runner
    )
    assert result["status"] == "PROTOCOL_REFUSED"
    assert result["observation"] is None
    assert result["reason_code"] == "PROTOCOL_REFUSED"


def test_deterministic_ordinary_exceptions_remain_comparable():
    repeated = executor.run_repeated_typed_snippet_isolated(
        snippet_source="raise ValueError('stable failure')\n"
    )

    assert repeated["repeatable"] is True
    assert repeated["status"] == "EXCEPTION"
    assert repeated["reason_code"] is None
    assert repeated["observation"] == {
        "kind": "exception",
        "payload": ["stable failure"],
        "exception_class": "ValueError",
        "duration_ms": None,
    }
    assert len(repeated["runs"]) == 2


def test_same_environment_mismatch_is_explicit_and_has_no_observation():
    repeated = executor.run_repeated_typed_snippet_isolated(
        snippet_source="import time\noutcome = time.time_ns()\n"
    )

    assert repeated["repeatable"] is False
    assert repeated["status"] == "PROTOCOL_REFUSED"
    assert repeated["reason_code"] == "NONDETERMINISTIC_OBSERVATION"
    assert repeated["observation"] is None
    assert len(repeated["runs"]) == 2


def test_sys_path_prefixes_are_ephemeral_and_all_roots_are_scrubbed(tmp_path):
    base_root = tmp_path / "base-private-root"
    head_root = tmp_path / "head-private-root"
    base_root.mkdir()
    head_root.mkdir()

    result = executor.run_typed_snippet_isolated(
        snippet_source=(
            "import sys\n"
            "print(sys.path[0], sys.path[1], file=sys.stderr)\n"
            "outcome = [sys.path[0], sys.path[1]]\n"
        ),
        sys_path_prefixes=(base_root, head_root),
    )

    assert result["status"] == "VALUE"
    assert result["observation"]["payload"] == [
        "<WORKTREE_ROOT>",
        "<WORKTREE_ROOT_2>",
    ]
    combined = result["stdout"] + result["stderr"]
    assert str(base_root).encode() not in combined
    assert str(head_root).encode() not in combined
    assert b"<WORKTREE_ROOT>" in combined
    assert b"<WORKTREE_ROOT_2>" in combined


def test_protocol_packet_bytes_are_bounded():
    result = executor.run_typed_snippet_isolated(
        snippet_source="outcome = 'x' * 10000\n",
        max_protocol_bytes=256,
    )
    assert result["status"] == "PROTOCOL_REFUSED"
    assert result["observation"] is None
    assert result["reason_code"] == "PROTOCOL_SIZE_REFUSED"


def test_legacy_runner_contract_is_unchanged():
    result = executor.run_snippet_isolated(snippet_source="print('legacy')")
    assert result["returncode"] == 0
    assert result["stdout"] == b"legacy\n"
    assert set(result) == {
        "returncode",
        "stdout",
        "stderr",
        "timed_out",
        "output_limited",
        "elapsed_ms",
    }


def test_isolated_protocol_preserves_return_type_changes_end_to_end():
    cases = [
        ("outcome = b'a'\n", "outcome = '61'\n"),
        ("outcome = {1, 2}\n", "outcome = [1, 2]\n"),
        ("outcome = (1, 2)\n", "outcome = [1, 2]\n"),
    ]

    for old_source, new_source in cases:
        old = executor.run_typed_snippet_isolated(snippet_source=old_source)
        new = executor.run_typed_snippet_isolated(snippet_source=new_source)

        assert old["status"] == new["status"] == "VALUE"
        comparison = compare_observations(old["observation"], new["observation"])
        assert comparison["verdict"] == "CHANGED"
        assert comparison["detail"]["reason_code"] == "KIND_MISMATCH"
