from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import struct

from .normalization import TYPE_TAG, VALUE_TAG


PROTOCOL_VERSION = 1
VALUE = "VALUE"
EXCEPTION = "EXCEPTION"
UNNORMALIZABLE = "UNNORMALIZABLE"
NETWORK_REFUSED = "NETWORK_REFUSED"
TIMEOUT = "TIMEOUT"
OUTPUT_LIMIT_REFUSED = "OUTPUT_LIMIT_REFUSED"
PROTOCOL_REFUSED = "PROTOCOL_REFUSED"

STATUSES = frozenset(
    {
        VALUE,
        EXCEPTION,
        UNNORMALIZABLE,
        NETWORK_REFUSED,
        TIMEOUT,
        OUTPUT_LIMIT_REFUSED,
        PROTOCOL_REFUSED,
    }
)

_FIELDS = frozenset(
    {
        "protocol_version",
        "status",
        "payload",
        "exception_class",
        "reason_code",
        "raw_type",
    }
)
_MAGIC = b"BRKCHK2\0"
_HEADER = struct.Struct(">8sQ")
_DIGEST_SIZE = hashlib.sha256().digest_size
_DEFAULT_MAX_PROTOCOL_BYTES = 1024 * 1024
_MAX_DEPTH = 64
_MAX_NODES = 10000
_MAX_CONTAINER_ITEMS = 10000
_MAX_TEXT_BYTES = 65536
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,255}\Z")
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")


def _refuse():
    raise ValueError(PROTOCOL_REFUSED)


def _json_value(value, *, depth=0, budget=None):
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > _MAX_NODES or depth > _MAX_DEPTH:
        _refuse()
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            _refuse()
        return
    if type(value) is str:
        if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
            _refuse()
        return
    if type(value) is list:
        if len(value) > _MAX_CONTAINER_ITEMS:
            _refuse()
        for item in value:
            _json_value(item, depth=depth + 1, budget=budget)
        return
    if type(value) is dict:
        if len(value) > _MAX_CONTAINER_ITEMS or any(
            type(key) is not str for key in value
        ):
            _refuse()
        for key in sorted(value):
            _json_value(key, depth=depth + 1, budget=budget)
            _json_value(value[key], depth=depth + 1, budget=budget)
        return
    _refuse()


def _optional_name(value):
    return value is None or (type(value) is str and _NAME.fullmatch(value))


def _optional_reason(value):
    return value is None or (type(value) is str and _REASON.fullmatch(value))


def validate_packet(packet):
    if type(packet) is not dict or set(packet) != _FIELDS:
        _refuse()
    if packet["protocol_version"] != PROTOCOL_VERSION:
        _refuse()
    status = packet["status"]
    if status not in STATUSES:
        _refuse()
    if not _optional_name(packet["exception_class"]):
        _refuse()
    if not _optional_reason(packet["reason_code"]):
        _refuse()
    if not _optional_name(packet["raw_type"]):
        _refuse()
    _json_value(packet["payload"])

    payload = packet["payload"]
    exception_class = packet["exception_class"]
    reason_code = packet["reason_code"]
    raw_type = packet["raw_type"]
    if status == VALUE:
        if any(value is not None for value in (exception_class, reason_code, raw_type)):
            _refuse()
    elif status == EXCEPTION:
        if exception_class is None or type(payload) is not list:
            _refuse()
        if reason_code is not None or raw_type is not None:
            _refuse()
    else:
        if payload is not None or exception_class is not None or reason_code is None:
            _refuse()
        if status != UNNORMALIZABLE and raw_type is not None:
            _refuse()
        if status == UNNORMALIZABLE and raw_type is None:
            _refuse()
    return packet


def _canonical_payload(packet):
    validate_packet(packet)
    return json.dumps(
        packet,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def encode_packet(packet, *, max_bytes=_DEFAULT_MAX_PROTOCOL_BYTES):
    if type(max_bytes) is not int or max_bytes < 256:
        _refuse()
    payload = _canonical_payload(packet)
    frame = (
        _HEADER.pack(_MAGIC, len(payload))
        + payload
        + hashlib.sha256(payload).digest()
    )
    if len(frame) > max_bytes:
        raise ValueError("PROTOCOL_SIZE_REFUSED")
    return frame


def _closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def _reject_constant(_value):
    _refuse()


def decode_packet(data, *, max_bytes=_DEFAULT_MAX_PROTOCOL_BYTES):
    if type(max_bytes) is not int or max_bytes < 256:
        _refuse()
    value = bytes(data or b"")
    if len(value) > max_bytes or len(value) < _HEADER.size + _DIGEST_SIZE:
        _refuse()
    magic, payload_size = _HEADER.unpack(value[: _HEADER.size])
    if magic != _MAGIC:
        _refuse()
    expected_size = _HEADER.size + payload_size + _DIGEST_SIZE
    if len(value) != expected_size:
        _refuse()
    payload = value[_HEADER.size : _HEADER.size + payload_size]
    digest = value[-_DIGEST_SIZE:]
    if not hmac.compare_digest(digest, hashlib.sha256(payload).digest()):
        _refuse()
    try:
        packet = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ValueError(PROTOCOL_REFUSED) from exc
    return validate_packet(packet)


def status_packet(status, reason_code, *, raw_type=None):
    packet = {
        "protocol_version": PROTOCOL_VERSION,
        "status": status,
        "payload": None,
        "exception_class": None,
        "reason_code": reason_code,
        "raw_type": raw_type,
    }
    return validate_packet(packet)


def child_source(
    snippet_source,
    *,
    protocol_fd,
    sys_path_prefixes=(),
    max_protocol_bytes=_DEFAULT_MAX_PROTOCOL_BYTES,
):
    if type(snippet_source) is not str or not snippet_source:
        raise ValueError("snippet_source")
    if type(protocol_fd) is not int or protocol_fd < 0:
        _refuse()
    if type(max_protocol_bytes) is not int or max_protocol_bytes < 256:
        _refuse()
    prefixes = tuple(str(value) for value in sys_path_prefixes)
    return f'''import collections.abc as _bc_collections
import hashlib as _bc_hashlib
import json as _bc_json
import math as _bc_math
import os as _bc_os
import struct as _bc_struct
import sys as _bc_sys

_bc_dumps = _bc_json.dumps
_bc_isfinite = _bc_math.isfinite
_bc_mapping = _bc_collections.Mapping
_bc_pack = _bc_struct.pack
_bc_sha256 = _bc_hashlib.sha256
_bc_write = _bc_os.write
_bc_type_tag = {TYPE_TAG!r}
_bc_value_tag = {VALUE_TAG!r}

def _bc_tag(kind, value):
    return {{_bc_type_tag: kind, _bc_value_tag: value}}

class _BreakcheckNetworkRefused(BaseException):
    pass

class _BreakcheckUnnormalizable(BaseException):
    def __init__(self, raw_type):
        self.raw_type = raw_type

def _bc_audit(event, args):
    if event.startswith("socket."):
        _bc_network_attempted[0] = True
        raise _BreakcheckNetworkRefused()

_bc_network_attempted = [False]
_bc_sys.addaudithook(_bc_audit)
_bc_budget = [0]

def _bc_normalize(value, depth=0):
    _bc_budget[0] += 1
    if _bc_budget[0] > {_MAX_NODES!r} or depth > {_MAX_DEPTH!r}:
        raise _BreakcheckUnnormalizable(type(value).__name__)
    if value is None or type(value) in (bool, str, int):
        if type(value) is str and len(value.encode("utf-8")) > {_MAX_TEXT_BYTES!r}:
            raise _BreakcheckUnnormalizable("str")
        return value
    if type(value) is float:
        if not _bc_isfinite(value):
            raise _BreakcheckUnnormalizable("float")
        return float(repr(value))
    if isinstance(value, bytes):
        if len(value) > {_MAX_TEXT_BYTES!r}:
            raise _BreakcheckUnnormalizable("bytes")
        return _bc_tag("bytes", value.hex())
    if isinstance(value, _bc_mapping):
        if len(value) > {_MAX_CONTAINER_ITEMS!r} or any(type(key) is not str for key in value):
            raise _BreakcheckUnnormalizable(type(value).__name__)
        normalized = {{key: _bc_normalize(value[key], depth + 1) for key in sorted(value)}}
        if _bc_type_tag in normalized or _bc_value_tag in normalized:
            return _bc_tag("mapping", [[key, normalized[key]] for key in sorted(normalized)])
        return normalized
    if isinstance(value, list):
        if len(value) > {_MAX_CONTAINER_ITEMS!r}:
            raise _BreakcheckUnnormalizable(type(value).__name__)
        return [_bc_normalize(item, depth + 1) for item in value]
    if isinstance(value, tuple):
        if len(value) > {_MAX_CONTAINER_ITEMS!r}:
            raise _BreakcheckUnnormalizable(type(value).__name__)
        return _bc_tag("tuple", [_bc_normalize(item, depth + 1) for item in value])
    if isinstance(value, (set, frozenset)):
        if len(value) > {_MAX_CONTAINER_ITEMS!r}:
            raise _BreakcheckUnnormalizable(type(value).__name__)
        items = [_bc_normalize(item, depth + 1) for item in value]
        items.sort(key=lambda item: (type(item).__name__, _bc_dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)))
        return _bc_tag("frozenset" if isinstance(value, frozenset) else "set", items)
    raise _BreakcheckUnnormalizable(type(value).__name__)

def _bc_packet(status, payload=None, exception_class=None, reason_code=None, raw_type=None):
    return {{
        "protocol_version": {PROTOCOL_VERSION!r},
        "status": status,
        "payload": payload,
        "exception_class": exception_class,
        "reason_code": reason_code,
        "raw_type": raw_type,
    }}

for _bc_prefix in reversed({prefixes!r}):
    _bc_sys.path.insert(0, _bc_prefix)

_bc_scope = {{"__name__": "__main__", "__file__": "<breakcheck-snippet>"}}
_bc_target_exception = None
try:
    exec(compile({snippet_source!r}, "<breakcheck-snippet>", "exec"), _bc_scope, _bc_scope)
except BaseException as _bc_exc:
    _bc_target_exception = _bc_exc

if _bc_network_attempted[0]:
    _bc_result = _bc_packet("NETWORK_REFUSED", reason_code="NETWORK_ACCESS_REFUSED")
elif _bc_target_exception is not None:
    try:
        _bc_budget[0] = 0
        _bc_args = _bc_normalize(list(_bc_target_exception.args))
        _bc_result = _bc_packet("EXCEPTION", payload=_bc_args, exception_class=type(_bc_target_exception).__name__)
    except BaseException:
        _bc_result = _bc_packet("UNNORMALIZABLE", reason_code="UNSTABLE_OBSERVATION_REFUSED", raw_type=type(_bc_target_exception).__name__)
elif "outcome" not in _bc_scope:
    _bc_result = _bc_packet("PROTOCOL_REFUSED", reason_code="OUTCOME_MISSING")
else:
    try:
        _bc_budget[0] = 0
        _bc_value = _bc_normalize(_bc_scope["outcome"])
        _bc_result = _bc_packet("VALUE", payload=_bc_value)
    except BaseException as _bc_exc:
        _bc_raw_type = getattr(_bc_exc, "raw_type", type(_bc_scope["outcome"]).__name__)
        _bc_result = _bc_packet("UNNORMALIZABLE", reason_code="UNSTABLE_OBSERVATION_REFUSED", raw_type=_bc_raw_type)

_bc_payload = _bc_dumps(_bc_result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
_bc_frame = _bc_pack(">8sQ", {_MAGIC!r}, len(_bc_payload)) + _bc_payload + _bc_sha256(_bc_payload).digest()
if len(_bc_frame) > {max_protocol_bytes!r}:
    _bc_result = _bc_packet("PROTOCOL_REFUSED", reason_code="PROTOCOL_SIZE_REFUSED")
    _bc_payload = _bc_dumps(_bc_result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    _bc_frame = _bc_pack(">8sQ", {_MAGIC!r}, len(_bc_payload)) + _bc_payload + _bc_sha256(_bc_payload).digest()

_bc_view = memoryview(_bc_frame)
while _bc_view:
    _bc_written = _bc_write({protocol_fd!r}, _bc_view)
    _bc_view = _bc_view[_bc_written:]
'''


__all__ = [
    "PROTOCOL_VERSION",
    "VALUE",
    "EXCEPTION",
    "UNNORMALIZABLE",
    "NETWORK_REFUSED",
    "TIMEOUT",
    "OUTPUT_LIMIT_REFUSED",
    "PROTOCOL_REFUSED",
    "STATUSES",
    "validate_packet",
    "encode_packet",
    "decode_packet",
    "status_packet",
    "child_source",
]
