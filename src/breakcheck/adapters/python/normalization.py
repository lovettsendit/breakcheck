from __future__ import annotations

import json
import math
from collections.abc import Mapping


TYPE_TAG = "$breakcheck_type"
VALUE_TAG = "$breakcheck_value"
TAGGED_TYPES = frozenset({"bytes", "tuple", "set", "frozenset", "mapping"})


def tagged_value_kind(value):
    if (
        type(value) is dict
        and set(value) == {TYPE_TAG, VALUE_TAG}
        and type(value[TYPE_TAG]) is str
        and value[TYPE_TAG] in TAGGED_TYPES
    ):
        return value[TYPE_TAG]
    return None


def tagged_value_payload(value):
    if tagged_value_kind(value) is None:
        raise ValueError("UNTAGGED_VALUE_REFUSED")
    return value[VALUE_TAG]


def _tag(kind, value):
    return {TYPE_TAG: kind, VALUE_TAG: value}


def _normalized(value):
    if value is None:
        return None
    if type(value) is bool:
        return value
    if type(value) is str:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("UNSTABLE_OBSERVATION_REFUSED")
        return float(repr(value))
    if isinstance(value, bytes):
        return _tag("bytes", value.hex())
    if isinstance(value, BaseException):
        return {
            "exception_class": value.__class__.__name__,
            "args": [_normalized(item) for item in value.args],
        }
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("UNSTABLE_OBSERVATION_REFUSED")
        items = sorted(value.items(), key=lambda item: item[0])
        normalized = {key: _normalized(item) for key, item in items}
        if TYPE_TAG in normalized or VALUE_TAG in normalized:
            return _tag(
                "mapping",
                [[key, normalized[key]] for key in sorted(normalized)],
            )
        return normalized
    if isinstance(value, list):
        return [_normalized(item) for item in value]
    if isinstance(value, tuple):
        return _tag("tuple", [_normalized(item) for item in value])
    if isinstance(value, (set, frozenset)):
        items = [_normalized(item) for item in value]
        items.sort(key=lambda item: (
            type(item).__name__,
            json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
        ))
        return _tag("frozenset" if isinstance(value, frozenset) else "set", items)
    raise ValueError("UNSTABLE_OBSERVATION_REFUSED")


def _field(value, name):
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def normalize_outcome(value):
    kind = _field(value, "kind")
    payload = _field(value, "payload")
    exception_class = _field(value, "exception_class")
    if isinstance(payload, BaseException):
        kind = "exception"
        exception_class = type(payload).__name__
        payload = {"args": [_normalized(item) for item in payload.args]}
    else:
        payload = _normalized(payload)
    if kind not in ("value", "exception", "timeout"):
        raise ValueError("UNSTABLE_OBSERVATION_REFUSED")
    if kind == "timeout":
        payload = None
    return {
        "kind": kind,
        "payload": payload,
        "exception_class": exception_class,
        "duration_ms": None,
    }


def normalize_protocol_packet(packet):
    """Convert an already validated child packet into a comparable observation.

    Refusal statuses deliberately return ``None``.  They are execution evidence,
    not observations, and therefore must never reach the equality engine.
    """
    from breakcheck.adapters.python import protocol

    protocol.validate_packet(packet)
    status = packet["status"]
    if status == protocol.VALUE:
        return {
            "kind": "value",
            "payload": packet["payload"],
            "exception_class": None,
            "duration_ms": None,
        }
    if status == protocol.EXCEPTION:
        return {
            "kind": "exception",
            "payload": packet["payload"],
            "exception_class": packet["exception_class"],
            "duration_ms": None,
        }
    return None


def observation_identity(value):
    """Return deterministic bytes for same-environment repeat comparison."""
    if value is None:
        return b"null"
    return canonical_json(value).encode("utf-8")


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
