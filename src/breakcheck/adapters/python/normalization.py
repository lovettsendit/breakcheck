from __future__ import annotations

import json
import math
from collections.abc import Mapping


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
        return value.hex()
    if isinstance(value, BaseException):
        return {
            "exception_class": value.__class__.__name__,
            "args": [_normalized(item) for item in value.args],
        }
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("UNSTABLE_OBSERVATION_REFUSED")
        items = sorted(value.items(), key=lambda item: item[0])
        return {key: _normalized(item) for key, item in items}
    if isinstance(value, (list, tuple)):
        return [_normalized(item) for item in value]
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
        return items
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


def canonical_json(value):
    return json.dumps(
        _normalized(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
