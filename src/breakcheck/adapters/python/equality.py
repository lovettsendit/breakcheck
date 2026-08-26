from __future__ import annotations

import math
from collections.abc import Mapping


class PythonEqualityRules:
    def __init__(self, rtol=1e-09, atol=0):
        self.rtol = float(rtol)
        self.atol = float(atol)


def float_eq(left, right, rules=None):
    rules = rules if rules is not None else PythonEqualityRules()
    if math.isnan(left) and math.isnan(right):
        return True
    if math.isnan(left) or math.isnan(right):
        return False
    if math.isinf(left) or math.isinf(right):
        return left == right
    distance = abs(left - right)
    limit = rules.atol + rules.rtol * max(abs(left), abs(right))
    return distance <= limit


_FLOAT_POLICY = 'rtol=1e-9;atol=0.0;nan_equal=true;inf_exact=true'
_REASONS = {
    "EQUAL", "KIND_MISMATCH", "EXCEPTION_CLASS", "VALUE_MISMATCH",
    "FLOAT_MISMATCH", "MISSING_KEY", "LENGTH_MISMATCH",
}


def _field(value, name):
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _summary(value):
    if value is None:
        return "NoneType:None"
    if type(value) is bool:
        return "bool:" + ("true" if value else "false")
    if type(value) is int:
        return "int:" + str(value)
    if type(value) is float:
        return "float:" + repr(value)
    if type(value) is str:
        return "str:" + value
    if isinstance(value, bytes):
        return "bytes:" + value.hex()
    if isinstance(value, Mapping):
        return "mapping:" + str(_stable_key(value))[:180]
    if isinstance(value, (list, tuple)):
        return "sequence:" + str(_stable_key(value))[:180]
    if isinstance(value, (set, frozenset)):
        return "set:" + str(_stable_key(value))[:180]
    raise ValueError("UNSTABLE_COMPARISON_REFUSED")


def _stable_key(value):
    if value is None:
        return ("none",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is float:
        if math.isnan(value):
            return ("float", "nan")
        if math.isinf(value):
            return ("float", "-inf" if value < 0 else "inf")
        return ("float", repr(value))
    if type(value) is str:
        return ("str", value)
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("UNSTABLE_COMPARISON_REFUSED")
        return ("mapping", tuple(
            (key, _stable_key(value[key])) for key in sorted(value)
        ))
    if isinstance(value, (list, tuple)):
        return ("sequence", tuple(_stable_key(item) for item in value))
    if isinstance(value, (set, frozenset)):
        return ("set", tuple(sorted(_stable_key(item) for item in value)))
    raise ValueError("UNSTABLE_COMPARISON_REFUSED")


def _observation_summary(value):
    kind = _field(value, "kind")
    if kind == "exception":
        return "exception:" + str(_field(value, "exception_class"))
    if kind == "timeout":
        return "timeout"
    return "value:" + _summary(_field(value, "payload"))


def _result(verdict, reason, path, old_summary, new_summary, policy):
    return {
        "verdict": verdict,
        "detail": {
            "reason_code": reason,
            "path": path,
            "old_summary": old_summary,
            "new_summary": new_summary,
            "policy": policy,
        },
    }


def _kind(value):
    if type(value) is bool:
        return "bool"
    if type(value) is int:
        return "int"
    if type(value) is float:
        return "float"
    if isinstance(value, Mapping):
        return "mapping"
    if isinstance(value, (list, tuple)):
        return "sequence"
    if isinstance(value, (set, frozenset)):
        return "set"
    return value.__class__.__name__


def _pointer(base, segment):
    text = str(segment).replace("~", "~0").replace("/", "~1")
    return base + "/" + text if base else "/" + text


def _compare_values(left, right, path, rules):
    left_kind = _kind(left)
    right_kind = _kind(right)
    if left_kind != right_kind:
        return False, "KIND_MISMATCH", path, left, right, "strict_json_type_before_numeric_value"
    if left_kind == "float":
        equal = float_eq(left, right, rules)
        return equal, "EQUAL" if equal else "FLOAT_MISMATCH", path, left, right, _FLOAT_POLICY
    if left_kind in {"bool", "int", "str", "bytes", "NoneType"}:
        equal = left == right
        return equal, "EQUAL" if equal else "VALUE_MISMATCH", path, left, right, "canonical_json_strict"
    if left_kind == "mapping":
        left_keys = set(left)
        right_keys = set(right)
        for key in sorted(left_keys | right_keys):
            child = _pointer(path, key)
            if key not in left_keys:
                return False, "MISSING_KEY", child, None, right[key], "mapping_key_set_exact"
            if key not in right_keys:
                return False, "MISSING_KEY", child, left[key], None, "mapping_key_set_exact"
            equal, reason, mismatch, old, new, policy = _compare_values(left[key], right[key], child, rules)
            if not equal:
                return False, reason, mismatch, old, new, policy
        return True, "EQUAL", path, left, right, "unordered_mapping_keyed"
    if left_kind == "sequence":
        if len(left) != len(right):
            return False, "LENGTH_MISMATCH", path, left, right, "sequence_length_exact"
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            child = _pointer(path, index)
            equal, reason, mismatch, old, new, policy = _compare_values(left_item, right_item, child, rules)
            if not equal:
                return False, reason, mismatch, old, new, "sequence_order_significant"
        return True, "EQUAL", path, left, right, "sequence_order_significant"
    if left_kind == "set":
        left_values = sorted(_stable_key(item) for item in left)
        right_values = sorted(_stable_key(item) for item in right)
        equal = left_values == right_values
        return equal, "EQUAL" if equal else "VALUE_MISMATCH", path, left, right, "unordered_set_canonical"
    equal = left == right
    return equal, "EQUAL" if equal else "VALUE_MISMATCH", path, left, right, "canonical_json_strict"


def _compare_observations(left, right, rules):
    _stable_key(_field(left, "payload"))
    _stable_key(_field(right, "payload"))
    left_kind = _field(left, "kind")
    right_kind = _field(right, "kind")
    if left_kind != right_kind:
        return _result(
            "CHANGED", "KIND_MISMATCH", None,
            _observation_summary(left), _observation_summary(right),
            "observation_kind_exact",
        )
    left_exception = _field(left, "exception_class")
    right_exception = _field(right, "exception_class")
    if left_exception != right_exception:
        return _result(
            "CHANGED", "EXCEPTION_CLASS", "/exception_class",
            "exception:" + str(left_exception), "exception:" + str(right_exception),
            "exception_class_exact",
        )
    equal, reason, path, old, new, policy = _compare_values(
        _field(left, "payload"), _field(right, "payload"), "", rules
    )
    if equal:
        return _result(
            "IDENTICAL", "EQUAL", None,
            _observation_summary(left), _observation_summary(right), policy,
        )
    return _result("CHANGED", reason, path, _summary(old), _summary(new), policy)


def compare_observations(left, right):
    return _compare_observations(left, right, PythonEqualityRules())


PythonEqualityRules.compare = lambda self, left, right: _compare_observations(left, right, self)


JSON_POINTER = "JSON Pointer"
