"""Closed, deterministic domain records for revision behavior comparisons."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping


__all__ = (
    "BaselineRefusal",
    "compare_frozen_baseline",
    "detect_fixture_revision_after_failure",
    "freeze_baseline",
    "validate_baseline",
)


_BASELINE_FIELDS = frozenset(
    (
        "revision",
        "tree_sha256",
        "dirty",
        "allow_dirty",
        "environment",
        "fixture",
        "target_observations",
        "invocation",
    )
)
_ENVIRONMENT_FIELDS = frozenset(("implementation", "python_version", "platform"))
_FIXTURE_FIELDS = frozenset(
    ("sha256", "source_revision", "source", "authored_by")
)
_TARGET_FIELDS = frozenset(
    (
        "symbol",
        "target_sha256",
        "signature_sha256",
        "fixture_binding_sha256",
        "provenance",
        "projection",
        "outcome",
    )
)
_REVISION_FINDING_FIELDS = frozenset(
    (
        "symbol",
        "verdict",
        "reason_code",
        "base_observation",
        "head_observation",
        "base_target_sha256",
        "head_target_sha256",
        "signature_sha256",
        "fixture_binding_sha256",
        "provenance",
        "projection_scope",
    )
)
_OUTCOME_FIELDS = frozenset(
    ("status", "observation", "reason_code", "repeatable")
)
_OBSERVATION_FIELDS = frozenset(
    ("kind", "payload", "exception_class", "duration_ms")
)
_EXERCISED_STATUSES = frozenset(("VALUE", "EXCEPTION"))
_REFUSAL_STATUSES = frozenset(
    (
        "UNNORMALIZABLE",
        "NETWORK_REFUSED",
        "TIMEOUT",
        "OUTPUT_LIMIT_REFUSED",
        "PROTOCOL_REFUSED",
    )
)
_PROVENANCE = frozenset(
    (
        "SOURCE_LITERAL",
        "SOURCE_FOLDED",
        "SOURCE_MODULE_CONSTANT",
        "SOURCE_NESTED_CALL",
        "OPERATOR_FIXTURE",
        "RUNTIME_CAPTURE",
    )
)
_FIXTURE_SOURCES = frozenset(("base", "head", "explicit"))
_FIXTURE_AUTHORS = frozenset(("human", "agent", "unknown"))
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SYMBOL = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)
_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/]", re.ASCII)


class BaselineRefusal(ValueError):
    """A baseline or revision comparison failed a closed domain check."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _refuse(code: str) -> None:
    raise BaselineRefusal(code)


def _plain_json(value: object, *, refusal: str) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _refuse(refusal)
        return value
    if type(value) is list:
        return [_plain_json(item, refusal=refusal) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or key in result:
                _refuse(refusal)
            result[key] = _plain_json(item, refusal=refusal)
        return result
    _refuse(refusal)


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _closed(value: object, fields: frozenset[str], code: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _refuse(code)
    return dict(value)


def _revision(value: object, code: str) -> str:
    if type(value) is not str or not _REVISION.fullmatch(value):
        _refuse(code)
    return value


def _sha256(value: object, code: str) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        _refuse(code)
    return value


def _symbol(value: object, code: str) -> str:
    if type(value) is not str or not _SYMBOL.fullmatch(value):
        _refuse(code)
    return value


def _contains_absolute_path(value: object) -> bool:
    if type(value) is str:
        return value.startswith(("/", "\\\\")) or bool(
            _WINDOWS_ABSOLUTE.match(value)
        )
    if type(value) is list:
        return any(_contains_absolute_path(item) for item in value)
    if isinstance(value, Mapping):
        return any(
            _contains_absolute_path(key) or _contains_absolute_path(item)
            for key, item in value.items()
        )
    return False


def _invocation(value: object, code: str) -> dict[str, object]:
    plain = _plain_json(value, refusal=code)
    if not isinstance(plain, dict):
        _refuse(code)
    if _contains_absolute_path(plain):
        _refuse("BASELINE_PATH_REFUSED")
    return plain


def _environment(value: object) -> dict[str, str]:
    data = _closed(value, _ENVIRONMENT_FIELDS, "BASELINE_ENVIRONMENT_REFUSED")
    result: dict[str, str] = {}
    for field in sorted(_ENVIRONMENT_FIELDS):
        item = data[field]
        if type(item) is not str or not item or len(item.encode("utf-8")) > 256:
            _refuse("BASELINE_ENVIRONMENT_REFUSED")
        result[field] = item
    if _contains_absolute_path(result):
        _refuse("BASELINE_PATH_REFUSED")
    return result


def _fixture(value: object) -> dict[str, str]:
    data = _closed(value, _FIXTURE_FIELDS, "BASELINE_FIXTURE_REFUSED")
    sha256 = _sha256(data["sha256"], "BASELINE_FIXTURE_REFUSED")
    source_revision = _revision(
        data["source_revision"], "BASELINE_FIXTURE_REFUSED"
    )
    source = data["source"]
    authored_by = data["authored_by"]
    if source not in _FIXTURE_SOURCES or authored_by not in _FIXTURE_AUTHORS:
        _refuse("BASELINE_FIXTURE_REFUSED")
    return {
        "sha256": sha256,
        "source_revision": source_revision,
        "source": str(source),
        "authored_by": str(authored_by),
    }


def _observation(value: object) -> dict[str, object]:
    data = _closed(value, _OBSERVATION_FIELDS, "BASELINE_OBSERVATION_REFUSED")
    kind = data["kind"]
    exception_class = data["exception_class"]
    duration_ms = data["duration_ms"]
    if kind not in ("value", "exception") or duration_ms is not None:
        _refuse("BASELINE_OBSERVATION_REFUSED")
    if kind == "value" and exception_class is not None:
        _refuse("BASELINE_OBSERVATION_REFUSED")
    if kind == "exception" and (
        type(exception_class) is not str or not exception_class
    ):
        _refuse("BASELINE_OBSERVATION_REFUSED")
    payload = _plain_json(data["payload"], refusal="BASELINE_OBSERVATION_REFUSED")
    return {
        "kind": kind,
        "payload": payload,
        "exception_class": exception_class,
        "duration_ms": None,
    }


def _outcome(value: object, *, baseline: bool) -> dict[str, object]:
    data = _closed(value, _OUTCOME_FIELDS, "BASELINE_OBSERVATION_REFUSED")
    status = data["status"]
    repeatable = data["repeatable"]
    reason_code = data["reason_code"]
    if status not in _EXERCISED_STATUSES | _REFUSAL_STATUSES or type(repeatable) is not bool:
        _refuse("BASELINE_OBSERVATION_REFUSED")
    if status in _EXERCISED_STATUSES:
        if not repeatable or reason_code is not None or data["observation"] is None:
            _refuse("BASELINE_OBSERVATION_REFUSED")
        observation = _observation(data["observation"])
        expected_kind = "value" if status == "VALUE" else "exception"
        if observation["kind"] != expected_kind:
            _refuse("BASELINE_OBSERVATION_REFUSED")
    else:
        if baseline or data["observation"] is not None:
            _refuse("BASELINE_OBSERVATION_REFUSED")
        if type(reason_code) is not str or not reason_code:
            _refuse("BASELINE_OBSERVATION_REFUSED")
        observation = None
    return {
        "status": status,
        "observation": observation,
        "reason_code": reason_code,
        "repeatable": repeatable,
    }


def _target(value: object, *, baseline: bool) -> dict[str, object]:
    data = _closed(value, _TARGET_FIELDS, "BASELINE_TARGET_REFUSED")
    symbol = _symbol(data["symbol"], "BASELINE_TARGET_REFUSED")
    target_sha256 = _sha256(data["target_sha256"], "BASELINE_TARGET_REFUSED")
    signature_sha256 = _sha256(
        data["signature_sha256"], "BASELINE_TARGET_REFUSED"
    )
    fixture_binding_sha256 = _sha256(
        data["fixture_binding_sha256"], "BASELINE_TARGET_REFUSED"
    )
    provenance = data["provenance"]
    projection = data["projection"]
    if provenance not in _PROVENANCE:
        _refuse("BASELINE_TARGET_REFUSED")
    if projection is not None and (type(projection) is not str or not projection):
        _refuse("BASELINE_TARGET_REFUSED")
    if _contains_absolute_path(projection):
        _refuse("BASELINE_PATH_REFUSED")
    return {
        "symbol": symbol,
        "target_sha256": target_sha256,
        "signature_sha256": signature_sha256,
        "fixture_binding_sha256": fixture_binding_sha256,
        "provenance": provenance,
        "projection": projection,
        "outcome": _outcome(data["outcome"], baseline=baseline),
    }


def _targets(values: object, *, baseline: bool, allow_empty: bool) -> list[dict[str, object]]:
    if isinstance(values, (str, bytes, Mapping)):
        _refuse("BASELINE_TARGET_REFUSED")
    try:
        rows = [_target(value, baseline=baseline) for value in values]  # type: ignore[union-attr]
    except TypeError:
        _refuse("BASELINE_TARGET_REFUSED")
    if not rows and not allow_empty:
        _refuse("VACUOUS_BASELINE_REFUSED" if baseline else "VACUOUS_REVISION_COMPARISON_REFUSED")
    rows.sort(key=lambda row: str(row["symbol"]))
    symbols = [row["symbol"] for row in rows]
    if len(set(symbols)) != len(symbols):
        _refuse("BASELINE_DUPLICATE_TARGET_REFUSED")
    return rows


def freeze_baseline(
    *,
    revision: str,
    tree_sha256: str,
    dirty: bool,
    allow_dirty: bool,
    environment: Mapping[str, object],
    fixture: Mapping[str, object],
    target_observations: Iterable[Mapping[str, object]],
    invocation: Mapping[str, object],
) -> dict[str, object]:
    """Create an immutable baseline payload from already repeated observations."""

    if type(dirty) is not bool or type(allow_dirty) is not bool:
        _refuse("DIRTY_TREE_REFUSED")
    if dirty and not allow_dirty:
        _refuse("DIRTY_TREE_REFUSED")
    payload = {
        "revision": _revision(revision, "BASELINE_REVISION_REFUSED"),
        "tree_sha256": _sha256(tree_sha256, "BASELINE_TREE_REFUSED"),
        "dirty": dirty,
        "allow_dirty": allow_dirty,
        "environment": _environment(environment),
        "fixture": _fixture(fixture),
        "target_observations": _targets(
            target_observations, baseline=True, allow_empty=False
        ),
        "invocation": _invocation(invocation, "BASELINE_INVOCATION_REFUSED"),
    }
    if bool(payload["invocation"].get("allow_dirty", allow_dirty)) != allow_dirty:
        _refuse("BASELINE_INVOCATION_REFUSED")
    return validate_baseline(payload)


def validate_baseline(value: object) -> dict[str, object]:
    """Validate and detach a baseline payload from caller-owned input objects."""

    data = _closed(value, _BASELINE_FIELDS, "BASELINE_SCHEMA_REFUSED")
    dirty = data["dirty"]
    allow_dirty = data["allow_dirty"]
    if type(dirty) is not bool or type(allow_dirty) is not bool or (dirty and not allow_dirty):
        _refuse("DIRTY_TREE_REFUSED")
    result = {
        "revision": _revision(data["revision"], "BASELINE_REVISION_REFUSED"),
        "tree_sha256": _sha256(data["tree_sha256"], "BASELINE_TREE_REFUSED"),
        "dirty": dirty,
        "allow_dirty": allow_dirty,
        "environment": _environment(data["environment"]),
        "fixture": _fixture(data["fixture"]),
        "target_observations": _targets(
            data["target_observations"], baseline=True, allow_empty=False
        ),
        "invocation": _invocation(
            data["invocation"], "BASELINE_INVOCATION_REFUSED"
        ),
    }
    return copy.deepcopy(result)


def _comparison_verdict(
    comparator: Callable[[object, object], object] | None,
    old: object,
    new: object,
) -> str:
    if comparator is None:
        return "IDENTICAL" if _canonical(old) == _canonical(new) else "CHANGED"
    result = comparator(copy.deepcopy(old), copy.deepcopy(new))
    if type(result) is str:
        verdict = result
    elif isinstance(result, Mapping):
        verdict = result.get("verdict")
    else:
        verdict = getattr(result, "verdict", None)
    if verdict not in ("IDENTICAL", "CHANGED"):
        _refuse("REVISION_COMPARATOR_REFUSED")
    return str(verdict)


def _finding(
    *,
    symbol: str,
    verdict: str,
    reason_code: str | None,
    base: Mapping[str, object] | None,
    head: Mapping[str, object] | None,
) -> dict[str, object]:
    projection = None
    source = base if base is not None else head
    if source is not None:
        projection = source["projection"]
    return {
        "symbol": symbol,
        "verdict": verdict,
        "reason_code": reason_code,
        "base_observation": (
            None if base is None else copy.deepcopy(base["outcome"]["observation"])  # type: ignore[index]
        ),
        "head_observation": (
            None if head is None else copy.deepcopy(head["outcome"]["observation"])  # type: ignore[index]
        ),
        "base_target_sha256": None if base is None else base["target_sha256"],
        "head_target_sha256": None if head is None else head["target_sha256"],
        "signature_sha256": None if base is None else base["signature_sha256"],
        "fixture_binding_sha256": (
            None if base is None else base["fixture_binding_sha256"]
        ),
        "provenance": None if source is None else source["provenance"],
        "projection_scope": projection,
    }


def compare_frozen_baseline(
    baseline: Mapping[str, object] | None,
    *,
    head_revision: str,
    head_tree_sha256: str,
    environment: Mapping[str, object],
    fixture: Mapping[str, object],
    target_observations: Iterable[Mapping[str, object]],
    fixtures_predate_change: bool,
    invocation: Mapping[str, object],
    comparator: Callable[[object, object], object] | None = None,
) -> dict[str, object]:
    """Compare a validated frozen side with repeated head observations."""

    if baseline is None:
        _refuse("NO_BASELINE_REVISION")
    frozen = validate_baseline(baseline)
    head_revision_value = _revision(head_revision, "HEAD_REVISION_REFUSED")
    head_tree = _sha256(head_tree_sha256, "HEAD_TREE_REFUSED")
    if (
        head_revision_value == frozen["revision"]
        or head_tree == frozen["tree_sha256"]
    ):
        _refuse("IDENTICAL_REVISIONS_REFUSED")
    head_environment = _environment(environment)
    if head_environment != frozen["environment"]:
        _refuse("BASELINE_ENVIRONMENT_MISMATCH")
    head_fixture = _fixture(fixture)
    if head_fixture != frozen["fixture"]:
        _refuse("BASELINE_FIXTURE_MISMATCH")
    if type(fixtures_predate_change) is not bool:
        _refuse("BASELINE_FIXTURE_REFUSED")
    head_rows = _targets(target_observations, baseline=False, allow_empty=False)
    base_by_symbol = {
        str(row["symbol"]): row for row in frozen["target_observations"]  # type: ignore[union-attr]
    }
    head_by_symbol = {str(row["symbol"]): row for row in head_rows}
    findings: list[dict[str, object]] = []
    for symbol in sorted(set(base_by_symbol) | set(head_by_symbol)):
        base_row = base_by_symbol.get(symbol)
        head_row = head_by_symbol.get(symbol)
        if base_row is None:
            findings.append(
                _finding(
                    symbol=symbol,
                    verdict="NOT_EXERCISED",
                    reason_code="NO_BASELINE_REVISION",
                    base=None,
                    head=head_row,
                )
            )
            continue
        if head_row is None:
            findings.append(
                _finding(
                    symbol=symbol,
                    verdict="NOT_EXERCISED",
                    reason_code="SYMBOL_REMOVED",
                    base=base_row,
                    head=None,
                )
            )
            continue
        if base_row["signature_sha256"] != head_row["signature_sha256"]:
            findings.append(
                _finding(
                    symbol=symbol,
                    verdict="NOT_EXERCISED",
                    reason_code="FIXTURE_SIGNATURE_DRIFT",
                    base=base_row,
                    head=head_row,
                )
            )
            continue
        if base_row["fixture_binding_sha256"] != head_row["fixture_binding_sha256"]:
            findings.append(
                _finding(
                    symbol=symbol,
                    verdict="NOT_EXERCISED",
                    reason_code="FIXTURE_BINDING_MISMATCH",
                    base=base_row,
                    head=head_row,
                )
            )
            continue
        if base_row["projection"] != head_row["projection"]:
            findings.append(
                _finding(
                    symbol=symbol,
                    verdict="NOT_EXERCISED",
                    reason_code="PROJECTION_SCOPE_MISMATCH",
                    base=base_row,
                    head=head_row,
                )
            )
            continue
        head_outcome = head_row["outcome"]
        if head_outcome["status"] not in _EXERCISED_STATUSES:  # type: ignore[index]
            findings.append(
                _finding(
                    symbol=symbol,
                    verdict="NOT_EXERCISED",
                    reason_code=str(head_outcome["reason_code"]),  # type: ignore[index]
                    base=base_row,
                    head=head_row,
                )
            )
            continue
        verdict = _comparison_verdict(
            comparator,
            base_row["outcome"]["observation"],  # type: ignore[index]
            head_outcome["observation"],  # type: ignore[index]
        )
        if base_row["projection"] is not None:
            verdict += "_UNDER_PROJECTION"
        findings.append(
            _finding(
                symbol=symbol,
                verdict=verdict,
                reason_code=None,
                base=base_row,
                head=head_row,
            )
        )
    counts = {
        "changed": sum(
            row["verdict"] in ("CHANGED", "CHANGED_UNDER_PROJECTION")
            for row in findings
        ),
        "identical": sum(
            row["verdict"] in ("IDENTICAL", "IDENTICAL_UNDER_PROJECTION")
            for row in findings
        ),
        "not_exercised": sum(row["verdict"] == "NOT_EXERCISED" for row in findings),
        "total": len(findings),
    }
    return {
        "base_revision": frozen["revision"],
        "head_revision": head_revision_value,
        "base_tree_sha256": frozen["tree_sha256"],
        "head_tree_sha256": head_tree,
        "findings": findings,
        "summary": counts,
        "fixtures_predate_change": fixtures_predate_change,
        "invocation": _invocation(invocation, "BASELINE_INVOCATION_REFUSED"),
    }


def detect_fixture_revision_after_failure(
    previous: Mapping[str, object], current: Mapping[str, object]
) -> tuple[str, ...]:
    """Return bindings whose changed result became identical after fixture edits."""

    if not isinstance(previous, Mapping) or not isinstance(current, Mapping):
        _refuse("FIXTURE_HISTORY_REFUSED")
    required = frozenset(("base_revision", "fixture_sha256", "findings"))
    if not required.issubset(previous) or not required.issubset(current):
        _refuse("FIXTURE_HISTORY_REFUSED")
    base_previous = _revision(previous["base_revision"], "FIXTURE_HISTORY_REFUSED")
    base_current = _revision(current["base_revision"], "FIXTURE_HISTORY_REFUSED")
    old_fixture = _sha256(previous["fixture_sha256"], "FIXTURE_HISTORY_REFUSED")
    new_fixture = _sha256(current["fixture_sha256"], "FIXTURE_HISTORY_REFUSED")
    if base_previous != base_current or old_fixture == new_fixture:
        return ()

    def verdicts(value: object) -> dict[str, str]:
        if isinstance(value, (str, bytes, Mapping)):
            _refuse("FIXTURE_HISTORY_REFUSED")
        result: dict[str, str] = {}
        try:
            rows = list(value)  # type: ignore[arg-type]
        except TypeError:
            _refuse("FIXTURE_HISTORY_REFUSED")
        for row in rows:
            if not isinstance(row, Mapping) or set(row) not in (
                {"symbol", "verdict"},
                _REVISION_FINDING_FIELDS,
            ):
                _refuse("FIXTURE_HISTORY_REFUSED")
            symbol = _symbol(row["symbol"], "FIXTURE_HISTORY_REFUSED")
            verdict = row["verdict"]
            if verdict not in (
                "IDENTICAL",
                "CHANGED",
                "IDENTICAL_UNDER_PROJECTION",
                "CHANGED_UNDER_PROJECTION",
                "NOT_EXERCISED",
            ) or symbol in result:
                _refuse("FIXTURE_HISTORY_REFUSED")
            result[symbol] = str(verdict)
        return result

    old = verdicts(previous["findings"])
    new = verdicts(current["findings"])
    return tuple(
        symbol
        for symbol in sorted(set(old) & set(new))
        if old[symbol] in ("CHANGED", "CHANGED_UNDER_PROJECTION")
        and new[symbol] in ("IDENTICAL", "IDENTICAL_UNDER_PROJECTION")
    )
