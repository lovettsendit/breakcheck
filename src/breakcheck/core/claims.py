"""Closed behavior-preservation claims and deterministic adjudication."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import json
import math
import re
from collections.abc import Iterable, Mapping


__all__ = (
    "BehaviorClaim",
    "ClaimRefusal",
    "adjudicate_claim",
    "claim_exit_code",
    "parse_claim",
)


_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SYMBOL = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)
_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/]", re.ASCII)
_FINDING_FIELDS = frozenset(
    ("symbol", "verdict", "reason_code", "projection_scope")
)
_FINDING_VERDICTS = frozenset(
    (
        "IDENTICAL",
        "CHANGED",
        "IDENTICAL_UNDER_PROJECTION",
        "CHANGED_UNDER_PROJECTION",
        "NOT_EXERCISED",
    )
)
_DISPOSITIONS = frozenset(
    (
        "CLAIM_VERIFIED",
        "CLAIM_REFUTED",
        "CLAIM_UNVERIFIABLE",
        "CLAIM_OUT_OF_SCOPE",
    )
)


class ClaimRefusal(ValueError):
    """A claim cannot be parsed or adjudicated without guessing."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class BehaviorClaim:
    schema_version: int
    claim: str
    base_revision: str
    targets: tuple[str, ...]


def _refuse(code: str) -> None:
    raise ClaimRefusal(code)


def _revision(value: object, code: str) -> str:
    if type(value) is not str or not _REVISION.fullmatch(value):
        _refuse(code)
    return value


def _symbol(value: object, code: str) -> str:
    if type(value) is not str or not _SYMBOL.fullmatch(value):
        _refuse(code)
    return value


def _quoted(raw: str) -> str:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        _refuse("CLAIM_SYNTAX_REFUSED")
    if type(value) is not str or "\x00" in value:
        _refuse("CLAIM_SYNTAX_REFUSED")
    return value


def parse_claim(source: str) -> BehaviorClaim:
    """Parse the intentionally small, dependency-free claim TOML subset."""

    if type(source) is not str or len(source.encode("utf-8")) > 65_536:
        _refuse("CLAIM_SYNTAX_REFUSED")
    top: dict[str, object] = {}
    targets: list[dict[str, object]] = []
    current: dict[str, object] = top
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[target]]":
            current = {}
            targets.append(current)
            continue
        if line.startswith("[") or "=" not in line:
            _refuse("CLAIM_SYNTAX_REFUSED")
        name, raw_value = line.split("=", 1)
        name = name.strip()
        raw_value = raw_value.strip()
        allowed = (
            frozenset(("schema_version", "claim", "base_revision"))
            if current is top
            else frozenset(("symbol",))
        )
        if name not in allowed or name in current:
            _refuse("CLAIM_SCHEMA_REFUSED")
        if name == "schema_version":
            if raw_value != "1":
                _refuse("CLAIM_SCHEMA_VERSION_REFUSED")
            current[name] = 1
        else:
            current[name] = _quoted(raw_value)
    if set(top) != {"schema_version", "claim", "base_revision"}:
        _refuse("CLAIM_SCHEMA_REFUSED")
    if top["schema_version"] != 1:
        _refuse("CLAIM_SCHEMA_VERSION_REFUSED")
    if top["claim"] != "behavior_preserved":
        _refuse("CLAIM_TYPE_REFUSED")
    base_revision = _revision(top["base_revision"], "CLAIM_REVISION_REFUSED")
    if not targets:
        _refuse("CLAIM_VACUOUS_REFUSED")
    symbols = []
    for target in targets:
        if set(target) != {"symbol"}:
            _refuse("CLAIM_SCHEMA_REFUSED")
        symbols.append(_symbol(target["symbol"], "CLAIM_TARGET_REFUSED"))
    if len(set(symbols)) != len(symbols):
        _refuse("CLAIM_DUPLICATE_TARGET_REFUSED")
    return BehaviorClaim(
        schema_version=1,
        claim="behavior_preserved",
        base_revision=base_revision,
        targets=tuple(sorted(symbols)),
    )


def _plain_json(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _refuse("CLAIM_INVOCATION_REFUSED")
        return value
    if type(value) is list:
        return [_plain_json(item) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or key in result:
                _refuse("CLAIM_INVOCATION_REFUSED")
            result[key] = _plain_json(item)
        return result
    _refuse("CLAIM_INVOCATION_REFUSED")


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


def _invocation(value: object) -> dict[str, object]:
    plain = _plain_json(value)
    if not isinstance(plain, dict):
        _refuse("CLAIM_INVOCATION_REFUSED")
    if _contains_absolute_path(plain):
        _refuse("CLAIM_PATH_REFUSED")
    return plain


def _changed_targets(values: object) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, Mapping)):
        _refuse("CLAIM_CHANGED_TARGETS_REFUSED")
    try:
        symbols = [_symbol(value, "CLAIM_CHANGED_TARGETS_REFUSED") for value in values]  # type: ignore[union-attr]
    except TypeError:
        _refuse("CLAIM_CHANGED_TARGETS_REFUSED")
    if not symbols:
        _refuse("CLAIM_NO_CHANGED_TARGETS")
    if len(set(symbols)) != len(symbols):
        _refuse("CLAIM_CHANGED_TARGETS_REFUSED")
    return tuple(sorted(symbols))


def _findings(values: object, changed: frozenset[str]) -> dict[str, dict[str, object]]:
    if isinstance(values, (str, bytes, Mapping)):
        _refuse("CLAIM_FINDING_REFUSED")
    result: dict[str, dict[str, object]] = {}
    try:
        rows = list(values)  # type: ignore[arg-type]
    except TypeError:
        _refuse("CLAIM_FINDING_REFUSED")
    for value in rows:
        if not isinstance(value, Mapping) or set(value) != _FINDING_FIELDS:
            _refuse("CLAIM_FINDING_REFUSED")
        symbol = _symbol(value["symbol"], "CLAIM_FINDING_REFUSED")
        verdict = value["verdict"]
        reason_code = value["reason_code"]
        projection_scope = value["projection_scope"]
        if (
            symbol in result
            or symbol not in changed
            or verdict not in _FINDING_VERDICTS
            or (reason_code is not None and (type(reason_code) is not str or not reason_code))
            or (
                projection_scope is not None
                and (type(projection_scope) is not str or not projection_scope)
            )
        ):
            _refuse("CLAIM_FINDING_REFUSED")
        projected = verdict in (
            "IDENTICAL_UNDER_PROJECTION",
            "CHANGED_UNDER_PROJECTION",
        )
        if projected != (projection_scope is not None):
            _refuse("CLAIM_FINDING_REFUSED")
        if verdict == "NOT_EXERCISED" and reason_code is None:
            _refuse("CLAIM_FINDING_REFUSED")
        if verdict != "NOT_EXERCISED" and reason_code is not None:
            _refuse("CLAIM_FINDING_REFUSED")
        result[symbol] = {
            "symbol": symbol,
            "verdict": verdict,
            "reason_code": reason_code,
            "projection_scope": projection_scope,
        }
    return result


def _separation_reason(
    *,
    source: str,
    fixture_revision: str,
    base_revision: str,
    authored_by: str,
    predates: bool,
    strict: bool,
) -> str | None:
    if source not in ("base", "head", "explicit"):
        _refuse("FIXTURE_SOURCE_REFUSED")
    if authored_by not in ("human", "agent", "unknown"):
        _refuse("FIXTURE_AUTHOR_REFUSED")
    if type(predates) is not bool or type(strict) is not bool:
        _refuse("FIXTURE_SEPARATION_REFUSED")
    _revision(fixture_revision, "FIXTURE_SOURCE_REVISION_REFUSED")
    if not strict:
        return None
    if source == "head":
        return "FIXTURE_AUTHORED_AGAINST_HEAD"
    if authored_by == "unknown":
        return "FIXTURE_AUTHOR_UNKNOWN"
    if source == "base" and fixture_revision != base_revision:
        return "FIXTURE_SOURCE_REVISION_MISMATCH"
    if not predates:
        return "FIXTURE_POSTDATES_CHANGE"
    return None


def _disposition(
    symbol: str,
    disposition: str,
    reason_code: str | None,
    *,
    projection_scope: str | None = None,
) -> dict[str, object]:
    if disposition not in _DISPOSITIONS:
        _refuse("CLAIM_DISPOSITION_REFUSED")
    scope = "UNDER_PROJECTION" if projection_scope is not None else (
        "FULL_OBSERVATION" if disposition in ("CLAIM_VERIFIED", "CLAIM_REFUTED") else "NONE"
    )
    return {
        "symbol": symbol,
        "disposition": disposition,
        "reason_code": reason_code,
        "verification_scope": scope,
        "projection_scope": projection_scope,
    }


def adjudicate_claim(
    claim: BehaviorClaim,
    *,
    head_revision: str,
    changed_targets: Iterable[str],
    findings: Iterable[Mapping[str, object]],
    fixture_source: str = "base",
    fixture_revision: str,
    fixture_authored_by: str,
    fixtures_predate_change: bool,
    strict_separation: bool = True,
    invocation: Mapping[str, object],
) -> dict[str, object]:
    """Adjudicate an independently supplied changed-target census."""

    if not isinstance(claim, BehaviorClaim):
        _refuse("CLAIM_SCHEMA_REFUSED")
    if (
        claim.schema_version != 1
        or claim.claim != "behavior_preserved"
        or not claim.targets
    ):
        _refuse("CLAIM_SCHEMA_REFUSED")
    validated_claim_targets = tuple(
        sorted(_symbol(symbol, "CLAIM_SCHEMA_REFUSED") for symbol in claim.targets)
    )
    if (
        validated_claim_targets != claim.targets
        or len(set(validated_claim_targets)) != len(validated_claim_targets)
    ):
        _refuse("CLAIM_SCHEMA_REFUSED")
    base_revision = _revision(claim.base_revision, "CLAIM_REVISION_REFUSED")
    head = _revision(head_revision, "CLAIM_REVISION_REFUSED")
    if head == base_revision:
        _refuse("IDENTICAL_REVISIONS_REFUSED")
    changed = _changed_targets(changed_targets)
    changed_set = frozenset(changed)
    by_symbol = _findings(findings, changed_set)
    separation_reason = _separation_reason(
        source=fixture_source,
        fixture_revision=fixture_revision,
        base_revision=base_revision,
        authored_by=fixture_authored_by,
        predates=fixtures_predate_change,
        strict=strict_separation,
    )
    claimed = frozenset(validated_claim_targets)
    dispositions: list[dict[str, object]] = []
    for symbol in changed:
        if symbol not in claimed:
            dispositions.append(
                _disposition(
                    symbol,
                    "CLAIM_OUT_OF_SCOPE",
                    "CLAIM_TARGET_OMITTED",
                )
            )
            continue
        finding = by_symbol.get(symbol)
        if finding is None:
            dispositions.append(
                _disposition(
                    symbol,
                    "CLAIM_UNVERIFIABLE",
                    "MISSING_REVISION_FINDING",
                )
            )
            continue
        verdict = finding["verdict"]
        projection_scope = finding["projection_scope"]
        if verdict in ("CHANGED", "CHANGED_UNDER_PROJECTION"):
            dispositions.append(
                _disposition(
                    symbol,
                    "CLAIM_REFUTED",
                    None,
                    projection_scope=projection_scope,  # type: ignore[arg-type]
                )
            )
        elif verdict == "NOT_EXERCISED":
            dispositions.append(
                _disposition(
                    symbol,
                    "CLAIM_UNVERIFIABLE",
                    str(finding["reason_code"]),
                )
            )
        elif separation_reason is not None:
            dispositions.append(
                _disposition(
                    symbol,
                    "CLAIM_UNVERIFIABLE",
                    separation_reason,
                )
            )
        else:
            dispositions.append(
                _disposition(
                    symbol,
                    "CLAIM_VERIFIED",
                    None,
                    projection_scope=projection_scope,  # type: ignore[arg-type]
                )
            )
    for symbol in sorted(claimed - changed_set):
        dispositions.append(
            _disposition(
                symbol,
                "CLAIM_UNVERIFIABLE",
                "CLAIM_TARGET_UNCHANGED_OR_UNMAPPED",
            )
        )
    dispositions.sort(key=lambda row: str(row["symbol"]))
    summary = {
        "verified": sum(row["disposition"] == "CLAIM_VERIFIED" for row in dispositions),
        "refuted": sum(row["disposition"] == "CLAIM_REFUTED" for row in dispositions),
        "unverifiable": sum(
            row["disposition"] == "CLAIM_UNVERIFIABLE" for row in dispositions
        ),
        "out_of_scope": sum(
            row["disposition"] == "CLAIM_OUT_OF_SCOPE" for row in dispositions
        ),
        "total": len(dispositions),
    }
    return {
        "claim": claim.claim,
        "base_revision": base_revision,
        "head_revision": head,
        "dispositions": copy.deepcopy(dispositions),
        "summary": summary,
        "fixtures_predate_change": fixtures_predate_change,
        "invocation": _invocation(invocation),
    }


def claim_exit_code(report: Mapping[str, object]) -> int:
    """Return the fixed public exit precedence for a claim report."""

    if not isinstance(report, Mapping):
        _refuse("CLAIM_DISPOSITION_REFUSED")
    values = report.get("dispositions")
    if isinstance(values, (str, bytes, Mapping)):
        _refuse("CLAIM_DISPOSITION_REFUSED")
    try:
        rows = list(values)  # type: ignore[arg-type]
    except TypeError:
        _refuse("CLAIM_DISPOSITION_REFUSED")
    if not rows:
        _refuse("CLAIM_VACUOUS_REFUSED")
    dispositions = []
    for row in rows:
        if not isinstance(row, Mapping) or row.get("disposition") not in _DISPOSITIONS:
            _refuse("CLAIM_DISPOSITION_REFUSED")
        dispositions.append(row["disposition"])
    invocation = report.get("invocation", {})
    if isinstance(invocation, Mapping):
        strict = invocation.get("strict", True)
    elif isinstance(invocation, list):
        try:
            strict = {
                row["name"]: row["value"]
                for row in invocation
                if isinstance(row, Mapping)
            }.get("strict", True)
        except (KeyError, TypeError):
            _refuse("CLAIM_DISPOSITION_REFUSED")
    else:
        _refuse("CLAIM_DISPOSITION_REFUSED")
    if type(strict) is not bool:
        _refuse("CLAIM_DISPOSITION_REFUSED")
    if "CLAIM_OUT_OF_SCOPE" in dispositions:
        return 3
    if strict and "CLAIM_UNVERIFIABLE" in dispositions:
        return 2
    if "CLAIM_REFUTED" in dispositions:
        return 1
    permitted = {"CLAIM_VERIFIED"}
    if not strict:
        permitted.add("CLAIM_UNVERIFIABLE")
    if set(dispositions) <= permitted:
        return 0
    _refuse("CLAIM_DISPOSITION_REFUSED")
