"""Fail-closed orchestration for behavior comparisons across Git revisions."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
from collections.abc import Iterable, Mapping

from .adapters.python.equality import compare_observations
from .adapters.python.executor import run_repeated_typed_snippet_isolated
from .adapters.python.fixtures import (
    FixtureBinding,
    FixtureFile,
    FixtureRefusal,
    load_fixture_file,
    render_fixture_source,
)
from .adapters.python.symbols import (
    SymbolAnalysisRefusal,
    SymbolChange,
    SymbolDefinition,
    compare_symbol_trees,
    inventory_symbols,
    tracked_tree_identity,
)
from .adapters.python.worktrees import WorktreeRefusal, revision_worktrees
from .core.baselines import BaselineRefusal, freeze_baseline
from .core.claims import (
    ClaimRefusal,
    adjudicate_claim,
    claim_exit_code,
    parse_claim,
)
from .revision_report import make_evidence_artifact, make_revision_artifact
from .schema import (
    artifact_digest,
    canonicalize_invocation,
    record_identity,
    validate_artifact,
    verify_artifact,
)


_EXERCISED = frozenset(("VALUE", "EXCEPTION"))
_CHANGED_STATUSES = frozenset(
    (
        "CHANGED",
        "CONTEXT_CHANGED",
        "FIXTURE_SIGNATURE_DRIFT",
        "NO_BASELINE_REVISION",
        "SYMBOL_REMOVED",
        "SYMBOL_AMBIGUOUS",
    )
)


class RevisionModeRefusal(ValueError):
    """A revision command could not produce evidence without guessing."""

    def __init__(self, code: str, *, detail: Mapping[str, object] | None = None):
        self.code = code
        self.detail = None if detail is None else dict(detail)
        super().__init__(code)


@dataclass(frozen=True)
class RevisionCommandResult:
    report: dict[str, object]
    evidence: dict[str, object]
    exit_code: int


@dataclass(frozen=True)
class _Replay:
    status: str
    reason_code: str | None
    observation: dict[str, object] | None
    repeat_sha256: tuple[str, str] | None
    provenance: tuple[str, ...]
    replay_source: str


@dataclass(frozen=True)
class _FixtureContext:
    fixture: FixtureFile
    source_revision: str
    authored_by: str
    source: str
    predates_change: bool
    bindings: Mapping[str, FixtureBinding]


def _refuse(code: str) -> None:
    raise RevisionModeRefusal(code)


def _translate(exc: Exception) -> RevisionModeRefusal:
    code = getattr(exc, "code", None)
    if type(code) is not str or not code:
        code = str(exc) if str(exc) else "REVISION_MODE_REFUSED"
    detail = getattr(exc, "detail", None)
    return RevisionModeRefusal(
        code,
        detail=detail if isinstance(detail, Mapping) else None,
    )


def _git(repository: Path, *arguments: str) -> bytes:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
        if key in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            env=environment,
            shell=False,
        )
    except OSError as exc:
        raise RevisionModeRefusal("REPOSITORY_REFUSED") from exc
    if result.returncode != 0:
        _refuse("REPOSITORY_REFUSED")
    return result.stdout


def _repository_root(repository: Path | str) -> Path:
    requested = Path(repository)
    if requested.is_symlink() or not requested.is_dir():
        _refuse("REPOSITORY_REFUSED")
    try:
        top = Path(
            _git(requested, "rev-parse", "--show-toplevel")
            .decode("utf-8", errors="strict")
            .strip()
        ).resolve(strict=True)
    except (OSError, UnicodeError):
        _refuse("REPOSITORY_REFUSED")
    if requested.resolve(strict=True) != top:
        _refuse("REPOSITORY_REFUSED")
    return top


def _dirty(repository: Path) -> bool:
    return bool(
        _git(repository, "status", "--porcelain=v1", "--untracked-files=normal")
    )


def _relative_path(value: Path | str, code: str) -> str:
    if isinstance(value, Path):
        text = value.as_posix()
    elif type(value) is str:
        text = value
    else:
        _refuse(code)
    if not text or "\\" in text:
        _refuse(code)
    relative = PurePosixPath(text)
    if relative.is_absolute() or any(
        part in ("", ".", "..") for part in relative.parts
    ):
        _refuse(code)
    if relative.as_posix() != text:
        _refuse(code)
    return text


def _target_list(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, Mapping)):
        _refuse("REVISION_TARGET_REFUSED")
    try:
        rows = tuple(sorted(values))
    except TypeError:
        _refuse("REVISION_TARGET_REFUSED")
    if any(type(value) is not str or not value for value in rows):
        _refuse("REVISION_TARGET_REFUSED")
    if len(set(rows)) != len(rows):
        _refuse("REVISION_TARGET_REFUSED")
    return rows


def _environment_schema() -> dict[str, str]:
    return {
        "implementation": platform.python_implementation().lower(),
        "machine": platform.machine() or "unknown",
        "platform": sys.platform,
        "python": platform.python_version(),
    }


def _environment_domain() -> dict[str, str]:
    schema = _environment_schema()
    return {
        "implementation": schema["implementation"],
        "python_version": schema["python"],
        "platform": schema["platform"] + "-" + schema["machine"],
    }


def _api(definition: SymbolDefinition) -> str:
    return definition.module + "." + definition.symbol


def _inventory_rows(
    definitions: Iterable[SymbolDefinition],
) -> list[dict[str, object]]:
    return [
        {
            "file": definition.relative_path,
            "line": definition.line,
            "column": definition.column,
            "api": _api(definition),
        }
        for definition in definitions
    ]


def _definition_map(
    definitions: Iterable[SymbolDefinition],
) -> dict[str, SymbolDefinition | None]:
    grouped: dict[str, list[SymbolDefinition]] = {}
    for definition in definitions:
        grouped.setdefault(definition.target, []).append(definition)
    return {
        target: values[0] if len(values) == 1 else None
        for target, values in grouped.items()
    }


def _load_fixtures(
    *,
    repository: Path,
    pair,
    fixture_path: Path | str,
    fixture_source: str,
    source_definitions: tuple[SymbolDefinition, ...],
) -> _FixtureContext:
    relative = _relative_path(fixture_path, "FIXTURE_BINDING_PATH_REFUSED")
    if fixture_source == "base":
        root = pair.base_root
        revision = pair.base_commit
        predates = pair.base_commit != pair.head_commit
    elif fixture_source == "head":
        root = pair.head_root
        revision = pair.head_commit
        predates = False
    elif fixture_source == "explicit":
        root = repository
        try:
            revision = (
                _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
                .decode("ascii", errors="strict")
                .strip()
            )
        except UnicodeError:
            _refuse("FIXTURE_SOURCE_REVISION_REFUSED")
        predates = revision != pair.head_commit
    else:
        _refuse("FIXTURE_SOURCE_REFUSED")
    fixture = load_fixture_file(
        root / relative,
        repository_root=root,
        inventory=_inventory_rows(source_definitions),
    )
    if not fixture.bindings:
        _refuse("FIXTURE_VACUOUS_REFUSED")
    authors = {binding.fixture_authored_by for binding in fixture.bindings}
    if len(authors) != 1:
        _refuse("FIXTURE_AUTHOR_MIXED_REFUSED")
    by_key = {
        (
            definition.relative_path,
            definition.line,
            definition.column,
            _api(definition),
        ): definition.target
        for definition in source_definitions
    }
    bindings: dict[str, FixtureBinding] = {}
    for binding in fixture.bindings:
        target = by_key.get(binding.key)
        if target is None or target in bindings:
            _refuse("FIXTURE_AMBIGUOUS_REFUSED")
        bindings[target] = binding
    return _FixtureContext(
        fixture=fixture,
        source_revision=revision,
        authored_by=next(iter(authors)),
        source=fixture_source,
        predates_change=predates,
        bindings=bindings,
    )


def _fixture_schema(context: _FixtureContext) -> dict[str, str]:
    return {
        "authored_by": context.authored_by,
        "sha256": context.fixture.canonical_sha256,
        "source_revision": context.source_revision,
    }


def _fixture_domain(context: _FixtureContext) -> dict[str, str]:
    return {
        "sha256": context.fixture.canonical_sha256,
        "source_revision": context.source_revision,
        "source": context.source,
        "authored_by": context.authored_by,
    }


def _import_roots(
    root: Path, definition: SymbolDefinition
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    resolved_root = root.resolve(strict=True)
    relative = PurePosixPath(definition.relative_path)
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        _refuse("REVISION_IMPORT_ROOT_REFUSED")
    if relative.parts[0] != "src":
        return (str(resolved_root),), (".",)
    source_root = resolved_root / "src"
    try:
        if source_root.is_symlink() or not source_root.is_dir():
            _refuse("REVISION_IMPORT_ROOT_REFUSED")
        resolved_source = source_root.resolve(strict=True)
    except OSError:
        _refuse("REVISION_IMPORT_ROOT_REFUSED")
    if resolved_source != source_root or resolved_source.parent != resolved_root:
        _refuse("REVISION_IMPORT_ROOT_REFUSED")
    return (str(resolved_source),), ("src",)


def _import_root_identity(
    root: Path,
    definitions: Iterable[SymbolDefinition],
    *,
    tree_sha256: str,
) -> str:
    labels = set()
    for definition in definitions:
        _, chosen = _import_roots(root, definition)
        labels.update(chosen)
    return artifact_digest(
        {"roots": sorted(labels), "tree_sha256": tree_sha256}
    )


def _verified_previous_report(
    previous_report: Mapping[str, object] | None,
) -> tuple[dict[str, object] | None, str | None]:
    if previous_report is None:
        return None, None
    try:
        artifact = validate_artifact(previous_report)
        if artifact["artifact_kind"] != "revision_report":
            _refuse("PREVIOUS_REPORT_REFUSED")
        verify_artifact(artifact)
    except RevisionModeRefusal:
        raise
    except ValueError:
        _refuse("PREVIOUS_REPORT_REFUSED")
    return artifact["payload"], artifact_digest(artifact)


def _fixture_revision_events(
    previous_payload: Mapping[str, object] | None,
    *,
    base_revision: str,
    findings: list[dict[str, object]],
) -> list[dict[str, object]]:
    if previous_payload is None:
        return []
    if previous_payload["base_revision"] != base_revision:
        _refuse("PREVIOUS_REPORT_BASE_MISMATCH")
    prior_by_target = {
        str(row["target_id"]): row for row in previous_payload["findings"]
    }
    events = []
    for current in findings:
        prior = prior_by_target.get(str(current["target_id"]))
        if prior is None:
            continue
        prior_fixture = prior["fixture_binding_sha256"]
        current_fixture = current["fixture_binding_sha256"]
        if (
            prior_fixture is None
            or current_fixture is None
            or prior_fixture == current_fixture
            or prior["verdict"]
            not in ("CHANGED", "CHANGED_UNDER_PROJECTION")
            or current["verdict"]
            not in ("IDENTICAL", "IDENTICAL_UNDER_PROJECTION")
        ):
            continue
        event = {
            "event_id": "",
            "target_id": current["target_id"],
            "prior_finding_id": prior["finding_id"],
            "current_finding_id": current["finding_id"],
            "prior_fixture_binding_sha256": prior_fixture,
            "current_fixture_binding_sha256": current_fixture,
            "prior_verdict": prior["verdict"],
            "current_verdict": current["verdict"],
            "reason_code": "FIXTURE_REVISED_AFTER_FAILURE",
        }
        event["event_id"] = record_identity(event, "event_id")
        events.append(event)
    events.sort(key=lambda row: str(row["event_id"]))
    return events


def _projection(binding: FixtureBinding) -> dict[str, str] | None:
    if binding.projection is None:
        return None
    return {
        "source": binding.projection,
        "sha256": artifact_digest(binding.projection),
    }


def _snippet(
    definition: SymbolDefinition, binding: FixtureBinding
) -> tuple[str, str]:
    marker_suffix = hashlib.sha256(
        (definition.target + "\0" + binding.binding_sha256).encode("utf-8")
    ).hexdigest()[:16]
    marker = "_BreakcheckImportFailed_" + marker_suffix
    call_source = render_fixture_source(
        binding, "_bc_target_module." + definition.symbol
    )
    indented_call = "".join(
        "    " + line for line in call_source.splitlines(True)
    )
    source = (
        "import importlib as _bc_importlib\n"
        + "class "
        + marker
        + "(BaseException):\n    pass\n"
        + "try:\n"
        + "    _bc_target_module = _bc_importlib.import_module("
        + repr(definition.module)
        + ")\n"
        + "except BaseException as _bc_import_error:\n"
        + "    raise "
        + marker
        + "(type(_bc_import_error).__name__, list(_bc_import_error.args))\n"
        + "else:\n"
        + indented_call
    )
    return source, marker


def _replay(
    root: Path,
    definition: SymbolDefinition,
    binding: FixtureBinding,
    *,
    executor,
) -> _Replay:
    source, import_marker = _snippet(definition, binding)
    prefixes, _ = _import_roots(root, definition)
    result = executor(
        snippet_source=source,
        sys_path_prefixes=prefixes,
        runs=2,
    )
    if not isinstance(result, Mapping):
        _refuse("REVISION_EXECUTOR_REFUSED")
    repeatable = result.get("repeatable")
    status = result.get("status")
    reason = result.get("reason_code")
    observation = result.get("observation")
    if type(repeatable) is not bool or type(status) is not str:
        _refuse("REVISION_EXECUTOR_REFUSED")
    if not repeatable:
        return _Replay(
            "PROTOCOL_REFUSED",
            "NONDETERMINISTIC_OBSERVATION",
            None,
            None,
            ("OPERATOR_FIXTURE",),
            source,
        )
    if status == "EXCEPTION" and isinstance(observation, Mapping):
        if observation.get("exception_class") == import_marker:
            return _Replay(
                "PROTOCOL_REFUSED",
                "IMPORT_FAILED",
                None,
                None,
                ("OPERATOR_FIXTURE",),
                source,
            )
    if status not in _EXERCISED:
        if type(reason) is not str or not reason:
            _refuse("REVISION_EXECUTOR_REFUSED")
        return _Replay(
            status, reason, None, None, ("OPERATOR_FIXTURE",), source
        )
    if not isinstance(observation, Mapping):
        _refuse("REVISION_EXECUTOR_REFUSED")
    try:
        domain = {
            "kind": observation["kind"],
            "payload": copy.deepcopy(observation["payload"]),
            "exception_class": observation["exception_class"],
            "duration_ms": None,
        }
    except KeyError:
        _refuse("REVISION_EXECUTOR_REFUSED")
    schema_observation = {
        "kind": domain["kind"],
        "payload": copy.deepcopy(domain["payload"]),
        "exception_class": domain["exception_class"],
        "provenance": ["OPERATOR_FIXTURE"],
    }
    digest = artifact_digest(schema_observation)
    return _Replay(
        status,
        None,
        domain,
        (digest, digest),
        ("OPERATOR_FIXTURE",),
        source,
    )


def _schema_observation(replay: _Replay) -> dict[str, object]:
    if replay.observation is None:
        _refuse("REVISION_EXECUTOR_REFUSED")
    return {
        "kind": replay.observation["kind"],
        "payload": copy.deepcopy(replay.observation["payload"]),
        "exception_class": replay.observation["exception_class"],
        "provenance": list(replay.provenance),
    }


def _domain_target(
    definition: SymbolDefinition,
    binding: FixtureBinding,
    replay: _Replay,
) -> dict[str, object]:
    return {
        "symbol": definition.target,
        "target_sha256": definition.definition_sha256,
        "signature_sha256": definition.signature_sha256,
        "fixture_binding_sha256": binding.binding_sha256,
        "provenance": "OPERATOR_FIXTURE",
        "projection": binding.projection,
        "outcome": {
            "status": replay.status,
            "observation": copy.deepcopy(replay.observation),
            "reason_code": replay.reason_code,
            "repeatable": replay.status in _EXERCISED,
        },
    }


def _baseline_target(
    definition: SymbolDefinition,
    binding: FixtureBinding,
    replay: _Replay,
) -> dict[str, object]:
    observation = _schema_observation(replay)
    target = {
        "target_id": "",
        "module": definition.module,
        "symbol": definition.symbol,
        "definition_sha256": definition.definition_sha256,
        "signature_sha256": definition.signature_sha256,
        "observation": observation,
        "repeat_sha256": list(replay.repeat_sha256 or ()),
        "projection_sha256": (
            None
            if binding.projection is None
            else artifact_digest(binding.projection)
        ),
    }
    target["target_id"] = record_identity(target, "target_id")
    return target


def _result(
    report: Mapping[str, object],
    *,
    environment_artifacts: list[dict[str, str]],
    exit_code: int,
) -> RevisionCommandResult:
    evidence = make_evidence_artifact(
        report,
        environment_artifacts=sorted(
            environment_artifacts, key=lambda row: row["name"]
        ),
    )
    return RevisionCommandResult(
        report=copy.deepcopy(dict(report)),
        evidence=copy.deepcopy(evidence),
        exit_code=exit_code,
    )


def _selection(
    changes: tuple[SymbolChange, ...], targets: tuple[str, ...], allow_empty: bool
) -> tuple[str, ...]:
    available = {change.target for change in changes}
    if targets:
        if any(target not in available for target in targets):
            _refuse("REVISION_TARGET_UNMATCHED")
        return targets
    selected = tuple(
        change.target for change in changes if change.status in _CHANGED_STATUSES
    )
    if not selected and not allow_empty:
        _refuse("NO_CHANGED_TARGETS")
    return selected


def freeze_revision(
    repository: Path | str,
    *,
    revision: str = "HEAD",
    fixture_path: Path | str = "breakcheck.fixtures.toml",
    runtime_root: Path | str,
    targets: Iterable[str] = (),
    allow_dirty: bool = False,
    fixture_policy: str = "require",
    executor=run_repeated_typed_snippet_isolated,
) -> RevisionCommandResult:
    """Capture repeated observations for fixture-bound targets at one revision."""

    try:
        if fixture_policy != "require":
            _refuse("FIXTURE_REQUIRED")
        if type(allow_dirty) is not bool:
            _refuse("DIRTY_TREE_REFUSED")
        top = _repository_root(repository)
        dirty = _dirty(top)
        if dirty:
            _refuse(
                "DIRTY_TREE_CAPTURE_UNSUPPORTED"
                if allow_dirty
                else "DIRTY_TREE_REFUSED"
            )
        requested_targets = _target_list(targets)
        with revision_worktrees(top, revision, revision, runtime_root) as pair:
            definitions = inventory_symbols(pair.base_root).definitions
            by_target = _definition_map(definitions)
            context = _load_fixtures(
                repository=top,
                pair=pair,
                fixture_path=fixture_path,
                fixture_source="base",
                source_definitions=definitions,
            )
            selected = requested_targets or tuple(sorted(context.bindings))
            if not selected:
                _refuse("VACUOUS_BASELINE_REFUSED")
            domain_targets = []
            artifact_targets = []
            selected_definitions = []
            for target in selected:
                definition = by_target.get(target)
                binding = context.bindings.get(target)
                if definition is None:
                    _refuse("REVISION_TARGET_UNMATCHED")
                if binding is None:
                    _refuse("FIXTURE_REQUIRED")
                selected_definitions.append(definition)
                replay = _replay(
                    pair.base_root, definition, binding, executor=executor
                )
                if replay.status not in _EXERCISED:
                    _refuse("BASELINE_TARGET_NOT_EXERCISED")
                domain_targets.append(_domain_target(definition, binding, replay))
                artifact_targets.append(
                    _baseline_target(definition, binding, replay)
                )
            tree = tracked_tree_identity(pair.base_root)
            import_root_sha256 = _import_root_identity(
                pair.base_root,
                selected_definitions,
                tree_sha256=tree.sha256,
            )
            invocation_flags: dict[str, object] = {
                "allow_dirty": allow_dirty,
                "fixture_file": _relative_path(
                    fixture_path, "FIXTURE_BINDING_PATH_REFUSED"
                ),
                "fixture_policy": fixture_policy,
                "target": list(selected),
            }
            freeze_baseline(
                revision=pair.base_commit,
                tree_sha256=tree.sha256,
                dirty=dirty,
                allow_dirty=allow_dirty,
                environment=_environment_domain(),
                fixture=_fixture_domain(context),
                target_observations=domain_targets,
                invocation=copy.deepcopy(invocation_flags),
            )
            artifact_targets.sort(key=lambda row: str(row["target_id"]))
            report = make_revision_artifact(
                "baseline",
                {
                    "revision": pair.base_commit,
                    "tree_sha256": tree.sha256,
                    "dirty": dirty,
                    "allow_dirty": allow_dirty,
                    "environment": _environment_schema(),
                    "fixture": _fixture_schema(context),
                    "target_observations": artifact_targets,
                    "invocation": canonicalize_invocation(
                        "baseline", invocation_flags
                    ),
                },
            )
            return _result(
                report,
                environment_artifacts=[
                    {"name": "revision_tree", "sha256": tree.sha256},
                    {
                        "name": "revision_import_roots",
                        "sha256": import_root_sha256,
                    },
                    {
                        "name": "fixture",
                        "sha256": context.fixture.canonical_sha256,
                    },
                ],
                exit_code=0,
            )
    except (
        FixtureRefusal,
        WorktreeRefusal,
        SymbolAnalysisRefusal,
        BaselineRefusal,
    ) as exc:
        raise _translate(exc) from exc


def _reason(base: _Replay, head: _Replay) -> str | None:
    base_import = base.reason_code == "IMPORT_FAILED"
    head_import = head.reason_code == "IMPORT_FAILED"
    if base_import != head_import:
        return "IMPORT_ASYMMETRY"
    if base_import and head_import:
        return "IMPORT_FAILED"
    if base.status not in _EXERCISED or head.status not in _EXERCISED:
        if base.reason_code == head.reason_code and base.reason_code is not None:
            return base.reason_code
        return "REPLAY_ASYMMETRY"
    return None


def _finding(
    *,
    target: str,
    base_definition: SymbolDefinition | None,
    head_definition: SymbolDefinition | None,
    binding: FixtureBinding | None,
    base: _Replay | None,
    head: _Replay | None,
    reason_code: str | None,
) -> tuple[dict[str, object], dict[str, object] | None]:
    definition = base_definition or head_definition
    if definition is None:
        _refuse("REVISION_TARGET_REFUSED")
    target_id = artifact_digest({"target": target})
    projection = None if binding is None else _projection(binding)
    if reason_code is not None:
        verdict = "NOT_EXERCISED"
        base_observation = None
        head_observation = None
        projection = None
    else:
        if (
            base is None
            or head is None
            or base.observation is None
            or head.observation is None
        ):
            _refuse("REVISION_EXECUTOR_REFUSED")
        comparison = compare_observations(base.observation, head.observation)
        verdict = comparison["verdict"]
        if binding is not None and binding.projection is not None:
            verdict += "_UNDER_PROJECTION"
        base_observation = _schema_observation(base)
        head_observation = _schema_observation(head)
    finding = {
        "finding_id": "",
        "target_id": target_id,
        "module": definition.module,
        "symbol": definition.symbol,
        "verdict": verdict,
        "base": base_observation,
        "head": head_observation,
        "reason_code": reason_code,
        "projection": projection,
        "fixture_binding_sha256": (
            None if binding is None else binding.binding_sha256
        ),
    }
    finding["finding_id"] = record_identity(finding, "finding_id")
    if reason_code is not None:
        return finding, None
    assert base is not None and head is not None
    witness = {
        "witness_id": "",
        "finding_id": finding["finding_id"],
        "target_id": target_id,
        "base_observation_sha256": artifact_digest(base_observation),
        "head_observation_sha256": artifact_digest(head_observation),
        "base_repeat_sha256": list(base.repeat_sha256 or ()),
        "head_repeat_sha256": list(head.repeat_sha256 or ()),
        "projection_sha256": (
            None if projection is None else projection["sha256"]
        ),
        "provenance": ["OPERATOR_FIXTURE"],
        "replay": {
            "source": base.replay_source,
            "sha256": artifact_digest(base.replay_source),
        },
    }
    witness["witness_id"] = record_identity(witness, "witness_id")
    return finding, witness


def _evaluate_pair(
    *,
    top: Path,
    pair,
    fixture_path: Path | str,
    fixture_source: str,
    targets: tuple[str, ...],
    allow_empty: bool,
    min_coverage: float,
    strict_separation: bool,
    executor,
    previous_payload: Mapping[str, object] | None = None,
    previous_report_sha256: str | None = None,
) -> tuple[
    dict[str, object],
    _FixtureContext,
    int,
    tuple[str, ...],
    dict[str, str],
]:
    if type(allow_empty) is not bool or type(strict_separation) is not bool:
        _refuse("REVISION_POLICY_REFUSED")
    if (
        type(min_coverage) not in (int, float)
        or not 0 < float(min_coverage) <= 100
    ):
        _refuse("REVISION_COVERAGE_REFUSED")
    if strict_separation and fixture_source == "explicit":
        _refuse("FIXTURE_EXPLICIT_STRICT_REFUSED")
    changes = compare_symbol_trees(pair.base_root, pair.head_root)
    selected = _selection(changes, targets, allow_empty)
    base_definitions = inventory_symbols(pair.base_root).definitions
    head_definitions = inventory_symbols(pair.head_root).definitions
    base_map = _definition_map(base_definitions)
    head_map = _definition_map(head_definitions)
    source_definitions = (
        base_definitions if fixture_source == "base" else head_definitions
    )
    if fixture_source == "explicit":
        source_definitions = base_definitions
    context = _load_fixtures(
        repository=top,
        pair=pair,
        fixture_path=fixture_path,
        fixture_source=fixture_source,
        source_definitions=source_definitions,
    )
    if strict_separation and (
        not context.predates_change or context.authored_by == "unknown"
    ):
        _refuse("FIXTURE_SEPARATION_REFUSED")
    change_map = {change.target: change for change in changes}
    findings = []
    witnesses = []
    for target in selected:
        change = change_map[target]
        base_definition = base_map.get(target)
        head_definition = head_map.get(target)
        binding = context.bindings.get(target)
        reason_code = None
        base_replay = None
        head_replay = None
        if change.status in (
            "SYMBOL_AMBIGUOUS",
            "NO_BASELINE_REVISION",
            "SYMBOL_REMOVED",
            "FIXTURE_SIGNATURE_DRIFT",
        ):
            reason_code = change.status
        elif base_definition is None or head_definition is None:
            reason_code = "SYMBOL_AMBIGUOUS"
        elif binding is None:
            reason_code = "FIXTURE_REQUIRED"
        else:
            base_replay = _replay(
                pair.base_root, base_definition, binding, executor=executor
            )
            head_replay = _replay(
                pair.head_root, head_definition, binding, executor=executor
            )
            reason_code = _reason(base_replay, head_replay)
        finding, witness = _finding(
            target=target,
            base_definition=base_definition,
            head_definition=head_definition,
            binding=binding,
            base=base_replay,
            head=head_replay,
            reason_code=reason_code,
        )
        findings.append(finding)
        if witness is not None:
            witnesses.append(witness)
    findings.sort(key=lambda row: str(row["finding_id"]))
    witnesses.sort(key=lambda row: str(row["witness_id"]))
    fixture_revision_events = _fixture_revision_events(
        previous_payload,
        base_revision=pair.base_commit,
        findings=findings,
    )
    summary = {
        "changed": sum(row["verdict"] == "CHANGED" for row in findings),
        "changed_under_projection": sum(
            row["verdict"] == "CHANGED_UNDER_PROJECTION" for row in findings
        ),
        "identical": sum(row["verdict"] == "IDENTICAL" for row in findings),
        "identical_under_projection": sum(
            row["verdict"] == "IDENTICAL_UNDER_PROJECTION" for row in findings
        ),
        "not_exercised": sum(
            row["verdict"] == "NOT_EXERCISED" for row in findings
        ),
    }
    total = len(findings)
    exercised = total - summary["not_exercised"]
    coverage = 0.0 if total == 0 else 100.0 * exercised / total
    if total == 0 and not allow_empty:
        _refuse("VACUOUS_REVISION_COMPARISON_REFUSED")
    if summary["changed"] or summary["changed_under_projection"]:
        exit_code = 3
    elif coverage < float(min_coverage):
        exit_code = 4
    else:
        exit_code = 0
    base_tree = tracked_tree_identity(pair.base_root)
    head_tree = tracked_tree_identity(pair.head_root)
    import_root_identities = {
        "base": _import_root_identity(
            pair.base_root,
            (base_map[target] for target in selected if target in base_map),
            tree_sha256=base_tree.sha256,
        ),
        "head": _import_root_identity(
            pair.head_root,
            (head_map[target] for target in selected if target in head_map),
            tree_sha256=head_tree.sha256,
        ),
    }
    flags: dict[str, object] = {
        "allow_empty": allow_empty,
        "fixture_file": _relative_path(
            fixture_path, "FIXTURE_BINDING_PATH_REFUSED"
        ),
        "fixture_policy": "require",
        "fixture_source": fixture_source,
        "min_coverage": float(min_coverage),
        "strict_separation": strict_separation,
    }
    if selected:
        flags["target"] = list(selected)
    if previous_report_sha256 is not None:
        flags["previous_report_sha256"] = previous_report_sha256
    payload = {
        "base_revision": pair.base_commit,
        "head_revision": pair.head_commit,
        "base_tree_sha256": base_tree.sha256,
        "head_tree_sha256": head_tree.sha256,
        "findings": findings,
        "witnesses": witnesses,
        "fixture_revision_events": fixture_revision_events,
        "summary": summary,
        "fixture": _fixture_schema(context),
        "fixtures_predate_change": context.predates_change,
        "invocation": canonicalize_invocation("revision_report", flags),
    }
    return payload, context, exit_code, selected, import_root_identities


def diff_revisions(
    repository: Path | str,
    *,
    base_revision: str | None = None,
    baseline: Mapping[str, object] | None = None,
    previous_report: Mapping[str, object] | None = None,
    head_revision: str,
    fixture_path: Path | str = "breakcheck.fixtures.toml",
    runtime_root: Path | str,
    targets: Iterable[str] = (),
    fixture_source: str = "base",
    allow_empty: bool = False,
    min_coverage: float = 80.0,
    strict_separation: bool = False,
    executor=run_repeated_typed_snippet_isolated,
) -> RevisionCommandResult:
    """Compare fixture-bound behavior across two committed revisions."""

    try:
        top = _repository_root(repository)
        selected = _target_list(targets)
        previous_payload, previous_report_sha256 = _verified_previous_report(
            previous_report
        )
        baseline_payload = None
        if baseline is not None:
            verified = validate_artifact(baseline)
            if verified["artifact_kind"] != "baseline":
                _refuse("BASELINE_ARTIFACT_REFUSED")
            verify_artifact(verified)
            baseline_payload = verified["payload"]
            recorded_base = str(baseline_payload["revision"])
            if base_revision is not None and base_revision != recorded_base:
                _refuse("BASELINE_REVISION_MISMATCH")
            base_revision = recorded_base
            recorded_targets = tuple(
                sorted(
                    str(row["module"]) + ":" + str(row["symbol"])
                    for row in baseline_payload["target_observations"]
                )
            )
            if selected and selected != recorded_targets:
                _refuse("BASELINE_TARGET_MISMATCH")
            selected = recorded_targets
        if base_revision is None:
            _refuse("NO_BASELINE_REVISION")
        with revision_worktrees(
            top, base_revision, head_revision, runtime_root
        ) as pair:
            if pair.base_commit == pair.head_commit:
                _refuse("IDENTICAL_REVISIONS_REFUSED")
            if (
                previous_payload is not None
                and previous_payload["base_revision"] != pair.base_commit
            ):
                _refuse("PREVIOUS_REPORT_BASE_MISMATCH")
            payload, context, exit_code, _, import_roots = _evaluate_pair(
                top=top,
                pair=pair,
                fixture_path=fixture_path,
                fixture_source=fixture_source,
                targets=selected,
                allow_empty=allow_empty,
                min_coverage=min_coverage,
                strict_separation=strict_separation,
                executor=executor,
                previous_payload=previous_payload,
                previous_report_sha256=previous_report_sha256,
            )
            if baseline_payload is not None:
                if baseline_payload["environment"] != _environment_schema():
                    _refuse("BASELINE_ENVIRONMENT_MISMATCH")
                if baseline_payload["tree_sha256"] != payload["base_tree_sha256"]:
                    _refuse("BASELINE_TREE_MISMATCH")
                if baseline_payload["fixture"] != payload["fixture"]:
                    _refuse("BASELINE_FIXTURE_MISMATCH")
                baseline_targets = {
                    str(row["module"]) + ":" + str(row["symbol"]): row
                    for row in baseline_payload["target_observations"]
                }
                if set(baseline_targets) != set(selected):
                    _refuse("BASELINE_TARGET_MISMATCH")
                for finding in payload["findings"]:
                    target = (
                        str(finding["module"])
                        + ":"
                        + str(finding["symbol"])
                    )
                    baseline_target = baseline_targets.get(target)
                    if baseline_target is None:
                        _refuse("BASELINE_TARGET_MISMATCH")
                    if finding["base"] is not None and (
                        finding["base"] != baseline_target["observation"]
                    ):
                        _refuse("BASELINE_OBSERVATION_MISMATCH")
                    projection = finding["projection"]
                    projection_sha = (
                        None if projection is None else projection["sha256"]
                    )
                    if projection_sha != baseline_target["projection_sha256"]:
                        _refuse("BASELINE_PROJECTION_MISMATCH")
            report = make_revision_artifact("revision_report", payload)
            return _result(
                report,
                environment_artifacts=[
                    {
                        "name": "base_tree",
                        "sha256": payload["base_tree_sha256"],
                    },
                    {
                        "name": "base_import_roots",
                        "sha256": import_roots["base"],
                    },
                    {
                        "name": "fixture",
                        "sha256": context.fixture.canonical_sha256,
                    },
                    {
                        "name": "head_tree",
                        "sha256": payload["head_tree_sha256"],
                    },
                    {
                        "name": "head_import_roots",
                        "sha256": import_roots["head"],
                    },
                ],
                exit_code=exit_code,
            )
    except (FixtureRefusal, WorktreeRefusal, SymbolAnalysisRefusal) as exc:
        raise _translate(exc) from exc


def _read_text(root: Path, relative: Path | str, code: str) -> tuple[str, str]:
    name = _relative_path(relative, code)
    path = root / name
    if path.is_symlink() or not path.is_file():
        _refuse(code)
    try:
        data = path.read_bytes()
        if len(data) > 65_536:
            _refuse(code)
        return data.decode("utf-8", errors="strict"), name
    except (OSError, UnicodeError):
        _refuse(code)


def _claim_disposition(
    row: Mapping[str, object], *, strict_separation: bool
) -> dict[str, object]:
    disposition = str(row["disposition"])
    reason = row["reason_code"]
    if not strict_separation and disposition == "CLAIM_VERIFIED":
        disposition = "CLAIM_UNVERIFIABLE"
        reason = "STRICT_SEPARATION_REQUIRED"
    if disposition == "CLAIM_REFUTED" and reason is None:
        reason = "BEHAVIOR_CHANGED"
    symbol = str(row["symbol"])
    result = {
        "disposition_id": "",
        "target_id": artifact_digest({"target": symbol}),
        "symbol": symbol,
        "disposition": disposition,
        "reason_code": reason,
        "projection_scope": row["projection_scope"],
    }
    result["disposition_id"] = record_identity(result, "disposition_id")
    return result


def attest_revision(
    repository: Path | str,
    *,
    head_revision: str,
    claim_path: Path | str,
    previous_report: Mapping[str, object] | None = None,
    fixture_path: Path | str = "breakcheck.fixtures.toml",
    runtime_root: Path | str,
    fixture_source: str = "base",
    allow_empty: bool = False,
    min_coverage: float = 80.0,
    strict: bool = True,
    strict_separation: bool = True,
    executor=run_repeated_typed_snippet_isolated,
) -> RevisionCommandResult:
    """Adjudicate a closed preservation claim against the independent diff census."""

    try:
        if type(strict) is not bool:
            _refuse("CLAIM_POLICY_REFUSED")
        top = _repository_root(repository)
        previous_payload, previous_report_sha256 = _verified_previous_report(
            previous_report
        )
        claim_relative = _relative_path(claim_path, "CLAIM_FILE_REFUSED")
        head_commit = (
            _git(
                top,
                "rev-parse",
                "--verify",
                "--end-of-options",
                f"{head_revision}^{{commit}}",
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        with revision_worktrees(
            top, head_commit, head_commit, runtime_root
        ) as claim_pair:
            claim_text, _ = _read_text(
                claim_pair.head_root, claim_relative, "CLAIM_FILE_REFUSED"
            )
            claim = parse_claim(claim_text)
        comparison_root = Path(runtime_root)
        if comparison_root.exists() or comparison_root.is_symlink():
            _refuse("REVISION_WORKTREE_CLEANUP_REFUSED")
        with revision_worktrees(
            top, claim.base_revision, head_commit, comparison_root
        ) as pair:
            if (
                previous_payload is not None
                and previous_payload["base_revision"] != pair.base_commit
            ):
                _refuse("PREVIOUS_REPORT_BASE_MISMATCH")
            (
                payload,
                context,
                _,
                changed_targets,
                import_roots,
            ) = _evaluate_pair(
                top=top,
                pair=pair,
                fixture_path=fixture_path,
                fixture_source=fixture_source,
                targets=(),
                allow_empty=allow_empty,
                min_coverage=min_coverage,
                strict_separation=strict_separation,
                executor=executor,
                previous_payload=previous_payload,
                previous_report_sha256=previous_report_sha256,
            )
            simple_findings = [
                {
                    "symbol": str(row["module"]) + ":" + str(row["symbol"]),
                    "verdict": row["verdict"],
                    "reason_code": row["reason_code"],
                    "projection_scope": (
                        None
                        if row["projection"] is None
                        else row["projection"]["source"]
                    ),
                }
                for row in payload["findings"]
            ]
            domain = adjudicate_claim(
                claim,
                head_revision=pair.head_commit,
                changed_targets=changed_targets,
                findings=simple_findings,
                fixture_source=fixture_source,
                fixture_revision=context.source_revision,
                fixture_authored_by=context.authored_by,
                fixtures_predate_change=context.predates_change,
                strict_separation=strict_separation,
                invocation={
                    "strict": strict,
                    "strict_separation": strict_separation,
                },
            )
            dispositions = [
                _claim_disposition(row, strict_separation=strict_separation)
                for row in domain["dispositions"]
            ]
            dispositions.sort(key=lambda row: str(row["disposition_id"]))
            summary = {
                "claim_out_of_scope": sum(
                    row["disposition"] == "CLAIM_OUT_OF_SCOPE"
                    for row in dispositions
                ),
                "claim_refuted": sum(
                    row["disposition"] == "CLAIM_REFUTED"
                    for row in dispositions
                ),
                "claim_unverifiable": sum(
                    row["disposition"] == "CLAIM_UNVERIFIABLE"
                    for row in dispositions
                ),
                "claim_verified": sum(
                    row["disposition"] == "CLAIM_VERIFIED"
                    for row in dispositions
                ),
                "total": len(dispositions),
            }
            flags = {
                "allow_empty": allow_empty,
                "claim_file": claim_relative,
                "fixture_file": _relative_path(
                    fixture_path, "FIXTURE_BINDING_PATH_REFUSED"
                ),
                "fixture_source": fixture_source,
                "min_coverage": float(min_coverage),
                "strict": strict,
                "strict_separation": strict_separation,
            }
            if previous_report_sha256 is not None:
                flags["previous_report_sha256"] = previous_report_sha256
            claim_payload = {
                "claim": claim.claim,
                "base_revision": pair.base_commit,
                "head_revision": pair.head_commit,
                "dispositions": dispositions,
                "summary": summary,
                "fixture": _fixture_schema(context),
                "fixtures_predate_change": context.predates_change,
                "fixture_revision_events": payload[
                    "fixture_revision_events"
                ],
                "invocation": canonicalize_invocation("claim_report", flags),
            }
            report = make_revision_artifact("claim_report", claim_payload)
            return _result(
                report,
                environment_artifacts=[
                    {
                        "name": "base_tree",
                        "sha256": payload["base_tree_sha256"],
                    },
                    {
                        "name": "base_import_roots",
                        "sha256": import_roots["base"],
                    },
                    {
                        "name": "fixture",
                        "sha256": context.fixture.canonical_sha256,
                    },
                    {
                        "name": "head_tree",
                        "sha256": payload["head_tree_sha256"],
                    },
                    {
                        "name": "head_import_roots",
                        "sha256": import_roots["head"],
                    },
                ],
                exit_code=claim_exit_code(claim_payload),
            )
    except (
        ClaimRefusal,
        FixtureRefusal,
        WorktreeRefusal,
        SymbolAnalysisRefusal,
    ) as exc:
        raise _translate(exc) from exc


__all__ = (
    "RevisionCommandResult",
    "RevisionModeRefusal",
    "attest_revision",
    "diff_revisions",
    "freeze_revision",
)
