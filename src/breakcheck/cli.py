from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.metadata as _metadata
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from breakcheck.adapters.python.fixtures import REFUSAL_CODES as _FIXTURE_REFUSALS

def _load_pipeline():
    from breakcheck.adapters.python.files import iter_python_files as inventory
    from breakcheck.adapters.python.scanner import PythonUsageScanner as scanner
    from breakcheck.adapters.python.literals import synthesize_snippet as synthesize
    from breakcheck.adapters.python.envs import PythonEnvBuilder as environment_builder
    from breakcheck.adapters.python.executor import run_snippet_isolated as execute
    from breakcheck.adapters.python.normalization import normalize_outcome as normalize
    from breakcheck.adapters.python.equality import compare_observations as compare
    from breakcheck.report import finding_id as finding_id
    from breakcheck.report import render_json as render_json
    from breakcheck.report import render_human as render_human
    from breakcheck.report import ci_exit_code as exit_code
    from breakcheck.verify import verify_report as verify_report
    return (inventory, scanner, synthesize, environment_builder, execute,
            normalize, compare, finding_id, render_json, render_human,
            exit_code, verify_report)

_HELP_PREFIX = (
    "modes:\n"
    "  dependency comparison: breakcheck <package>@<new-version> [options]\n"
    "  offline demonstration: breakcheck demo --output-root <path>\n"
    "  revision verification: breakcheck {freeze,diff,attest} --help\n"
    "  machine capabilities: breakcheck --capabilities --json\n\n"
    "Dependency comparison requires an explicit local wheelhouse. "
    "The default coverage threshold is 80 percent. Refusal codes: "
)
_MISSING_CURRENT = "CURRENT_DISTRIBUTION_MISSING"
_MIN_COVERAGE_REFUSAL_CODE = "MIN_COVERAGE_REFUSED"
_DEMO_REFUSAL_CODES = frozenset(
    (
        "DEMO_EXECUTION_REFUSED",
        "DEMO_OUTPUT_EXISTS_REFUSED",
        "DEMO_VERIFICATION_REFUSED",
    )
)
_IMPORT_ROOT_OVERRIDES = {
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
}

_SUPPORTED_PLATFORMS = frozenset(('linux', 'darwin'))
_PLATFORM_REFUSAL_CODE = 'PLATFORM_REFUSED'
_WHEELHOUSE_REQUIRED_CODE = 'WHEELHOUSE_REQUIRED'
_OPERATIONAL_EXCEPTION_CODES = {'ImportError': 'PIPELINE_IMPORT_REFUSED', 'OSError': 'FILESYSTEM_REFUSED', 'UnicodeError': 'TEXT_ENCODING_REFUSED'}
_DECLARED_REFUSAL_CODES = (frozenset(('NONLITERAL_ARGS', 'CURRENT_DISTRIBUTION_MISSING', 'PLATFORM_REFUSED', 'WHEELHOUSE_REQUIRED', 'MISSING_WHEEL_REFUSED', 'AMBIGUOUS_WHEEL_REFUSED', 'PIPELINE_IMPORT_REFUSED', 'FILESYSTEM_REFUSED', 'TEXT_ENCODING_REFUSED', 'ENVIRONMENT_INSTALL_REFUSED', _MIN_COVERAGE_REFUSAL_CODE)) | frozenset(('API_ABSENT_BOTH_ENVIRONMENTS', 'CALL_SITE_PATH_REFUSED', 'CALL_SITE_SCAN_REFUSED', 'CALL_SITE_SCHEMA_REFUSED', 'CALL_SITE_SOURCE_REFUSED', 'ENVIRONMENT_ARTIFACT_SYMLINK_REFUSED', 'ENVIRONMENT_FINGERPRINT_REFUSED', 'ENVIRONMENT_PAIR_REFUSED', 'IMPORT_ROOT_REFUSED', 'INVENTORY_ROOT_SYMLINK_REFUSED', 'OBSERVATION_ENCODING_REFUSED', 'OUTPUT_PATH_COLLISION_REFUSED', 'OUTPUT_PATH_REFUSED', 'PRESENCE_CENSUS_REFUSED', 'SOURCE_SYNTAX_REFUSED', 'TARGET_GRAMMAR_REFUSED', 'UNSUPPORTED_USAGE_SCHEMA_REFUSED', 'WHEELHOUSE_REFUSED')) | _FIXTURE_REFUSALS | _DEMO_REFUSAL_CODES)
_HELP = _HELP_PREFIX + ','.join(sorted(_DECLARED_REFUSAL_CODES))

def _bounded_refusal(exc):
    for base in type(exc).__mro__:
        code = _OPERATIONAL_EXCEPTION_CODES.get(base.__name__)
        if code is not None:
            return code
    if isinstance(exc, (ValueError, RuntimeError)):
        code = str(exc).split(':', 1)[0]
        if code in _DECLARED_REFUSAL_CODES:
            return code
    return None

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _print_refusal_detail(exc):
    detail = getattr(exc, "detail", None)
    if isinstance(detail, dict):
        print("REFUSAL_DETAIL:" + _canonical(detail), file=sys.stderr)

def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()

def _bounded_workers(value):
    if value < 1: raise ValueError("workers must be positive")
    return min(value, 8)


def _coverage_threshold(value):
    try:
        threshold = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(_MIN_COVERAGE_REFUSAL_CODE) from exc
    if not 0 < threshold <= 100:
        raise argparse.ArgumentTypeError(_MIN_COVERAGE_REFUSAL_CODE)
    return threshold

def _target(value):
    if not isinstance(value, str) or value.count("@") != 1:
        raise ValueError("TARGET_GRAMMAR_REFUSED")
    package, version = value.split("@", 1)
    if (not package or not version or package != package.strip() or
            version != version.strip() or any(char.isspace() for char in value)):
        raise ValueError("TARGET_GRAMMAR_REFUSED")
    return package, version

def _import_root(package):
    distribution_key = re.sub(r"[-_.]+", "-", str(package)).lower()
    override = _IMPORT_ROOT_OVERRIDES.get(distribution_key)
    if override is not None:
        return override
    try:
        distribution = _metadata.distribution(package)
        declared = distribution.read_text("top_level.txt") or ""
        rows = sorted({row.strip() for row in declared.splitlines()
                       if row.strip().isidentifier()})
        if len(rows) == 1:
            return rows[0]
    except Exception as exc:
        if not isinstance(exc, _metadata.PackageNotFoundError):
            raise
    value = re.sub(r"[-.]+", "_", package).lower()
    if not value.isidentifier():
        raise ValueError("IMPORT_ROOT_REFUSED")
    return value

def _confined_file(root, relative, inventory):
    path = (root / relative).resolve()
    path.relative_to(root)
    if path not in inventory or not path.is_file() or path.is_symlink():
        raise ValueError("CALL_SITE_PATH_REFUSED")
    return path

def _node_source(lines, node):
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    if end_line is None or end_column is None:
        raise ValueError("CALL_SITE_SOURCE_REFUSED")
    start_line = node.lineno
    if start_line == end_line:
        return lines[start_line - 1][node.col_offset:end_column]
    pieces = [lines[start_line - 1][node.col_offset:]]
    pieces.extend(lines[start_line:end_line - 1])
    pieces.append(lines[end_line - 1][:end_column])
    return "".join(pieces)


def _dotted_name(node):
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        raise ValueError("CALL_SITE_SOURCE_REFUSED")
    parts.append(current.id)
    parts.reverse()
    if not all(part.isidentifier() for part in parts):
        raise ValueError("CALL_SITE_SOURCE_REFUSED")
    return parts


def _replay_import_statement(tree, call, api):
    call_parts = _dotted_name(call.func)
    local_root = call_parts[0]
    suffix = call_parts[1:]
    candidates = []
    call_position = (call.lineno, call.col_offset)
    for node in ast.walk(tree):
        position = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        if position > call_position:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                if local_name != local_root:
                    continue
                bound = alias.name if alias.asname else alias.name.split(".")[0]
                if ".".join([bound, *suffix]) != api:
                    continue
                statement = "import " + alias.name
                if alias.asname:
                    statement += " as " + alias.asname
                candidates.append((position, statement))
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
        ):
            for alias in node.names:
                local_name = alias.asname or alias.name
                if local_name != local_root or alias.name == "*":
                    continue
                bound = node.module + "." + alias.name
                if ".".join([bound, *suffix]) != api:
                    continue
                statement = "from " + node.module + " import " + alias.name
                if alias.asname:
                    statement += " as " + alias.asname
                candidates.append((position, statement))
    if candidates:
        return sorted(candidates, key=lambda item: (item[0], item[1]))[-1][1]
    if call_parts == api.split(".") and local_root == api.split(".", 1)[0]:
        return "import " + local_root
    raise ValueError("CALL_SITE_SOURCE_REFUSED")

def _call_sources(root, grouped, inventory):
    from breakcheck.adapters.python.scanner import build_static_context

    requested = {}
    for api, sites in grouped.items():
        for site in sites:
            key = (site["file"], site["line"], site["column"])
            if key in requested and requested[key] != api:
                raise ValueError("CALL_SITE_SOURCE_REFUSED")
            requested[key] = api
    by_file = {}
    for relative, line, column in sorted(requested):
        by_file.setdefault(relative, set()).add((line, column))
    result = {}
    for relative in sorted(by_file):
        path = _confined_file(root, relative, inventory)
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        tree = ast.parse(text, filename=relative)
        static_context = build_static_context(tree)
        matches = {item: [] for item in by_file[relative]}
        for node in ast.walk(tree):
            key = (getattr(node, "lineno", None), getattr(node, "col_offset", None))
            if isinstance(node, ast.Call) and key in matches:
                matches[key].append(node)
        for line, column in sorted(matches):
            nodes = matches[(line, column)]
            if not nodes:
                raise ValueError("CALL_SITE_SOURCE_REFUSED")
            api = requested[(relative, line, column)]
            selected = []
            for node in nodes:
                try:
                    import_statement = _replay_import_statement(tree, node, api)
                except ValueError as exc:
                    if str(exc) != "CALL_SITE_SOURCE_REFUSED":
                        raise
                    continue
                selected.append((node, import_statement))
            if len(selected) != 1:
                raise ValueError("CALL_SITE_SOURCE_REFUSED")
            node, import_statement = selected[0]
            source = _node_source(lines, node)
            if not isinstance(source, str) or not source:
                raise ValueError("CALL_SITE_SOURCE_REFUSED")
            result[(relative, line, column)] = {
                "expression": source,
                "import_statement": import_statement,
                "module_constants": static_context.module_constants,
                "imported_names": static_context.imported_names,
            }
    return result


def _synthesize_replay(replay_source):
    """Return replay source plus deterministic argument provenance.

    Tests and embedders may inject the historical two-argument synthesizer. The
    production pipeline uses the context-aware synthesizer so bounded folds,
    module constants, and safe nested calls retain their provenance.
    """

    from breakcheck.adapters.python.literals import (
        synthesize_snippet,
        synthesize_with_provenance,
    )

    if _synthesize is synthesize_snippet:
        synthesized = synthesize_with_provenance(
            replay_source["expression"],
            replay_source["import_statement"],
            module_constants=replay_source["module_constants"],
            imported_names=replay_source["imported_names"],
        )
        return synthesized.source, synthesized.provenance
    return (
        _synthesize(
            replay_source["expression"], replay_source["import_statement"]
        ),
        ("SOURCE_LITERAL",),
    )

def _canonical_call_expression(api, expression):
    """Bind a scanned call to its canonical distribution API identity."""
    try:
        call = ast.parse(expression, mode="eval").body
        target = ast.parse(api, mode="eval").body
    except (SyntaxError, ValueError) as exc:
        raise ValueError("CALL_SITE_SOURCE_REFUSED") from exc
    if not isinstance(call, ast.Call) or not isinstance(
        target, (ast.Name, ast.Attribute)
    ):
        raise ValueError("CALL_SITE_SOURCE_REFUSED")
    call.func = target
    ast.fix_missing_locations(call)
    return ast.unparse(call)

def _scan_inventory(root, package, inventory):
    scanner = _Scanner(package)
    imports = []
    call_sites = []
    unsupported = []
    candidates = []
    for source_path in sorted(
        inventory, key=lambda item: item.relative_to(root).as_posix()
    ):
        relative = source_path.relative_to(root).as_posix()
        source_text = source_path.read_text(encoding="utf-8")
        observed = scanner.scan(
            source=source_text, path=relative, package=package
        )
        if not isinstance(observed, dict):
            raise ValueError("CALL_SITE_SCAN_REFUSED")
        observed_imports = observed.get("imports")
        observed_calls = observed.get("call_sites")
        observed_unsupported = observed.get("unsupported", [])
        observed_candidates = observed.get("candidates", [])
        if (not isinstance(observed_imports, list) or not isinstance(observed_calls, list)
                or not isinstance(observed_unsupported, list)
                or not isinstance(observed_candidates, list)):
            raise ValueError("CALL_SITE_SCAN_REFUSED")
        imports.extend(observed_imports)
        call_sites.extend(observed_calls)
        unsupported.extend(observed_unsupported)
        candidates.extend(observed_candidates)
    imports.sort(key=lambda row: _canonical(row))
    call_sites.sort(
        key=lambda row: (
            row.get("file", ""), row.get("line", 0), row.get("column", 0), row.get("api", "")
        ) if isinstance(row, dict) else ("", 0, 0, "")
    )
    unsupported.sort(key=lambda row: _canonical(row))
    candidates.sort(key=lambda row: _canonical(row))
    return {
        "imports": imports,
        "call_sites": call_sites,
        "unsupported": unsupported,
        "candidates": candidates,
    }


def _fixture_suggestion_candidates(repository, scan, inventory):
    grouped = {}
    for row in scan["call_sites"]:
        grouped.setdefault(row["api"], []).append(
            {"file": row["file"], "line": row["line"], "column": row["column"]}
        )
    call_sources = _call_sources(repository, grouped, inventory)
    candidates = []
    for row in sorted(
        scan["call_sites"],
        key=lambda item: (item["file"], item["line"], item["column"], item["api"]),
    ):
        source = call_sources[(row["file"], row["line"], row["column"])]
        try:
            _synthesize_replay(source)
        except Exception as exc:
            if str(exc) != "NONLITERAL_ARGS":
                raise
            candidates.append(
                {
                    **row,
                    "signature": None,
                    "type_hints": None,
                    "nearby_source": source["expression"],
                }
            )
    return candidates


def _write_fixture_suggestions(args, repository, candidates):
    from breakcheck.adapters.python.fixtures import suggest_fixtures

    digest = suggest_fixtures(
        args.suggest_fixtures,
        candidates,
        repository_root=repository,
    )
    print(
        _canonical(
            {
                "schema_version": 1,
                "fixture_suggestions": len(candidates),
                "sha256": digest,
            }
        )
    )
    return 0


def _observation_text(data):
    try:
        return bytes(data or b"").decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("OBSERVATION_ENCODING_REFUSED") from exc


def _process_observation(result):
    if result.get("timed_out"):
        return _normalize({"kind": "timeout", "payload": None,
                           "exception_class": None, "duration_ms": None})
    if result.get("returncode") == 0:
        text = _observation_text(result.get("stdout", b"")).strip()
        try:
            payload = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            payload = text
        return _normalize({"kind": "value", "payload": payload,
                           "exception_class": None, "duration_ms": None})
    lines = [line.strip() for line in _observation_text(
        result.get("stderr", b"")
    ).splitlines() if line.strip()]
    tail = lines[-1] if lines else "RuntimeError: execution failed"
    exception_class, separator, message = tail.partition(":")
    if not separator or not exception_class.isidentifier():
        exception_class, message = "RuntimeError", tail
    return _normalize({"kind": "exception", "payload": [message.strip()],
                       "exception_class": exception_class,
                       "duration_ms": None})


def _repeat_observation(snippet, environment):
    """Run an admitted snippet exactly twice and fail closed on disagreement.

    The injected legacy runner branch preserves the narrow test seam used by the
    schema-1 compatibility suite.  Production always uses the framed private
    protocol, so ordinary stdout can never impersonate an observation.
    """
    from breakcheck.adapters.python.executor import (
        run_repeated_typed_snippet_isolated,
        run_snippet_isolated,
    )

    if _execute is run_snippet_isolated:
        return run_repeated_typed_snippet_isolated(
            snippet_source=snippet,
            environment=environment,
        )
    runs = []
    for _ in range(2):
        observation = _process_observation(
            _execute(snippet_source=snippet, environment=environment)
        )
        runs.append(observation)
    if _digest(runs[0]) != _digest(runs[1]):
        return {
            "runs": runs,
            "repeatable": False,
            "status": "PROTOCOL_REFUSED",
            "reason_code": "NONDETERMINISTIC_OBSERVATION",
            "observation": None,
        }
    return {
        "runs": runs,
        "repeatable": True,
        "status": "VALUE" if runs[0]["kind"] == "value" else "EXCEPTION",
        "reason_code": None,
        "observation": runs[0],
    }


def _typed_refusal(run):
    if run.get("status") in {"VALUE", "EXCEPTION"} and run.get("repeatable"):
        return None
    reason = run.get("reason_code")
    return reason if isinstance(reason, str) and reason else "PROTOCOL_REFUSED"


def _typed_raw_type(run):
    rows = run.get("runs")
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        value = rows[0].get("raw_type")
        if isinstance(value, str) and value:
            return value
    return None


def _fixture_snippet(binding, replay_source):
    from breakcheck.adapters.python.fixtures import render_fixture_source

    try:
        call = ast.parse(replay_source["expression"], mode="eval").body
    except (SyntaxError, ValueError, TypeError) as exc:
        raise ValueError("CALL_SITE_SOURCE_REFUSED") from exc
    if not isinstance(call, ast.Call):
        raise ValueError("CALL_SITE_SOURCE_REFUSED")
    callable_source = ast.unparse(call.func)
    return (
        replay_source["import_statement"]
        + "\n\n"
        + render_fixture_source(binding, callable_source)
    )


def _invocation(args):
    return {
        "allow_empty": bool(getattr(args, "allow_empty", False)),
        "ci": bool(getattr(args, "ci", False)),
        "coverage_report": bool(getattr(args, "coverage_report", None)),
        "fixture_file": getattr(args, "fixtures", None),
        "fixture_policy": getattr(args, "fixture_policy", "forbid"),
        "json": bool(getattr(args, "json", False)),
        "min_coverage": float(getattr(args, "min_coverage", 80.0)),
        "suggest_fixtures": bool(getattr(args, "suggest_fixtures", None)),
    }


def _artifact_invocation(args, repository, kind):
    from breakcheck.schema import canonicalize_invocation

    values = _invocation(args)
    selected = {
        "dependency_report": (
            "allow_empty", "ci", "coverage_report", "fixture_policy", "json",
            "min_coverage", "suggest_fixtures",
        ),
        "coverage_report": (
            "allow_empty", "fixture_policy", "min_coverage", "suggest_fixtures",
        ),
    }[kind]
    flags = {name: values[name] for name in selected}
    fixture_path = getattr(args, "fixtures", None)
    if fixture_path:
        try:
            relative = Path(fixture_path).resolve().relative_to(repository)
        except ValueError as exc:
            raise ValueError("FIXTURE_PATH_REFUSED") from exc
        flags["fixture_file"] = relative.as_posix()
    return canonicalize_invocation(kind, flags)


def _schema_two_observation(observation, provenance):
    return {
        "kind": observation["kind"],
        "payload": copy.deepcopy(observation["payload"]),
        "exception_class": observation["exception_class"],
        "provenance": list(provenance),
    }


def _schema_two_dependency_report(
    legacy_report, terminal_records, args, repository
):
    from breakcheck.schema import (
        artifact_digest,
        make_artifact,
        record_identity,
    )

    terminal_by_location = {
        (row["api"], row["file"], row["line"], row["column"]): row
        for row in terminal_records
    }
    findings = []
    witnesses = []
    for legacy in legacy_report["findings"]:
        site = legacy["call_sites"][0]
        terminal = terminal_by_location[
            (legacy["api"], site["file"], site["line"], site["column"])
        ]
        provenance = terminal["provenance"]
        replay = legacy["repro"]
        projection_source = replay.get("projection")
        projection = (
            None
            if projection_source is None
            else {
                "source": projection_source,
                "sha256": artifact_digest(projection_source),
            }
        )
        finding = {
            "finding_id": "",
            "candidate_id": terminal["candidate_id"],
            "api": legacy["api"],
            "call_sites": copy.deepcopy(legacy["call_sites"]),
            "verdict": legacy["verdict"],
            "old": (
                None
                if legacy["old"] is None
                else _schema_two_observation(legacy["old"], provenance)
            ),
            "new": (
                None
                if legacy["new"] is None
                else _schema_two_observation(legacy["new"], provenance)
            ),
            "reason_code": legacy["reason_code"],
            "reason_detail": terminal.get("reason_detail"),
            "comparison": (
                None if legacy["verdict"] == "NOT_EXERCISED"
                else copy.deepcopy(legacy["comparison"])
            ),
            "projection": projection,
            "fixture_binding_sha256": replay.get("fixture_binding_sha256"),
            "suggested_action": copy.deepcopy(legacy["suggested_action"]),
        }
        finding["finding_id"] = record_identity(finding, "finding_id")
        findings.append(finding)
        if finding["verdict"] != "NOT_EXERCISED":
            old_digest = artifact_digest(finding["old"])
            new_digest = artifact_digest(finding["new"])
            witness = {
                "witness_id": "",
                "finding_id": finding["finding_id"],
                "candidate_id": finding["candidate_id"],
                "old_observation_sha256": old_digest,
                "new_observation_sha256": new_digest,
                "old_repeat_sha256": [old_digest, old_digest],
                "new_repeat_sha256": [new_digest, new_digest],
                "projection_sha256": (
                    None if projection is None else projection["sha256"]
                ),
                "provenance": list(provenance),
                "replay": {
                    "source": replay["code"],
                    "sha256": artifact_digest(replay["code"]),
                },
            }
            witness["witness_id"] = record_identity(witness, "witness_id")
            witnesses.append(witness)
    findings.sort(key=lambda row: row["finding_id"])
    witnesses.sort(key=lambda row: row["witness_id"])
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
    payload = {
        "package": legacy_report["package"],
        "current_version": legacy_report["current_version"],
        "new_version": legacy_report["new_version"],
        "coverage": copy.deepcopy(legacy_report["coverage"]),
        "findings": findings,
        "witnesses": witnesses,
        "summary": summary,
        "invocation": _artifact_invocation(args, repository, "dependency_report"),
    }
    return make_artifact("dependency_report", payload)


def _schema_two_coverage_report(
    package, current_version, new_version, terminal_records, args, repository
):
    from breakcheck.adapters.python.coverage import count_terminal_records
    from breakcheck.schema import make_artifact

    payload = {
        "package": package,
        "current_version": current_version,
        "new_version": new_version,
        "candidates": sorted(
            copy.deepcopy(terminal_records), key=lambda row: row["candidate_id"]
        ),
        "counts": count_terminal_records(terminal_records),
        "invocation": _artifact_invocation(args, repository, "coverage_report"),
    }
    return make_artifact("coverage_report", payload)

def _presence_source(apis):
    return (
        "import importlib\n"
        "_apis = " + repr(tuple(apis)) + "\n"
        "_prefixes = sorted({'.'.join(_api.split('.')[:_cut]) "
        "for _api in _apis for _cut in range(1, len(_api.split('.')))}, "
        "key=lambda _value: (_value.count('.'), _value))\n"
        "_modules = {}\n"
        "for _prefix in _prefixes:\n"
        "    try:\n"
        "        _modules[_prefix] = importlib.import_module(_prefix)\n"
        "    except (ImportError, ModuleNotFoundError):\n"
        "        _modules[_prefix] = None\n"
        "_rows = {}\n"
        "for _api in _apis:\n"
        "    _parts = _api.split('.')\n"
        "    _present = False\n"
        "    for _cut in range(len(_parts) - 1, 0, -1):\n"
        "        _value = _modules.get('.'.join(_parts[:_cut]))\n"
        "        if _value is None:\n"
        "            continue\n"
        "        try:\n"
        "            for _name in _parts[_cut:]:\n"
        "                _value = getattr(_value, _name)\n"
        "            _present = True\n"
        "        except AttributeError:\n"
        "            _present = False\n"
        "        break\n"
        "    _rows[_api] = _present\n"
        "print(repr(_rows))\n"
    )

def _presence_census(apis, environment, batch_size=512):
    ordered = sorted(set(apis))
    observed = {}
    for offset in range(0, len(ordered), batch_size):
        batch = ordered[offset:offset + batch_size]
        row = _process_observation(_execute(
            snippet_source=_presence_source(batch), environment=environment
        ))
        payload = row.get("payload") if isinstance(row, dict) else None
        if (
            not isinstance(payload, dict) or set(payload) != set(batch)
            or any(type(value) is not bool for value in payload.values())
        ):
            raise ValueError("PRESENCE_CENSUS_REFUSED")
        observed.update(payload)
    return observed

def _contextualize_comparison(comparison, expression, old, new):
    result = copy.deepcopy(comparison)
    try:
        call = ast.parse(expression, mode="eval").body
        zero_argument_call = (
            isinstance(call, ast.Call) and not call.args and not call.keywords
        )
    except (SyntaxError, ValueError, TypeError):
        zero_argument_call = False
    detail = result.get("detail") if isinstance(result, dict) else None
    if (
        zero_argument_call and isinstance(detail, dict)
        and detail.get("reason_code") == "VALUE_MISMATCH"
        and isinstance(old, dict) and isinstance(new, dict)
        and old.get("kind") == new.get("kind") == "value"
        and type(old.get("payload")) is int
        and type(new.get("payload")) is int
    ):
        detail["policy"] = "fresh_process_per_observation"
    return result

def _refuse_symlink_components(path):
    absolute = Path(path).absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError("OUTPUT_PATH_REFUSED") from exc
        if stat.S_ISLNK(mode):
            raise ValueError("OUTPUT_PATH_REFUSED")


def _write(path, text):
    destination = Path(path).absolute()
    _refuse_symlink_components(destination.parent)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError("OUTPUT_PATH_REFUSED") from exc
    _refuse_symlink_components(destination.parent)
    if destination.is_symlink():
        raise ValueError("OUTPUT_PATH_REFUSED")
    descriptor = None
    temporary_name = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="." + destination.name + ".",
            suffix=".tmp",
            dir=destination.parent,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = None
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    except OSError as exc:
        raise ValueError("OUTPUT_PATH_REFUSED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _validate_output_paths(args):
    selected = []
    for name in ("output", "evidence", "coverage_report", "suggest_fixtures"):
        value = getattr(args, name, None)
        if value:
            selected.append((name, Path(value).absolute().resolve(strict=False)))
    resolved = [path for _name, path in selected]
    if len(set(resolved)) != len(resolved):
        raise ValueError("OUTPUT_PATH_COLLISION_REFUSED")
    return tuple(selected)

def _console_payload(report, rendered, max_bytes=1000000):
    if len(rendered.encode("utf-8")) <= max_bytes:
        return rendered
    if report.get("schema_version") == 2:
        payload = report["payload"]
        return _canonical({
            "artifact_kind": report["artifact_kind"],
            "coverage": copy.deepcopy(payload.get("coverage")),
            "findings": len(payload.get("findings", [])),
            "summary": copy.deepcopy(payload.get("summary")),
        })
    return _canonical({
        "coverage": copy.deepcopy(report["coverage"]),
        "findings": len(report["findings"]),
        "summary": copy.deepcopy(report["summary"]),
    })

def _artifact_digest(root):
    base = Path(root).resolve()
    rows = []
    if base.is_dir():
        for path in sorted(base.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(base).as_posix()
            if path.is_symlink():
                try:
                    target = path.resolve(strict=True)
                    target_kind = "file" if target.is_file() else "directory"
                    target_sha256 = (
                        hashlib.sha256(target.read_bytes()).hexdigest()
                        if target.is_file() else None
                    )
                    link_value = os.readlink(path)
                except (OSError, RuntimeError) as exc:
                    raise ValueError(
                        "ENVIRONMENT_ARTIFACT_SYMLINK_REFUSED"
                    ) from exc
                rows.append({
                    "kind": "symlink",
                    "path": relative,
                    "mode": stat.S_IMODE(path.lstat().st_mode),
                    "link_sha256": hashlib.sha256(
                        os.fsencode(link_value)
                    ).hexdigest(),
                    "target_kind": target_kind,
                    "target_sha256": target_sha256,
                })
            elif path.is_file():
                metadata = path.stat()
                rows.append({
                    "kind": "file",
                    "path": relative,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "size": metadata.st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                })
    return {"root": str(base), "exists": base.is_dir(),
            "sha256": _digest(rows)}

def _not_exercised(api, call_sites, reason):
    repro = {"snippet_id": _digest({"api": api, "reason": reason}),
             "api": api, "call_sites": copy.deepcopy(call_sites), "code": "",
             "args_source": "refused", "reason_code": reason}
    finding = {"finding_id": "", "api": api,
               "call_sites": copy.deepcopy(call_sites),
               "verdict": "NOT_EXERCISED", "old": None, "new": None,
               "repro": repro,
               "suggested_action": [{"kind": "review", "argument": api}],
               "reason_code": reason,
               "comparison": {"verdict": "IDENTICAL", "detail": {
                   "reason_code": "EQUAL", "path": None,
                   "old_summary": "not_exercised",
                   "new_summary": "not_exercised",
                   "policy": "literal_arguments_required",
               }}}
    finding["finding_id"] = _finding_id(finding)
    return finding

def _public_action_sites(call_sites):
    projected = []
    for site in call_sites:
        location = {"file": site["file"], "line": site["line"]}
        if location not in projected:
            projected.append(location)
        if len(projected) == 3:
            break
    return projected

def _build(args):
    if args.runtime_root:
        return _build_with_runtime(args, Path(args.runtime_root).resolve())
    runtime_root = Path(tempfile.mkdtemp(prefix="breakcheck-runtime-")).resolve()
    try:
        return _build_with_runtime(args, runtime_root)
    finally:
        if runtime_root.is_symlink() or (runtime_root.exists() and not runtime_root.is_dir()):
            runtime_root.unlink(missing_ok=True)
        elif runtime_root.exists():
            shutil.rmtree(runtime_root)


def _build_with_runtime(args, runtime_root):
    _validate_output_paths(args)
    if sys.platform not in _SUPPORTED_PLATFORMS:
        raise ValueError(_PLATFORM_REFUSAL_CODE)
    package, new_version = _target(args.target)
    wheelhouse = args.wheelhouse
    if not wheelhouse and not getattr(args, "suggest_fixtures", None):
        raise ValueError(_WHEELHOUSE_REQUIRED_CODE)
    global _inventory, _Scanner, _synthesize, _EnvironmentBuilder
    global _execute, _normalize, _compare, _finding_id
    global _render_json, _render_human, _exit_code, _verify_report
    (_inventory, _Scanner, _synthesize, _EnvironmentBuilder, _execute,
     _normalize, _compare, _finding_id, _render_json, _render_human,
     _exit_code, _verify_report) = _load_pipeline()
    import_root = _import_root(package)
    repository = Path.cwd().resolve()
    excluded = {runtime_root}
    for value in (args.output, args.evidence):
        if value:
            excluded.add(Path(value).resolve())
    inventoried = _inventory(repository, excluded_paths=excluded)
    inventory = {Path(path).resolve() for path in inventoried}
    scan = _scan_inventory(repository, import_root, inventory)
    call_sites = scan.get("call_sites") if isinstance(scan, dict) else None
    if not isinstance(call_sites, list):
        raise ValueError("CALL_SITE_SCAN_REFUSED")
    suggesting_fixtures = bool(getattr(args, "suggest_fixtures", None))
    suggestion_candidates = (
        _fixture_suggestion_candidates(repository, scan, inventory)
        if suggesting_fixtures else []
    )
    if suggesting_fixtures and not wheelhouse:
        return _write_fixture_suggestions(args, repository, suggestion_candidates)
    try:
        current_version = _metadata.version(package)
    except Exception:
        print(_MISSING_CURRENT, file=sys.stderr)
        return 2
    grouped = {}
    for row in call_sites:
        if not isinstance(row, dict) or set(row) != {"api", "file", "line", "column"}:
            raise ValueError("CALL_SITE_SCHEMA_REFUSED")
        grouped.setdefault(row["api"], []).append(
            {"file": row["file"], "line": row["line"], "column": row["column"]}
        )
    from breakcheck.adapters.python.fixtures import resolve_fixture_policy

    fixture_file = resolve_fixture_policy(
        getattr(args, "fixture_policy", "forbid"),
        fixture_path=getattr(args, "fixtures", None),
        repository_root=repository,
        inventory=call_sites,
    )
    fixture_bindings = {
        binding.key: binding for binding in (() if fixture_file is None else fixture_file.bindings)
    }
    from breakcheck.adapters.python.literals import LiteralRefusal
    
    try:
        pair = _EnvironmentBuilder(
            package=package, current_version=current_version,
            new_version=new_version, wheelhouse=wheelhouse,
            destination=str(runtime_root), allow_network=False,
        ).build()
    except Exception as exc:
        code = _bounded_refusal(exc)
        if code is None:
            raise
        if isinstance(getattr(exc, "detail", None), dict):
            raise
        raise RuntimeError(code) from None
    if not isinstance(pair, dict) or set(pair) != {"current", "new"}:
        raise ValueError("ENVIRONMENT_PAIR_REFUSED")
    findings = []
    witnesses = []
    terminal_records = []
    exercised = 0
    call_sources = _call_sources(repository, grouped, inventory)
    from breakcheck.adapters.python.coverage import (
        count_terminal_records,
        make_candidate,
        terminal_record,
    )
    for row in scan.get("unsupported", []):
        if not isinstance(row, dict) or row.get("reason_code") not in {
            "DYNAMIC_USAGE_UNSUPPORTED", "SOURCE_SYNTAX_REFUSED"
        }:
            raise ValueError("UNSUPPORTED_USAGE_SCHEMA_REFUSED")
        sites = [{"file": row.get("file"), "line": row.get("line"),
                  "column": row.get("column")}]
        findings.append(_not_exercised(
            str(row.get("api", "dynamic")),
            sites,
            row["reason_code"],
        ))
        candidate = make_candidate(
            api=str(row.get("api", "dynamic")),
            file=str(row.get("file")),
            line=int(row.get("line")),
            column=int(row.get("column")),
        )
        terminal_records.append(terminal_record(
            candidate,
            "G1_NOT_DISCOVERABLE",
            reason_code=row["reason_code"],
            provenance=("SOURCE_LITERAL",),
        ))
    prepared = []
    for api in sorted(grouped):
        internal_sites = sorted(
            grouped[api], key=lambda row: (row["file"], row["line"], row["column"])
        )
        for site in internal_sites:
            sites = [{"file": site["file"], "line": site["line"],
                      "column": site["column"]}]
            candidate = make_candidate(
                api=api,
                file=site["file"],
                line=site["line"],
                column=site["column"],
            )
            binding = fixture_bindings.get(
                (site["file"], site["line"], site["column"], api)
            )
            try:
                replay_source = call_sources[
                    (site["file"], site["line"], site["column"])
                ]
                expression = replay_source["expression"]
                if binding is None:
                    snippet, provenance = _synthesize_replay(replay_source)
                    projection = None
                else:
                    snippet = _fixture_snippet(binding, replay_source)
                    provenance = ("OPERATOR_FIXTURE",)
                    projection = binding.projection
            except LiteralRefusal as exc:
                reason = "NONLITERAL_ARGS"
                findings.append(_not_exercised(api, sites, reason))
                terminal_records.append(terminal_record(
                    candidate,
                    "G2_NONLITERAL",
                    reason_code=reason,
                    reason_detail=getattr(exc, "reason_detail", "OTHER"),
                    provenance=("SOURCE_LITERAL",),
                ))
                continue
            prepared.append({
                "api": api,
                "sites": sites,
                "expression": expression,
                "snippet": snippet,
                "site": (site["file"], site["line"], site["column"]),
                "candidate": candidate,
                "provenance": provenance,
                "projection": projection,
                "fixture_binding_sha256": (
                    None if binding is None else binding.binding_sha256
                ),
            })
    prepared_apis = sorted({row["api"] for row in prepared})
    current_presence = _presence_census(
        prepared_apis, pair["current"]
    )
    new_presence = _presence_census(prepared_apis, pair["new"])
    for row in sorted(prepared, key=lambda item: (item["api"], item["site"])):
        api = row["api"]
        sites = row["sites"]
        expression = row["expression"]
        snippet = row["snippet"]
        if not current_presence[api] and not new_presence[api]:
            findings.append(_not_exercised(
                api, sites, "API_ABSENT_BOTH_ENVIRONMENTS"
            ))
            terminal_records.append(terminal_record(
                row["candidate"],
                "G4_IMPURE",
                reason_code="API_ABSENT_BOTH_ENVIRONMENTS",
                environment="both",
                provenance=row["provenance"],
            ))
            continue
        old_run = _repeat_observation(snippet, pair["current"])
        new_run = _repeat_observation(snippet, pair["new"])
        old_refusal = _typed_refusal(old_run)
        new_refusal = _typed_refusal(new_run)
        if old_refusal is not None or new_refusal is not None:
            reason = (
                old_refusal
                if old_refusal is not None and old_refusal == new_refusal
                else old_refusal or new_refusal or "ENVIRONMENT_PAIR_REFUSED"
            )
            findings.append(_not_exercised(api, sites, reason))
            unnormalizable = (
                old_run.get("status") == "UNNORMALIZABLE"
                or new_run.get("status") == "UNNORMALIZABLE"
            )
            if (
                suggesting_fixtures
                and unnormalizable
                and old_run.get("repeatable") is True
                and new_run.get("repeatable") is True
            ):
                old_type = _typed_raw_type(old_run)
                new_type = _typed_raw_type(new_run)
                raw_type = old_type if old_type == new_type else _canonical(
                    {"current": old_type, "new": new_type}
                )
                suggestion_candidates.append(
                    {
                        "api": api,
                        "file": row["site"][0],
                        "line": row["site"][1],
                        "column": row["site"][2],
                        "signature": None,
                        "type_hints": None,
                        "nearby_source": expression,
                        "coverage_bucket": "G3_UNNORMALIZABLE",
                        "reason_code": reason,
                        "raw_type": raw_type,
                        "projection_required": True,
                    }
                )
            terminal_records.append(terminal_record(
                row["candidate"],
                "G3_UNNORMALIZABLE" if unnormalizable else "G4_IMPURE",
                reason_code=reason,
                raw_type=(
                    _typed_raw_type(old_run) or _typed_raw_type(new_run)
                    if unnormalizable else None
                ),
                environment=(
                    "both" if old_refusal is not None and new_refusal is not None
                    else "current" if old_refusal is not None else "new"
                ),
                provenance=row["provenance"],
            ))
            continue
        old = old_run["observation"]
        new = new_run["observation"]
        exercised += 1
        comparison = _contextualize_comparison(
            _compare(old, new), expression, old, new
        )
        verdict = comparison["verdict"]
        if row["projection"] is not None:
            verdict = (
                "IDENTICAL_UNDER_PROJECTION"
                if verdict == "IDENTICAL"
                else "CHANGED_UNDER_PROJECTION"
            )
        actions = [] if verdict in {"IDENTICAL", "IDENTICAL_UNDER_PROJECTION"} else [
            {"kind": "pin", "argument": package + "==" + current_version},
            {"kind": "adapt", "argument": _public_action_sites(sites)},
        ]
        snippet_id = _digest({"api": api, "code": snippet, "call_sites": sites})
        repro = {"snippet_id": snippet_id, "api": api,
                 "call_sites": copy.deepcopy(sites), "code": snippet,
                 "args_source": (
                     "fixture"
                     if "OPERATOR_FIXTURE" in row["provenance"]
                     else "source"
                 ), "reason_code": None,
                 "provenance": list(row["provenance"]),
                 "projection": row["projection"],
                 "fixture_binding_sha256": row["fixture_binding_sha256"]}
        finding = {"finding_id": "", "api": api,
                   "call_sites": copy.deepcopy(sites), "verdict": verdict,
                   "old": old, "new": new, "repro": repro,
                   "suggested_action": actions, "reason_code": None,
                   "comparison": comparison}
        finding["finding_id"] = _finding_id(finding)
        witness = {"witness_id": "", "finding_id": finding["finding_id"],
                   "snippet_id": snippet_id, "api": api, "code": snippet,
                   "current_version": current_version,
                   "new_version": new_version,
                   "old_observation_sha256": _digest(old),
                   "new_observation_sha256": _digest(new)}
        witness["witness_id"] = _digest(witness)
        findings.append(finding)
        witnesses.append(witness)
        terminal_records.append(terminal_record(
            row["candidate"],
            "EXERCISED",
            provenance=row["provenance"],
        ))
    if suggesting_fixtures:
        return _write_fixture_suggestions(args, repository, suggestion_candidates)
    findings.sort(key=lambda row: row["finding_id"])
    witnesses.sort(key=lambda row: row["witness_id"])
    changed = sum(row["verdict"] in {"CHANGED", "CHANGED_UNDER_PROJECTION"} for row in findings)
    identical = sum(row["verdict"] in {"IDENTICAL", "IDENTICAL_UNDER_PROJECTION"} for row in findings)
    refused = sum(row["verdict"] == "NOT_EXERCISED" for row in findings)
    total = len(findings)
    legacy_report = {"schema_version": 1, "package": package,
              "current_version": current_version, "new_version": new_version,
              "coverage": {"exercised": exercised, "total": total,
                           "percent": (100.0 * exercised / total) if total else 0.0},
              "findings": findings, "witnesses": witnesses,
              "summary": {"changed": changed, "identical": identical,
                          "not_exercised": refused},
              "invocation": _invocation(args)}
    report = _schema_two_dependency_report(
        legacy_report, terminal_records, args, repository
    )
    rendered = _render_json(report)
    from breakcheck.schema import artifact_digest, make_artifact

    environment_artifacts = [
        {"name": name, "sha256": _artifact_digest(pair[name])["sha256"]}
        for name in ("current", "new")
    ]
    evidence = make_artifact(
        "evidence",
        {
            "report_artifact_sha256": artifact_digest(report),
            "report_payload_sha256": report["payload_sha256"],
            "report_kind": report["artifact_kind"],
            "witnesses": copy.deepcopy(report["payload"]["witnesses"]),
            "environment_artifacts": environment_artifacts,
            "invocation": copy.deepcopy(report["payload"]["invocation"]),
        },
    )
    if args.output:
        _write(args.output, rendered + "\n")
    if args.evidence:
        _write(args.evidence, _render_json(evidence) + "\n")
    if getattr(args, "coverage_report", None):
        coverage = _schema_two_coverage_report(
            package, current_version, new_version, terminal_records, args, repository
        )
        _write(args.coverage_report, _render_json(coverage) + "\n")
    print(_console_payload(report, rendered) if args.json else _render_human(report))
    percent = report["payload"]["coverage"]["percent"]
    if exercised == 0 and not getattr(args, "allow_empty", False):
        return 4
    if args.ci and percent < float(getattr(args, "min_coverage", 80.0)):
        return 4
    if args.ci:
        return 3 if changed else 0
    return 0

def _verify(args):
    try:
        verify_report = _load_pipeline()[-1]
        report = json.loads(Path(args.verify).read_text(encoding="utf-8"))
        evidence_path = args.evidence or str(Path(args.verify).with_suffix(".witnesses.json"))
        witness = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
        verify_report(report, witness)
        if report.get("schema_version") == 2:
            print("VERIFIED")
            return 0
        if witness.get("witnesses") != report.get("witnesses"):
            raise ValueError("witness rows mismatch")
        artifacts = witness.get("environment_artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != {"current", "new"}:
            raise ValueError("environment artifacts missing")
        for identity in ("current", "new"):
            expected = artifacts[identity]
            if not isinstance(expected, dict) or set(expected) != {"root", "exists", "sha256"}:
                raise ValueError("environment artifact schema mismatch")
            root = Path(expected["root"])
            if expected["exists"] is not True or root.is_symlink() or not root.is_dir():
                raise ValueError("environment artifact missing")
            if _artifact_digest(root) != expected:
                raise ValueError("environment artifact drift")
    except Exception as exc:
        code = _bounded_refusal(exc)
        if code is None and isinstance(exc, ValueError):
            code = "VERIFY_REFUSED"
        if code is None:
            raise
        print("VERIFY_REFUSED:" + code, file=sys.stderr)
        return 2
    print("VERIFIED")
    return 0


def _capabilities():
    return {
        "schema_version": 2,
        "python": ["3.10", "3.11", "3.12", "3.13"],
        "platforms": ["linux", "macos"],
        "report_schemas": [1, 2],
        "features": [
            "claim_attestation",
            "dependency_comparison",
            "fixture_suggestions",
            "projection_suggestions",
            "revision_baselines",
            "revision_comparison",
        ],
        "interactive": False,
        "runtime_dependencies": [],
    }


def _demo(output_root):
    from breakcheck.demo import run_demo

    return run_demo(output_root, _build)


def _present_long_options(arguments):
    return {
        argument.split("=", 1)[0]
        for argument in arguments
        if argument.startswith("--")
    }


def _require_mode_options(parser, arguments, *, mode, allowed):
    unexpected = sorted(_present_long_options(arguments) - set(allowed))
    if unexpected:
        parser.error(
            mode + " mode does not accept: " + ", ".join(unexpected)
        )


def _revision_runtime_root(requested):
    if requested:
        return Path(requested).resolve(), None
    temporary_parent = Path(tempfile.mkdtemp(prefix="breakcheck-revision-"))
    return temporary_parent / "worktrees", temporary_parent


def _load_json_artifact(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("ARTIFACT_INPUT_REFUSED") from exc


def _emit_revision_result(result, args):
    from breakcheck.report import render_human
    from breakcheck.schema import canonical_json

    rendered_report = canonical_json(result.report)
    if args.output:
        _write(args.output, rendered_report + "\n")
    if args.evidence:
        _write(args.evidence, canonical_json(result.evidence) + "\n")
    print(rendered_report if args.json else render_human(result.report))
    return result.exit_code


def _revision_parser(command):
    parser = argparse.ArgumentParser(
        prog="breakcheck " + command,
        description={
            "freeze": "capture a deterministic behavioral baseline for fixture-bound symbols",
            "diff": "compare fixture-bound behavior across two Git revisions",
            "attest": "adjudicate a behavior-preservation claim against an independent revision comparison",
        }[command],
    )
    parser.add_argument(
        "--fixtures",
        default="breakcheck.fixtures.toml",
        help="repository-relative fixture file (default: breakcheck.fixtures.toml)",
    )
    parser.add_argument(
        "--runtime-root",
        help="absent path used for detached worktrees; a temporary path is used by default",
    )
    parser.add_argument(
        "--output",
        required=command == "freeze",
        help="write the canonical report artifact to this path",
    )
    parser.add_argument(
        "--evidence", help="write the matching evidence artifact to this path"
    )
    parser.add_argument("--json", action="store_true", help="print canonical JSON")
    if command == "freeze":
        parser.add_argument(
            "--revision", default="HEAD", help="Git revision to capture (default: HEAD)"
        )
        parser.add_argument(
            "--target",
            action="append",
            default=[],
            help="module.path:symbol target; repeat for multiple targets",
        )
        parser.add_argument(
            "--allow-dirty",
            action="store_true",
            help="request dirty-tree capture; currently refused rather than silently omitting changes",
        )
    elif command == "diff":
        base = parser.add_mutually_exclusive_group(required=True)
        base.add_argument("--base", help="baseline Git revision")
        base.add_argument("--baseline", help="baseline artifact created by freeze")
        parser.add_argument("--head", required=True, help="head Git revision")
        parser.add_argument(
            "--previous-report",
            help="verified earlier revision report used to disclose fixture retuning",
        )
        parser.add_argument(
            "--target",
            action="append",
            default=[],
            help="module.path:symbol target; repeat for multiple targets",
        )
        parser.add_argument(
            "--fixture-source",
            choices=("base", "head", "explicit"),
            default="base",
            help="revision that owns fixture provenance (default: base)",
        )
        parser.add_argument(
            "--allow-empty",
            action="store_true",
            help="permit a comparison with no selected targets and record that choice",
        )
        parser.add_argument(
            "--min-coverage",
            type=_coverage_threshold,
            default=80.0,
            help="minimum exercised target percentage (default: 80)",
        )
        parser.add_argument(
            "--strict-separation",
            action="store_true",
            help="require fixtures to predate the head revision",
        )
    else:
        parser.add_argument("--head", required=True, help="head Git revision")
        parser.add_argument(
            "--claim", required=True, help="repository-relative behavior claim file"
        )
        parser.add_argument(
            "--previous-report",
            help="verified earlier revision report used to disclose fixture retuning",
        )
        parser.add_argument(
            "--fixture-source",
            choices=("base", "head", "explicit"),
            default="base",
            help="revision that owns fixture provenance (default: base)",
        )
        parser.add_argument(
            "--allow-empty",
            action="store_true",
            help="permit an empty target set and record that choice",
        )
        parser.add_argument(
            "--min-coverage",
            type=_coverage_threshold,
            default=80.0,
            help="minimum exercised target percentage (default: 80)",
        )
        parser.add_argument(
            "--strict",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="fail when any claim is unverifiable (default: enabled)",
        )
        parser.add_argument(
            "--strict-separation",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="require fixtures to predate the head revision (default: enabled)",
        )
    return parser


def _revision_command(command, argv):
    from breakcheck.revision_cli import (
        RevisionModeRefusal,
        attest_revision,
        diff_revisions,
        freeze_revision,
    )

    parser = _revision_parser(command)
    args = parser.parse_args(argv)
    _validate_output_paths(args)
    runtime_root, temporary_parent = _revision_runtime_root(args.runtime_root)
    try:
        if command == "freeze":
            result = freeze_revision(
                Path.cwd(),
                revision=args.revision,
                fixture_path=args.fixtures,
                runtime_root=runtime_root,
                targets=args.target,
                allow_dirty=args.allow_dirty,
            )
        elif command == "diff":
            result = diff_revisions(
                Path.cwd(),
                base_revision=args.base,
                baseline=(
                    None if args.baseline is None else _load_json_artifact(args.baseline)
                ),
                previous_report=(
                    None
                    if args.previous_report is None
                    else _load_json_artifact(args.previous_report)
                ),
                head_revision=args.head,
                fixture_path=args.fixtures,
                runtime_root=runtime_root,
                targets=args.target,
                fixture_source=args.fixture_source,
                allow_empty=args.allow_empty,
                min_coverage=args.min_coverage,
                strict_separation=args.strict_separation,
            )
        else:
            result = attest_revision(
                Path.cwd(),
                head_revision=args.head,
                claim_path=args.claim,
                previous_report=(
                    None
                    if args.previous_report is None
                    else _load_json_artifact(args.previous_report)
                ),
                fixture_path=args.fixtures,
                runtime_root=runtime_root,
                fixture_source=args.fixture_source,
                allow_empty=args.allow_empty,
                min_coverage=args.min_coverage,
                strict=args.strict,
                strict_separation=args.strict_separation,
            )
        return _emit_revision_result(result, args)
    except RevisionModeRefusal as exc:
        print("REVISION_REFUSED:" + exc.code, file=sys.stderr)
        _print_refusal_detail(exc)
        return 2
    except ValueError:
        print("REVISION_REFUSED:ARTIFACT_INPUT_REFUSED", file=sys.stderr)
        return 2
    finally:
        if temporary_parent is not None:
            try:
                temporary_parent.rmdir()
            except OSError:
                pass

def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"freeze", "diff", "attest"}:
        return _revision_command(arguments[0], arguments[1:])
    parser = argparse.ArgumentParser(
        prog='breakcheck',
        usage='breakcheck <package>@<new-version> [options]',
        description=(
            "deterministic behavioral comparison for Python dependency upgrades "
            "and source revisions. Isolation is best-effort and is not a "
            "security sandbox."
        ),
        epilog=_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", metavar='<package>@<new-version>', nargs="?")
    parser.add_argument('--json', action="store_true")
    parser.add_argument('--ci', action="store_true")
    parser.add_argument('--verify', metavar="REPORT")
    parser.add_argument(
        '--wheelhouse', dest="wheelhouse",
        help='single explicit local wheel directory; no network or environment fallback',
    )
    parser.add_argument('--output')
    parser.add_argument('--evidence')
    parser.add_argument('--runtime-root')
    parser.add_argument(
        '--capabilities', action="store_true", help="print the machine-readable capability contract"
    )
    parser.add_argument('--output-root', help="absent directory for demonstration artifacts")
    parser.add_argument('--coverage-report', help="write call-site coverage diagnostics")
    parser.add_argument('--fixtures', help="load operator-reviewed fixture bindings")
    parser.add_argument(
        '--fixture-policy', choices=("forbid", "allow", "require"), default="forbid"
    )
    parser.add_argument('--suggest-fixtures', help="write fixture suggestions for unexercised calls")
    parser.add_argument(
        '--min-coverage', type=_coverage_threshold, default=80.0, help="minimum exercised percentage (default: 80)"
    )
    parser.add_argument(
        '--allow-empty', action="store_true", help="permit an empty comparison and record that choice"
    )
    args = parser.parse_args(arguments)
    if args.capabilities:
        if args.target:
            parser.error("capabilities mode is exclusive")
        _require_mode_options(
            parser,
            arguments,
            mode="capabilities",
            allowed=("--capabilities", "--json"),
        )
        print(_canonical(_capabilities()))
        return 0
    if args.target == "demo":
        if not args.output_root:
            parser.error("demo requires --output-root")
        _require_mode_options(
            parser,
            arguments,
            mode="demo",
            allowed=("--output-root",),
        )
        try:
            return _demo(args.output_root)
        except ValueError as exc:
            code = str(exc)
            if code not in _DEMO_REFUSAL_CODES:
                raise
            print("DEMO_REFUSED:" + code, file=sys.stderr)
            return 2
    if args.verify:
        if args.target:
            parser.error("verify mode is exclusive")
        _require_mode_options(
            parser,
            arguments,
            mode="verify",
            allowed=("--verify", "--evidence"),
        )
        return _verify(args)
    if not args.target:
        parser.error("target is required")
    if args.output_root:
        parser.error("--output-root is only valid in demo mode")
    try:
        return _build(args)
    except Exception as exc:
        code = _bounded_refusal(exc)
        if code is None:
            raise
        print("BUILD_REFUSED:" + code, file=sys.stderr)
        _print_refusal_detail(exc)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
