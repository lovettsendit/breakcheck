from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.metadata as _metadata
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

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

_HELP_PREFIX = 'target grammar: <package>@<new-version>; flags: --json, --ci, --verify, --wheelhouse, --output, --evidence, --runtime-root; an explicit local wheelhouse is required; CI coverage threshold: 80.0; exit 0, exit 3, exit 4; refusal codes: '
_MISSING_CURRENT = "CURRENT_DISTRIBUTION_MISSING"

_SUPPORTED_PLATFORMS = frozenset(('linux', 'darwin'))
_PLATFORM_REFUSAL_CODE = 'PLATFORM_REFUSED'
_WHEELHOUSE_REQUIRED_CODE = 'WHEELHOUSE_REQUIRED'
_OPERATIONAL_EXCEPTION_CODES = {'ImportError': 'PIPELINE_IMPORT_REFUSED', 'OSError': 'FILESYSTEM_REFUSED', 'UnicodeError': 'TEXT_ENCODING_REFUSED'}
_DECLARED_REFUSAL_CODES = frozenset(('NONLITERAL_ARGS', 'CURRENT_DISTRIBUTION_MISSING', 'PLATFORM_REFUSED', 'WHEELHOUSE_REQUIRED', 'MISSING_WHEEL_REFUSED', 'PIPELINE_IMPORT_REFUSED', 'FILESYSTEM_REFUSED', 'TEXT_ENCODING_REFUSED')) | frozenset(('API_ABSENT_BOTH_ENVIRONMENTS', 'CALL_SITE_PATH_REFUSED', 'CALL_SITE_SCAN_REFUSED', 'CALL_SITE_SCHEMA_REFUSED', 'CALL_SITE_SOURCE_REFUSED', 'ENVIRONMENT_ARTIFACT_SYMLINK_REFUSED', 'ENVIRONMENT_PAIR_REFUSED', 'IMPORT_ROOT_REFUSED', 'INVENTORY_ROOT_SYMLINK_REFUSED', 'OBSERVATION_ENCODING_REFUSED', 'PRESENCE_CENSUS_REFUSED', 'SOURCE_SYNTAX_REFUSED', 'TARGET_GRAMMAR_REFUSED', 'UNSUPPORTED_USAGE_SCHEMA_REFUSED', 'WHEELHOUSE_REFUSED'))
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

def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()

def _bounded_workers(value):
    if value < 1: raise ValueError("workers must be positive")
    return min(value, 8)

def _target(value):
    if not isinstance(value, str) or value.count("@") != 1:
        raise ValueError("TARGET_GRAMMAR_REFUSED")
    package, version = value.split("@", 1)
    if (not package or not version or package != package.strip() or
            version != version.strip() or any(char.isspace() for char in value)):
        raise ValueError("TARGET_GRAMMAR_REFUSED")
    return package, version

def _import_root(package):
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
        matches = {item: [] for item in by_file[relative]}
        for node in ast.walk(tree):
            key = (getattr(node, "lineno", None), getattr(node, "col_offset", None))
            if isinstance(node, ast.Call) and key in matches:
                matches[key].append(node)
        for line, column in sorted(matches):
            nodes = matches[(line, column)]
            if not nodes:
                raise ValueError("CALL_SITE_SOURCE_REFUSED")
            source = _node_source(lines, nodes[0])
            if not isinstance(source, str) or not source:
                raise ValueError("CALL_SITE_SOURCE_REFUSED")
            result[(relative, line, column)] = {
                "expression": source,
                "import_statement": _replay_import_statement(
                    tree,
                    nodes[0],
                    requested[(relative, line, column)],
                ),
            }
    return result

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
        if (not isinstance(observed_imports, list) or not isinstance(observed_calls, list)
                or not isinstance(observed_unsupported, list)):
            raise ValueError("CALL_SITE_SCAN_REFUSED")
        imports.extend(observed_imports)
        call_sites.extend(observed_calls)
        unsupported.extend(observed_unsupported)
    imports.sort(key=lambda row: _canonical(row))
    call_sites.sort(
        key=lambda row: (
            row.get("file", ""), row.get("line", 0), row.get("column", 0), row.get("api", "")
        ) if isinstance(row, dict) else ("", 0, 0, "")
    )
    unsupported.sort(key=lambda row: _canonical(row))
    return {"imports": imports, "call_sites": call_sites, "unsupported": unsupported}

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

def _write(path, text):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(destination)

def _console_payload(report, rendered, max_bytes=1000000):
    if len(rendered.encode("utf-8")) <= max_bytes:
        return rendered
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
    if sys.platform not in _SUPPORTED_PLATFORMS:
        raise ValueError(_PLATFORM_REFUSAL_CODE)
    package, new_version = _target(args.target)
    wheelhouse = args.wheelhouse
    if not wheelhouse:
        raise ValueError(_WHEELHOUSE_REQUIRED_CODE)
    try:
        current_version = _metadata.version(package)
    except Exception:
        print(_MISSING_CURRENT, file=sys.stderr)
        return 2
    global _inventory, _Scanner, _synthesize, _EnvironmentBuilder
    global _execute, _normalize, _compare, _finding_id
    global _render_json, _render_human, _exit_code, _verify_report
    (_inventory, _Scanner, _synthesize, _EnvironmentBuilder, _execute,
     _normalize, _compare, _finding_id, _render_json, _render_human,
     _exit_code, _verify_report) = _load_pipeline()
    import_root = _import_root(package)
    repository = Path.cwd().resolve()
    runtime_root = Path(args.runtime_root).resolve() if args.runtime_root else Path(
        tempfile.mkdtemp(prefix='breakcheck-runtime-')
    ).resolve()
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
    grouped = {}
    for row in call_sites:
        if not isinstance(row, dict) or set(row) != {"api", "file", "line", "column"}:
            raise ValueError("CALL_SITE_SCHEMA_REFUSED")
        grouped.setdefault(row["api"], []).append(
            {"file": row["file"], "line": row["line"], "column": row["column"]}
        )
    
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
        raise RuntimeError(code) from None
    if not isinstance(pair, dict) or set(pair) != {"current", "new"}:
        raise ValueError("ENVIRONMENT_PAIR_REFUSED")
    findings = []
    witnesses = []
    exercised = 0
    call_sources = _call_sources(repository, grouped, inventory)
    for row in scan.get("unsupported", []):
        if not isinstance(row, dict) or row.get("reason_code") not in {
            "DYNAMIC_USAGE_UNSUPPORTED", "SOURCE_SYNTAX_REFUSED"
        }:
            raise ValueError("UNSUPPORTED_USAGE_SCHEMA_REFUSED")
        findings.append(_not_exercised(
            str(row.get("api", "dynamic")),
            [{"file": row.get("file"), "line": row.get("line"),
              "column": row.get("column")}],
            row["reason_code"],
        ))
    prepared = []
    for api in sorted(grouped):
        internal_sites = sorted(
            grouped[api], key=lambda row: (row["file"], row["line"], row["column"])
        )
        for site in internal_sites:
            sites = [{"file": site["file"], "line": site["line"],
                      "column": site["column"]}]
            try:
                replay_source = call_sources[
                    (site["file"], site["line"], site["column"])
                ]
                expression = replay_source["expression"]
                snippet = _synthesize(
                    expression, replay_source["import_statement"]
                )
            except Exception as exc:
                reason = (
                    "DYNAMIC_USAGE_UNSUPPORTED"
                    if str(exc) == "DYNAMIC_USAGE_UNSUPPORTED"
                    else "NONLITERAL_ARGS"
                )
                findings.append(_not_exercised(api, sites, reason))
                continue
            prepared.append({
                "api": api,
                "sites": sites,
                "expression": expression,
                "snippet": snippet,
                "site": (site["file"], site["line"], site["column"]),
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
            continue
        old = _process_observation(_execute(
            snippet_source=snippet, environment=pair["current"]
        ))
        new = _process_observation(_execute(
            snippet_source=snippet, environment=pair["new"]
        ))
        exercised += 1
        comparison = _contextualize_comparison(
            _compare(old, new), expression, old, new
        )
        verdict = comparison["verdict"]
        actions = [] if verdict == "IDENTICAL" else [
            {"kind": "pin", "argument": package + "==" + current_version},
            {"kind": "adapt", "argument": _public_action_sites(sites)},
        ]
        snippet_id = _digest({"api": api, "code": snippet, "call_sites": sites})
        repro = {"snippet_id": snippet_id, "api": api,
                 "call_sites": copy.deepcopy(sites), "code": snippet,
                 "args_source": "literal", "reason_code": None}
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
    findings.sort(key=lambda row: row["finding_id"])
    witnesses.sort(key=lambda row: row["witness_id"])
    changed = sum(row["verdict"] == "CHANGED" for row in findings)
    identical = sum(row["verdict"] == "IDENTICAL" for row in findings)
    refused = sum(row["verdict"] == "NOT_EXERCISED" for row in findings)
    total = len(findings)
    report = {"schema_version": 1, "package": package,
              "current_version": current_version, "new_version": new_version,
              "coverage": {"exercised": exercised, "total": total,
                           "percent": (100.0 * exercised / total) if total else 0.0},
              "findings": findings, "witnesses": witnesses,
              "summary": {"changed": changed, "identical": identical,
                          "not_exercised": refused}}
    rendered = _render_json(report)
    evidence = {"report": report, "report_sha256": _digest(report),
                "witnesses": witnesses,
                "environment_artifacts": {
                    "current": _artifact_digest(pair["current"]),
                    "new": _artifact_digest(pair["new"]),
                }}
    evidence["witness_sha256"] = _digest(evidence)
    if args.output:
        _write(args.output, rendered + "\n")
    if args.evidence:
        _write(args.evidence, _canonical(evidence) + "\n")
    print(_console_payload(report, rendered) if args.json else _render_human(report))
    return _exit_code(report) if args.ci else 0

def _verify(args):
    try:
        verify_report = _load_pipeline()[-1]
        report = json.loads(Path(args.verify).read_text(encoding="utf-8"))
        evidence_path = args.evidence or str(Path(args.verify).with_suffix(".witnesses.json"))
        witness = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
        verify_report(report, witness)
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

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='breakcheck',
        usage='breakcheck <package>@<new-version> [options]',
        description=('behavioral upgrade analysis via sandboxed replay.' +
            " Isolation is best-effort and not a security sandbox."),
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
    args = parser.parse_args(argv)
    if args.verify:
        if args.target: parser.error("verify mode is exclusive")
        return _verify(args)
    if not args.target: parser.error("target is required")
    try:
        return _build(args)
    except Exception as exc:
        code = _bounded_refusal(exc)
        if code is None:
            raise
        print("BUILD_REFUSED:" + code, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
