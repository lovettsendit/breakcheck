import copy
import hashlib
import json

_THRESHOLD = 80.0
_CLEAN = 0
_CHANGED = 3
_COVERAGE = 4

def _mapping(value):
    if hasattr(value, "to_dict") and callable(value.to_dict): value = value.to_dict()
    if not isinstance(value, dict): raise TypeError("record must be a mapping")
    return copy.deepcopy(value)

def _without_id(value):
    return {key: item for key, item in _mapping(value).items() if key != "finding_id"}

def finding_id(finding):
    raw = json.dumps(_without_id(finding), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def suggested_action(finding):
    item = _mapping(finding)
    verdict = item.get("verdict")
    if verdict == "IDENTICAL": return []
    if verdict == "CHANGED":
        actions = [{"kind": "pin", "argument": item.get("api")}]
        call_sites = copy.deepcopy(item.get("call_sites", []))
        if 1 <= len(call_sites) <= 3: actions.append({"kind": "adapt", "argument": call_sites})
        return actions
    return [{"kind": "review", "argument": item.get("api")}]

def _ordered(report):
    value = _mapping(report)
    findings = []
    for finding in value.get("findings", []):
        item = _mapping(finding)
        if not item.get("finding_id"): item["finding_id"] = finding_id(item)
        findings.append(item)
    value["findings"] = sorted(findings, key=lambda item: (item.get("finding_id", ""), json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True)))
    return value

def render_json(report):
    if isinstance(report, dict) and report.get("schema_version") == 2:
        from breakcheck.schema import canonical_json, validate_artifact

        return canonical_json(validate_artifact(report))
    return json.dumps(_ordered(report), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def render_human(report):
    if isinstance(report, dict) and report.get("schema_version") == 2:
        from breakcheck.schema import validate_artifact

        artifact = validate_artifact(report)
        kind = artifact["artifact_kind"]
        payload = artifact["payload"]
        if kind == "claim_report":
            summary = payload["summary"]
            lines = [
                "claims "
                + "CLAIM_VERIFIED=" + str(summary["claim_verified"])
                + " CLAIM_REFUTED=" + str(summary["claim_refuted"])
                + " CLAIM_UNVERIFIABLE=" + str(summary["claim_unverifiable"])
                + " CLAIM_OUT_OF_SCOPE=" + str(summary["claim_out_of_scope"])
            ]
            for item in payload["dispositions"]:
                scope = (
                    " projection=" + item["projection_scope"]
                    if item["projection_scope"] is not None
                    else ""
                )
                lines.append(
                    item["disposition_id"]
                    + " "
                    + item["disposition"]
                    + scope
                )
            for event in payload["fixture_revision_events"]:
                lines.append(
                    "warning "
                    + event["reason_code"]
                    + " target="
                    + event["target_id"]
                )
            return "\n".join(lines)
        if kind == "coverage_report":
            counts = payload["counts"]
            return "coverage " + " ".join(
                name + "=" + str(counts[name])
                for name in (
                    "EXERCISED",
                    "G1_NOT_DISCOVERABLE",
                    "G2_NONLITERAL",
                    "G3_UNNORMALIZABLE",
                    "G4_IMPURE",
                )
            )
        if kind not in ("dependency_report", "revision_report"):
            return "artifact=" + kind
        summary = payload["summary"]
        summary_line = (
            "verdicts "
            + "IDENTICAL=" + str(summary["identical"])
            + " CHANGED=" + str(summary["changed"])
            + " IDENTICAL_UNDER_PROJECTION="
            + str(summary["identical_under_projection"])
            + " CHANGED_UNDER_PROJECTION="
            + str(summary["changed_under_projection"])
            + " NOT_EXERCISED=" + str(summary["not_exercised"])
        )
        lines = [summary_line]
        for item in payload["findings"]:
            identity = item["finding_id"]
            verdict = item["verdict"]
            projection = item.get("projection")
            scope = (
                " projection=" + projection["source"]
                if projection is not None
                else ""
            )
            lines.append(identity + " " + verdict + scope)
        if kind == "revision_report":
            for event in payload["fixture_revision_events"]:
                lines.append(
                    "warning "
                    + event["reason_code"]
                    + " target="
                    + event["target_id"]
                )
        return "\n".join(lines)
    value = _ordered(report)
    lines = ["coverage=" + str(value.get("coverage", {}).get("percent")), "findings="]
    for item in value["findings"]:
        lines.append(item.get("finding_id", "") + " " + str(item.get("verdict", "")) + " " + str(copy.deepcopy(item.get("suggested_action", []))))
    return "\n".join(lines)

def ci_exit_code(report):
    if isinstance(report, dict) and report.get("schema_version") == 2:
        from breakcheck.schema import validate_artifact

        artifact = validate_artifact(report)
        if artifact["artifact_kind"] == "claim_report":
            from breakcheck.core.claims import claim_exit_code

            payload = artifact["payload"]
            return claim_exit_code(
                {
                    "dispositions": payload["dispositions"],
                    "invocation": payload["invocation"],
                }
            )
        if artifact["artifact_kind"] not in ("dependency_report", "revision_report"):
            return _CLEAN
        payload = artifact["payload"]
        invocation = {row["name"]: row["value"] for row in payload["invocation"]}
        if artifact["artifact_kind"] == "dependency_report":
            percent = payload["coverage"]["percent"]
            if percent < invocation.get("min_coverage", _THRESHOLD):
                return _COVERAGE
        if any(
            item["verdict"] in ("CHANGED", "CHANGED_UNDER_PROJECTION")
            for item in payload["findings"]
        ):
            return _CHANGED
        if artifact["artifact_kind"] == "revision_report":
            total = len(payload["findings"])
            exercised = sum(
                item["verdict"] != "NOT_EXERCISED" for item in payload["findings"]
            )
            percent = 0.0 if total == 0 else 100.0 * exercised / total
            if percent < invocation.get("min_coverage", _THRESHOLD):
                return _COVERAGE
        return _CLEAN
    value = _ordered(report)
    coverage = value.get("coverage", {})
    percent = coverage.get("percent", 0) if isinstance(coverage, dict) else 0
    if percent < _THRESHOLD: return _COVERAGE
    if any(item.get("verdict") == "CHANGED" for item in value.get("findings", [])): return _CHANGED
    return _CLEAN
