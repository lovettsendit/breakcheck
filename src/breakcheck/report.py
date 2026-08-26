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
    return json.dumps(_ordered(report), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def render_human(report):
    value = _ordered(report)
    lines = ["coverage=" + str(value.get("coverage", {}).get("percent")), "findings="]
    for item in value["findings"]:
        lines.append(item.get("finding_id", "") + " " + str(item.get("verdict", "")) + " " + str(copy.deepcopy(item.get("suggested_action", []))))
    return "\n".join(lines)

def ci_exit_code(report):
    value = _ordered(report)
    coverage = value.get("coverage", {})
    percent = coverage.get("percent", 0) if isinstance(coverage, dict) else 0
    if percent < _THRESHOLD: return _COVERAGE
    if any(item.get("verdict") == "CHANGED" for item in value.get("findings", [])): return _CHANGED
    return _CLEAN
