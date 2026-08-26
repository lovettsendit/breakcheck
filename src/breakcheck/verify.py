import copy
import hashlib
import json

def _plain(value):
    if hasattr(value, "to_dict") and callable(value.to_dict): return value.to_dict()
    return value

def _digest(value):
    return hashlib.sha256(json.dumps(_plain(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _without_identity(value, field):
    if not isinstance(value, dict):
        raise ValueError(field + " row malformed")
    copied = copy.deepcopy(value)
    observed = copied.pop(field, None)
    return observed, copied


def verify_report(report, witness):
    report = _plain(report)
    if not isinstance(report, dict):
        raise ValueError("report malformed")
    if not isinstance(witness, dict) or witness.get("report") != report: raise ValueError("witness mismatch")
    if witness.get("report_sha256") != _digest(report): raise ValueError("report hash mismatch")
    if "witness_sha256" not in witness:
        raise ValueError("witness hash missing")
    value = copy.deepcopy(witness)
    expected = value.pop("witness_sha256")
    if expected != _digest(value): raise ValueError("witness hash mismatch")
    findings = report.get("findings")
    witnesses = report.get("witnesses")
    if not isinstance(findings, list) or not isinstance(witnesses, list):
        raise ValueError("report rows malformed")
    if witness.get("witnesses") != witnesses:
        raise ValueError("witness rows mismatch")
    by_finding = {}
    exercised_ids = set()
    for finding in findings:
        observed, identity_payload = _without_identity(finding, "finding_id")
        if observed != _digest(identity_payload):
            raise ValueError("finding identity mismatch")
        if observed in by_finding:
            raise ValueError("duplicate finding identity")
        by_finding[observed] = finding
        if finding.get("verdict") in ("IDENTICAL", "CHANGED"):
            exercised_ids.add(observed)
    witnessed_ids = set()
    for row in witnesses:
        if not isinstance(row, dict):
            raise ValueError("witness_id row malformed")
        observed = row.get("witness_id")
        identity_payload = copy.deepcopy(row)
        identity_payload["witness_id"] = ""
        if observed != _digest(identity_payload):
            raise ValueError("witness identity mismatch")
        finding = by_finding.get(row.get("finding_id"))
        if finding is None or row.get("finding_id") in witnessed_ids:
            raise ValueError("witness finding mismatch")
        witnessed_ids.add(row["finding_id"])
        repro = finding.get("repro")
        if not isinstance(repro, dict) or (
            row.get("api") != finding.get("api")
            or row.get("code") != repro.get("code")
            or row.get("snippet_id") != repro.get("snippet_id")
            or row.get("current_version") != report.get("current_version")
            or row.get("new_version") != report.get("new_version")
            or row.get("old_observation_sha256") != _digest(finding.get("old"))
            or row.get("new_observation_sha256") != _digest(finding.get("new"))
        ):
            raise ValueError("witness content mismatch")
    if witnessed_ids != exercised_ids:
        raise ValueError("witness coverage mismatch")
    return 'VERIFIED'
