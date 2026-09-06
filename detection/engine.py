"""
Detection engine.

Evaluates normalized findings against the rule registry in
config/detection_rules.py and produces one Detection record per match.

A Detection carries enough context for an analyst to audit WHY a finding
was flagged:

  detection_id        stable id (D-0001..)
  rule_id             e.g. RULE-001
  rule_name           human label
  severity            the floor this rule imposes on affected findings
  description         what the rule fires on
  evidence            the concrete reason this instance fired
  affected_url        the endpoint the detection is about
  finding_ids         the findings the detection attaches to
  recommended_action  what to do about it

Two scopes:
  - "finding" rules fire once per matching finding.
  - "group"   rules fire once per endpoint-group that matches; the detection
              attaches to every finding in that group.
"""

from typing import List, Dict, Any
from urllib.parse import urlparse

from config.detection_rules import RULES, DetectionRule
from config.clean import safe_str


def _endpoint_key(finding: Dict[str, Any]) -> str:
    """Stable endpoint key = host + path (query stripped) for grouping.

    Findings without a parseable URL collapse into a single '(unknown)'
    bucket; they won't usually form multi-finding groups anyway.
    """
    url = finding.get("url", "")
    if not isinstance(url, str) or not url.startswith("http"):
        return "(unknown)"
    try:
        p = urlparse(url)
        return f"{p.netloc}{p.path or '/'}"
    except Exception:
        return "(unknown)"


def _affected_url(finding: Dict[str, Any]) -> str:
    return safe_str(finding.get("url"), "(unknown URL)")


def group_findings_by_endpoint(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group findings by host+path. Returns a list of group dicts:

        {"endpoint": "...", "members": [finding, ...]}
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        key = _endpoint_key(f)
        groups.setdefault(key, []).append(f)
    return [{"endpoint": key, "members": members} for key, members in groups.items()]


def _run_finding_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    for f in findings:
        for rule in RULES:
            if rule.scope != "finding":
                continue
            try:
                evidence = rule.check(f)
            except Exception as exc:  # a buggy rule must never break the pipeline
                evidence = None
                print(f"[detection] {rule.rule_id} check raised: {exc}")
            if evidence:
                detections.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "description": rule.description,
                    "evidence": str(evidence),
                    "affected_url": _affected_url(f),
                    "finding_ids": [f.get("finding_id", "?")],
                    "recommended_action": rule.recommended_action,
                })
    return detections


def _run_group_rules(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    for group in groups:
        members = group["members"]
        if len(members) < 1:
            continue
        for rule in RULES:
            if rule.scope != "group":
                continue
            try:
                result = rule.check(group)
            except Exception as exc:
                result = None
                print(f"[detection] {rule.rule_id} group check raised: {exc}")
            if not result:
                continue
            # group rules return (evidence, finding_ids) naming the specific
            # members the detection applies to (NOT the whole group).
            if isinstance(result, tuple) and len(result) == 2:
                evidence, finding_ids = result
            else:
                # defensive: a rule that returned a bare string attaches to
                # the whole group -- discouraged but tolerated.
                evidence, finding_ids = str(result), [m.get("finding_id", "?") for m in members]
            if not finding_ids:
                # endpoint-level observation with no member findings attached:
                # record the detection for the panel, but it floors nothing.
                member_ids = []
            else:
                member_ids = finding_ids
            detections.append({
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "description": rule.description,
                "evidence": str(evidence),
                "affected_url": group["endpoint"],
                "finding_ids": member_ids,
                "recommended_action": rule.recommended_action,
            })
    return detections


def run_detection(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluate every rule against the findings. Assigns stable detection ids.

    Order is deterministic: finding-scope rules first (in rule order, then
    finding order), then group-scope rules (in rule order, then endpoint
    order). Same input -> same output.
    """
    detections = _run_finding_rules(findings)
    groups = group_findings_by_endpoint(findings)
    detections.extend(_run_group_rules(groups))

    # stable ids
    for idx, d in enumerate(detections, start=1):
        d["detection_id"] = f"D-{idx:04d}"
        # severity should always be a canonical label
        from config.risks import normalize_risk
        d["severity"] = normalize_risk(d["severity"])

    return detections


def attach_detections_to_findings(
    findings: List[Dict[str, Any]],
    detections: List[Dict[str, Any]],
) -> None:
    """Mutates each finding dict, adding:
       - detection_rules   : comma-joined rule ids that fired on it
       - detection_ids     : comma-joined detection ids
       - detection_severity: highest severity among its detections (or '')
    """
    from config.risks import risk_index, normalize_risk
    by_finding: Dict[str, List[Dict[str, Any]]] = {}
    for d in detections:
        for fid in d["finding_ids"]:
            by_finding.setdefault(fid, []).append(d)

    for f in findings:
        fid = f.get("finding_id")
        ds = by_finding.get(fid, [])
        # "—" (em dash) is used instead of the string "None" because pandas'
        # default NA-values list includes "None" and would convert it to NaN
        # on read-back, leaking "nan" into the report CSV.
        f["detection_rules"] = ", ".join(sorted({d["rule_id"] for d in ds})) if ds else "—"
        f["detection_ids"] = ", ".join(sorted({d["detection_id"] for d in ds})) if ds else "—"
        if ds:
            f["detection_severity"] = normalize_risk(
                max((risk_index(d["severity"]) for d in ds), default=0)
            )
        else:
            f["detection_severity"] = "Informational"
