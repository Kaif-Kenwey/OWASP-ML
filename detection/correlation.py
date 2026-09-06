"""
Correlation engine.

Groups findings into correlated security events -- the SIEM-style
reasoning layer of the pipeline. Instead of treating every finding as
independent, findings that hit the same endpoint are bundled into one
event so an analyst sees the multi-vector attack surface at a glance.

The correlation score is deliberately transparent and documented:

    correlation_score = related_findings_count      (>= 2 to qualify)
                      + severity_weight              (max risk index among members, 0..4)
                      + confidence_weight             (1 if any member is High confidence)

Capped at CORRELATION_MAX_SCORE so a single noisy endpoint cannot
dominate the priority queue.

This is NOT severity inflation: a correlated event can escalate its
member findings by at most CORRELATION_ESCALATION_STEP levels, and only
when its score crosses CORRELATION_ESCALATION_SCORE (see config/settings).
"""

from typing import List, Dict, Any
from urllib.parse import urlparse

from config.risks import normalize_risk, risk_index, risk_from_index
from config.clean import safe_str
from config.settings import (
    CORRELATION_MAX_SCORE,
    CORRELATION_MIN_FINDINGS,
    CORRELATION_ESCALATION_SCORE,
)


def _endpoint_key(finding: Dict[str, Any]) -> str:
    url = finding.get("url", "")
    if not isinstance(url, str) or not url.startswith("http"):
        return "(unknown)"
    try:
        p = urlparse(url)
        return f"{p.netloc}{p.path or '/'}"
    except Exception:
        return "(unknown)"


def _event_severity(score: int) -> str:
    """Map a capped correlation score to a severity label."""
    if score >= 6:
        return "Critical"
    if score >= 4:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def correlate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build correlated events from a list of normalized findings.

    Returns a list of event dicts:
      correlation_id   C-0001..
      endpoint         host+path
      finding_ids      members
      attack_types     distinct attack families
      risk_levels      distinct risk labels
      high_confidence  bool (any member High confidence)
      correlation_score capped int score
      severity         derived label
      description      short human description
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for f in findings:
        key = _endpoint_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    events: List[Dict[str, Any]] = []
    idx = 0
    for endpoint in order:
        members = groups[endpoint]
        if len(members) < CORRELATION_MIN_FINDINGS:
            continue
        idx += 1

        attack_types = sorted({safe_str(m.get("attack_type"), "Other") for m in members} - {"Other"} | {safe_str(m.get("attack_type"), "Other") for m in members})
        # keep distinct non-Other attack types, plus "Other" if present
        distinct_attacks = {m.get("attack_type", "Other") for m in members}
        attack_list = sorted(distinct_attacks)

        risk_levels = sorted({normalize_risk(m.get("risk")) for m in members})
        max_risk_index = max((risk_index(normalize_risk(m.get("risk"))) for m in members), default=0)
        high_confidence = any(normalize_risk(m.get("confidence")) == "High" for m in members)
        # confidence_weight (documented): 1 if any member High confidence else 0
        confidence_weight = 1 if high_confidence else 0

        raw_score = len(members) + max_risk_index + confidence_weight
        score = min(raw_score, CORRELATION_MAX_SCORE)
        severity = _event_severity(score)

        description = (
            f"{len(members)} findings across {len(attack_list)} attack "
            f"classe(s) on {endpoint}"
        )

        events.append({
            "correlation_id": f"C-{idx:04d}",
            "endpoint": endpoint,
            "finding_ids": [m.get("finding_id", "?") for m in members],
            "attack_types": attack_list,
            "risk_levels": risk_levels,
            "high_confidence": high_confidence,
            "correlation_score": int(score),
            "severity": severity,
            "description": description,
        })

    return events


def attach_correlations_to_findings(
    findings: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> None:
    """Mutates each finding dict, adding:
       - correlation_id    : the event id (or 'None')
       - correlation_score : the event's capped score (or 0)
       - correlation_severity : the event's severity (or '')
    """
    by_finding: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        for fid in ev["finding_ids"]:
            by_finding[fid] = ev

    for f in findings:
        fid = f.get("finding_id")
        ev = by_finding.get(fid)
        if ev:
            f["correlation_id"] = ev["correlation_id"]
            f["correlation_score"] = ev["correlation_score"]
            f["correlation_severity"] = ev["severity"]
        else:
            # "—" sentinel (pandas-safe; see detection/engine.py)
            f["correlation_id"] = "—"
            f["correlation_score"] = 0
            f["correlation_severity"] = "Informational"


def should_escalate(event: Dict[str, Any]) -> bool:
    """True if a correlated event is strong enough to escalate its members.

    Conservative policy (avoids severity inflation):
      - the event must be a TRUE multi-vector signal -- >= 2 distinct
        non-"Other" attack classes on the same endpoint (the
        "multi-layered attack" the thesis is about), AND
      - the event's correlation_score must cross CORRELATION_ESCALATION_SCORE.

    A large but single-class endpoint group (e.g. 40 Informational findings
    from one fuzzer) is NOT escalated -- it is just a noisy endpoint, not a
    multi-layered attack.
    """
    try:
        cs = int(event.get("correlation_score", 0))
    except (TypeError, ValueError):
        cs = 0
    if cs < CORRELATION_ESCALATION_SCORE:
        return False
    attacks = [a for a in event.get("attack_types", []) if a and a != "Other"]
    return len(set(attacks)) >= 2


def member_should_escalate(finding: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """True if THIS finding should be escalated by its correlated event.

    Even for a true multi-vector event, we only escalate findings that are
    already at least Medium (max of scanner risk + ML prediction). Bumping
    an Informational finding to High purely because it shares an endpoint
    with diverse attacks would be noise, not signal.
    """
    if not should_escalate(event):
        return False
    from config.risks import risk_index, normalize_risk
    base = max(
        risk_index(normalize_risk(finding.get("original_risk", "Informational"))),
        risk_index(normalize_risk(finding.get("predicted_risk", "Unknown"))),
    )
    return base >= risk_index("Medium")
