"""
Detection rule definitions for the OWASP-ML detection-engineering layer.

Each rule is a declarative DetectionRule with:
  - rule_id        : stable identifier shown in the dashboard
  - name           : short label
  - severity       : the floor this rule imposes on affected findings
  - description    : what the rule fires on (human-readable)
  - recommended_action : what the analyst should do
  - scope          : "finding" (per-alert) or "group" (needs the engine to
                     pre-group findings by endpoint)
  - check          : predicate returning evidence when the rule fires

Return contract (IMPORTANT -- avoids severity inflation):
  - finding-scope: check(finding) -> Optional[str]
        Returns an evidence string, or None. The detection attaches to that
        single finding and floors its risk to the rule's severity.
  - group-scope:   check(group) -> Optional[(evidence_str, finding_ids)]
        Returns (evidence, [finding_id, ...]) naming EXACTLY the member
        findings the detection applies to, or None. Returning the whole
        group would floor every member (including unrelated Informational
        findings) up to the rule severity -- that is severity inflation and
        is forbidden by the project's risk policy.

Rules are intentionally lightweight and transparent -- they are NOT an ML
prediction. They add SIEM-inspired reasoning on top of normalized findings,
and their evidence is surfaced verbatim in the dashboard so an analyst can
audit why a finding was flagged.

Adding a rule = append one DetectionRule here + (optionally) a test in
tests/test_detection.py. The detection engine picks it up automatically.
"""

from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Tuple, Union

from config.risks import normalize_risk, risk_index
from config.settings import ANOMALY_SCORE_THRESHOLD


# Attack families that are "injection-shaped" -- used by RULE-002 and RULE-004.
INJECTION_ATTACKS = {
    "SQL Injection",
    "Cross Site Scripting (XSS)",
    "Command Injection",
}


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    severity: str           # Critical / High / Medium / Low / Informational
    description: str
    recommended_action: str
    scope: str              # "finding" or "group"
    # predicate signature depends on scope:
    #   finding -> check(finding: dict) -> Optional[str]   (evidence string)
    #   group   -> check(group: dict)   -> Optional[str]
    check: Callable = field(repr=False)


# ---------------------------------------------------------------------------
# Per-finding rules
# ---------------------------------------------------------------------------

def _check_rule_001(f: dict) -> Optional[str]:
    """RULE-001: High-confidence SQL Injection."""
    if f.get("attack_type") == "SQL Injection" and normalize_risk(f.get("confidence")) == "High":
        return "SQL Injection finding reported with High scanner confidence"
    return None


def _check_rule_003(f: dict) -> Optional[str]:
    """RULE-003: High-risk authentication finding."""
    if f.get("attack_type") in {"Broken Authentication", "Broken Access Control"} \
            and risk_index(normalize_risk(f.get("risk"))) >= risk_index("Medium"):
        return f"{f.get('attack_type')} with scanner risk >= Medium"
    return None


def _check_rule_004(f: dict) -> Optional[str]:
    """RULE-004: Suspicious parameterized endpoint carrying an injection finding."""
    if f.get("has_query_params") == 1 and f.get("attack_type") in INJECTION_ATTACKS:
        return f"Endpoint exposes query parameters and carries {f.get('attack_type')}"
    return None


def _check_rule_006(f: dict) -> Optional[str]:
    """RULE-006: Anomalous finding (IsolationForest anomaly score above threshold).

    The anomaly score is the negated IsolationForest decision_function clamped
    to [0,1]; values > 0 correspond to points the model itself classified as
    anomalous (decision_function < 0). We use a small epsilon so a strict 0.0
    does not fire on floating-point dust.
    """
    score = f.get("anomaly_score")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    if score is not None and score > 0.001:
        return f"IsolationForest anomaly score {score:.4f} (> 0, model-flagged anomalous)"
    return None


# ---------------------------------------------------------------------------
# Group rules (the engine pre-groups findings by endpoint = host+path)
#
# Each group check returns (evidence_str, [finding_id, ...]) naming EXACTLY
# the member findings the detection applies to, or None. Returning the whole
# group would floor every member (incl. unrelated Informational findings)
# up to the rule severity -- that is severity inflation and is forbidden.
# ---------------------------------------------------------------------------

def _check_rule_002(group: dict) -> Optional[Tuple[str, List[str]]]:
    """RULE-002: Potential injection chain on one endpoint.

    Fires when >= 2 distinct injection classes appear on the same endpoint.
    The detection attaches ONLY to the injection-class members (not the
    whole endpoint), so non-injection findings on the same URL are not
    inflated.
    """
    members: List[dict] = group["members"]
    injection_members = [m for m in members if m.get("attack_type") in INJECTION_ATTACKS]
    injection_classes = {m.get("attack_type") for m in injection_members}
    if len(injection_classes) >= 2:
        evidence = (
            f"Multiple injection classes on the same endpoint: "
            f"{', '.join(sorted(injection_classes))}"
        )
        fids = [m.get("finding_id", "?") for m in injection_members]
        return (evidence, fids)
    return None


def _check_rule_005(group: dict) -> Optional[Tuple[str, List[str]]]:
    """RULE-005: Repeated high-risk findings on one endpoint.

    Fires when >= 2 High/Critical findings affect the same endpoint. The
    detection attaches ONLY to those High/Critical members (not Informational
    findings that happen to share the URL).
    """
    members: List[dict] = group["members"]
    high_or_critical = [m for m in members
                         if risk_index(normalize_risk(m.get("risk"))) >= risk_index("High")]
    if len(high_or_critical) >= 2:
        evidence = (
            f"{len(high_or_critical)} High/Critical findings on the same endpoint "
            f"({group['endpoint']})"
        )
        fids = [m.get("finding_id", "?") for m in high_or_critical]
        return (evidence, fids)
    return None


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: List[DetectionRule] = [
    DetectionRule(
        rule_id="RULE-001",
        name="High Confidence SQL Injection",
        severity="Critical",
        description=(
            "A SQL Injection finding reported by the scanner with High "
            "confidence. Treat as exploitable until proven otherwise."
        ),
        recommended_action=(
            "Parameterize the query, use a prepared statement / ORM with "
            "bound parameters, validate input, and apply least privilege to "
            "the database account."
        ),
        scope="finding",
        check=_check_rule_001,
    ),
    DetectionRule(
        rule_id="RULE-002",
        name="Injection Chain on Endpoint",
        severity="High",
        description=(
            "Two or more distinct injection classes (SQLi, XSS, command "
            "injection) affect the same endpoint -- a likely multi-vector "
            "attack surface worth prioritizing."
        ),
        recommended_action=(
            "Review the endpoint holistically: harden input handling for "
            "every parameter, add context-aware output encoding, and verify "
            "no parameter reaches a shell or SQL string."
        ),
        scope="group",
        check=_check_rule_002,
    ),
    DetectionRule(
        rule_id="RULE-003",
        name="High-Risk Authentication Finding",
        severity="High",
        description=(
            "Broken Authentication / Broken Access Control finding with "
            "scanner risk of Medium or above."
        ),
        recommended_action=(
            "Audit session handling, enforce MFA, rotate credentials if "
            "exposed, and verify authorization checks on every state-changing "
            "endpoint."
        ),
        scope="finding",
        check=_check_rule_003,
    ),
    DetectionRule(
        rule_id="RULE-004",
        name="Suspicious Parameterized Endpoint",
        severity="Medium",
        description=(
            "Endpoint exposes query parameters and carries an injection-class "
            "finding -- parameters are the most common injection vector."
        ),
        recommended_action=(
            "Validate and encode every parameter on this endpoint; consider "
            "an allowlist for accepted parameter values."
        ),
        scope="finding",
        check=_check_rule_004,
    ),
    DetectionRule(
        rule_id="RULE-005",
        name="Repeated High-Risk Endpoint",
        severity="High",
        description=(
            "Two or more High/Critical findings affect the same endpoint -- "
            "concentrated risk that is cheap to remediate in one pass."
        ),
        recommended_action=(
            "Prioritize this endpoint for a focused fix pass; one change "
            "can close multiple findings."
        ),
        scope="group",
        check=_check_rule_005,
    ),
    DetectionRule(
        rule_id="RULE-006",
        name="Anomalous Finding",
        severity="Medium",
        description=(
            "The IsolationForest anomaly score for this finding exceeds the "
            "configured threshold, marking it statistically unusual relative "
            "to the rest of the scan."
        ),
        recommended_action=(
            "Manually review the finding: anomaly signals unusualness, not "
            "necessarily exploitability. Confirm or dismiss with evidence."
        ),
        scope="finding",
        check=_check_rule_006,
    ),
]


def get_rule(rule_id: str) -> Optional[DetectionRule]:
    for r in RULES:
        if r.rule_id == rule_id:
            return r
    return None


def rule_map() -> Dict[str, DetectionRule]:
    return {r.rule_id: r for r in RULES}
