"""
Unit tests for the detection-engineering layer.

Covers:
  - each detection rule (RULE-001..006) fires on the right findings and not
    on irrelevant ones
  - group rules return the specific finding_ids they apply to (the
    anti-severity-inflation contract)
  - correlation engine builds events from shared endpoints, with the
    documented capped score formula
  - correlation escalation is conservative (only multi-vector events, only
    already-serious members)

Runs without ZAP or trained models -- pure logic over synthetic findings.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.detection_rules import RULES, rule_map
from config.risks import normalize_risk, risk_index
from detection.engine import run_detection, attach_detections_to_findings, group_findings_by_endpoint
from detection.correlation import (
    correlate,
    attach_correlations_to_findings,
    should_escalate,
    member_should_escalate,
)


def _finding(**overrides):
    """Build a normalized finding dict with sensible defaults."""
    base = {
        "finding_id": "F-0001",
        "url": "http://example.com/login",
        "risk": "Medium",
        "confidence": "Medium",
        "attack_type": "Other",
        "has_query_params": 0,
        "anomaly_score": 0.0,
        "original_risk": "Medium",
        "predicted_risk": "Medium",
    }
    base.update(overrides)
    return base


# -----------------------------
# RULE-001: High-confidence SQL Injection
# -----------------------------

def test_rule_001_fires_on_high_confidence_sqli():
    rule = rule_map()["RULE-001"]
    f = _finding(attack_type="SQL Injection", confidence="High")
    assert rule.check(f) is not None


def test_rule_001_does_not_fire_on_medium_confidence_sqli():
    rule = rule_map()["RULE-001"]
    f = _finding(attack_type="SQL Injection", confidence="Medium")
    assert rule.check(f) is None


def test_rule_001_does_not_fire_on_non_sqli():
    rule = rule_map()["RULE-001"]
    f = _finding(attack_type="XSS", confidence="High")
    assert rule.check(f) is None


# -----------------------------
# RULE-002: Injection chain (group rule)
# -----------------------------

def test_rule_002_fires_on_multiple_injection_classes_same_endpoint():
    rule = rule_map()["RULE-002"]
    members = [
        _finding(finding_id="F-1", attack_type="SQL Injection"),
        _finding(finding_id="F-2", attack_type="Cross Site Scripting (XSS)"),
    ]
    group = {"endpoint": "example.com/login", "members": members}
    result = rule.check(group)
    assert result is not None
    evidence, fids = result
    assert "SQL Injection" in evidence
    assert set(fids) == {"F-1", "F-2"}


def test_rule_002_does_not_fire_on_single_injection_class():
    rule = rule_map()["RULE-002"]
    members = [
        _finding(finding_id="F-1", attack_type="SQL Injection"),
        _finding(finding_id="F-2", attack_type="SQL Injection"),
    ]
    group = {"endpoint": "example.com/login", "members": members}
    assert rule.check(group) is None


# -----------------------------
# RULE-003: High-risk authentication finding
# -----------------------------

def test_rule_003_fires_on_auth_medium_plus():
    rule = rule_map()["RULE-003"]
    f = _finding(attack_type="Broken Authentication", risk="Medium")
    assert rule.check(f) is not None


def test_rule_003_does_not_fire_on_low_risk_auth():
    rule = rule_map()["RULE-003"]
    f = _finding(attack_type="Broken Authentication", risk="Low")
    assert rule.check(f) is None


# -----------------------------
# RULE-004: Suspicious parameterized endpoint
# -----------------------------

def test_rule_004_fires_on_params_plus_injection():
    rule = rule_map()["RULE-004"]
    f = _finding(attack_type="SQL Injection", has_query_params=1)
    assert rule.check(f) is not None


def test_rule_004_does_not_fire_without_params():
    rule = rule_map()["RULE-004"]
    f = _finding(attack_type="SQL Injection", has_query_params=0)
    assert rule.check(f) is None


# -----------------------------
# RULE-005: Repeated high-risk endpoint (group rule)
# -----------------------------

def test_rule_005_fires_on_two_high_findings_same_endpoint():
    rule = rule_map()["RULE-005"]
    members = [
        _finding(finding_id="F-1", risk="High"),
        _finding(finding_id="F-2", risk="High"),
        _finding(finding_id="F-3", risk="Informational"),  # must NOT be attached
    ]
    group = {"endpoint": "example.com/login", "members": members}
    result = rule.check(group)
    assert result is not None
    _, fids = result
    # only the High members are attached -- the Informational one is excluded
    # (this is the anti-severity-inflation contract)
    assert set(fids) == {"F-1", "F-2"}


def test_rule_005_does_not_fire_on_single_high():
    rule = rule_map()["RULE-005"]
    members = [
        _finding(finding_id="F-1", risk="High"),
        _finding(finding_id="F-2", risk="Low"),
    ]
    group = {"endpoint": "example.com/login", "members": members}
    assert rule.check(group) is None


# -----------------------------
# RULE-006: Anomalous finding
# -----------------------------

def test_rule_006_fires_on_positive_anomaly_score():
    rule = rule_map()["RULE-006"]
    f = _finding(anomaly_score=0.23)
    assert rule.check(f) is not None


def test_rule_006_does_not_fire_on_zero_anomaly():
    rule = rule_map()["RULE-006"]
    f = _finding(anomaly_score=0.0)
    assert rule.check(f) is None


def test_rule_006_handles_missing_anomaly_score():
    rule = rule_map()["RULE-006"]
    f = _finding()
    f.pop("anomaly_score")
    assert rule.check(f) is None


# -----------------------------
# Detection engine: ids + attach
# -----------------------------

def test_run_detection_assigns_stable_ids():
    findings = [
        _finding(finding_id="F-1", attack_type="SQL Injection", confidence="High", anomaly_score=0.1),
        _finding(finding_id="F-2", attack_type="Other", anomaly_score=0.0),
    ]
    dets = run_detection(findings)
    assert all(d["detection_id"].startswith("D-") for d in dets)
    # the SQLi finding should have RULE-001 attached
    attach_detections_to_findings(findings, dets)
    assert findings[0]["detection_rules"].startswith("RULE-001")
    assert findings[1]["detection_rules"] == "—"  # pandas-safe 'no detection' sentinel


def test_run_detection_is_deterministic():
    findings = [
        _finding(finding_id="F-1", attack_type="SQL Injection", confidence="High"),
    ]
    a = run_detection(findings)
    b = run_detection(findings)
    assert [d["detection_id"] for d in a] == [d["detection_id"] for d in b]


def test_group_rules_attach_only_to_relevant_members():
    """RULE-005 on an endpoint with 2 High + 1 Info must NOT flag the Info one."""
    members = [
        _finding(finding_id="H1", risk="High", url="http://h/x"),
        _finding(finding_id="H2", risk="High", url="http://h/x"),
        _finding(finding_id="I1", risk="Informational", url="http://h/x"),
    ]
    dets = run_detection(members)
    rule_005 = [d for d in dets if d["rule_id"] == "RULE-005"]
    assert rule_005, "RULE-005 should have fired"
    attached = set(rule_005[0]["finding_ids"])
    assert "I1" not in attached
    assert attached == {"H1", "H2"}


# -----------------------------
# Correlation engine
# -----------------------------

def test_correlate_groups_shared_endpoints():
    findings = [
        _finding(finding_id="F-1", url="http://h/login", attack_type="SQL Injection"),
        _finding(finding_id="F-2", url="http://h/login", attack_type="XSS"),
        _finding(finding_id="F-3", url="http://h/other", attack_type="CSRF"),
    ]
    events = correlate(findings)
    # only /login has >= 2 findings -> one event
    assert len(events) == 1
    ev = events[0]
    assert "login" in ev["endpoint"]
    assert len(ev["finding_ids"]) == 2
    assert ev["correlation_score"] >= 2


def test_correlate_caps_score():
    """A huge endpoint group must not exceed CORRELATION_MAX_SCORE."""
    from config.settings import CORRELATION_MAX_SCORE
    findings = [
        _finding(finding_id=f"F-{i}", url="http://h/x", risk="High", confidence="High")
        for i in range(50)
    ]
    events = correlate(findings)
    assert events[0]["correlation_score"] <= CORRELATION_MAX_SCORE


def test_correlate_skips_single_finding_endpoints():
    findings = [_finding(finding_id="F-1", url="http://h/alone")]
    events = correlate(findings)
    assert events == []


def test_should_escalate_requires_multi_vector():
    # single attack class -> not multi-vector -> no escalation
    single = {"correlation_score": 10, "attack_types": ["SQL Injection"]}
    assert should_escalate(single) is False
    # two distinct classes -> multi-vector -> escalate (score 10 >= threshold)
    multi = {"correlation_score": 10, "attack_types": ["SQL Injection", "Cross Site Scripting (XSS)"]}
    assert should_escalate(multi) is True


def test_member_should_escalate_requires_medium_base():
    event = {"correlation_score": 10, "attack_types": ["SQL Injection", "XSS"]}
    # Informational finding -> base < Medium -> no escalation
    low = {"original_risk": "Informational", "predicted_risk": "Informational"}
    assert member_should_escalate(low, event) is False
    # Medium finding -> base >= Medium -> escalation allowed
    med = {"original_risk": "Medium", "predicted_risk": "Medium"}
    assert member_should_escalate(med, event) is True


def test_attach_correlations_to_findings():
    findings = [
        _finding(finding_id="F-1", url="http://h/login"),
        _finding(finding_id="F-2", url="http://h/login"),
    ]
    events = correlate(findings)
    attach_correlations_to_findings(findings, events)
    assert findings[0]["correlation_id"] == events[0]["correlation_id"]
    assert findings[0]["correlation_score"] == events[0]["correlation_score"]


# -----------------------------
# Empty / edge inputs
# -----------------------------

def test_run_detection_on_empty_findings():
    assert run_detection([]) == []


def test_correlate_on_empty_findings():
    assert correlate([]) == []


def test_group_findings_by_endpoint_handles_malformed_urls():
    findings = [
        _finding(finding_id="F-1", url="not-a-url"),
        _finding(finding_id="F-2", url=""),
    ]
    groups = group_findings_by_endpoint(findings)
    # both collapse to the '(unknown)' bucket
    assert len(groups) == 1
    assert len(groups[0]["members"]) == 2
