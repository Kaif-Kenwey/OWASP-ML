"""
Unit tests for the OWASP-ML core logic.

These run in CI without ZAP, Flask, or trained models — they only test
pure functions so the suite stays fast and deterministic.
"""

import json
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.alert_processor import map_to_attack, extract_numeric, extract_risk, count_references
from ml.encodings import encode_confidence, encode_method, risk_index, risk_from_index
from ml.threat_intelligence import escalate_risk, map_owasp_category
from ml.features import build_sample_features, build_features


# -----------------------------
# alert_processor
# -----------------------------

def test_map_to_attack_known_cwes():
    assert map_to_attack("89") == "SQL Injection"
    assert map_to_attack("79") == "Cross Site Scripting (XSS)"
    assert map_to_attack("918") == "SSRF"
    assert map_to_attack("693") == "Security Misconfiguration"


def test_map_to_attack_unknown_and_empty():
    assert map_to_attack("") == "Other"
    assert map_to_attack(None) == "Other"
    assert map_to_attack("12345") == "Other"


def test_map_to_attack_matches_whole_ids_not_substrings():
    # CWE "189" must NOT match CWE "89" (the old substring loop matched it)
    assert map_to_attack("189") == "Other"


def test_extract_numeric():
    assert extract_numeric("550") == 550
    assert extract_numeric("") == 0
    assert extract_numeric(None) == 0


def test_extract_risk_uses_risk_field_not_riskdesc():
    # THE regression test for the v1 critical bug: ZAP's JSON API returns
    # `risk`, not `riskdesc`. All labels came out empty in v1.
    alert = {"risk": "High", "riskdesc": None}
    assert extract_risk(alert) == "High"

    alert_no_risk = {"riskdesc": "Medium (High Confidence)"}
    assert extract_risk(alert_no_risk) == "Medium"

    assert extract_risk({}) == "Informational"


def test_count_references_handles_zap_string_format():
    # ZAP returns newline-separated strings, not lists
    assert count_references("https://a\nhttps://b\nhttps://c") == 3
    assert count_references(["a", "b"]) == 2
    assert count_references("") == 0
    assert count_references(None) == 0


# -----------------------------
# encodings
# -----------------------------

def test_fixed_encodings_are_stable():
    # identical inputs must always produce identical codes — this is the
    # guarantee that replaced the unstable `cat.codes` behaviour
    assert encode_confidence("High") == encode_confidence("High")
    assert encode_confidence("Medium") != encode_confidence("High")
    assert encode_confidence("TotallyUnknown") == encode_confidence("Low")

    assert encode_method("get") == encode_method("GET")
    assert encode_method("BREW") == encode_method("PROPFIND")  # both -> OTHER


def test_risk_roundtrip():
    for label in ["Informational", "Low", "Medium", "High", "Critical"]:
        assert risk_from_index(risk_index(label)) == label
    # unknown labels sit at the honest floor: Informational, never inflated
    assert risk_index("Weird") == risk_index("Informational")


# -----------------------------
# threat_intelligence
# -----------------------------

def test_escalate_risk_uses_original_risk():
    # v1 ignored original_risk; v2 takes the max of scanner + ML prediction
    assert escalate_risk("High", "Low", 0.10) == "High"
    assert escalate_risk("Low", "High", 0.10) == "High"
    assert escalate_risk("Low", "Low", 0.10) == "Low"


def test_escalate_risk_escalates_on_strong_hybrid_score():
    assert escalate_risk("Low", "Low", 0.80) == "Medium"
    assert escalate_risk("High", "High", 0.90) == "Critical"


def test_escalate_risk_handles_unknown_labels():
    # unknown/missing labels resolve to the Informational floor
    assert escalate_risk("", "", 0.10) == "Informational"
    # an unknown ML prediction must not inflate a real scanner risk
    assert escalate_risk("Medium", "Unknown", 0.10) == "Medium"


def test_map_owasp_category():
    assert map_owasp_category("SQL Injection") == "A03 - Injection"
    assert map_owasp_category("Something New") == "Uncategorized"


# -----------------------------
# features
# -----------------------------

def test_build_sample_features_one_hots_attack_type():
    feats = build_sample_features({
        "confidence_encoded": 2,
        "method_encoded": 0,
        "url_length": 42,
        "attack_type": "SQL Injection",
    })

    assert feats["attack_SQL Injection"] == 1
    assert feats["attack_Other"] == 0
    assert feats["url_length"] == 42
    # all attack one-hots present and exactly one is hot
    attack_cols = {k: v for k, v in feats.items() if k.startswith("attack_")}
    assert sum(attack_cols.values()) == 1


def test_build_features_dataframe_matches_sample_builder():
    df = pd.DataFrame([
        {"confidence_encoded": 1, "method_encoded": 0, "url_length": 30,
         "param_length": 5, "has_query_params": 1, "path_depth": 1,
         "description_length": 100, "solution_length": 50,
         "reference_count": 2, "attack_type": "XSS"},
        {"confidence_encoded": 2, "method_encoded": 0, "url_length": 60,
         "param_length": 0, "has_query_params": 0, "path_depth": 2,
         "description_length": 200, "solution_length": 80,
         "reference_count": 1, "attack_type": "Other"},
    ])
    # replace the informal "XSS" with the exact category name
    df.loc[0, "attack_type"] = "Cross Site Scripting (XSS)"

    X = build_features(df)
    assert list(X.columns) == list(build_sample_features({"attack_type": "Other"}).keys())
    assert X.loc[0, "attack_Cross Site Scripting (XSS)"] == 1
    assert X.loc[1, "attack_Other"] == 1


# -----------------------------
# sample data integrity (guards demo mode)
# -----------------------------

SAMPLE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "sample", "latest_scan.json"
)


@pytest.mark.skipif(not os.path.exists(SAMPLE_PATH), reason="sample data not bundled")
def test_bundled_sample_data_is_valid_and_labeled():
    with open(SAMPLE_PATH) as f:
        alerts = json.load(f)

    assert isinstance(alerts, list) and len(alerts) > 0

    risks = {extract_risk(a) for a in alerts}
    # every alert must yield a real risk label — empty labels were the v1 bug
    assert "" not in risks
    assert risks.issubset({"Informational", "Low", "Medium", "High", "Critical"})
