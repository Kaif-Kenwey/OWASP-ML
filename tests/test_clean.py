"""
Unit tests for the value-cleaning + risk normalization layer (the "nan"
defense) and for the centralized config mappings.

These tests pin the behaviors the spec calls out:
  - missing / NaN-ish / "nan" string values resolve to explicit fallbacks,
    never silently inflating a risk to High/Critical
  - risk ordering + weights are centralized and round-trip correctly
  - CWE -> attack -> OWASP mapping is deterministic and whole-id only
"""

import os
import sys
import math

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.clean import (
    is_missing, safe_str, safe_text, safe_int, safe_float,
    safe_risk, safe_confidence, clean_finding_for_display,
)
from config.risks import (
    normalize_risk, risk_index, risk_from_index, risk_weight,
    max_risk, is_higher_or_equal, RISK_ORDER, RISK_WEIGHT,
)
from config.owasp_mapping import (
    map_cwe_to_attack, map_attack_to_owasp, ATTACK_TYPES, ATTACK_TO_OWASP,
)


# -----------------------------
# is_missing / safe_str / safe_text
# -----------------------------

def test_is_missing_recognizes_nan_family():
    for v in [None, float("nan"), "", "nan", "None", "null", "  ", "N/A", "n/a"]:
        assert is_missing(v) is True


def test_is_missing_keeps_real_values():
    for v in [0, 0.0, "0", "Medium", "High", False]:
        assert is_missing(v) is False


def test_safe_str_uses_fallback():
    assert safe_str(None) == ""
    assert safe_str("nan") == ""
    assert safe_str(None, fallback="Unknown") == "Unknown"
    assert safe_str("  text  ") == "text"


def test_safe_text_defaults_to_NA():
    assert safe_text(None) == "N/A"
    assert safe_text("hello") == "hello"


def test_safe_int_handles_garbage():
    assert safe_int("12") == 12
    assert safe_int("12.9") == 12
    assert safe_int(None) == 0
    assert safe_int("abc", default=5) == 5


def test_safe_float_handles_nan():
    assert safe_float("0.5") == 0.5
    assert safe_float(float("nan")) == 0.0
    assert safe_float(None) == 0.0
    assert safe_float("abc") == 0.0


# -----------------------------
# Risk normalization -- the core anti-inflation guard
# -----------------------------

def test_normalize_risk_canonicalizes_case_and_whitespace():
    assert normalize_risk("high") == "High"
    assert normalize_risk("  Medium ") == "Medium"


def test_normalize_risk_floors_unknown_to_informational():
    assert normalize_risk("") == "Informational"
    assert normalize_risk(None) == "Informational"
    assert normalize_risk("nan") == "Informational"
    assert normalize_risk("TotallyUnknown") == "Informational"


def test_normalize_risk_accepts_numeric_ids():
    assert normalize_risk(3) == "High"
    assert normalize_risk("4") == "Critical"
    assert normalize_risk("99") == "Informational"  # out of range -> floor


def test_risk_roundtrip():
    for label in RISK_ORDER:
        assert risk_from_index(risk_index(label)) == label


def test_risk_weight_covers_critical():
    assert risk_weight("Critical") == 1.0
    assert risk_weight("Informational") == 0.1
    assert risk_weight("Unknown") == 0.1


def test_max_risk_picks_most_severe():
    assert max_risk("Low", "High", "Medium") == "High"
    assert max_risk("Informational", "Unknown") == "Informational"


def test_is_higher_or_equal():
    assert is_higher_or_equal("High", "Medium")
    assert is_higher_or_equal("Medium", "Medium")
    assert not is_higher_or_equal("Low", "High")


# -----------------------------
# clean_finding_for_display -- the dashboard-side nan defense
# -----------------------------

def test_clean_finding_for_display_fills_every_field():
    raw = {
        "Final_Risk": None,
        "predicted_risk": "nan",
        "original_risk": "",
        "OWASP_Category": None,
        "attack_type": "nan",
        "method": "",
        "alert_name": None,
        "url": None,
        "cweid": "",
        "Explanation": float("nan"),
        "Remediation": None,
        "hybrid_score": "nan",
    }
    cleaned = clean_finding_for_display(raw)
    # every field that the templates render must be a clean string/number
    assert cleaned["Final_Risk"] == "Informational"
    assert cleaned["predicted_risk"] == "Informational"
    assert cleaned["original_risk"] == "Informational"
    assert cleaned["OWASP_Category"] == "Uncategorized"
    assert cleaned["attack_type"] == "Other"
    assert cleaned["method"] == "Unknown"
    assert cleaned["alert_name"] == "Untitled finding"
    assert cleaned["url"] == "(unknown URL)"
    assert cleaned["cweid"] == "0"
    assert cleaned["Explanation"] == "N/A"
    assert cleaned["Remediation"] == "N/A"
    assert cleaned["hybrid_score"] == 0.0


def test_clean_finding_never_inflates_unknown_to_high():
    """The spec's golden rule: missing risk must never become High/Critical."""
    cleaned = clean_finding_for_display({"Final_Risk": None, "predicted_risk": ""})
    assert cleaned["Final_Risk"] in {"Informational", "Low"}
    assert cleaned["predicted_risk"] == "Informational"


# -----------------------------
# OWASP / CWE mapping
# -----------------------------

def test_map_cwe_to_attack_known():
    assert map_cwe_to_attack("89") == "SQL Injection"
    assert map_cwe_to_attack("79") == "Cross Site Scripting (XSS)"
    assert map_cwe_to_attack("918") == "SSRF"


def test_map_cwe_to_attack_whole_id_only():
    # CWE "189" must NOT match CWE "89"
    assert map_cwe_to_attack("189") == "Other"


def test_map_cwe_to_attack_handles_zap_sentinels():
    assert map_cwe_to_attack("0") == "Other"
    assert map_cwe_to_attack("-1") == "Other"
    assert map_cwe_to_attack("") == "Other"
    assert map_cwe_to_attack(None) == "Other"


def test_map_cwe_to_attack_comma_separated():
    assert map_cwe_to_attack("89, 79") in {"SQL Injection", "Cross Site Scripting (XSS)"}


def test_map_attack_to_owasp_known():
    assert map_attack_to_owasp("SQL Injection") == "A03 - Injection"
    assert map_attack_to_owasp("Security Misconfiguration") == "A05 - Security Misconfiguration"
    assert map_attack_to_owasp("SSRF") == "A10 - Server-Side Request Forgery"


def test_map_attack_to_owasp_unknown():
    assert map_attack_to_owasp("Brand New Attack") == "Uncategorized"


def test_attack_types_list_is_complete_and_stable():
    assert "Other" in ATTACK_TYPES
    assert len(ATTACK_TYPES) == len(set(ATTACK_TYPES))
    # every tracked attack has an OWASP mapping
    for a in ATTACK_TYPES:
        assert a in ATTACK_TO_OWASP
