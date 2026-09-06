"""
Defensive value cleaning for the pipeline and dashboard.

The "nan problem" historically seen on the Detailed Report page came from
pandas turning empty/missing cells into NaN, which str() renders as the
literal string "nan" in Jinja templates. These helpers centralize the
fallback rules so missing data is always rendered explicitly and never
silently inflates a risk.

Rules:
  - None / NaN-ish / empty / "nan" / "none" -> "" or an explicit fallback
  - risk labels -> normalize_risk() (Informational floor, never inflated)
  - numbers -> safe floats/ints with an explicit default
"""

import math
from typing import Any, Optional

from config.risks import normalize_risk, RISK_FALLBACK

_NAN_STRINGS = {"", "nan", "none", "null", "undefined", "na", "n/a", "nil", "—"}


def is_missing(value: Any) -> bool:
    """True for None, NaN, empty strings, and the literal 'nan'/'none' family.

    Includes the pandas-safe sentinel '—' used by the detection / correlation
    engines to mark 'no value' without triggering pandas' default NA
    conversion (which would turn the string 'None' into NaN on CSV read-back).
    NOTE: '-' (single hyphen) is intentionally NOT treated as missing, because
    ZAP uses '-1' as a sentinel cweid.
    """
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    s = str(value).strip().lower()
    return s in _NAN_STRINGS


def safe_str(value: Any, fallback: str = "") -> str:
    """Return a clean display string; missing values become `fallback`."""
    if is_missing(value):
        return fallback
    return str(value).strip()


def safe_text(value: Any, fallback: str = "N/A") -> str:
    """Like safe_str but defaults to 'N/A' for descriptive fields."""
    return safe_str(value, fallback)


def safe_int(value: Any, default: int = 0) -> int:
    """Best-effort int; missing/invalid -> default."""
    if is_missing(value):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Best-effort float; missing/invalid -> default."""
    if is_missing(value):
        return default
    try:
        f = float(value)
        if math.isnan(f):
            return default
        return f
    except (TypeError, ValueError):
        return default


def safe_risk(value: Any) -> str:
    """Canonical risk label; missing/unknown -> Informational floor."""
    return normalize_risk(value)


def safe_confidence(value: Any) -> str:
    """Canonical confidence label; missing -> 'Unknown'."""
    if is_missing(value):
        return "Unknown"
    return str(value).strip()


def safe_pct(value: Any, digits: int = 1) -> Optional[str]:
    """Format a 0..1 fraction as a percentage string, or None if missing."""
    f = safe_float(value, default=float("nan"))
    if math.isnan(f):
        return None
    return f"{round(f * 100, digits)}%"


def clean_finding_for_display(finding: dict) -> dict:
    """Apply fallbacks to every commonly-displayed field of a finding.

    Used by dashboard/app.py before passing rows to the templates so no
    'nan' can ever reach the rendered HTML.
    """
    out = dict(finding)
    out["risk"] = safe_risk(out.get("risk"))
    out["original_risk"] = safe_risk(out.get("original_risk"))
    out["predicted_risk"] = safe_risk(out.get("predicted_risk"))
    out["Final_Risk"] = safe_risk(out.get("Final_Risk"))
    out["confidence"] = safe_confidence(out.get("confidence"))
    out["attack_type"] = safe_str(out.get("attack_type"), "Other") or "Other"
    out["OWASP_Category"] = safe_str(out.get("OWASP_Category"), "Uncategorized") or "Uncategorized"
    out["method"] = safe_str(out.get("method"), "Unknown") or "Unknown"
    out["alert_name"] = safe_str(out.get("alert_name"), "Untitled finding")
    out["url"] = safe_str(out.get("url"), "(unknown URL)")
    out["cweid"] = safe_str(out.get("cweid"), "0")
    out["Explanation"] = safe_text(out.get("Explanation"))
    out["Remediation"] = safe_text(out.get("Remediation"))
    # detection / correlation sentinels: "—" (pandas-safe em dash) means "none
    # fired". Keep it as the display value so the column reads cleanly instead
    # of showing the literal string "None".
    out["detection_rule"] = safe_str(out.get("detection_rules"), "—") or "—"
    if is_missing(out["detection_rule"]):
        out["detection_rule"] = "—"
    out["correlation_id"] = safe_str(out.get("correlation_id"), "—") or "—"
    if is_missing(out["correlation_id"]):
        out["correlation_id"] = "—"
    # numeric display fields: keep the raw float for charts, add a safe str
    out["hybrid_score"] = safe_float(out.get("hybrid_score"))
    out["Hybrid_Threat_Score"] = safe_float(out.get("Hybrid_Threat_Score"))
    out["classifier_confidence"] = safe_float(out.get("classifier_confidence"))
    out["anomaly_score"] = safe_float(out.get("anomaly_score"))
    out["static_risk_weight"] = safe_float(out.get("static_risk_weight"))
    return out
