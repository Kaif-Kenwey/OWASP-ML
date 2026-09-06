import os
import math
import pandas as pd

from config.risks import (
    normalize_risk,
    risk_index,
    risk_from_index,
    risk_weight,
    max_risk,
)
from config.owasp_mapping import map_attack_to_owasp, owasp_description, attack_description
from config.settings import (
    ESCALATION_HYBRID_THRESHOLD,
    CORRELATION_ESCALATION_SCORE,
    CORRELATION_ESCALATION_STEP,
)
from config.clean import safe_str, safe_float, is_missing
from remediation.remedy_engine import get_remediation
from detection.engine import run_detection, attach_detections_to_findings
from detection.correlation import (
    correlate,
    attach_correlations_to_findings,
    should_escalate,
    member_should_escalate,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROCESSED_PATH = os.path.join(BASE_DIR, "data", "processed_latest.csv")
FINAL_RESULTS_PATH = os.path.join(BASE_DIR, "data", "final_results.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "threat_report.csv")
DETECTIONS_PATH = os.path.join(BASE_DIR, "data", "detections.csv")
CORRELATIONS_PATH = os.path.join(BASE_DIR, "data", "correlations.csv")


# -----------------------------
# OWASP CATEGORY (rule-based enrichment, NOT ML)
# -----------------------------
def map_owasp_category(attack_type):
    """Rule-based OWASP Top 10 (2021) enrichment. NOT an ML prediction."""
    return map_attack_to_owasp(attack_type)


# -----------------------------
# FINAL RISK ESCALATION (transparent + conservative)
# -----------------------------
def _risk_level(risk):
    """Position on the ZAP risk scale; unknown/missing -> Informational floor."""
    return risk_index(normalize_risk(risk))


def escalate_risk(
    original_risk,
    predicted_risk,
    hybrid_score,
    detection_severity="",
    correlation_severity="",
    correlation_score=0,
):
    """
    Conservative, transparent final-risk escalation.

    Inputs (all signals):
      original_risk       scanner-assigned risk label
      predicted_risk      ML classifier prediction (or 'Unknown')
      hybrid_score        0..1 hybrid threat score (NOT a probability)
      detection_severity  highest severity among detection rules that fired
      correlation_severity severity of the correlated event this finding belongs to
      correlation_score    capped correlation score of the event

    Policy:
      1. base = MORE SEVERE of scanner risk and ML predicted risk
         (ML must never silently downgrade a serious scanner finding)
      2. escalate one level if hybrid_score >= ESCALATION_HYBRID_THRESHOLD
      3. floor to detection_severity (a Critical detection rule => at least Critical)
      4. escalate one more level if the correlated event is strong
      Everything capped at Critical. Missing/unknown signals are ignored,
      never inflated.
    """
    base = max(_risk_level(original_risk), _risk_level(predicted_risk))

    # ML signal
    try:
        hs = float(hybrid_score) if hybrid_score is not None and not (
            isinstance(hybrid_score, float) and math.isnan(hybrid_score)
        ) else None
    except (TypeError, ValueError):
        hs = None
    if hs is not None and hs >= ESCALATION_HYBRID_THRESHOLD:
        base = min(base + 1, risk_index("Critical"))

    # Detection signal (floor, never downgrade)
    if detection_severity:
        base = max(base, _risk_level(detection_severity))

    # Correlation signal (one-step bump if the event is strong)
    if correlation_severity:
        try:
            cs = int(correlation_score)
        except (TypeError, ValueError):
            cs = 0
        if cs >= CORRELATION_ESCALATION_SCORE:
            base = min(base + CORRELATION_ESCALATION_STEP, risk_index("Critical"))

    return risk_from_index(base)


# -----------------------------
# EXPLANATION ENGINE
# -----------------------------
def generate_explanation(row):
    """Human-readable, evidence-based explanation of why this finding matters."""
    reasons = []

    attack = safe_str(row.get("attack_type"), "Other")
    if attack != "Other":
        reasons.append(f"{attack} class finding")

    if safe_str(row.get("confidence"), "") == "High":
        reasons.append("high scanner confidence")

    if int(row.get("has_query_params", 0) or 0) == 1:
        reasons.append("URL exposes query parameters (common injection vector)")

    if attack in {"SQL Injection", "Cross Site Scripting (XSS)", "Command Injection"}:
        reasons.append("injection-related CWE")

    try:
        url_len = int(row.get("url_length", 0) or 0)
    except (TypeError, ValueError):
        url_len = 0
    if url_len > 60:
        reasons.append("unusually long URL")

    det = safe_str(row.get("detection_rules"), "—")
    if det and not is_missing(det):
        reasons.append(f"detection rule(s) fired: {det}")

    corr = safe_str(row.get("correlation_id"), "—")
    if corr and not is_missing(corr):
        reasons.append(f"part of correlated event {corr}")

    if not reasons:
        return "Standard vulnerability pattern detected"
    return "; ".join(reasons) + "."


# -----------------------------
# MAIN GENERATOR
# -----------------------------
def generate_threat_report():
    """Build the final threat-intelligence report.

    Stages:
      1. JOIN processed + ML results on finding_id (no more positional concat)
      2. Run detection rules -> detections.csv
      3. Run correlation engine -> correlations.csv
      4. Attach detection + correlation back to findings
      5. Compute Final_Risk using ALL signals (scanner + ML + detection + correlation)
      6. Add OWASP enrichment (rule-based), explanation, remediation
      7. Write threat_report.csv
    """

    if not os.path.exists(FINAL_RESULTS_PATH):
        print("No ML results found.")
        return None
    if not os.path.exists(PROCESSED_PATH):
        print("No processed alerts found.")
        return None

    ml_df = pd.read_csv(FINAL_RESULTS_PATH)
    processed_df = pd.read_csv(PROCESSED_PATH)

    if ml_df.empty or processed_df.empty:
        print("Nothing to report on.")
        return None

    # ---- 1. Stable join on finding_id (replaces the old positional concat) ----
    if "finding_id" not in ml_df.columns or "finding_id" not in processed_df.columns:
        print("finding_id missing from one of the inputs -- falling back to positional join.")
        combined = pd.concat(
            [processed_df.reset_index(drop=True), ml_df.reset_index(drop=True)], axis=1
        )
    else:
        combined = processed_df.merge(ml_df, on="finding_id", how="left", suffixes=("", "_ml"))

    # ---- normalize the join (ensure risk/original_risk columns exist) ----
    if "original_risk" not in combined.columns:
        combined["original_risk"] = combined.get("risk", "Informational")
    # 'risk' is the scanner risk; keep it as 'risk' and also mirror to original_risk
    if "risk" in combined.columns:
        combined["original_risk"] = combined["risk"]

    findings = combined.to_dict(orient="records")

    # ---- 2 + 3. detection + correlation ----
    detections = run_detection(findings)
    events = correlate(findings)

    # ---- 4. attach back to findings ----
    attach_detections_to_findings(findings, detections)
    attach_correlations_to_findings(findings, events)

    # index events by id so we can decide escalation per-finding
    events_by_id = {ev["correlation_id"]: ev for ev in events}

    # ---- 5 + 6. final risk, OWASP, score, explanation, remediation ----
    for f in findings:
        f["OWASP_Category"] = map_owasp_category(f.get("attack_type", "Other"))
        f["OWASP_Description"] = owasp_description(f["OWASP_Category"])
        f["Attack_Description"] = attack_description(f.get("attack_type", "Other"))

        # Conservative correlation escalation: only pass the correlation
        # severity/score to escalate_risk when THIS finding's event is a
        # true multi-vector signal AND the finding is already at least
        # Medium. Otherwise we'd inflate unrelated Informational findings.
        corr_event = events_by_id.get(f.get("correlation_id"))
        if corr_event and member_should_escalate(f, corr_event):
            corr_sev = corr_event.get("severity", "")
            corr_score = corr_event.get("correlation_score", 0)
        else:
            corr_sev = ""
            corr_score = 0

        f["Final_Risk"] = escalate_risk(
            f.get("original_risk", "Informational"),
            f.get("predicted_risk", "Unknown"),
            f.get("hybrid_threat_score", f.get("hybrid_score", 0)),
            detection_severity=f.get("detection_severity", ""),
            correlation_severity=corr_sev,
            correlation_score=corr_score,
        )

        # The hybrid threat score is the explainable combined signal (0..1).
        # We keep the legacy column name too for one release so older readers
        # do not break, but the dashboard renders the renamed field.
        f["Hybrid_Threat_Score"] = safe_float(
            f.get("hybrid_threat_score", f.get("hybrid_score", 0))
        )
        f["hybrid_score"] = f["Hybrid_Threat_Score"]
        # legacy alias for the old "ML_Confidence_%" column -- the value is the
        # hybrid threat score * 100, NOT a calibrated confidence.
        f["ML_Confidence_%"] = round(f["Hybrid_Threat_Score"] * 100, 2)

        f["Explanation"] = generate_explanation(f)
        f["Remediation"] = get_remediation(f.get("attack_type", "Other"))

    combined = pd.DataFrame(findings)

    # ---- 7. persist ----
    combined.to_csv(OUTPUT_PATH, index=False)
    if detections:
        pd.DataFrame(detections).to_csv(DETECTIONS_PATH, index=False)
    else:
        # always write a header so the dashboard's loader sees the schema
        pd.DataFrame(columns=[
            "detection_id", "rule_id", "rule_name", "severity", "description",
            "evidence", "affected_url", "finding_ids", "recommended_action"
        ]).to_csv(DETECTIONS_PATH, index=False)
    if events:
        pd.DataFrame(events).to_csv(CORRELATIONS_PATH, index=False)
    else:
        pd.DataFrame(columns=[
            "correlation_id", "endpoint", "finding_ids", "attack_types",
            "risk_levels", "high_confidence", "correlation_score", "severity", "description"
        ]).to_csv(CORRELATIONS_PATH, index=False)

    print("\nThreat intelligence report generated:")
    print("  report:       ", OUTPUT_PATH)
    print("  detections:   ", DETECTIONS_PATH, f"({len(detections)} rows)")
    print("  correlations: ", CORRELATIONS_PATH, f"({len(events)} rows)")
    print("Total entries:", len(combined))
    print("Final risk distribution:", combined["Final_Risk"].value_counts().to_dict())

    return combined


if __name__ == "__main__":
    generate_threat_report()
