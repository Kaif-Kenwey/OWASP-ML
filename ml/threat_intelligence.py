import os
import pandas as pd

from ml.encodings import RISK_ORDER, risk_index, risk_from_index
from remediation.remedy_engine import get_remediation

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FINAL_RESULTS_PATH = os.path.join(BASE_DIR, "data", "final_results.csv")
PROCESSED_PATH = os.path.join(BASE_DIR, "data", "processed_latest.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "threat_report.csv")


# -----------------------------
# OWASP CATEGORY MAPPING
# -----------------------------
def map_owasp_category(attack_type):
    mapping = {
        "SQL Injection": "A03 - Injection",
        "Cross Site Scripting (XSS)": "A03 - Injection",
        "Command Injection": "A03 - Injection",
        "CSRF": "A01 - Broken Access Control",
        "Path Traversal": "A01 - Broken Access Control",
        "Broken Authentication": "A07 - Identification & Authentication Failures",
        "Sensitive Data Exposure": "A02 - Cryptographic Failures",
        "Insecure Deserialization": "A08 - Software & Data Integrity Failures",
        "SSRF": "A10 - Server-Side Request Forgery",
        "Security Misconfiguration": "A05 - Security Misconfiguration",
        "Other": "Uncategorized"
    }

    return mapping.get(attack_type, "Uncategorized")


# -----------------------------
# FINAL RISK ESCALATION LOGIC
# -----------------------------
def _risk_level(risk):
    """Position on the ZAP risk scale; unknown/missing labels are treated
    as Informational (the honest floor — never inflate a risk)."""
    return risk_index(risk)


def escalate_risk(original_risk, predicted_risk, hybrid_score):
    """
    Final risk in v2 uses ALL three signals (the old version ignored
    original_risk entirely):

      1. Base = the MORE SEVERE of scanner risk and ML predicted risk.
      2. Escalate one level if the hybrid score is very strong (>= 0.75),
         capped at Critical.

    This keeps the scanner's judgment authoritative while still letting
    strong ML confidence promote borderline findings.
    """
    base = max(_risk_level(original_risk), _risk_level(predicted_risk))

    if hybrid_score is not None and hybrid_score >= 0.75:
        base = min(base + 1, _risk_level("Critical"))

    return risk_from_index(base)


# -----------------------------
# EXPLANATION ENGINE
# -----------------------------
def generate_explanation(row):

    reasons = []

    if row.get("has_query_params", 0) == 1:
        reasons.append("URL contains query parameters")

    if row.get("attack_type", "Other") in ["SQL Injection", "Cross Site Scripting (XSS)", "Command Injection"]:
        reasons.append("Injection-related CWE detected")

    if row.get("url_length", 0) > 60:
        reasons.append("Long URL structure")

    if row.get("confidence", "") == "High":
        reasons.append("High scanner confidence")

    if not reasons:
        return "Standard vulnerability pattern detected"

    return ", ".join(reasons)


# -----------------------------
# MAIN GENERATOR
# -----------------------------
def generate_threat_report():

    if not os.path.exists(FINAL_RESULTS_PATH):
        print("No ML results found.")
        return None

    if not os.path.exists(PROCESSED_PATH):
        print("No processed alerts found.")
        return None

    ml_df = pd.read_csv(FINAL_RESULTS_PATH)
    processed_df = pd.read_csv(PROCESSED_PATH)

    if len(ml_df) != len(processed_df):
        print("Row count mismatch between ML results and processed alerts.")
        return None

    # positional join is safe only because both frames come from the same
    # alert ordering; the length check above guards that assumption
    combined = pd.concat([processed_df.reset_index(drop=True),
                          ml_df.reset_index(drop=True)], axis=1)

    combined["OWASP_Category"] = combined["attack_type"].apply(map_owasp_category)

    combined["Final_Risk"] = combined.apply(
        lambda row: escalate_risk(
            row["risk"],
            row["predicted_risk"],
            row["hybrid_score"]
        ),
        axis=1
    )

    combined["ML_Confidence_%"] = (combined["hybrid_score"] * 100).round(2)

    combined["Explanation"] = combined.apply(generate_explanation, axis=1)

    # per-finding fix guidance from remediation/remedy_engine.py
    combined["Remediation"] = combined["alert_name"].apply(get_remediation)

    combined.to_csv(OUTPUT_PATH, index=False)

    print("\nThreat intelligence report generated:")
    print("Saved to:", OUTPUT_PATH)
    print("Total entries:", len(combined))
    print("Final risk distribution:", combined["Final_Risk"].value_counts().to_dict())

    return combined


if __name__ == "__main__":
    generate_threat_report()
