import os
import pandas as pd

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

def escalate_risk(original_risk, predicted_risk, hybrid_score):

    # Critical if extremely strong ML confidence
    if hybrid_score >= 0.70:
        return "Critical"

    # High if ML strongly predicts High OR strong hybrid
    if predicted_risk == "High" or hybrid_score >= 0.55:
        return "High"

    # Medium for moderate confidence
    if hybrid_score >= 0.45:
        return "Medium"

    return "Low"

# -----------------------------
# EXPLANATION ENGINE
# -----------------------------
def generate_explanation(row):

    reasons = []

    if row["has_query_params"] == 1:
        reasons.append("URL contains query parameters")

    if row["attack_type"] in ["SQL Injection", "Cross Site Scripting (XSS)", "Command Injection"]:
        reasons.append("Injection-related CWE detected")

    if row["url_length"] > 60:
        reasons.append("Long URL structure")

    if row["confidence"] == "High":
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
        return

    if not os.path.exists(PROCESSED_PATH):
        print("No processed alerts found.")
        return

    ml_df = pd.read_csv(FINAL_RESULTS_PATH)
    processed_df = pd.read_csv(PROCESSED_PATH)

    combined = pd.concat([processed_df, ml_df], axis=1)

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

    combined.to_csv(OUTPUT_PATH, index=False)

    print("\nThreat intelligence report generated:")
    print("Saved to:", OUTPUT_PATH)
    print("Total entries:", len(combined))


if __name__ == "__main__":
    generate_threat_report()
