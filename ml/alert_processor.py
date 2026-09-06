import os
import json
import re
import pandas as pd

from ml.encodings import encode_confidence, encode_method

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_SCAN_PATH = os.path.join(BASE_DIR, "data", "latest_scan.json")
PROCESSED_OUTPUT_PATH = os.path.join(BASE_DIR, "data", "processed_latest.csv")


# ==============================
# OWASP ATTACK MAPPING
# ==============================

def map_to_attack(cwe):
    if not cwe:
        return "Other"

    cwe_str = str(cwe)

    mapping = {
        "89": "SQL Injection",
        "79": "Cross Site Scripting (XSS)",
        "78": "Command Injection",
        "352": "CSRF",
        "22": "Path Traversal",
        "287": "Broken Authentication",
        "200": "Sensitive Data Exposure",
        "502": "Insecure Deserialization",
        "918": "SSRF",
        "693": "Security Misconfiguration"
    }

    # match whole CWE ids (comma separated in some ZAP responses)
    cwe_ids = [c.strip() for c in re.split(r"[,\s]+", cwe_str) if c.strip()]

    for cwe_id in cwe_ids:
        if cwe_id in mapping:
            return mapping[cwe_id]

    return "Other"


def extract_numeric(value):
    if not value:
        return 0
    match = re.search(r"\d+", str(value))
    return int(match.group()) if match else 0


def extract_risk(alert):
    """
    Extract the scanner-assigned risk label.

    FIX (v2): the ZAP JSON API exposes the plain label in the `risk` field
    (e.g. "High"). The old code read `riskdesc`, which is not present in
    core/view/alerts responses, so every label came out empty and the
    model silently trained on blank targets. We now read `risk` first
    and fall back to `riskdesc` only if `risk` is missing.
    """
    risk = str(alert.get("risk") or "").strip()
    if not risk:
        # fallback: riskdesc looks like "High (Medium Confidence)"
        risk = str(alert.get("riskdesc") or "").split(" ")[0].strip()
    return risk if risk else "Informational"


def count_references(references):
    """
    ZAP returns `reference` as a newline-separated string, not a list.
    The old check `isinstance(references, list)` was almost never True,
    so reference_count was always 1. Split on newlines instead.
    """
    if isinstance(references, list):
        return max(len(references), 1)
    if isinstance(references, str) and references.strip():
        return len([line for line in references.splitlines() if line.strip()])
    return 0


# ==============================
# MAIN PROCESSOR
# ==============================

def process_alerts(raw_scan_path=None):
    """Turn raw ZAP alerts into engineered features for ML + reporting."""

    scan_file = raw_scan_path or RAW_SCAN_PATH

    if not os.path.exists(scan_file):
        print("No scan file found at:", scan_file)
        return pd.DataFrame()

    with open(scan_file, "r") as f:
        scan_data = json.load(f)

    alerts_list = []

    if isinstance(scan_data, list):
        alerts_list = scan_data
    elif isinstance(scan_data, dict):
        sites = scan_data.get("site", [])
        for site in sites:
            alerts_list.extend(site.get("alerts", []))
    else:
        print("Unknown JSON format.")
        return pd.DataFrame()

    if not alerts_list:
        print("No alerts found in scan.")
        return pd.DataFrame()

    processed = []

    for alert in alerts_list:

        url = alert.get("url", "")
        risk = extract_risk(alert)
        confidence = alert.get("confidence", "")
        cwe = alert.get("cweid", "")
        method = alert.get("method", "")
        description = alert.get("description", "")
        solution = alert.get("solution", "")
        references = alert.get("reference", "")

        cwe_numeric = extract_numeric(cwe)

        processed.append({
            "risk": risk,
            "confidence": confidence,
            "cweid": cwe,
            "cwe_numeric": cwe_numeric,
            "attack_type": map_to_attack(cwe),
            "alert_name": alert.get("alert", ""),
            "method": method,
            "url": url,
            "url_length": len(url),
            "param_length": len(url.split("?")[1]) if "?" in url else 0,
            "has_query_params": 1 if "?" in url else 0,
            "path_depth": url.count("/") - 2 if url.startswith("http") else 0,
            "description_length": len(description),
            "solution_length": len(solution),
            "reference_count": count_references(references),
            "confidence_encoded": encode_confidence(confidence),
            "method_encoded": encode_method(method)
        })

    df = pd.DataFrame(processed)

    os.makedirs(os.path.dirname(PROCESSED_OUTPUT_PATH), exist_ok=True)
    df.to_csv(PROCESSED_OUTPUT_PATH, index=False)

    print("Processed alerts saved to:", PROCESSED_OUTPUT_PATH)
    print("Total alerts processed:", len(df))
    print("Risk label distribution:", df["risk"].value_counts().to_dict())

    return df


if __name__ == "__main__":
    df = process_alerts()
    print(df.head())
