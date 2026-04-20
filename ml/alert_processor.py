import os
import json
import re
import pandas as pd

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

    for key in mapping:
        if key in cwe_str:
            return mapping[key]

    return "Other"


def extract_numeric(value):
    if not value:
        return 0
    match = re.search(r"\d+", str(value))
    return int(match.group()) if match else 0


# ==============================
# MAIN PROCESSOR
# ==============================

def process_alerts():

    if not os.path.exists(RAW_SCAN_PATH):
        print("No scan file found.")
        return pd.DataFrame()

    with open(RAW_SCAN_PATH, "r") as f:
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
        risk = alert.get("riskdesc", "").split(" ")[0]
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
            "cwe_numeric": cwe_numeric,   # 🔥 RESTORED
            "attack_type": map_to_attack(cwe),
            "method": method,
            "url": url,
            "url_length": len(url),
            "param_length": len(url.split("?")[1]) if "?" in url else 0,
            "has_query_params": 1 if "?" in url else 0,
            "path_depth": url.count("/") - 2 if url.startswith("http") else 0,
            "description_length": len(description),
            "solution_length": len(solution),
            "reference_count": len(references) if isinstance(references, list) else 1
        })

    df = pd.DataFrame(processed)

    df["confidence_encoded"] = df["confidence"].astype("category").cat.codes
    df["method_encoded"] = df["method"].astype("category").cat.codes

    df.to_csv(PROCESSED_OUTPUT_PATH, index=False)

    print("Processed alerts saved to:", PROCESSED_OUTPUT_PATH)
    print("Total alerts processed:", len(df))

    return df


if __name__ == "__main__":
    df = process_alerts()
    print(df.head())
