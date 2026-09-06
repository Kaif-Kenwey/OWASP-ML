import os
import json
import re
import hashlib

import pandas as pd

from ml.encodings import encode_confidence, encode_method
from config.owasp_mapping import map_cwe_to_attack
from config.clean import safe_str

# Backward-compatible alias: older code/tests imported map_to_attack from
# this module. The canonical implementation now lives in
# config.owasp_mapping.map_cwe_to_attack.
map_to_attack = map_cwe_to_attack

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_SCAN_PATH = os.path.join(BASE_DIR, "data", "latest_scan.json")
PROCESSED_OUTPUT_PATH = os.path.join(BASE_DIR, "data", "processed_latest.csv")


# ==============================
# Helpers (kept here because they are ZAP-JSON-specific)
# ==============================

def extract_numeric(value):
    """Best-effort integer extraction from a ZAP field (e.g. cweid='89')."""
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


def _stable_signature(alert):
    """Deterministic signature for an alert -- used for finding_id + correlation."""
    raw = "|".join([
        safe_str(alert.get("url", "")),
        safe_str(alert.get("alert") or alert.get("name") or alert.get("alert_name", "")),
        safe_str(alert.get("cweid", "")),
        safe_str(alert.get("method", "")).upper(),
        safe_str(alert.get("param", "")),
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def _path_depth(url):
    """Number of path segments (excluding scheme/host). Defensive for malformed URLs."""
    if not isinstance(url, str) or not url.startswith("http"):
        return 0
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path
        path = path.strip("/")
        return len([seg for seg in path.split("/") if seg]) if path else 0
    except Exception:
        return 0


def _param_count(url):
    """Number of distinct query parameters in the URL."""
    if not isinstance(url, str) or "?" not in url:
        return 0
    query = url.split("?", 1)[1]
    if not query:
        return 0
    return len([kv for kv in query.split("&") if kv and "=" in kv or kv])


def _hostname_length(url):
    if not isinstance(url, str) or not url.startswith("http"):
        return 0
    try:
        from urllib.parse import urlparse
        return len(urlparse(url).netloc or "")
    except Exception:
        return 0


def _https_indicator(url):
    return 1 if isinstance(url, str) and url.lower().startswith("https://") else 0


def _special_char_count(url):
    special = set("'\"<>{}|;&$`\\%*?")
    if not isinstance(url, str) or not url:
        return 0
    return sum(1 for ch in url if ch in special)


# ==============================
# MAIN PROCESSOR
# ==============================

def process_alerts(raw_scan_path=None):
    """Turn raw ZAP alerts into engineered features for ML + reporting.

    Assigns a stable finding_id (F-0001..) and a content signature to every
    alert so downstream stages can JOIN on finding_id instead of relying on
    a fragile positional concat.
    """

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

    for idx, alert in enumerate(alerts_list, start=1):
        url = alert.get("url", "")
        risk = extract_risk(alert)
        confidence = alert.get("confidence", "")
        cwe = alert.get("cweid", "")
        method = alert.get("method", "")
        description = alert.get("description", "")
        solution = alert.get("solution", "")
        references = alert.get("reference", "")
        attack = map_cwe_to_attack(cwe)

        finding_id = f"F-{idx:04d}"
        signature = _stable_signature(alert)

        processed.append({
            # ---- traceability (stable ids, not positional) ----
            "finding_id": finding_id,
            "signature": signature,
            # ---- raw scanner fields ----
            "risk": risk,
            "confidence": confidence,
            "cweid": cwe,
            "cwe_numeric": extract_numeric(cwe),
            "attack_type": attack,
            "alert_name": alert.get("alert") or alert.get("name") or "",
            "method": method,
            "url": url,
            "param": alert.get("param", ""),
            # ---- engineered features used by the ML model ----
            "confidence_encoded": encode_confidence(confidence),
            "method_encoded": encode_method(method),
            "url_length": len(str(url)),
            "param_length": len(str(url).split("?")[1]) if "?" in str(url) else 0,
            "param_count": _param_count(url),
            "has_query_params": 1 if "?" in str(url) else 0,
            "path_depth": _path_depth(url),
            "hostname_length": _hostname_length(url),
            "https_indicator": _https_indicator(url),
            "special_char_count": _special_char_count(url),
            "description_length": len(str(description)),
            "solution_length": len(str(solution)),
            "reference_count": count_references(references),
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
