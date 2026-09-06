"""
Hybrid ML scoring pipeline.

Two ways to run:
  1. python ml/scan_and_predict.py --no-scan
     -> predict on already-processed alerts (used by run_pipeline.py)
  2. python ml/scan_and_predict.py <target_url> [--demo]
     -> one-shot: acquire alerts (scan or demo sample), process, predict
"""

import os
import shutil
import argparse
import pandas as pd

from ml.threat_intelligence import generate_threat_report
from ml.alert_processor import process_alerts
from ml.hybrid_predict import hybrid_predict
from ml.features import build_sample_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_SCAN_PATH = os.path.join(BASE_DIR, "data", "sample", "latest_scan.json")
RAW_SCAN_PATH = os.path.join(BASE_DIR, "data", "latest_scan.json")


def acquire_alerts(target_url=None, demo=False):
    """Get raw alerts into data/latest_scan.json (scan or bundled sample)."""
    if demo:
        print("[DEMO MODE] Using bundled sample scan data (no ZAP required).")
        print(f"Sample source: {SAMPLE_SCAN_PATH}\n")
        shutil.copyfile(SAMPLE_SCAN_PATH, RAW_SCAN_PATH)
        return

    if not target_url:
        raise ValueError("A target URL is required unless --demo is used.")

    from scanner.zap_scan import scan_url
    scan_url(target_url, skip_confirmation=True)


def predict_and_report():
    """Score every processed alert with the hybrid model and build the report.

    Carries finding_id end-to-end and writes the four separated ML signals
    (classifier_confidence, anomaly_score, static_risk_weight,
    hybrid_threat_score) so the threat-intelligence stage can JOIN on
    finding_id instead of doing a fragile positional concat.
    """

    processed_path = os.path.join(BASE_DIR, "data", "processed_latest.csv")
    if not os.path.exists(processed_path):
        print("No processed alerts found -- run the preprocessing step first.")
        return None

    df = pd.read_csv(processed_path)

    if df.empty:
        print("Processed dataset is empty.")
        return None

    print("\nRunning Hybrid ML Scoring...\n")

    results = []

    for _, row in df.iterrows():
        sample = {
            "confidence_encoded": row["confidence_encoded"],
            "method_encoded": row["method_encoded"],
            "url_length": row["url_length"],
            "param_length": row["param_length"],
            "param_count": row["param_count"],
            "has_query_params": row["has_query_params"],
            "path_depth": row["path_depth"],
            "hostname_length": row["hostname_length"],
            "https_indicator": row["https_indicator"],
            "special_char_count": row["special_char_count"],
            "description_length": row["description_length"],
            "solution_length": row["solution_length"],
            "reference_count": row["reference_count"],
            "attack_type": row["attack_type"],
        }

        # shared feature builder guarantees train/inference parity
        features = build_sample_features(sample)

        prediction = hybrid_predict(features)

        results.append({
            "finding_id": row["finding_id"],
            "original_risk": row["risk"],
            "predicted_risk": prediction["predicted_risk"],
            "classifier_confidence": prediction["classifier_confidence"],
            "anomaly_score": prediction["anomaly_score"],
            "static_risk_weight": prediction["static_risk_weight"],
            "hybrid_threat_score": prediction["hybrid_threat_score"],
            # kept for backward compatibility with any old reader
            "hybrid_score": prediction["hybrid_threat_score"],
        })

    results_df = pd.DataFrame(results)

    save_path = os.path.join(BASE_DIR, "data", "final_results.csv")
    results_df.to_csv(save_path, index=False)
    generate_threat_report()

    print("Final ML results saved to:", save_path)
    print("\n===== SCORING COMPLETE =====\n")

    print(results_df.head())

    return results_df


def full_scan_pipeline(target_url=None, demo=False):
    """
    One-shot pipeline:
    1. Acquire alerts (ZAP scan or demo sample)
    2. Process alerts into engineered features
    3. Run Hybrid ML scoring
    4. Generate the threat intelligence report
    """

    print("\n===== STARTING FULL SCAN PIPELINE =====\n")

    acquire_alerts(target_url, demo=demo)

    df = process_alerts()

    if df.empty:
        print("No alerts found.")
        return None

    return predict_and_report()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the hybrid ML scoring pipeline")
    parser.add_argument("url", nargs="?", help="Target URL to scan (skip if using --demo or --no-scan)")
    parser.add_argument("--demo", action="store_true", help="Use bundled sample data instead of scanning")
    parser.add_argument("--no-scan", action="store_true", help="Predict on already-processed alerts")
    args = parser.parse_args()

    if args.no_scan:
        predict_and_report()
    else:
        full_scan_pipeline(args.url, demo=args.demo)
