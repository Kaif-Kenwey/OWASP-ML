import os
import pandas as pd

from ml.threat_intelligence import generate_threat_report
from ml.url_scanner import scan_url
from ml.alert_processor import process_alerts
from ml.hybrid_predict import hybrid_predict


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def full_scan_pipeline(target_url):
    """
    Full pipeline:
    1. Run ZAP scan
    2. Process alerts into engineered features
    3. Run Hybrid ML scoring
    4. Return structured results
    """

    print("\n===== STARTING FULL SCAN PIPELINE =====\n")

    # -------------------------------
    # STEP 1: Run ZAP Scan
    # -------------------------------
    scan_url(target_url)

    # -------------------------------
    # STEP 2: Process Alerts
    # -------------------------------
    df = process_alerts()

    if df.empty:
        print("No alerts found.")
        return None

    print("\nRunning Hybrid ML Scoring...\n")

    results = []

    # -------------------------------
    # STEP 3: Run Hybrid Prediction
    # -------------------------------
    for _, row in df.iterrows():

        sample = {
            "confidence_encoded": row["confidence_encoded"],
            "method_encoded": row["method_encoded"],
            "cwe_numeric": row["cwe_numeric"],
            "url_length": row["url_length"],
            "param_length": row["param_length"],
            "has_query_params": row["has_query_params"],
            "path_depth": row["path_depth"],
            "description_length": row["description_length"],
            "solution_length": row["solution_length"],
            "reference_count": row["reference_count"]
        }

        prediction = hybrid_predict(sample)

        results.append({
            "original_risk": row["risk"],
            "predicted_risk": prediction["predicted_risk"],
            "hybrid_score": prediction["hybrid_threat_score"]
        })

    results_df = pd.DataFrame(results)

    # -------------------------------
    # STEP 4: Save Results
    # -------------------------------
    save_path = os.path.join(BASE_DIR, "data", "final_results.csv")
    results_df.to_csv(save_path, index=False)
    generate_threat_report() 

    print("Final ML results saved to:", save_path)
    print("\n===== PIPELINE COMPLETE =====\n")

    print(results_df.head())

    return results_df


if __name__ == "__main__":
    url = input("Enter URL to scan: ")
    full_scan_pipeline(url)
