"""
OWASP-ML unified pipeline orchestrator.

Single entry point for the whole flow:
  scan (or demo sample) -> preprocess -> train -> hybrid predict
  -> threat intelligence report -> AI analyst summary (optional)

Usage:
  python run_pipeline.py --demo                  # 30-second demo, no ZAP needed
  python run_pipeline.py https://your-target     # real scan (requires ZAP running)
  python run_pipeline.py --demo --skip-train     # reuse existing models
"""

import argparse
import subprocess
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def run_step(module_name, step_name, args=None):
    print(f"\n--- {step_name} ---")

    cmd = [sys.executable, "-m", module_name] + (args or [])
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR)

    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        print(f"{step_name} failed.")
        sys.exit(1)


def run_ai_summary():
    """Best-effort AI summary. Skips silently when no API key is configured."""
    print("\n--- AI Analyst Summary ---")
    result = subprocess.run(
        [sys.executable, "-m", "ml.ai_analyst"],
        capture_output=True, text=True, cwd=BASE_DIR
    )
    print(result.stdout)
    if result.returncode != 0:
        print("(AI summary unavailable — dashboard will use the rule-based engine.)")


def main():
    # optional .env support (AI keys, ZAP config) — project runs fine without it
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(BASE_DIR, ".env"))
    except ImportError:
        pass

    parser = argparse.ArgumentParser(description="OWASP-ML detection pipeline")
    parser.add_argument("target", nargs="?", help="Target URL to scan with OWASP ZAP")
    parser.add_argument("--demo", action="store_true",
                        help="Run on bundled sample data (no ZAP required)")
    parser.add_argument("--skip-train", action="store_true",
                        help="Reuse existing models instead of retraining")
    args = parser.parse_args()

    if not args.demo and not args.target:
        parser.error("provide a target URL or use --demo")

    print("Starting pipeline...")
    if args.demo:
        print("[DEMO MODE] ZAP is not required — using bundled sample scan.")

    # STEP 1: acquire raw alerts into data/latest_scan.json
    if args.demo:
        run_step("ml.acquire_demo_data",
                 "Demo Data (bundled sample scan)")
    else:
        run_step("scanner.zap_scan", "Running ZAP Scan",
                 [args.target, "--yes"])

    # STEP 2: preprocess into engineered features
    run_step("ml.alert_processor", "Preprocessing Alerts")

    # STEP 3: train hybrid models (or reuse)
    if args.skip_train:
        print("\n--- Training skipped (--skip-train) ---")
    else:
        run_step("ml.train_hybrid_model", "Training Hybrid Model")

    # STEP 4: hybrid scoring + threat intelligence report
    run_step("ml.scan_and_predict", "Hybrid Prediction",
             ["--no-scan"])

    # STEP 5: AI analyst summary (optional, graceful fallback)
    run_ai_summary()

    print("\nPipeline completed successfully.")
    print("Launch the dashboard with:  python dashboard/app.py")


if __name__ == "__main__":
    main()
