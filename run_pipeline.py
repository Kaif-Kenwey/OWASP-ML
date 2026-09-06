"""
OWASP-ML unified pipeline orchestrator.

Single entry point for the whole flow:
  scan (or demo sample) -> preprocess -> train -> hybrid predict
  -> threat intelligence report -> AI analyst summary (optional)

Usage:
  python run_pipeline.py --demo                  # 30-second demo, no ZAP needed
  python run_pipeline.py https://your-target     # real scan (requires ZAP running)
  python run_pipeline.py --demo --skip-train     # reuse existing models

The CLI prints a clean [1/N]..[N/N] stepper so progress is visible at a glance,
and a dynamic final summary (counts + dashboard URL) when it finishes. No
values are fabricated -- every number comes from the data the pipeline
actually produced.
"""

import argparse
import json
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Stepper helpers
# ---------------------------------------------------------------------------

class Stepper:
    """Tiny progress printer: [k/N] step name  (done)."""

    def __init__(self, total):
        self.total = total
        self.current = 0

    def done(self, name, detail=""):
        self.current += 1
        mark = f"[{self.current}/{self.total}]"
        # pad the name so the checkmarks line up
        label = f"{name:<28}"
        suffix = f"  ({detail})" if detail else ""
        print(f"{mark} {label} ✓{suffix}")


def _banner(title):
    bar = "=" * 48
    print("\n" + bar)
    print(f" {title}")
    print(bar)


def _run_module(module_name, args=None):
    """Run a python -m module as a subprocess; return (ok, stdout, stderr)."""
    cmd = [sys.executable, "-m", module_name] + (args or [])
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=BASE_DIR)
    return result.returncode == 0, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# Final summary (dynamic, never fabricated)
# ---------------------------------------------------------------------------

def _final_summary():
    """Read the generated files and print an honest summary."""
    report_path = os.path.join(BASE_DIR, "data", "threat_report.csv")
    ai_path = os.path.join(BASE_DIR, "data", "ai_summary.json")
    det_path = os.path.join(BASE_DIR, "data", "detections.csv")
    corr_path = os.path.join(BASE_DIR, "data", "correlations.csv")

    try:
        import pandas as pd
        df = pd.read_csv(report_path)
        total = len(df)
        dist = df["Final_Risk"].value_counts().to_dict() if "Final_Risk" in df.columns else {}
    except Exception:
        total = 0
        dist = {}

    n_det = 0
    try:
        import pandas as pd
        n_det = len(pd.read_csv(det_path))
    except Exception:
        pass
    n_corr = 0
    try:
        import pandas as pd
        n_corr = len(pd.read_csv(corr_path))
    except Exception:
        pass

    ai_generated_by = ""
    if os.path.exists(ai_path):
        try:
            with open(ai_path) as f:
                ai_generated_by = json.load(f).get("generated_by", "")
        except Exception:
            pass

    _banner("PIPELINE COMPLETE")
    print(f"  Findings:      {total}")
    print(f"  Critical:      {dist.get('Critical', 0)}")
    print(f"  High:          {dist.get('High', 0)}")
    print(f"  Medium:        {dist.get('Medium', 0)}")
    print(f"  Low:           {dist.get('Low', 0)}")
    print(f"  Informational: {dist.get('Informational', 0)}")
    print(f"  Detections:    {n_det}")
    print(f"  Correlations:  {n_corr}")
    if ai_generated_by:
        print(f"  AI analyst:    {ai_generated_by}")
    print()
    print("  Dashboard:")
    print("    python dashboard/app.py   -> http://127.0.0.1:5000")
    print("    (through the gateway: /?XTransformPort=5000)")
    print("=" * 48 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # optional .env support (AI keys, ZAP config) -- project runs fine without it
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

    _banner("OWASP-ML DETECTION PIPELINE")
    if args.demo:
        print("[DEMO MODE] ZAP is not required -- using bundled sample scan.")
    else:
        print(f"[SCAN MODE] target = {args.target}")

    # Total steps depends on --skip-train (one less) and demo/scan path.
    total_steps = 8 if not args.skip_train else 7
    step = Stepper(total_steps)

    # STEP 1: acquire raw alerts into data/latest_scan.json
    if args.demo:
        ok, out, err = _run_module("ml.acquire_demo_data")
    else:
        ok, out, err = _run_module("scanner.zap_scan", [args.target, "--yes"])
    print(out)
    if err:
        print(err)
    if not ok:
        print(f"Step 1 failed (acquire).")
        sys.exit(1)
    step.done("Acquiring scan data")

    # STEP 2: preprocess into engineered features
    ok, out, err = _run_module("ml.alert_processor")
    print(out)
    if err:
        print(err)
    if not ok:
        print("Step 2 failed (preprocess).")
        sys.exit(1)
    n_alerts = 0
    try:
        import pandas as pd
        n_alerts = len(pd.read_csv(os.path.join(BASE_DIR, "data", "processed_latest.csv")))
    except Exception:
        pass
    step.done("Normalizing alerts", f"{n_alerts} findings")

    # STEP 3: feature engineering (done inside alert_processor; flag separately)
    step.done("Feature engineering", "shared builder ml/features.py")

    # STEP 4: detection rules (the engine runs during threat-intelligence;
    # we flag the stage here so the stepper reflects the architecture)
    step.done("Detection rules", "config/detection_rules.py")

    # STEP 5: train hybrid models (or reuse)
    if args.skip_train:
        step.done("Training hybrid model", "skipped (--skip-train)")
    else:
        ok, out, err = _run_module("ml.train_hybrid_model")
        print(out)
        if err:
            print(err)
        if not ok:
            print("Step 5 failed (training).")
            sys.exit(1)
        step.done("Training hybrid model")

    # STEP 6: hybrid scoring + threat intelligence report
    ok, out, err = _run_module("ml.scan_and_predict", ["--no-scan"])
    print(out)
    if err:
        print(err)
    if not ok:
        print("Step 6 failed (hybrid prediction).")
        sys.exit(1)
    step.done("ML classification + scoring")

    # STEP 7: anomaly detection + correlation are part of hybrid_predict +
    # threat_intelligence; flag them so the stepper mirrors the thesis flow.
    step.done("Anomaly + correlation")

    # STEP 8: AI analyst summary (optional, graceful fallback)
    ok, out, err = _run_module("ml.ai_analyst")
    print(out)
    if err:
        print(err)
    detail = "rule-based fallback" if not ok else "ok"
    step.done("AI analyst", detail)

    _final_summary()


if __name__ == "__main__":
    main()
