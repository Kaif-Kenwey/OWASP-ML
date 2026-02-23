import subprocess
import sys

def run_step(script_path, step_name):
    print(f"\n--- {step_name} ---")

    result = subprocess.run(
        ["python", script_path],
        capture_output=True,
        text=True
    )

    print(result.stdout)
    print(result.stderr)

    if result.returncode != 0:
        print(f"{step_name} failed.")
        sys.exit()

print("Starting pipeline...")

run_step("scanner/zap_scan.py", "Running Scan")
run_step("ml/preprocess.py", "Preprocessing Data")
run_step("ml/train_model.py", "Training Model")

print("\nPipeline completed successfully.")
