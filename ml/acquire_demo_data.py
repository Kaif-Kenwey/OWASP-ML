"""
Copy the bundled sample scan into data/latest_scan.json.

This makes demo mode structurally identical to a real scan: everything
downstream (preprocessing, training, prediction) reads the same file,
so the demo path exercises exactly the same code as production.
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_SCAN_PATH = os.path.join(BASE_DIR, "data", "sample", "latest_scan.json")
RAW_SCAN_PATH = os.path.join(BASE_DIR, "data", "latest_scan.json")

if not os.path.exists(SAMPLE_SCAN_PATH):
    print("Sample data missing:", SAMPLE_SCAN_PATH)
    raise SystemExit(1)

os.makedirs(os.path.dirname(RAW_SCAN_PATH), exist_ok=True)
shutil.copyfile(SAMPLE_SCAN_PATH, RAW_SCAN_PATH)

print("[DEMO MODE] Using bundled sample scan data (no ZAP required).")
print("Sample source:", SAMPLE_SCAN_PATH)
print("Copied to:", RAW_SCAN_PATH)
