import os
import json
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "report.json")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "processed.csv")

print("Loading report from:", DATA_PATH)

if not os.path.exists(DATA_PATH):
    print("Report file not found.")
    exit()

with open(DATA_PATH, "r") as f:
    alerts = json.load(f)

print("Total alerts:", len(alerts))

rows = []

for alert in alerts:
    rows.append({
        "risk": alert.get("risk", ""),
        "confidence": alert.get("confidence", ""),
        "cweid": alert.get("cweid", 0),
        "method": alert.get("method", ""),
        "url_length": len(alert.get("url", ""))
    })

df = pd.DataFrame(rows)

print("Dataset shape:", df.shape)

df.to_csv(OUTPUT_PATH, index=False)

print("Preprocessing complete. Saved to:", OUTPUT_PATH)
