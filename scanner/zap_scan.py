import os
import time
import json
from zapv2 import ZAPv2

ZAP_PROXY = "http://127.0.0.1:8080"
TARGET = "http://localhost:3000"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "report.json")

zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

print("Accessing target...")
zap.urlopen(TARGET)
time.sleep(2)

print("Starting spider...")
scan_id = zap.spider.scan(TARGET)

while int(zap.spider.status(scan_id)) < 100:
    print("Spider progress:", zap.spider.status(scan_id), "%")
    time.sleep(2)

print("Spider complete.")

print("Starting active scan...")
scan_id = zap.ascan.scan(TARGET)

while int(zap.ascan.status(scan_id)) < 100:
    print("Active scan progress:", zap.ascan.status(scan_id), "%")
    time.sleep(5)

print("Scan complete.")

alerts = zap.core.alerts()

os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)

with open(DATA_PATH, "w") as f:
    json.dump(alerts, f, indent=4)

print("Report saved to:", DATA_PATH)
