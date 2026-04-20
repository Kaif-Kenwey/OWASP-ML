import os
import time
import json
import sys
from zapv2 import ZAPv2

ZAP_PROXY = "http://127.0.0.1:8080"

# ---------------------------------
# Custom Target Handling
# ---------------------------------
if len(sys.argv) > 1:
    TARGET = sys.argv[1]
else:
    print("Usage: python zap_scan.py <target_url>")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "report.json")

zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

try:
    print("Target:", TARGET)
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
    ascan_id = zap.ascan.scan(TARGET)

    while int(zap.ascan.status(ascan_id)) < 100:
        print("Active scan progress:", zap.ascan.status(ascan_id), "%")
        time.sleep(5)

    print("Active scan complete.")

    while int(zap.pscan.records_to_scan) > 0:
        print("Waiting for passive scan to finish...")
        time.sleep(2)

    print("Passive scan complete.")

    alerts = []
    start = 0
    batch_size = 500

    while True:
        batch = zap.core.alerts(start=start, count=batch_size)
        if not batch:
            break
        alerts.extend(batch)
        start += batch_size

    print("Total alerts collected:", len(alerts))

    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)

    with open(DATA_PATH, "w") as f:
        json.dump(alerts, f, indent=4)

    print("Report saved to:", DATA_PATH)

except Exception as e:
    print("Scan failed:", str(e))
