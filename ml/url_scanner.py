import requests
import time
import os
import json

ZAP_API = "http://127.0.0.1:8080"   # Change to 8080 if needed
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "latest_scan.json")


def wait_for_spider(spider_id):
    while True:
        progress = requests.get(
            f"{ZAP_API}/JSON/spider/view/status/",
            params={"scanId": spider_id}
        ).json()["status"]

        print(f"Spider progress: {progress}%")

        if progress == "100":
            break

        time.sleep(2)

    print("Spider completed.")


def wait_for_active_scan(scan_id):
    while True:
        progress = requests.get(
            f"{ZAP_API}/JSON/ascan/view/status/",
            params={"scanId": scan_id}
        ).json()["status"]

        print(f"Active scan progress: {progress}%")

        if progress == "100":
            break

        time.sleep(5)

    print("Active scan completed.")


def scan_url(target_url):

    print(f"\nStarting scan for: {target_url}\n")

    # -------------------
    # SPIDER
    # -------------------
    spider_resp = requests.get(
        f"{ZAP_API}/JSON/spider/action/scan/",
        params={"url": target_url}
    ).json()

    spider_id = spider_resp.get("scan")

    wait_for_spider(spider_id)

    # -------------------
    # ACTIVE SCAN
    # -------------------
    active_resp = requests.get(
        f"{ZAP_API}/JSON/ascan/action/scan/",
        params={"url": target_url}
    ).json()

    active_id = active_resp.get("scan")

    wait_for_active_scan(active_id)

    # -------------------
    # FETCH ALERTS
    # -------------------
    alerts = requests.get(
        f"{ZAP_API}/JSON/core/view/alerts/"
    ).json().get("alerts", [])

    print(f"\nTotal alerts found: {len(alerts)}")

    with open(OUTPUT_PATH, "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"Alerts saved to: {OUTPUT_PATH}\n")

    return alerts
