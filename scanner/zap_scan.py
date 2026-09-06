"""
OWASP ZAP scanner — the single scanning entry point for the pipeline.

v2 changes:
- Merged the duplicate REST-based scanner (ml/url_scanner.py) into this
  module so there is only ONE scanning implementation to maintain.
- Added ZAP_API_KEY support (modern ZAP builds reject keyless API calls).
- Added request timeouts and proper error handling.
- Added an authorization guard before running an ACTIVE scan: only scan
  targets you are permitted to test. Active scanning sends real attack
  traffic and may be illegal without written permission.

Usage:
    python scanner/zap_scan.py <target_url>            # interactive consent
    python scanner/zap_scan.py <target_url> --yes      # skip prompt
"""

import argparse
import json
import os
import sys
import time

import requests

ZAP_API = os.environ.get("ZAP_API", "http://127.0.0.1:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

REQUEST_TIMEOUT = 30
POLL_INTERVAL_SPIDER = 2
POLL_INTERVAL_ASCAN = 5

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "latest_scan.json")


def _zap_get(path, params=None):
    """GET a ZAP JSON API endpoint with API key + timeout handling."""
    params = dict(params or {})
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY

    try:
        resp = requests.get(f"{ZAP_API}{path}", params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        print(f"Could not reach ZAP at {ZAP_API}.")
        print("Start it first, e.g.:  zap.sh -daemon -port 8080 -config api.key=<yourkey>")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print("ZAP API request failed:", e)
        sys.exit(1)


def confirm_authorization(target_url):
    """Refuse to active-scan a target unless the operator confirms consent."""
    print("\n" + "=" * 60)
    print("ACTIVE SCAN AUTHORIZATION REQUIRED")
    print("=" * 60)
    print(f"Target: {target_url}")
    print("Active scanning sends real attack traffic to the target.")
    print("Only scan systems you own or have WRITTEN permission to test.")
    print("=" * 60)
    answer = input("Type 'YES' to confirm you are authorized: ").strip()
    if answer != "YES":
        print("Aborted. No scan was performed.")
        sys.exit(1)


def wait_for_spider(spider_id):
    while True:
        progress = _zap_get("/JSON/spider/view/status/", {"scanId": spider_id})["status"]
        print(f"Spider progress: {progress}%")
        if progress == "100":
            break
        time.sleep(POLL_INTERVAL_SPIDER)
    print("Spider completed.")


def wait_for_active_scan(scan_id):
    while True:
        progress = _zap_get("/JSON/ascan/view/status/", {"scanId": scan_id})["status"]
        print(f"Active scan progress: {progress}%")
        if progress == "100":
            break
        time.sleep(POLL_INTERVAL_ASCAN)
    print("Active scan completed.")


def scan_url(target_url, skip_confirmation=False):
    """Spider + active scan a target, then persist raw alerts as JSON."""

    print(f"\nStarting scan for: {target_url}\n")

    if not skip_confirmation:
        confirm_authorization(target_url)

    # -------------------
    # SPIDER
    # -------------------
    spider_resp = _zap_get("/JSON/spider/action/scan/", {"url": target_url})
    spider_id = spider_resp.get("scan")
    wait_for_spider(spider_id)

    # -------------------
    # ACTIVE SCAN
    # -------------------
    active_resp = _zap_get("/JSON/ascan/action/scan/", {"url": target_url})
    active_id = active_resp.get("scan")
    wait_for_active_scan(active_id)

    # -------------------
    # PASSIVE SCAN DRAIN
    # -------------------
    while True:
        remaining = _zap_get("/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0)
        if int(remaining) <= 0:
            break
        print(f"Waiting for passive scan to finish ({remaining} records left)...")
        time.sleep(2)

    # -------------------
    # FETCH ALERTS (paginated)
    # -------------------
    alerts = []
    start = 0
    batch_size = 500

    while True:
        batch = _zap_get("/JSON/core/view/alerts/", {"start": start, "count": batch_size})
        page = batch.get("alerts", [])
        if not page:
            break
        alerts.extend(page)
        start += batch_size

    print(f"\nTotal alerts found: {len(alerts)}")

    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    with open(DATA_PATH, "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"Alerts saved to: {DATA_PATH}\n")

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Scan a target URL with OWASP ZAP")
    parser.add_argument("target", help="Target URL (must be authorized for testing)")
    parser.add_argument("--yes", action="store_true", help="Skip authorization prompt")
    args = parser.parse_args()

    scan_url(args.target, skip_confirmation=args.yes)


if __name__ == "__main__":
    main()
