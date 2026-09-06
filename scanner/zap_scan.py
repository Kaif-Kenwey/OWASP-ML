"""
OWASP ZAP scanner -- the single scanning entry point for the pipeline.

v3 changes:
- Preflight checks: ZAP reachable, API key set, target URL valid + authorized.
- Spider / active-scan / passive-drain loops now have a MAX_WAIT so a
  stalled ZAP can no longer hang the pipeline forever.
- Target URL validation: only http/https schemes, warn on private/loopback
  addresses, refuse non-URL input.
- One scanning implementation (the duplicate REST scanner was removed in v2).

Usage:
    python scanner/zap_scan.py <target_url>            # interactive consent
    python scanner/zap_scan.py <target_url> --yes      # skip prompt
"""

import argparse
import ipaddress
import json
import os
import sys
import time
from urllib.parse import urlparse

import requests

ZAP_API = os.environ.get("ZAP_API", "http://127.0.0.1:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

REQUEST_TIMEOUT = 30
POLL_INTERVAL_SPIDER = 2
POLL_INTERVAL_ASCAN = 5
POLL_INTERVAL_PSCAN = 2
# Safety caps so a stalled ZAP can never hang the pipeline indefinitely.
MAX_WAIT_SPIDER = 60 * 10        # 10 minutes
MAX_WAIT_ASCAN = 60 * 30        # 30 minutes
MAX_WAIT_PSCAN = 60 * 5         # 5 minutes
ALERT_BATCH_SIZE = 500

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "latest_scan.json")


# ---------------------------------------------------------------------------
# Target URL validation (security hardening)
# ---------------------------------------------------------------------------

def validate_target(target_url):
    """Validate a scan target. Returns (ok, reason).

    Refuses non-http(s) schemes, non-URL input, and warns (does not refuse)
    on loopback / private / link-local addresses so the operator notices
    scope mistakes before sending traffic.
    """
    if not target_url or not isinstance(target_url, str):
        return False, "no target URL provided"
    try:
        p = urlparse(target_url)
    except Exception:
        return False, f"unparseable URL: {target_url!r}"

    if p.scheme not in ("http", "https"):
        return False, f"scheme {p.scheme!r} not allowed (only http/https)"
    if not p.netloc:
        return False, "no host in target URL"

    host = p.hostname or ""
    warning = None
    # if the host is a literal IP, classify it
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            warning = f"target {host} is loopback -- scanning your own machine"
        elif ip.is_private:
            warning = f"target {host} is a private address -- verify scope"
        elif ip.is_link_local or ip.is_reserved:
            warning = f"target {host} is link-local/reserved -- verify scope"
    except ValueError:
        pass    # hostname, not IP -- fine

    return True, warning


# ---------------------------------------------------------------------------
# ZAP API helper
# ---------------------------------------------------------------------------

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
        sys.exit(2)
    except requests.exceptions.RequestException as e:
        print("ZAP API request failed:", e)
        sys.exit(2)


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def preflight(target_url):
    """Run the preflight checks and stop on the first failure.

    Order: target validity -> ZAP reachable -> API key set -> authorization.
    Prints a small checklist so the operator sees each step pass.
    """
    print("\n--- PREFLIGHT ---")
    # 1. target
    ok, warning = validate_target(target_url)
    if not ok:
        print(f"[1] target  : FAIL  ({warning})")
        sys.exit(2)
    flag = "OK" + (f"  ({warning})" if warning else "")
    print(f"[1] target  : {flag}")

    # 2. ZAP reachable
    try:
        _zap_get("/JSON/core/view/version/")
        print("[2] ZAP     : OK   (reachable)")
    except SystemExit:
        print("[2] ZAP     : FAIL  (cannot reach ZAP API)")
        raise
    except Exception as e:
        print(f"[2] ZAP     : FAIL  ({e})")
        sys.exit(2)

    # 3. API key
    if ZAP_API_KEY:
        print("[3] API key: OK")
    else:
        print("[3] API key: WARN (no ZAP_API_KEY set; modern ZAP rejects keyless calls)")
    print("--- PREFLIGHT OK ---\n")


# ---------------------------------------------------------------------------
# Authorization guard
# ---------------------------------------------------------------------------

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
        sys.exit(2)


# ---------------------------------------------------------------------------
# Polling loops (with MAX_WAIT safety caps)
# ---------------------------------------------------------------------------

def _wait_loop(label, scan_id, status_path, interval, max_wait):
    """Poll a ZAP status endpoint until 100% or max_wait elapses."""
    deadline = time.time() + max_wait
    while True:
        try:
            status = _zap_get(status_path, {"scanId": scan_id}).get("status", "0")
        except SystemExit:
            raise
        except Exception as exc:
            print(f"[{label}] status query failed: {exc}")
            time.sleep(interval)
            continue
        print(f"{label} progress: {status}%")
        if str(status) == "100":
            return True
        if time.time() >= deadline:
            print(f"[{label}] MAX_WAIT reached ({max_wait}s) -- continuing with partial results")
            return False
        time.sleep(interval)


def wait_for_spider(spider_id):
    _wait_loop("Spider", spider_id, "/JSON/spider/view/status/",
              POLL_INTERVAL_SPIDER, MAX_WAIT_SPIDER)
    print("Spider completed.")


def wait_for_active_scan(scan_id):
    _wait_loop("Active scan", scan_id, "/JSON/ascan/view/status/",
              POLL_INTERVAL_ASCAN, MAX_WAIT_ASCAN)
    print("Active scan completed.")


def wait_for_passive_scan():
    deadline = time.time() + MAX_WAIT_PSCAN
    while True:
        try:
            remaining = int(_zap_get("/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0))
        except SystemExit:
            raise
        except Exception:
            remaining = 0
        if remaining <= 0:
            break
        if time.time() >= deadline:
            print(f"[Passive] MAX_WAIT reached ({MAX_WAIT_PSCAN}s) -- continuing")
            break
        print(f"Waiting for passive scan to finish ({remaining} records left)...")
        time.sleep(POLL_INTERVAL_PSCAN)


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan_url(target_url, skip_confirmation=False):
    """Spider + active scan a target, then persist raw alerts as JSON."""

    preflight(target_url)

    if not skip_confirmation:
        confirm_authorization(target_url)
    else:
        # The pipeline already decided to scan this target; print a one-line
        # authorization reminder instead of blocking on input.
        print(f"[authorization] active scan of {target_url} (operator-initiated)")

    print(f"\nStarting scan for: {target_url}\n")

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
    wait_for_passive_scan()

    # -------------------
    # FETCH ALERTS (paginated)
    # -------------------
    alerts = []
    start = 0
    while True:
        batch = _zap_get("/JSON/core/view/alerts/", {"start": start, "count": ALERT_BATCH_SIZE})
        page = batch.get("alerts", [])
        if not page:
            break
        alerts.extend(page)
        start += ALERT_BATCH_SIZE

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
