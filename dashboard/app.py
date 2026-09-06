"""
OWASP-ML Flask dashboard server.

Three pages + four JSON API endpoints:

  Pages (server-rendered with Jinja):
    /              SOC command center (KPIs, threat activity, detection rules,
                   correlation, attack matrix, AI analyst, charts)
    /ml-insights   Model evaluation, confusion matrix, feature importance,
                   cross-target validation, disclaimer
    /reports       Detailed findings table (sortable, filterable) + detail drawer

  JSON API (clean separation of data from rendering):
    /api/summary      dashboard headline summary
    /api/findings     paginated + filterable findings
    /api/detections   detection-rule matches
    /api/correlations correlated security events

All missing values pass through config.clean before reaching the templates,
so the "nan" problem cannot recur. The dashboard reads generated files under
data/, so run the pipeline at least once first (demo mode counts).
"""

import os
import sys

# When launched as `python dashboard/app.py` the script dir is on sys.path
# but the repo root (which contains config/, ml/, detection/...) is not.
# Add it so the absolute imports resolve.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import json
from urllib.parse import urlparse

import pandas as pd
from flask import Flask, render_template, send_file, redirect, url_for, request, jsonify

from config.risks import (
    RISK_ORDER,
    normalize_risk,
    risk_index,
    SEVERITY_BADGES,
)
from config.clean import (
    safe_str,
    safe_int,
    safe_float,
    safe_risk,
    safe_confidence,
    clean_finding_for_display,
    safe_text,
)
from config.owasp_mapping import (
    ATTACK_TYPES,
    ATTACK_TO_OWASP,
    attack_description,
    owasp_description,
)
from config.detection_rules import RULES, rule_map
from remediation.remedy_engine import get_remediation_dict

app = Flask(__name__)

# ===============================
# PATHS (repo-relative)
# ===============================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPORT_PATH = os.path.join(BASE_DIR, "data", "threat_report.csv")
AI_SUMMARY_PATH = os.path.join(BASE_DIR, "data", "ai_summary.json")
DETECTIONS_PATH = os.path.join(BASE_DIR, "data", "detections.csv")
CORRELATIONS_PATH = os.path.join(BASE_DIR, "data", "correlations.csv")
METRICS_PATH = os.path.join(BASE_DIR, "models", "training_metrics.json")


# ===============================
# CONTEXT PROCESSOR -- XTransformPort propagation
# ===============================
@app.context_processor
def inject_gateway_helpers():
    """Expose `qp` so templates can append the gateway port to every link.

    When the dashboard is reached through the gateway (?XTransformPort=5000),
    every internal link and static asset URL must carry that query param or
    the gateway will route them to the Next.js app (port 3000) and 404.
    Direct localhost:5000 access gets empty strings.
    """
    port = request.args.get("XTransformPort") if request else None
    qp = f"?XTransformPort={port}" if port else ""
    # separator for adding to a URL that already has a query string
    ap = f"&XTransformPort={port}" if port else ""
    return {"qp": qp, "ap": ap, "gateway_port": port or ""}


# ===============================
# LOADERS
# ===============================
def load_data():
    """Read the threat report CSV, or an empty frame if it is missing."""
    if not os.path.exists(REPORT_PATH):
        return pd.DataFrame()
    try:
        df = pd.read_csv(REPORT_PATH)
    except Exception:
        return pd.DataFrame()
    if df.empty:
        return df
    # Apply explicit fallbacks to EVERY display column so no "nan" can ever
    # reach a template (the v2 "nan problem" fix).
    cleaned = [clean_finding_for_display(row) for _, row in df.iterrows()]
    return pd.DataFrame(cleaned)


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (ValueError, OSError):
        return None


def load_detections():
    if not os.path.exists(DETECTIONS_PATH):
        return pd.DataFrame()
    try:
        return pd.read_csv(DETECTIONS_PATH)
    except Exception:
        return pd.DataFrame()


def load_correlations():
    if not os.path.exists(CORRELATIONS_PATH):
        return pd.DataFrame()
    try:
        return pd.read_csv(CORRELATIONS_PATH)
    except Exception:
        return pd.DataFrame()


def to_json(payload):
    """Dump a dict to a JSON string safe to embed in a <script> block."""
    return json.dumps(payload, default=str).replace("</", "<\\/")


def url_to_path(url):
    if not isinstance(url, str) or url.strip() == "":
        return "(unknown)"
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            # decode percent-encoding for display (ZAP sends %2F, %3F, etc.)
            # so the dashboard shows /Login.asp?RetURL=/Default.asp? instead of
            # /Login.asp?RetURL=%2FDefault%2Easp%3F
            try:
                from urllib.parse import unquote
                path += "?" + unquote(parsed.query)
            except Exception:
                path += "?" + parsed.query
        return path
    except Exception:
        return str(url)[:80]


def sev_class(risk):
    return SEVERITY_BADGES.get(safe_risk(risk), "unknown")


def truncate(text, limit=160):
    text = "" if text is None else str(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def shorten_label(text, max_len=22):
    text = str(text)
    return text if len(text) <= max_len else text[: max_len - 1].rstrip() + "…"


# ===============================
# DASHBOARD DATA BUILDERS
# ===============================

def _risk_counts(df):
    if df.empty or "Final_Risk" not in df.columns:
        return {label: 0 for label in RISK_ORDER}
    counts = df["Final_Risk"].apply(safe_risk).value_counts()
    return {label: int(counts.get(label, 0)) for label in RISK_ORDER}


def _attack_surface(df):
    """Attack-surface summary: distinct endpoints/hosts, avg findings per endpoint,
    top host, and detection+correlation counts.

    Cheap to compute (groupby + counts) and gives the analyst a single-glance
    read of the attack surface without reading the whole table.
    """
    if df.empty:
        return {"endpoints": 0, "hosts": 0, "avg_per_endpoint": 0,
                "top_host": "—", "top_host_count": 0, "total": 0,
                "host_distribution": []}
    urls = df.get("url", pd.Series(dtype=str)).apply(safe_str)
    hosts = urls.apply(lambda u: urlparse(u).netloc if isinstance(u, str) and u.startswith("http") else "(unknown)")
    paths = urls.apply(lambda u: (urlparse(u).path or "/") if isinstance(u, str) and u.startswith("http") else "(unknown)")
    endpoints = (hosts + paths).dropna()
    n_hosts = int(hosts.nunique())
    n_endpoints = int(endpoints.nunique())
    total = len(df)
    avg = round(total / n_endpoints, 1) if n_endpoints else 0.0
    top_host_series = hosts.value_counts().head(1)
    top_host = safe_str(top_host_series.index[0]) if not top_host_series.empty else "—"
    top_host_count = int(top_host_series.iloc[0]) if not top_host_series.empty else 0
    # per-host distribution (for the mini donut), capped at 6 + "other"
    host_counts = hosts.value_counts()
    host_dist = [{"host": safe_str(h), "count": int(c)} for h, c in host_counts.head(6).items()]
    if len(host_counts) > 6:
        host_dist.append({"host": "other", "count": int(host_counts.iloc[6:].sum())})
    return {
        "endpoints": n_endpoints,
        "hosts": n_hosts,
        "avg_per_endpoint": avg,
        "top_host": top_host,
        "top_host_count": top_host_count,
        "total": total,
        "host_distribution": host_dist,
    }


def _freshness():
    """Data freshness: mtime of the threat report, as a human-readable string.

    Used by the hero + footer so the analyst can see at a glance whether the
    dashboard is showing a stale scan.
    """
    import time
    if not os.path.exists(REPORT_PATH):
        return {"available": False, "label": "no data", "age_seconds": None}
    mtime = os.path.getmtime(REPORT_PATH)
    age = time.time() - mtime
    if age < 60:
        label = f"{int(age)}s ago"
    elif age < 3600:
        label = f"{int(age // 60)}m ago"
    elif age < 86400:
        label = f"{int(age // 3600)}h ago"
    else:
        label = f"{int(age // 86400)}d ago"
    return {"available": True, "label": label, "age_seconds": int(age)}


def _threat_activity(df, limit=12):
    """Top findings for the SOC threat-activity feed (severity then score)."""
    if df.empty:
        return []
    if "Final_Risk" not in df.columns:
        return []
    rows = df.to_dict(orient="records")
    rows.sort(
        key=lambda r: (
            risk_index(safe_risk(r.get("Final_Risk"))),
            safe_float(r.get("Hybrid_Threat_Score", r.get("hybrid_score", 0))),
        ),
        reverse=True,
    )
    out = []
    for r in rows[:limit]:
        out.append({
            "finding_id": safe_str(r.get("finding_id"), "—"),
            "severity": safe_risk(r.get("Final_Risk")),
            "sev": sev_class(r.get("Final_Risk")),
            "alert_name": safe_str(r.get("alert_name"), "Untitled finding"),
            "attack_type": safe_str(r.get("attack_type"), "Other"),
            "owasp": safe_str(r.get("OWASP_Category"), "Uncategorized"),
            "cwe": safe_str(r.get("cweid"), "0"),
            "path": url_to_path(r.get("url")),
            "url": safe_str(r.get("url"), ""),
            "hybrid_score": safe_float(r.get("Hybrid_Threat_Score", r.get("hybrid_score", 0))),
        })
    return out


def _attack_matrix(df):
    """attack_type (rows) x risk (cols) heatmap data."""
    if df.empty:
        return {"rows": [], "cols": list(RISK_ORDER)}
    risk_cols = list(RISK_ORDER)
    matrix = {attack: {r: 0 for r in risk_cols} for attack in ATTACK_TYPES}
    for _, r in df.iterrows():
        attack = safe_str(r.get("attack_type"), "Other")
        if attack not in matrix:
            attack = "Other"
        risk = safe_risk(r.get("Final_Risk"))
        matrix[attack][risk] = matrix[attack].get(risk, 0) + 1
    rows = [{"attack": a, "values": [matrix[a][r] for r in risk_cols],
             "total": sum(matrix[a].values())}
            for a in ATTACK_TYPES if sum(matrix[a].values()) > 0]
    rows.sort(key=lambda x: x["total"], reverse=True)
    return {"rows": rows, "cols": risk_cols}


def _detection_summary(detections_df):
    """Per-rule trigger counts joined with rule metadata."""
    out = []
    counts = {}
    if not detections_df.empty and "rule_id" in detections_df.columns:
        counts = detections_df["rule_id"].value_counts().to_dict()
    for rule in RULES:
        out.append({
            "rule_id": rule.rule_id,
            "name": rule.name,
            "severity": rule.severity,
            "description": rule.description,
            "recommended_action": rule.recommended_action,
            "triggered": int(counts.get(rule.rule_id, 0)),
        })
    out.sort(key=lambda d: d["triggered"], reverse=True)
    return out


def _correlation_events(corr_df, limit=8):
    if corr_df.empty:
        return []
    rows = corr_df.sort_values("correlation_score", ascending=False).head(limit)
    out = []
    for _, r in rows.iterrows():
        out.append({
            "correlation_id": safe_str(r.get("correlation_id"), "—"),
            "endpoint": safe_str(r.get("endpoint"), "(unknown)"),
            "score": safe_int(r.get("correlation_score")),
            "severity": safe_risk(r.get("severity")),
            "sev": sev_class(r.get("severity")),
            "n_findings": len(str(r.get("finding_ids", "")).split(",")) if safe_str(r.get("finding_ids")) else 0,
            "attack_types": safe_str(r.get("attack_types"), ""),
            "description": safe_str(r.get("description"), ""),
        })
    return out


def _system_status(df, metrics, detections_df, ai_summary):
    return {
        "scanner_ready": not df.empty,
        "ml_ready": bool(metrics and metrics.get("classifier_trained")),
        "detection_ready": not detections_df.empty,
        "ai_ready": bool(ai_summary),
    }


# ===============================
# ROUTE: DASHBOARD
# ===============================
@app.route("/")
def dashboard():
    df = load_data()
    ai_summary = load_json(AI_SUMMARY_PATH)
    metrics = load_json(METRICS_PATH)
    detections_df = load_detections()
    corr_df = load_correlations()

    if df.empty:
        return render_template("dashboard.html", has_data=False, ai_summary=ai_summary,
                               status=_system_status(df, metrics, detections_df, ai_summary))

    counts = _risk_counts(df)
    total = int(sum(counts.values())) or 1

    # chart payloads
    attack_counts = df["attack_type"].apply(safe_str).value_counts().head(6) if "attack_type" in df.columns else pd.Series(dtype=int)
    owasp_counts = df["OWASP_Category"].apply(safe_str).value_counts().head(6) if "OWASP_Category" in df.columns else pd.Series(dtype=int)
    method_counts = df["method"].apply(safe_str).value_counts() if "method" in df.columns else pd.Series(dtype=int)

    hot_urls = {}
    if "url" in df.columns:
        hot = df[df["Final_Risk"].isin(["High", "Critical"])]
        hot_urls = hot["url"].value_counts().head(6)
    top_urls = [
        {"path": url_to_path(url), "url": url, "count": int(count)}
        for url, count in hot_urls.items()
    ]

    avg_score = 0.0
    if "Hybrid_Threat_Score" in df.columns:
        avg_score = round(float(pd.to_numeric(df["Hybrid_Threat_Score"], errors="coerce").mean() or 0), 3)

    # score distribution for the gauge / histogram
    scores = pd.to_numeric(df.get("Hybrid_Threat_Score", pd.Series(dtype=float)), errors="coerce").dropna()
    score_buckets = {
        "0-25%": int(((scores >= 0) & (scores < 0.25)).sum()),
        "25-50%": int(((scores >= 0.25) & (scores < 0.50)).sum()),
        "50-75%": int(((scores >= 0.50) & (scores < 0.75)).sum()),
        "75-100%": int(((scores >= 0.75) & (scores <= 1.0)).sum()),
    }

    chart_data = {
        "risk": {
            "labels": list(RISK_ORDER),
            "values": [counts[l] for l in RISK_ORDER],
        },
        "attack": {
            "labels": [shorten_label(a) for a in attack_counts.index],
            "values": [int(v) for v in attack_counts.values],
            "full_labels": [str(a) for a in attack_counts.index],
        },
        "owasp": {
            "labels": [shorten_label(a, 34) for a in owasp_counts.index],
            "values": [int(v) for v in owasp_counts.values],
            "full_labels": [str(a) for a in owasp_counts.index],
            "descriptions": [owasp_description(str(a)) for a in owasp_counts.index],
        },
        "method": {
            "labels": [shorten_label(a) for a in method_counts.index],
            "values": [int(v) for v in method_counts.values],
        },
        "score_buckets": {
            "labels": list(score_buckets.keys()),
            "values": list(score_buckets.values()),
        },
        "host_donut": {
            "labels": [h["host"] for h in _attack_surface(df).get("host_distribution", [])],
            "values": [h["count"] for h in _attack_surface(df).get("host_distribution", [])],
        },
    }

    return render_template(
        "dashboard.html",
        has_data=True,
        ai_summary=ai_summary,
        status=_system_status(df, metrics, detections_df, ai_summary),
        counts=counts,
        total=total,
        percentages={k: round(100 * v / total, 1) for k, v in counts.items()},
        avg_score=avg_score,
        threat_activity=_threat_activity(df),
        attack_matrix=_attack_matrix(df),
        attack_surface=_attack_surface(df),
        freshness=_freshness(),
        n_detections=int(len(detections_df)) if not detections_df.empty else 0,
        n_correlations=int(len(corr_df)) if not corr_df.empty else 0,
        detection_summary=_detection_summary(detections_df),
        correlation_events=_correlation_events(corr_df),
        top_urls=top_urls,
        chart_data=to_json(chart_data),
        owasp_descriptions={k: v for k, v in ATTACK_TO_OWASP.items()},
        rule_list=[{"rule_id": r.rule_id, "name": r.name, "severity": r.severity,
                    "description": r.description, "recommended_action": r.recommended_action}
                   for r in RULES],
    )


# ===============================
# ROUTE: ML INSIGHTS
# ===============================
@app.route("/ml-insights")
def ml_insights():
    df = load_data()
    metrics = load_json(METRICS_PATH)

    class_rows = []
    headline = {}
    feature_importance = []
    cross_target = {}
    cm_labels = []

    if metrics:
        report = metrics.get("classification_report", {})
        headline = metrics.get("headline_metrics", {}) or {}
        feature_importance = metrics.get("feature_importance", []) or []
        cross_target = metrics.get("cross_target_validation", {}) or {}
        ev = metrics.get("evaluation_methodology", {}) or {}

        for key in sorted(report.keys()):
            if not str(key).isdigit():
                continue
            row = report[key]
            idx = int(key)
            name = RISK_ORDER[idx] if idx < len(RISK_ORDER) else "Class " + str(key)
            class_rows.append({
                "label": name,
                "precision": row.get("precision"),
                "recall": row.get("recall"),
                "f1": row.get("f1-score"),
                "support": row.get("support"),
            })

        dist = metrics.get("class_distribution", {})
        cm_labels = [
            RISK_ORDER[int(k)] if int(k) < len(RISK_ORDER) else "Class " + str(k)
            for k in sorted(dist.keys(), key=lambda x: int(x))
        ]
        headline.setdefault("dataset_rows", metrics.get("dataset_rows", 0))
        headline.setdefault("feature_count", len(metrics.get("features", [])))
        headline.setdefault("stratified", ev.get("stratified"))
        headline.setdefault("roc_auc_note", ev.get("roc_auc_policy"))

    return render_template(
        "ml_insights.html",
        has_data=not df.empty,
        metrics=metrics,
        headline=headline,
        class_rows=class_rows,
        feature_importance=feature_importance[:15],
        cross_target=cross_target,
        cm_labels=cm_labels,
        risk_order=RISK_ORDER,
    )


# ===============================
# ROUTE: REPORTS
# ===============================
@app.route("/reports")
def reports():
    df = load_data()
    if df.empty:
        return render_template("reports.html", has_data=False, rows=[], total=0,
                               attack_types=[], owasp_categories=[])

    total = len(df)

    # build full row dicts for the table + the detail drawer
    rows = []
    for _, r in df.iterrows():
        final_risk = safe_risk(r.get("Final_Risk"))
        remediation = get_remediation_dict(r.get("attack_type", "Other"))
        rows.append({
            "finding_id": safe_str(r.get("finding_id"), "—"),
            "severity": final_risk,
            "sev": sev_class(final_risk),
            "scanner_risk": safe_risk(r.get("original_risk")),
            "ml_prediction": safe_risk(r.get("predicted_risk")),
            "classifier_confidence": safe_float(r.get("classifier_confidence")),
            "anomaly_score": safe_float(r.get("anomaly_score")),
            "hybrid_score": safe_float(r.get("Hybrid_Threat_Score", r.get("hybrid_score"))),
            "attack_type": safe_str(r.get("attack_type"), "Other"),
            "owasp": safe_str(r.get("OWASP_Category"), "Uncategorized"),
            "cwe": safe_str(r.get("cweid"), "0"),
            "method": safe_str(r.get("method"), "Unknown"),
            "path": url_to_path(r.get("url")),
            "url": safe_str(r.get("url"), ""),
            "alert_name": safe_str(r.get("alert_name"), "Untitled finding"),
            "confidence": safe_confidence(r.get("confidence")),
            "detection_rule": safe_str(r.get("detection_rules"), "—") or "—",
            "correlation_id": safe_str(r.get("correlation_id"), "—") or "—",
            "explanation": safe_text(r.get("Explanation")),
            "remediation": remediation,  # structured dict for the drawer
            "remediation_text": safe_text(r.get("Remediation")),
        })

    # pre-sort: severity desc, then hybrid score desc
    rows.sort(key=lambda r: (risk_index(r["severity"]), r["hybrid_score"]), reverse=True)

    # distinct filter values
    attack_types = sorted({r["attack_type"] for r in rows})
    owasp_categories = sorted({r["owasp"] for r in rows})

    # ?rule=RULE-006 -> pre-filter the table to findings that fired that rule.
    # Lets the dashboard "Detection Rules" panel jump straight into the findings.
    pre_rule = safe_str(request.args.get("rule"), "").upper()
    if pre_rule and pre_rule.startswith("RULE-"):
        rows = [r for r in rows if pre_rule in (safe_str(r.get("detection_rule"), ""))]

    # ?attack=SQL+Injection -> pre-filter by attack family (matrix-jump).
    pre_attack = safe_str(request.args.get("attack"), "")
    if pre_attack:
        rows = [r for r in rows if safe_str(r.get("attack_type"), "") == pre_attack]

    # ?severity=High -> pre-filter by severity (KPI-jump).
    pre_sev = safe_str(request.args.get("severity"), "")
    if pre_sev:
        rows = [r for r in rows if safe_risk(r.get("severity")) == safe_risk(pre_sev)]

    pre_label = ""
    if pre_rule: pre_label = f"detection rule {pre_rule}"
    elif pre_attack: pre_label = f"attack type: {pre_attack}"
    elif pre_sev: pre_label = f"severity: {safe_risk(pre_sev)}"

    return render_template(
        "reports.html",
        has_data=True,
        rows=rows[:500],
        total=total,
        shown=len(rows[:500]),
        attack_types=attack_types,
        owasp_categories=owasp_categories,
        pre_rule=pre_rule,
        pre_attack=pre_attack,
        pre_sev=safe_risk(pre_sev) if pre_sev else "",
        pre_label=pre_label,
    )


# ===============================
# API ROUTES
# ===============================
@app.route("/api/summary")
def api_summary():
    df = load_data()
    ai_summary = load_json(AI_SUMMARY_PATH)
    metrics = load_json(METRICS_PATH)
    detections_df = load_detections()
    corr_df = load_correlations()
    counts = _risk_counts(df)
    total = int(sum(counts.values())) or 1
    avg = 0.0
    if not df.empty and "Hybrid_Threat_Score" in df.columns:
        avg = round(float(pd.to_numeric(df["Hybrid_Threat_Score"], errors="coerce").mean() or 0), 3)
    return jsonify({
        "total_findings": int(sum(counts.values())),
        "risk_distribution": counts,
        "percentages": {k: round(100 * v / total, 1) for k, v in counts.items()},
        "avg_hybrid_threat_score": avg,
        "status": _system_status(df, metrics, detections_df, ai_summary),
        "detections": _detection_summary(detections_df),
        "correlations": _correlation_events(corr_df),
    })


@app.route("/api/findings")
def api_findings():
    df = load_data()
    if df.empty:
        return jsonify({"findings": [], "total": 0})
    severity = request.args.get("severity")
    attack = request.args.get("attack_type")
    limit = safe_int(request.args.get("limit"), 500)
    if severity:
        df = df[df["Final_Risk"].apply(safe_risk) == safe_risk(severity)]
    if attack and "attack_type" in df.columns:
        df = df[df["attack_type"].apply(safe_str) == attack]
    rows = [clean_finding_for_display(r) for _, r in df.head(limit).iterrows()]
    return jsonify({"findings": rows, "total": len(df)})


@app.route("/api/detections")
def api_detections():
    det_df = load_detections()
    summary = _detection_summary(det_df)
    return jsonify({"detections": summary, "total": int(len(det_df))})


@app.route("/api/correlations")
def api_correlations():
    corr_df = load_correlations()
    events = _correlation_events(corr_df, limit=50)
    return jsonify({"correlations": events, "total": int(len(corr_df))})


# ===============================
# CSV DOWNLOAD
# ===============================
@app.route("/download-report")
def download_report():
    if not os.path.exists(REPORT_PATH):
        return redirect(url_for("reports"))
    return send_file(REPORT_PATH, as_attachment=True, download_name="threat_report.csv")


# ===============================
# RE-RUN DEMO PIPELINE (demo-only, no ZAP, no keys)
# ===============================
import threading as _threading

_rerun_state = {"running": False, "started_at": None, "finished_at": None,
                "status": "idle", "log": [], "returncode": None}


def _run_demo_pipeline_background():
    """Run `python run_pipeline.py --demo` in a background thread.

    Demo mode is fully offline (bundled sample scan, no ZAP, no API keys),
    so this is safe to expose on the dashboard. Real-scan mode is NEVER
    triggered from the UI -- it requires explicit CLI consent.
    """
    import time, subprocess, sys as _sys
    _rerun_state["running"] = True
    _rerun_state["started_at"] = time.time()
    _rerun_state["finished_at"] = None
    _rerun_state["status"] = "running"
    _rerun_state["log"] = []
    _rerun_state["returncode"] = None
    try:
        proc = subprocess.Popen(
            [_sys.executable, "run_pipeline.py", "--demo"],
            cwd=BASE_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                _rerun_state["log"].append(line)
        proc.wait()
        _rerun_state["returncode"] = proc.returncode
        _rerun_state["status"] = "ok" if proc.returncode == 0 else "error"
    except Exception as exc:
        _rerun_state["log"].append(f"[dashboard] rerun failed: {exc}")
        _rerun_state["status"] = "error"
        _rerun_state["returncode"] = -1
    finally:
        _rerun_state["finished_at"] = time.time()
        _rerun_state["running"] = False


@app.route("/api/rerun", methods=["POST"])
def api_rerun_start():
    """Start a demo-pipeline re-run. Refuses if one is already running, and
    NEVER accepts a target URL -- real scans need CLI consent (see scanner/zap_scan.py).
    """
    if _rerun_state["running"]:
        return jsonify({"ok": False, "error": "a re-run is already in progress"}), 409
    # reset
    _rerun_state.update(running=True, started_at=None, finished_at=None,
                        status="running", log=[], returncode=None)
    t = _threading.Thread(target=_run_demo_pipeline_background, daemon=True)
    t.start()
    return jsonify({"ok": True, "status": "started"})


@app.route("/api/rerun/status")
def api_rerun_status():
    """Poll the re-run progress. The dashboard polls this every ~1.2s."""
    return jsonify({
        "running": _rerun_state["running"],
        "status": _rerun_state["status"],
        "returncode": _rerun_state["returncode"],
        "lines": _rerun_state["log"][-60:],   # tail, keep payload small
        "total_lines": len(_rerun_state["log"]),
        "started_at": _rerun_state["started_at"],
        "finished_at": _rerun_state["finished_at"],
    })


if __name__ == "__main__":
    # Debug mode stays off unless explicitly requested -- the Werkzeug
    # debugger should never be reachable on a shared network.
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
