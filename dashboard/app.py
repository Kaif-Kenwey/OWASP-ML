from flask import Flask, render_template, send_file, redirect, url_for
import pandas as pd
import json
import os
from urllib.parse import urlparse

app = Flask(__name__)

# ===============================
# PATHS (repo-relative, no more hardcoded home dirs)
# ===============================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root

REPORT_PATH = os.path.join(BASE_DIR, "data", "threat_report.csv")
AI_SUMMARY_PATH = os.path.join(BASE_DIR, "data", "ai_summary.json")
METRICS_PATH = os.path.join(BASE_DIR, "models", "training_metrics.json")

# Mirrors RISK_ORDER in ml/encodings.py — the model's encoded ints are
# positions on this scale, so we can turn "0..4" back into risk names
# without importing the ml package (keeps the dashboard dependency-free).
RISK_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


# ===============================
# LOADERS
# ===============================
def load_data():
    """Read the threat report CSV, or an empty frame if it is missing."""
    if not os.path.exists(REPORT_PATH):
        return pd.DataFrame()

    df = pd.read_csv(REPORT_PATH)

    # Clean missing values (original logic preserved)
    if "Final_Risk" in df.columns:
        df["Final_Risk"] = df["Final_Risk"].fillna("Unknown")

    if "attack_type" in df.columns:
        df["attack_type"] = df["attack_type"].fillna("Other")

    if "method" in df.columns:
        df["method"] = df["method"].fillna("Unknown")

    if "cwe_numeric" in df.columns:
        df["cwe_numeric"] = df["cwe_numeric"].fillna(0)

    return df


def load_json(path):
    """Small helper: read a JSON file or return None when it is missing."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (ValueError, OSError):
        return None


def to_json(payload):
    """Dump a dict to a JSON string safe to embed in a <script> block."""
    return json.dumps(payload).replace("</", "<\\/")


def url_to_path(url):
    """Strip scheme + host so URLs stay readable; the full url goes in the tooltip."""
    if not isinstance(url, str) or url.strip() == "":
        return "(unknown)"
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path


def sev_class(risk):
    """Map a Final_Risk label to a CSS severity class for badges/dots."""
    mapping = {
        "Critical": "sev-critical",
        "High": "sev-high",
        "Medium": "sev-medium",
        "Low": "sev-low",
        "Informational": "sev-informational",
    }
    return mapping.get(str(risk), "sev-informational")


def truncate(text, limit=140):
    """Shorten long text for table cells, keeping full text for the tooltip."""
    text = "" if text is None else str(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


# ===============================
# DASHBOARD ROUTE
# ===============================
def shorten_label(text, max_len=18):
    """Trim long axis labels so Chart.js never clips them on the left."""
    text = str(text)
    return text if len(text) <= max_len else text[: max_len - 1].rstrip() + "…"


@app.route("/")
def dashboard():
    df = load_data()
    ai_summary = load_json(AI_SUMMARY_PATH)

    if df.empty:
        return render_template("dashboard.html", has_data=False, ai_summary=ai_summary)

    # ---------- RISK COUNTS (Final_Risk = escalated verdict) ----------
    risk_counts = df["Final_Risk"].value_counts()
    critical_count = int(risk_counts.get("Critical", 0))
    high_count = int(risk_counts.get("High", 0))
    medium_count = int(risk_counts.get("Medium", 0))
    low_count = int(risk_counts.get("Low", 0))
    informational_count = int(risk_counts.get("Informational", 0))

    # ---------- CHART PAYLOADS ----------
    attack_counts = df["attack_type"].value_counts().head(5)
    owasp_counts = df["OWASP_Category"].value_counts().head(5) if "OWASP_Category" in df.columns else {}
    method_counts = df["method"].value_counts()

    # Top vulnerable URLs across High + Critical findings, path-only display
    hot_urls = {}
    if "url" in df.columns:
        hot = df[df["Final_Risk"].isin(["High", "Critical"])]
        hot_urls = hot["url"].value_counts().head(5)

    top_urls = [
        {"path": url_to_path(url), "url": url, "count": int(count)}
        for url, count in hot_urls.items()
    ]

    # Average ML confidence (column name carries the % sign)
    avg_confidence = 0.0
    if "ML_Confidence_%" in df.columns:
        avg_confidence = round(float(pd.to_numeric(df["ML_Confidence_%"], errors="coerce").mean() or 0), 1)

    chart_data = {
        "risk": {
            "labels": ["Critical", "High", "Medium", "Low", "Informational"],
            "values": [critical_count, high_count, medium_count, low_count, informational_count],
        },
        "attack": {"labels": [shorten_label(a) for a in attack_counts.index], "values": [int(v) for v in attack_counts.values]},
        "owasp": {"labels": [shorten_label(a) for a in owasp_counts.index], "values": [int(v) for v in owasp_counts.values]},
        "method": {"labels": list(method_counts.index), "values": [int(v) for v in method_counts.values]},
    }

    return render_template(
        "dashboard.html",
        has_data=True,
        ai_summary=ai_summary,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        informational_count=informational_count,
        avg_confidence=avg_confidence,
        top_urls=top_urls,
        method_counts=method_counts.to_dict(),
        chart_data=to_json(chart_data),
    )


# ===============================
# ML INSIGHTS ROUTE
# ===============================
@app.route("/ml-insights")
def ml_insights():
    df = load_data()
    metrics = load_json(METRICS_PATH)

    # ---------- PER-CLASS TABLE (from the persisted classification report) ----------
    class_rows = []
    accuracy = None
    macro_f1 = None
    cm_labels = []

    if metrics:
        report = metrics.get("classification_report", {})
        accuracy = report.get("accuracy")
        macro_avg = report.get("macro avg", {})
        macro_f1 = macro_avg.get("f1-score")

        for key in sorted(report.keys()):
            # only the numeric class keys (skip "accuracy", "macro avg", ...)
            if not str(key).isdigit():
                continue
            row = report[key]
            name = RISK_ORDER[int(key)] if int(key) < len(RISK_ORDER) else "Class " + str(key)
            class_rows.append({
                "label": name,
                "precision": row.get("precision"),
                "recall": row.get("recall"),
                "f1": row.get("f1-score"),
                "support": row.get("support"),
            })

        # confusion matrix labels follow the sorted class order
        dist = metrics.get("class_distribution", {})
        cm_labels = [
            RISK_ORDER[int(k)] if int(k) < len(RISK_ORDER) else "Class " + str(k)
            for k in sorted(dist.keys(), key=lambda x: int(x))
        ]

    # ---------- ORIGINAL vs PREDICTED (straight from the report CSV) ----------
    original_counts = {label: 0 for label in RISK_ORDER}
    predicted_counts = {label: 0 for label in RISK_ORDER}

    if not df.empty:
        orig = df["original_risk"].value_counts() if "original_risk" in df.columns else {}
        pred = df["predicted_risk"].value_counts() if "predicted_risk" in df.columns else {}
        for label in RISK_ORDER:
            original_counts[label] = int(orig.get(label, 0))
            predicted_counts[label] = int(pred.get(label, 0))

    # ---------- ML CONFIDENCE BUCKETS ----------
    conf_buckets = {label: 0 for label in ["0-25%", "25-50%", "50-75%", "75-100%"]}
    if not df.empty and "ML_Confidence_%" in df.columns:
        conf = pd.to_numeric(df["ML_Confidence_%"], errors="coerce").dropna()
        conf_buckets["0-25%"] = int(((conf >= 0) & (conf < 25)).sum())
        conf_buckets["25-50%"] = int(((conf >= 25) & (conf < 50)).sum())
        conf_buckets["50-75%"] = int(((conf >= 50) & (conf < 75)).sum())
        conf_buckets["75-100%"] = int(((conf >= 75) & (conf <= 100)).sum())

    chart_data = {
        "conf_buckets": {
            "labels": list(conf_buckets.keys()),
            "values": list(conf_buckets.values()),
        },
        "orig_pred": {
            "labels": RISK_ORDER,
            "original": [original_counts[label] for label in RISK_ORDER],
            "predicted": [predicted_counts[label] for label in RISK_ORDER],
        },
    }

    return render_template(
        "ml_insights.html",
        has_data=not df.empty,
        metrics=metrics,
        class_rows=class_rows,
        accuracy=accuracy,
        macro_f1=macro_f1,
        cm_labels=cm_labels,
        feature_count=len(metrics.get("features", [])) if metrics else 0,
        orig_counts=original_counts,
        pred_counts=predicted_counts,
        conf_buckets=conf_buckets,
        chart_data=to_json(chart_data),
    )


# ===============================
# REPORTS ROUTE
# ===============================
@app.route("/reports")
def reports():
    df = load_data()

    if df.empty:
        return render_template("reports.html", has_data=False, rows=[], total=0)

    # Sort by ML confidence (most confident predictions first), cap the table
    if "ML_Confidence_%" in df.columns:
        df = df.sort_values("ML_Confidence_%", ascending=False)

    total = len(df)
    df = df.head(500)

    # Pre-compute display fields once here so the template stays dumb
    rows = []
    for _, r in df.iterrows():
        final_risk = str(r.get("Final_Risk", "Unknown"))
        conf = pd.to_numeric(pd.Series([r.get("ML_Confidence_%")]), errors="coerce").iloc[0]
        url = r.get("url", "")
        rows.append({
            "severity": final_risk,
            "sev": sev_class(final_risk),
            "scanner_risk": r.get("risk", ""),
            "ml_prediction": r.get("predicted_risk", ""),
            "ml_conf": "" if pd.isna(conf) else round(float(conf), 1),
            "conf_width": 0 if pd.isna(conf) else max(0, min(100, float(conf))),
            "attack_type": r.get("attack_type", ""),
            "owasp": r.get("OWASP_Category", ""),
            "method": r.get("method", ""),
            "path": url_to_path(url),
            "url": url if isinstance(url, str) else "",
            "explanation": truncate(r.get("Explanation", "")),
        })

    return render_template("reports.html", has_data=True, rows=rows, total=total)


# ===============================
# CSV DOWNLOAD ROUTE
# ===============================
@app.route("/download-report")
def download_report():
    if not os.path.exists(REPORT_PATH):
        # Friendly fallback: send the user back to the reports empty state
        return redirect(url_for("reports"))

    return send_file(REPORT_PATH, as_attachment=True, download_name="threat_report.csv")


if __name__ == "__main__":
    app.run(debug=True)
