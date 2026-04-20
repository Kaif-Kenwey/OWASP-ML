from flask import Flask, render_template
import pandas as pd
import os

app = Flask(__name__)

DATA_PATH = os.path.expanduser("~/owasp_ml_detector/data/threat_report.csv")


# ===============================
# LOAD DATA FUNCTION (UNCHANGED LOGIC)
# ===============================
def load_data():
    if not os.path.exists(DATA_PATH):
        return pd.DataFrame()

    df = pd.read_csv(DATA_PATH)

    # Clean missing values (your original logic preserved)
    if "Final_Risk" in df.columns:
        df["Final_Risk"] = df["Final_Risk"].fillna("Unknown")

    if "attack_type" in df.columns:
        df["attack_type"] = df["attack_type"].fillna("Other")

    if "method" in df.columns:
        df["method"] = df["method"].fillna("Unknown")

    if "cwe_numeric" in df.columns:
        df["cwe_numeric"] = df["cwe_numeric"].fillna(0)

    return df


# ===============================
# DASHBOARD ROUTE
# ===============================
@app.route("/")
def dashboard():
    df = load_data()

    if df.empty:
        return render_template(
            "dashboard.html",
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            attack_counts={},
            top_urls={},
            method_counts={},
            cwe_counts={}
        )

    # ---------- STRICT RISK ORDER ----------
    risk_order = ["Low", "Medium", "High", "Critical"]
    risk_counts = df["Final_Risk"].value_counts()

    low_count = risk_counts.get("Low", 0)
    medium_count = risk_counts.get("Medium", 0)
    high_count = risk_counts.get("High", 0)
    critical_count = risk_counts.get("Critical", 0)

    # ---------- OTHER STATS (UNCHANGED) ----------
    attack_counts = df["attack_type"].value_counts().head(5).to_dict()

    top_urls = (
        df[df["Final_Risk"] == "High"]["url"]
        .value_counts()
        .head(5)
        .to_dict()
        if "url" in df.columns else {}
    )

    method_counts = df["method"].value_counts().to_dict()

    cwe_counts = df["cwe_numeric"].value_counts().head(5).to_dict()

    return render_template(
        "dashboard.html",
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        attack_counts=attack_counts,
        top_urls=top_urls,
        method_counts=method_counts,
        cwe_counts=cwe_counts
    )


# ===============================
# ML INSIGHTS ROUTE (UNCHANGED FLOW)
# ===============================
@app.route("/ml-insights")
def ml_insights():
    df = load_data()

    if df.empty:
        return render_template(
            "ml_insights.html",
            ml_low=0,
            ml_medium=0,
            ml_high=0,
            ml_critical=0
        )

    risk_counts = df["Final_Risk"].value_counts()

    return render_template(
        "ml_insights.html",
        ml_low=risk_counts.get("Low", 0),
        ml_medium=risk_counts.get("Medium", 0),
        ml_high=risk_counts.get("High", 0),
        ml_critical=risk_counts.get("Critical", 0)
    )


# ===============================
# REPORTS ROUTE (UNCHANGED)
# ===============================
@app.route("/reports")
def reports():
    df = load_data()

    if df.empty:
        return render_template("reports.html", data=[])

    data = df.to_dict(orient="records")
    return render_template("reports.html", data=data)


if __name__ == "__main__":
    app.run(debug=True)
