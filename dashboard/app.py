from flask import Flask, render_template
import pandas as pd
import os
import json

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "processed.csv")

def load_data():
    if not os.path.exists(DATA_PATH):
        return None
    return pd.read_csv(DATA_PATH)

@app.route("/")
def dashboard():
    df = load_data()
    if df is None:
        return "Run pipeline first."

    risk_counts = df["risk"].value_counts().to_dict()
    confidence_counts = df["confidence"].value_counts().to_dict()
    cwe_counts = df["cweid"].value_counts().head(6).to_dict()

    return render_template(
        "dashboard.html",
        total=len(df),
        high=risk_counts.get("High", 0),
        medium=risk_counts.get("Medium", 0),
        low=risk_counts.get("Low", 0),
        info=risk_counts.get("Informational", 0),
        risk_labels=json.dumps(list(risk_counts.keys())),
        risk_values=json.dumps(list(risk_counts.values())),
        conf_labels=json.dumps(list(confidence_counts.keys())),
        conf_values=json.dumps(list(confidence_counts.values())),
        cwe_labels=json.dumps(list(cwe_counts.keys())),
        cwe_values=json.dumps(list(cwe_counts.values()))
    )

@app.route("/reports")
def reports():
    df = load_data()
    if df is None:
        return "Run pipeline first."
    return render_template("reports.html", table=df.head(100).to_html(classes="table", index=False))

@app.route("/insights")
def insights():
    return render_template("insights.html")

@app.route("/settings")
def settings():
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(debug=True)

def load_data():
    if not os.path.exists(DATA_PATH):
        print("Processed CSV not found.")
        return None

    df = pd.read_csv(DATA_PATH)

    required_columns = ["risk", "confidence", "cweid"]
    for col in required_columns:
        if col not in df.columns:
            print(f"Missing column: {col}")
            return None

    return df
