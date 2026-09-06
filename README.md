# OWASP-ML
# 🔐 OWASP AI Threat Intelligence System
### Detection Engineering Model using SIEM + Machine Learning

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/Kaif-Kenwey/OWASP-ML/actions/workflows/ci.yml/badge.svg)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E?logo=scikit-learn&logoColor=white)

## 📌 Overview

OWASP-ML scans web applications with OWASP ZAP, then re-scores every finding with a hybrid machine learning model instead of trusting raw scanner severity alone. It works in three layers:

- 🔍 **ZAP scanning** — spider + active scan through the ZAP API, alerts saved as raw JSON
- 🤖 **Hybrid ML scoring** — a RandomForest classifier and an IsolationForest anomaly detector combine into one threat score per alert
- 🧠 **AI analyst** — turns the scored report into an executive summary with prioritized recommendations

Everything lands in a Flask dashboard where the results are readable at a glance. The whole flow runs from one command, and a bundled real scan means you can try it without installing ZAP.

## ⚡ Quickstart

```bash
git clone https://github.com/Kaif-Kenwey/OWASP-ML.git
cd OWASP-ML
pip install -r requirements.txt
python run_pipeline.py --demo
python dashboard/app.py   # open http://127.0.0.1:5000
```

That's the full demo — about 30 seconds once dependencies are installed. Demo mode uses a bundled, real ZAP scan (193 alerts collected from testasp.vulnweb.com), so there is no ZAP install and no live target involved. The sample goes through the exact same pipeline as a live scan: preprocessing, model training, hybrid scoring, threat report, AI summary.

Expected output: 193 alerts processed, ~94% classifier accuracy on the holdout split, and a final risk distribution of 10 High / 30 Medium / 63 Low / 90 Informational.

Tip: re-running with `python run_pipeline.py --demo --skip-train` reuses the trained models instead of retraining.

## 🧪 Scanning a real target

You need a running OWASP ZAP (daemon mode) and its API key:

```bash
# 1. Start ZAP in daemon mode with an API key
zap.sh -daemon -port 8080 -config api.key=<your-key>

# 2. Give the pipeline the same key
export ZAP_API_KEY=<your-key>

# 3. Run the full flow against your target
python run_pipeline.py https://your-target
```

What happens next: the pipeline drives ZAP through spider → active scan → passive-scan drain, then pulls the alerts in pages and saves them to `data/latest_scan.json`. From there it is the same path as demo mode — preprocessing, training, hybrid scoring, threat report, AI summary. If your ZAP listens somewhere other than `127.0.0.1:8080`, set `ZAP_API` too.

One note on consent: if you invoke the scanner module directly (`python scanner/zap_scan.py <url>`), it stops and asks you to type `YES` before any traffic is sent. The full pipeline skips that prompt, because launching a scan against an explicit target is already the decision.

> **⚠️ Ethical use:** active scanning sends real attack traffic to the target. Only scan systems you own or have written permission to test — a defined scope in writing, not a verbal okay. Unauthorized scanning is illegal in most jurisdictions. The bundled demo data exists precisely so you can evaluate this project without pointing it at anything you don't own.

## 🤖 The ML layer

Every processed alert gets a **hybrid threat score** built from three signals:

```
hybrid_score = 0.6 × classifier confidence   (how sure the RandomForest is)
             + 0.3 × anomaly score           (IsolationForest: how unusual the alert is)
             + 0.1 × static risk weight      (baseline severity of the predicted class)
```

The features are engineered from each raw alert: scanner confidence and HTTP method (fixed encodings shared by training and inference), URL length, query-parameter length and presence, path depth, description/solution lengths, reference count, plus the attack class. The full list lives in `ml/features.py`.

One design decision worth explaining: I one-hot encode the derived `attack_type` (SQL Injection, XSS, Path Traversal, …) instead of feeding raw CWE ids to the model. CWE ids are identifiers, not quantities — a model given `cwe_numeric` would invent a fake ordering where CWE-918 "exceeds" CWE-22. The one-hot carries the same meaning without the false ordinality.

Training and prediction build features through the same code path (`ml/features.py`), so the feature space can never drift between the two. Training is deterministic (`random_state=42`) and persists its evaluation to `models/training_metrics.json` after every run. The full honest write-up of the data, metrics and limitations is in [MODEL_CARD.md](MODEL_CARD.md) — the short version: ~94% accuracy on a 49-alert holdout from a single target's scan.

## 🧠 AI Analyst

After the threat report is built, the AI analyst writes a 4–6 sentence executive summary plus three prioritized recommendations, saved to `data/ai_summary.json` and shown in the dashboard.

It works with **any OpenAI-compatible chat completions API** — OpenAI, Groq, OpenRouter, or a local LLM server such as Ollama. Configure it in `.env` (copy `.env.example` and set `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL`).

No key configured? It falls back to a deterministic rule-based engine that builds the same kind of summary from the report statistics. That is why demo mode works fully offline — nothing in the pipeline hard-requires an external API.

## 📊 Dashboard

Flask + Chart.js, three pages:

- **Dashboard** (`/`) — KPI cards for Critical/High/Medium/Low, attack-type and risk charts, and the AI analyst panel with the executive summary and recommendations
- **ML Insights** (`/ml-insights`) — training metrics from the last run plus the confusion matrix
- **Reports** (`/reports`) — the full finding table, searchable and filterable by severity, with CSV export

Run it with `python dashboard/app.py` and open http://127.0.0.1:5000. It reads the generated files under `data/`, so run the pipeline at least once first (demo mode counts).

## 🧱 Architecture

```
Target URL
   |
   v
OWASP ZAP Scanner  (spider + active scan)
   |
   v
Raw Alerts (JSON)  ------------------>  data/latest_scan.json
   |
   v
Preprocessing Engine  --------------->  data/processed_latest.csv
   |
   v
Hybrid ML Scoring  (RandomForest + IsolationForest)
   |
   v
Threat Intelligence Report  --------->  data/threat_report.csv
   |
   v
AI Analyst  -------------------------->  data/ai_summary.json
   |
   v
Flask Dashboard  (http://127.0.0.1:5000)
```

The final risk for each finding takes the more severe of the scanner's rating and the ML prediction, then escalates one level if the hybrid score is very strong (>= 0.75). The scanner's judgment stays authoritative; ML can promote borderline findings, never silence them.

## 📂 Project Structure

```
OWASP-ML/
├── run_pipeline.py              # single entry point: scan → train → score → report → AI
├── requirements.txt
├── .env.example                 # AI + ZAP configuration template
├── LICENSE                      # MIT
├── README.md
├── MODEL_CARD.md                # honest model documentation
├── scanner/
│   ├── __init__.py
│   └── zap_scan.py              # ZAP API client: spider + active scan + alert fetch
├── ml/
│   ├── __init__.py
│   ├── acquire_demo_data.py     # copies the bundled sample into data/
│   ├── alert_processor.py       # raw ZAP JSON → engineered features (CSV)
│   ├── encodings.py             # fixed encoding maps (train/inference parity)
│   ├── features.py              # shared feature builder + attack one-hots
│   ├── train_hybrid_model.py    # RandomForest + IsolationForest training
│   ├── hybrid_predict.py        # 0.6 / 0.3 / 0.1 hybrid scoring
│   ├── scan_and_predict.py      # scores alerts, writes final_results.csv
│   ├── threat_intelligence.py   # final risk escalation + explanations
│   └── ai_analyst.py            # LLM summary + rule-based fallback
├── dashboard/
│   ├── app.py                   # Flask server (Dashboard / ML Insights / Reports)
│   ├── templates/               # base, dashboard, ml_insights, reports
│   └── static/                  # style.css + Chart.js (dashboard.js)
├── data/
│   ├── sample/
│   │   └── latest_scan.json     # bundled real scan (193 alerts) — powers demo mode
│   ├── latest_scan.json         # raw alerts (generated)
│   ├── processed_latest.csv     # engineered features (generated)
│   ├── final_results.csv        # hybrid scores (generated)
│   ├── threat_report.csv        # final report (generated)
│   └── ai_summary.json          # AI analyst output (generated)
├── models/                      # *.pkl + training_metrics.json (generated)
├── tests/
│   └── test_pipeline.py         # 15 unit tests — no ZAP or models needed
├── docs/
│   └── MAINTENANCE_GUIDE.md     # owner's manual: recipes, git flow, CI, releases
└── .github/
    └── workflows/
        └── ci.yml               # tests + demo-pipeline + dashboard smoke checks
```

## 🛠️ Tech Stack

- **Python 3.11+**
- **Flask** — dashboard server
- **pandas** — alert processing and report assembly
- **scikit-learn** — RandomForest classifier, IsolationForest anomaly detector (joblib for persistence)
- **Chart.js** — dashboard visualizations
- **OWASP ZAP API** — spider, active scan, alert retrieval
- **pytest** — unit tests (run in CI)

## 🧪 Tested On

- OWASP Juice Shop
- testphp.vulnweb.com
- testasp.vulnweb.com

## 🚀 Roadmap

Open ideas, not promises:

- SIEM integration (Splunk / ELK) — push findings as events instead of only serving them from a dashboard
- Real-time alerting system
- Deep learning-based anomaly detection alongside the IsolationForest
- Multi-target scanning automation with scheduled re-scans

## 📄 Docs

- [MODEL_CARD.md](MODEL_CARD.md) — training data, evaluation metrics, and known limitations of the ML layer
- [docs/MAINTENANCE_GUIDE.md](docs/MAINTENANCE_GUIDE.md) — repo map, common recipes, git workflow, CI, release checklist

## 👨‍💻 Author

**Mohammad Kaif**
B.Tech CSE (Data Science)
Cybersecurity & AI Enthusiast
