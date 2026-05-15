# OWASP-ML
# 🔐 OWASP AI Threat Intelligence System
### Detection Engineering Model using SIEM + Machine Learning

## 📌 Overview
This project is a **multi-layered web application security analysis system** that integrates:

- 🔍 OWASP ZAP (Passive + Active Scanning)
- 🤖 Machine Learning-based Risk Classification
- 🧠 Hybrid Threat Intelligence Engine
- 📊 Interactive Dashboard (Flask)

It simulates a **Detection Engineering Model using SIEM principles** to detect and prioritize vulnerabilities in real-world web applications.

---

## 🎯 Key Features

- ✅ Automated Web Scanning (Spider + Active Scan)
- ✅ Vulnerability Detection (CWE, OWASP categories)
- ✅ ML-based Risk Prediction
- ✅ Hybrid Risk Scoring Engine
- ✅ Threat Intelligence Report Generation
- ✅ Real-time Dashboard Visualization
- ✅ Top Attack Types & Vulnerable URLs Analysis

---

## 🧱 Architecture
Target URL
↓
OWASP ZAP Scanner
↓
Raw Alerts (JSON)
↓
Preprocessing Engine
↓
ML Risk Prediction
↓
Threat Intelligence Engine
↓
Final Risk Classification
↓
Dashboard (Flask)


---

## 🛠️ Tech Stack

- Python
- Flask
- Pandas, Scikit-learn
- OWASP ZAP API
- HTML/CSS (Dashboard)

---

## 📂 Project Structure
owasp_ml_detector/
│
├── scanner/
│ └── zap_scan.py
│
├── ml/
│ ├── preprocess.py
│ ├── scan_and_predict.py
│ ├── threat_intelligence.py
│
├── dashboard/
│ └── app.py
│
├── data/
│ ├── latest_scan.json
│ ├── processed_latest.csv
│ ├── final_results.csv
│ └── threat_report.csv
│
├── run_pipeline.py
└── README.md


---

## ⚙️ How to Run

### 1️⃣ Activate Environment
```bash
source venv/bin/activate
2️⃣ Start OWASP ZAP (in background)
./zap.sh -daemon -port 8080
3️⃣ Run Full Pipeline
python3 run_pipeline.py

OR manual:

python3 scanner/zap_scan.py <target_url>
python3 ml/scan_and_predict.py
python3 ml/threat_intelligence.py
flask run

🌐 Dashboard
Open in browser:
http://127.0.0.1:5000

📊Output
Risk Distribution (High / Medium / Low)
Top Attack Types (SQLi, XSS, etc.)
Top Vulnerable URLs
CWE Breakdown
ML Confidence Scores

🧪 Tested On
OWASP Juice Shop
testphp.vulnweb.com
testasp.vulnweb.com

🚀 Future Improvements
SIEM integration (Splunk / ELK)
Real-time alerting system
Deep learning-based anomaly detection
Multi-target scanning automation

👨‍💻 Author
Mohammad Kaif
B.Tech CSE (Data Science)
Cybersecurity & AI Enthusiast
