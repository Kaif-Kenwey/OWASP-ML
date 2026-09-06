# MODEL CARD — OWASP-ML Hybrid Risk Model

An honest description of what this model is, what it was trained on, how well it does, and where it should not be trusted. Metrics below are quoted from `models/training_metrics.json`, which is regenerated on every training run. Training is deterministic (`random_state=42`), so the numbers reproduce exactly from the bundled data.

---

## Model details

| Field | Value |
|---|---|
| Model | OWASP-ML hybrid risk scorer (classifier + anomaly detector) |
| Version | v2 |
| Task | Vulnerability risk classification + anomaly scoring of ZAP alerts |
| Framework | scikit-learn 1.4+ (persisted with joblib) |
| License | MIT |
| Owner / author | Mohammad Kaif |

## Purpose

OWASP ZAP assigns every finding a static risk rating (Informational → High). This model adds a second opinion: it predicts a risk class for each alert and produces a continuous hybrid threat score, which the threat intelligence engine uses to prioritize findings. It exists to support triage ordering — which findings a human should look at first — not to make final severity decisions on its own.

## Intended use

- **Education** — a worked example of applying classic ML to scanner output
- **Triage prioritization support** — ordering findings for human review
- **Portfolio demonstration** — the ML layer of this pipeline

**Out of scope:** production security decisions, compliance or audit evidence, automated remediation, and any use as a replacement for manual penetration testing.

## Training data

- A single bundled real ZAP scan: **193 alerts** from `testasp.vulnweb.com` (179 alerts; the spider also followed cross-links into its sister site `testaspnet.vulnweb.com`, 14 alerts). Stored at `data/sample/latest_scan.json`.
- **Labels are scanner-derived.** The target variable is ZAP's own `risk` field for each alert, so the classifier learns patterns consistent with the scanner's judgment — not independent ground truth. There is no manually verified label set behind it.
- Class distribution (decoded from the label encoder's alphabetical ordering):

| Risk class | Alerts |
|---|---|
| Informational | 92 |
| Low | 62 |
| Medium | 29 |
| High | 10 |
| **Total** | **193** |

- Split: 75% train / 25% test (49 alerts), stratified where class sizes allow.
- Features (20): `confidence_encoded`, `method_encoded`, `url_length`, `param_length`, `has_query_params`, `path_depth`, `description_length`, `solution_length`, `reference_count`, plus 11 one-hot columns for `attack_type` (SQL Injection, XSS, Command Injection, CSRF, Path Traversal, Broken Authentication, Sensitive Data Exposure, Insecure Deserialization, SSRF, Security Misconfiguration, Other). The attack class is derived from CWE ids via the mapping in `ml/alert_processor.py`; CWE ids are never fed to the model raw, because identifiers would imply a fake ordering. Feature construction is shared between training and inference in `ml/features.py`.

## Approach

Two unsupervised/supervised components trained together:

1. **RandomForestClassifier** — 200 trees, `max_depth=12`, `random_state=42`, class-predicted risk from the engineered features.
2. **IsolationForest** — 200 trees, `contamination=0.1`, `random_state=42`, flags statistically unusual alerts.

The two are combined per alert in `ml/hybrid_predict.py`:

```
hybrid_score = 0.6 × classifier confidence
             + 0.3 × IsolationForest anomaly score   (normalized to 0–1)
             + 0.1 × static risk weight              (Informational 0.1 → High 0.9)
```

If the classifier could not be trained (single-class data), the score falls back to the anomaly and risk-weight signals only, rescaled to the same range. Final risk assignment then takes the more severe of scanner risk and predicted risk, and escalates one level if `hybrid_score >= 0.75` (capped at Critical) — see `ml/threat_intelligence.py::escalate_risk`.

## Evaluation

Metrics from the 49-alert holdout of the bundled scan (`models/training_metrics.json`):

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| High | 1.000 | 1.000 | 1.000 | 3 |
| Informational | 1.000 | 0.913 | 0.955 | 23 |
| Low | 0.882 | 0.938 | 0.909 | 16 |
| Medium | 0.875 | 1.000 | 0.933 | 7 |
| **Accuracy** | | | **0.939** | 49 |
| Macro avg | 0.939 | 0.963 | 0.949 | 49 |
| Weighted avg | 0.944 | 0.939 | 0.939 | 49 |

Confusion matrix (rows = actual, columns = predicted, in the order High / Informational / Low / Medium):

```
              High  Info  Low  Medium
High            3     0     0     0
Informational   0    21     2     0
Low             0     0    15     1
Medium          0     0     0     7
```

Every misclassification is one level off, never across the scale — reasonable for triage ordering.

**Read these numbers with care.** 49 test samples means each one moves accuracy by ~2 percentage points, so 93.9% carries a wide error band. And because the labels come from the scanner itself (see below), this measures agreement with ZAP's ratings, not correctness about real-world exploitability.

## Known limitations

Stated plainly, because they matter:

1. **Small dataset.** 193 alerts from one scan. That is enough to demonstrate the pipeline, not enough to claim generalization.
2. **Labels are derived from the scanner's own risk rating.** The classifier learns scanner-consistent patterns rather than independent ground truth. If ZAP mis-rates something, the model is trained on the mis-rating.
3. **Single-target training corpus.** All training data comes from one deliberately vulnerable test site (a classic ASP stack). Behavior on other technologies — or on well-built applications — is untested.
4. **Heavy "Other" class in practice.** On the bundled scan, 153 of 193 alerts map to the `Other` attack class, because the CWE→attack mapping covers 10 classes. The model still scores them, but the attack-type features carry less information than the feature count suggests.
5. **Not a substitute for manual pentesting.** It re-orders scanner output; it does not find new vulnerabilities, verify exploits, or understand business context.
6. **Metrics are in-sample-ish.** Evaluation is a random split of the same scan the model trains on, not a fresh scan of a different target.

## Retraining / regeneration

```bash
python run_pipeline.py --demo            # full flow on the bundled data
# or, if data/processed_latest.csv already exists:
python -m ml.alert_processor
python -m ml.train_hybrid_model
```

This rewrites `models/*.pkl` and `models/training_metrics.json`. Given the same input data, the output is identical (`random_state=42` everywhere). To train on genuinely new data, scan a target you are authorized to test, then replace `data/sample/latest_scan.json` with the new `data/latest_scan.json` — see `docs/MAINTENANCE_GUIDE.md`.
