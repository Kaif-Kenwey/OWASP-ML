# MODEL CARD — OWASP-ML Hybrid Threat Model

An honest description of what this model is, what it was trained on, how well it does, and where
it should not be trusted. Metrics below are quoted from `models/training_metrics.json`, which is
regenerated on every training run. Training is deterministic (`random_state=42`), so the numbers
reproduce exactly from the bundled data.

---

## Model details

| Field | Value |
|---|---|
| Model | OWASP-ML hybrid threat scorer (classifier + anomaly detector) |
| Version | v3 |
| Task | Vulnerability risk classification + anomaly scoring + detection/correlation escalation of ZAP alerts |
| Framework | scikit-learn 1.4+ (persisted with joblib) |
| License | MIT |
| Owner / author | Mohammad Kaif |

## Purpose

OWASP ZAP assigns every finding a static risk rating (Informational → High). This model adds a
second opinion: it predicts a risk class for each alert and produces a continuous **Hybrid Threat
Score**, which the threat-intelligence engine uses to prioritize findings. It exists to support
**triage ordering** — which findings a human should look at first — **not** to make final severity
decisions on its own. The deterministic detection + correlation + risk-escalation layers are
authoritative; the ML layer only informs them.

## Intended use

- **Education** — a worked example of applying classic ML to scanner output
- **Triage prioritization support** — ordering findings for human review
- **Portfolio demonstration** — the ML layer of this pipeline
- **Research scaffold** — a reproducible baseline for detection-engineering + ML risk scoring

## Not recommended usage

- **Production security decisions** — the model is a proof of concept, not production-grade
- **Compliance or audit evidence** — outputs are not independently verified
- **Automated remediation** — remediation guidance is rule-based, not exploit-verified
- **Replacement for manual penetration testing** — it re-orders scanner output; it does not find
  new vulnerabilities or verify exploits
- **Real-world generalization claims** — see Limitations

## Training data

- A single bundled real ZAP scan: **193 alerts** from `testasp.vulnweb.com` (179 alerts; the spider
  also followed cross-links into `testaspnet.vulnweb.com`, 14 alerts). Stored at
  `data/sample/latest_scan.json`.
- **Labels are scanner-derived.** The target variable is ZAP's own `risk` field for each alert, so
  the classifier learns patterns consistent with the scanner's judgment — not independent ground
  truth. There is no manually verified label set behind it.

| Risk class | Alerts |
|---|---|
| Informational | 92 |
| Low | 62 |
| Medium | 29 |
| High | 10 |
| **Total** | **193** |

- Split: 75% train / 25% test (49 alerts), stratified where class sizes allow (`MIN_CLASS_SAMPLES=2`).
- Cross-target validation (leave-one-host-out) is computed when ≥ 2 hosts each have ≥ 10 findings.

## Features (24)

`confidence_encoded`, `method_encoded`, `url_length`, `param_length`, `param_count`,
`has_query_params`, `path_depth`, `hostname_length`, `https_indicator`, `special_char_count`,
`description_length`, `solution_length`, `reference_count`, plus 11 one-hot columns for
`attack_type` (SQL Injection, XSS, Command Injection, CSRF, Path Traversal, Broken Authentication,
Broken Access Control, Sensitive Data Exposure, Insecure Deserialization, SSRF, Security
Misconfiguration, Other).

The attack class is derived from CWE ids via the mapping in `config/owasp_mapping.py`; **CWE ids
are never fed to the model raw**, because identifiers would imply a fake ordering (CWE-918 > CWE-22
is meaningless). Feature construction is shared between training and inference in `ml/features.py`,
so the feature space cannot drift.

## Target labels

ZAP's `risk` field, label-encoded alphabetically by `sklearn.LabelEncoder`. The mapping is
persisted to `models/label_encoder.pkl` so inference decodes consistently.

## Training methodology

1. `RandomForestClassifier` — 200 trees, `max_depth=12`, `random_state=42`, `n_jobs=-1`.
2. `IsolationForest` — 200 trees, `contamination=0.1`, `random_state=42`. Trained on the full
   dataset (all classes), so it flags statistically unusual alerts regardless of risk label.
3. Both are combined per alert in `ml/hybrid_predict.py`:

   ```
   hybrid_threat_score = 0.6 × classifier_confidence
                       + 0.3 × anomaly_score        (normalized to 0–1)
                       + 0.1 × static_risk_weight    (Informational 0.1 → Critical 1.0)
   ```

   If the classifier could not be trained (single-class data), the score falls back to
   `0.9 × anomaly_score + 0.1 × static_risk_weight` (same 0–1 range).

4. Final risk (`ml/threat_intelligence.py::escalate_risk`) is conservative:
   `base = max(scanner_risk, predicted_risk)`, `+1` if `hybrid_score ≥ 0.75`, floor to
   `detection_severity`, `+1` if a true multi-vector correlated event affects a ≥ Medium member.
   Everything capped at Critical.

## Evaluation methodology

- **Split:** 75/25 stratified random split of the single bundled scan (`random_state=42`).
- **Metrics:** accuracy, precision/recall/F1 (macro + weighted), confusion matrix, per-class
  report, weighted OvR ROC-AUC (computed **only** when ≥ 2 classes and ≥ 20 test samples —
  otherwise reported as `None` with a reason).
- **Feature importance:** RandomForest Gini importance, persisted for explainability.
- **Cross-target (leave-one-host-out):** trains on N-1 hosts, tests on the held-out host. Reported
  honestly, including when a fold is skipped due to insufficient classes.
- **Reproducibility:** `random_state=42` everywhere; same input → identical output.

## Metrics

From the 49-alert holdout of the bundled scan:

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| High | 1.000 | 1.000 | 1.000 | 3 |
| Informational | 1.000 | 0.913 | 0.955 | 23 |
| Low | 0.882 | 0.938 | 0.909 | 16 |
| Medium | 0.875 | 1.000 | 0.933 | 7 |
| **Accuracy** | | | **0.939** | 49 |
| Macro F1 | | | 0.949 | |
| Weighted F1 | | | 0.939 | |
| ROC-AUC (weighted OvR)* | | | 0.999 | |

\* Indicative, not statistically robust (49 test samples). Every misclassification is one level
off, never across the scale — reasonable for triage ordering.

**Cross-target validation (leave-one-host-out):**

| Held-out host | Train | Test | Accuracy | Weighted F1 | Macro F1 |
|---|---|---|---|---|---|
| testasp.vulnweb.com | 14 | 179 | 0.358 | 0.527 | 0.553 |
| testaspnet.vulnweb.com | 179 | 14 | 0.857 | 0.886 | 0.810 |

The asymmetry is the honest signal: training on 14 alerts generalizes poorly to 179; training on
179 generalizes reasonably to 14.

## Limitations

1. **Small dataset** — 193 alerts from one scan. Enough to demonstrate the pipeline, not to claim
   generalization.
2. **Scanner-derived labels** — the classifier learns scanner-consistent patterns rather than
   independent ground truth. If ZAP mis-rates something, the model is trained on the mis-rating.
3. **Single-target training corpus** — all training data comes from one deliberately vulnerable
   test site (a classic ASP stack). Behavior on other technologies — or on well-built applications
   — is untested.
4. **Heavy "Other" class** — 91 of 193 alerts map to `Other` (CWE not in the tracked mapping). The
   attack-type features carry less information than the feature count suggests.
5. **In-sample-ish evaluation** — the headline metrics are a random split of the same scan the
   model trains on, not a fresh scan of a different target. The cross-target fold mitigates this
   partially.
6. **Not a substitute for manual pentesting** — it re-orders scanner output; it does not find new
   vulnerabilities, verify exploits, or understand business context.
7. **ROC-AUC is not robust** at this sample size; treat 0.999 as an artifact of near-perfect
   separation on a tiny set, not a generalization estimate.

## Potential label leakage

- Features are derived from the **same alert** whose risk label is the target (e.g.
  `description_length`, `solution_length`). These are legitimate alert-level features, but because
  ZAP generates both the alert metadata and the risk label, there is a structural coupling: the
  model may learn "long solution text ↔ High risk" patterns that reflect the scanner's authoring
  rather than intrinsic exploitability. This is a known limitation of scanner-labelled training.
- `cwe_numeric` is **not** a model feature (CWE ids are identifiers, not quantities). It is kept in
  the report CSV for display only.
- No future-looking features are used (no response bodies, no timing data beyond what ZAP exposes).

## Bias

- The model inherits the scanner's biases: ZAP rates findings based on its plugin rules, which are
  stronger for some vulnerability classes (injection, headers) than others.
- 91 of 193 alerts are "Other" — the model is under-trained on the long tail of CWE ids.
- The bundled scan is a single ASP target; the model has no exposure to non-ASP stacks, modern
  SPAs, or API-only backends.

## Generalization

Not established. The cross-target fold shows 0.86 accuracy when training on the larger host and
testing on the smaller one, but 0.36 in the reverse direction. **Generalization to unseen targets
requires additional labeled scans** of targets you are authorized to test — drop them under
`data/sample/` and re-run.

## Recommended usage

- Triage ordering of ZAP findings on similar (classic web app) targets
- As a baseline to compare future, larger models against
- As a teaching example of detection engineering + hybrid ML on scanner output

## Retraining / regeneration

```bash
python run_pipeline.py --demo            # full flow on the bundled data
# or, if data/processed_latest.csv already exists:
python -m ml.alert_processor
python -m ml.train_hybrid_model
```

This rewrites `models/*.pkl` and `models/training_metrics.json`. Given the same input data, the
output is identical (`random_state=42` everywhere). To train on genuinely new data, scan a target
you are authorized to test, then replace `data/sample/latest_scan.json` with the new
`data/latest_scan.json` — see `docs/MAINTENANCE_GUIDE.md`.

## Disclaimer

> The current model is a proof-of-concept risk-prioritization model trained using scanner-labelled
> vulnerability findings. Its evaluation does **not** establish broad real-world vulnerability
> detection accuracy.
