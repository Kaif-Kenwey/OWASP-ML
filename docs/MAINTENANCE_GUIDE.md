# OWASP-ML Maintenance Guide

The owner's manual — for me (Kaif), and for anyone who forks or contributes. Everything here
assumes you are in the repo root and have run `pip install -r requirements.txt`.

---

## Repo map

| Path | What it does |
|---|---|
| `run_pipeline.py` | `[1/8]..[8/8]` stepper orchestrator: scan → preprocess → train → score → detection → correlation → report → AI |
| `config/risks.py` | Canonical risk scale, weights, `normalize_risk` (the single source of truth for ordering) |
| `config/owasp_mapping.py` | CWE→attack, attack→OWASP, descriptions (centralized — was 2 inline dicts in v2) |
| `config/detection_rules.py` | RULE-001..006 declarative registry (findings-scope + group-scope) |
| `config/settings.py` | Thresholds, hybrid weights, `random_state`, correlation caps |
| `config/clean.py` | NaN-safe value helpers (`is_missing`, `safe_str`, `clean_finding_for_display`) — the "nan" defense |
| `detection/engine.py` | Evaluate rules → `detections.csv`; attach detections to findings (with the anti-inflation contract) |
| `detection/correlation.py` | Endpoint grouping → `correlations.csv`; capped score; conservative escalation gate |
| `scanner/zap_scan.py` | ZAP client: preflight + spider/active/passive + paginated alerts; max-wait safety caps; target validation |
| `ml/acquire_demo_data.py` | Copy bundled sample → `data/latest_scan.json` (demo mode = same code path as a real scan) |
| `ml/alert_processor.py` | Raw ZAP JSON → engineered features CSV; assigns `finding_id` + content `signature` |
| `ml/encodings.py` | Fixed encoding maps (re-exports risk helpers from `config/risks.py`) |
| `ml/features.py` | Shared feature builder (train + inference parity) — ATTACK_TYPES sourced from config |
| `ml/train_hybrid_model.py` | RF + IF training; metrics; cross-target (leave-one-host-out) validation; feature importance |
| `ml/hybrid_predict.py` | 4 separated signals: classifier_confidence, anomaly_score, static_risk_weight, hybrid_threat_score |
| `ml/scan_and_predict.py` | Score alerts, carry `finding_id` end-to-end → `final_results.csv` |
| `ml/threat_intelligence.py` | JOIN on `finding_id` (no positional concat); detection + correlation; conservative escalation; OWASP enrichment |
| `ml/ai_analyst.py` | LLM summary + rule-based fallback; reads detections.csv + correlations.csv for the digest |
| `remediation/remedy_engine.py` | Structured remediation per attack class (why/impact/fix/best-practice) |
| `dashboard/app.py` | Flask: 3 pages + 4 JSON APIs + XTransformPort gateway support + NaN-safe loaders |
| `dashboard/templates/` | `base.html`, `dashboard.html`, `ml_insights.html`, `reports.html` (dark SOC theme) |
| `dashboard/static/` | `css/style.css` (dark SOC) + `js/dashboard.js` (Chart.js + drawer + filters) |
| `tests/test_pipeline.py` | Core logic + finding_id + malformed + duplicate + escalation tests |
| `tests/test_detection.py` | RULE-001..006 + correlation engine + anti-inflation contract |
| `tests/test_clean.py` | NaN helpers + risk normalization + OWASP mapping |
| `data/sample/latest_scan.json` | Bundled real scan (193 alerts) — committed on purpose, powers demo mode |
| `models/` | Generated: `*.pkl` + `training_metrics.json` (gitignored, rebuild via `--demo`) |

## Common recipes

### 1. Add a new CWE → attack mapping

Now a **one-file** change (was three files in v2):

1. `config/owasp_mapping.py` — add the CWE id to `CWE_TO_ATTACK` (whole-id matching; `"189"`
   never matches `"89"`). If the attack family is new, also add it to `ATTACK_TYPES` and
   `ATTACK_TO_OWASP`.

Then add a test next to the existing ones in `tests/test_clean.py` and run:

```bash
python -m pytest tests/ -q
```

### 2. Add a detection rule

1. `config/detection_rules.py` — append a `DetectionRule(...)` to `RULES`. For finding-scope
   rules, write a `check(finding) -> Optional[str]`. For group-scope rules, write
   `check(group) -> Optional[(evidence, finding_ids)]` naming **exactly** the member findings the
   detection applies to (returning the whole group would floor every member up to the rule
   severity — that is severity inflation and is forbidden).
2. (optional) Add a test in `tests/test_detection.py`.

The engine picks it up automatically. Re-run `python run_pipeline.py --demo` to see it fire.

### 3. Change the hybrid score weights

The weights live in `config/settings.py::HYBRID_WEIGHTS`:

```python
HYBRID_WEIGHTS = {"classifier": 0.6, "anomaly": 0.3, "static_risk": 0.1}
```

Keep them summing to 1.0 so scores stay comparable to the `ESCALATION_HYBRID_THRESHOLD = 0.75`
escalation threshold. Update `HYBRID_WEIGHTS_FALLBACK` consistently (the no-classifier path).
No retraining needed — weights are applied at prediction time.

### 4. Change the risk escalation policy

`ml/threat_intelligence.py::escalate_risk()` is the whole policy: base = max(scanner, ML);
`+1` if `hybrid_score ≥ 0.75`; floor to `detection_severity`; `+1` if a true multi-vector
correlated event affects a ≥ Medium member. Change thresholds in `config/settings.py`. The
behavior is pinned by tests in `tests/test_pipeline.py` (`test_escalate_risk_*`).

### 5. Change the correlation scoring formula

`detection/correlation.py::correlate()` builds events; the score formula is documented at the top
of the file. The escalation gate (`should_escalate`, `member_should_escalate`) lives there too —
multi-vector + ≥ Medium member. Pinned by `tests/test_detection.py`.

### 6. Retrain on new scan data

```bash
python run_pipeline.py https://your-authorized-target     # writes data/latest_scan.json
cp data/latest_scan.json data/sample/latest_scan.json
python -m pytest tests/ -q                                 # integrity test must pass
```

### 7. Rotate the AI provider

```bash
cp .env.example .env
# AI_API_KEY=<key>  AI_BASE_URL=<provider>  AI_MODEL=<model>
python -m ml.ai_analyst     # prints who generated the summary; falls back if the call fails
```

`AI_BASE_URL` examples: OpenAI `https://api.openai.com/v1`, Groq `https://api.groq.com/openai/v1`,
OpenRouter `https://openrouter.ai/api/v1`, local Ollama `http://localhost:11434/v1`.

## CI explanation

`.github/workflows/ci.yml` runs on every PR and push to `main`, on Python 3.11:

1. **Install dependencies** — proves `requirements.txt` is complete.
2. **Unit tests** — 78 tests (detection, correlation, NaN, mappings, features, malformed, dup).
3. **Demo pipeline smoke** — `python run_pipeline.py --demo` (full flow on bundled data).
4. **Generated-file verification** — asserts `detections.csv`, `correlations.csv`,
   `threat_report.csv`, `training_metrics.json`, etc. all exist.
5. **Critical-column NaN check** — asserts the 12 critical display columns never contain
   `nan`/`none`/empty (the "nan problem" regression guard).
6. **Dashboard boot check** — imports the Flask app and asserts all 3 pages + 4 APIs return 200.

No external API keys are needed in CI — the AI analyst uses the rule-based fallback.

## Adding a new feature to the dashboard

1. `dashboard/app.py` — compute the aggregate + pass it to `render_template(...)`.
2. `dashboard/templates/<page>.html` — add the markup; append `{{ qp }}` to every internal
   `href`/`src` so links work through the gateway (`?XTransformPort=5000`).
3. `dashboard/static/js/dashboard.js` — render any chart with Chart.js (copy the risk/attack pattern).
4. `dashboard/static/css/style.css` — use the existing CSS variables (`--cyan`, `--critical`, ...).

The `qp` / `ap` context variables are injected by `inject_gateway_helpers()` so the dashboard works
both on `localhost:5000` and through the sandbox gateway.

## Demo data note

`data/sample/latest_scan.json` is committed **on purpose**. It is a real ZAP scan (193 alerts)
that makes the demo work with zero setup. `tests/test_pipeline.py::test_bundled_sample_data_is_valid_and_labeled`
guards its integrity. Keep it one representative scan; if you regenerate it, update the "Tested On"
section of the README and the training-data section of `MODEL_CARD.md` so the docs stay truthful.

## Release checklist

- [ ] `python -m pytest tests/ -q` — all green
- [ ] `python run_pipeline.py --demo` — completes, sane risk distribution
- [ ] `python dashboard/app.py` — all 3 pages + 4 APIs load with data
- [ ] README + MODEL_CARD still truthful (quote fresh `models/training_metrics.json`)
- [ ] `git status` clean of generated files (`data/`, `models/` are gitignored)

---

*Maintained by Mohammad Kaif — B.Tech CSE (Data Science), Cybersecurity & AI Enthusiast.*
