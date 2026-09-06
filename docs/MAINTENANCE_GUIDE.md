# 🛠️ OWASP-ML Maintenance Guide

The owner's manual — for me (Kaif), and for anyone who forks or contributes. Everything here assumes you are in the repo root and have run `pip install -r requirements.txt`.

---

## 📂 Repo map

What every file does, one line each:

| Path | What it does |
|---|---|
| `run_pipeline.py` | Single entry point; orchestrates scan → preprocess → train → score → report → AI summary (`--demo`, `--skip-train`, or a target URL) |
| `scanner/zap_scan.py` | ZAP API client: spider, active scan, passive-scan drain, paginated alert fetch; writes `data/latest_scan.json`; has the authorization consent guard |
| `ml/acquire_demo_data.py` | Copies `data/sample/latest_scan.json` → `data/latest_scan.json` so demo mode runs the identical code path as a real scan |
| `ml/alert_processor.py` | Raw ZAP JSON → engineered features CSV; owns `map_to_attack()` (CWE→attack) and `extract_risk()` (reads ZAP's `risk` field, not `riskdesc`) |
| `ml/encodings.py` | Fixed encoding maps for confidence, HTTP method, and the risk scale; shared by training and inference so codes can't drift |
| `ml/features.py` | Shared feature builder (`build_sample_features`, `build_features`) + the `ATTACK_TYPES` list that drives the one-hot columns |
| `ml/train_hybrid_model.py` | Trains the RandomForest classifier + IsolationForest, saves `models/*.pkl` and `models/training_metrics.json`; handles single-class data gracefully |
| `ml/hybrid_predict.py` | The 0.6/0.3/0.1 hybrid score per alert; lazy model loading so a fresh clone never crashes on import |
| `ml/scan_and_predict.py` | Scores every processed alert with `hybrid_predict`, writes `data/final_results.csv`, then triggers the threat report |
| `ml/threat_intelligence.py` | OWASP Top-10 category mapping, final risk escalation (`escalate_risk`), per-finding explanations; writes `data/threat_report.csv` |
| `ml/ai_analyst.py` | Builds a stats digest of the report, calls any OpenAI-compatible LLM for an executive summary, falls back to a rule-based engine without a key; writes `data/ai_summary.json` |
| `dashboard/app.py` | Flask server for the three pages (Dashboard, ML Insights, Reports); loads `data/threat_report.csv` |
| `dashboard/templates/` | Jinja templates — `base.html`, `dashboard.html`, `ml_insights.html`, `reports.html` |
| `dashboard/static/` | `css/style.css` and `js/dashboard.js` (Chart.js rendering) |
| `remediation/remedy_engine.py` | Alert-name → fix-text lookup. Wired into the threat report as the `Remediation` column — extend its dictionary to improve fix guidance |
| `tests/test_pipeline.py` | 15 unit tests over the pure logic (mappings, encodings, escalation, features, sample-data integrity); no ZAP or models needed |
| `data/sample/latest_scan.json` | The bundled real scan (193 alerts) that powers demo mode — committed on purpose |
| `data/latest_scan.json`, `data/*.csv`, `data/ai_summary.json` | Generated pipeline outputs (regenerated on every run) |
| `models/` | Generated artifacts: `risk_classifier.pkl`, `anomaly_detector.pkl`, `label_encoder.pkl`, `feature_columns.pkl`, `training_metrics.json` |
| `.github/workflows/ci.yml` | CI: unit tests + demo-pipeline smoke test + dashboard boot check |
| `.env.example` | Template for AI provider and ZAP settings; copy to `.env` |
| `MODEL_CARD.md` | Honest documentation of the model: data, metrics, limitations |
| `docs/MAINTENANCE_GUIDE.md` | This file |

## 🧰 Common recipes

### 1. Add a new CWE → attack mapping

Three files must stay in sync:

1. `ml/alert_processor.py` — add the CWE id to the `mapping` dict inside `map_to_attack()` (whole-id matching, so `"189"` never matches `"89"`).
2. `ml/features.py` — add the new attack name to `ATTACK_TYPES`. Without this, the one-hot column doesn't exist and the feature space at train time and inference time can disagree.
3. `ml/threat_intelligence.py` — add the attack name to `map_owasp_category()` so it lands in an OWASP Top-10 category instead of `Uncategorized`.

Then add a test next to the existing ones in `tests/test_pipeline.py` (`test_map_to_attack_known_cwes` is the pattern) and run:

```bash
python -m pytest tests/ -q
```

### 2. Change the hybrid score weights

The weights live in one line in `ml/hybrid_predict.py`:

```python
final_score = 0.6 * max_prob + 0.3 * anomaly_score + 0.1 * RISK_WEIGHT.get(predicted_risk, 0.1)
```

Two things to remember:

- Keep the three weights summing to 1.0 so scores stay interpretable against the 0.75 escalation threshold in `escalate_risk`.
- There is a **second** score line in the same file — the no-classifier fallback (`0.7 * anomaly_score + ...`). Update it consistently, or at least consciously.

No retraining needed — weights are applied at prediction time. Re-run `python run_pipeline.py --demo --skip-train` to see the effect on the final distribution.

### 3. Change the risk escalation rules

`ml/threat_intelligence.py::escalate_risk()` is the whole policy: base = the more severe of scanner risk and ML prediction; escalate one level if `hybrid_score >= 0.75`; cap at Critical. Change the threshold or the promotion rule there.

The behavior is pinned by tests — `test_escalate_risk_uses_original_risk`, `test_escalate_risk_escalates_on_strong_hybrid_score`, and `test_escalate_risk_handles_unknown_labels` in `tests/test_pipeline.py`. If you change the rules, change those tests in the same commit, and run:

```bash
python -m pytest tests/ -q
```

### 4. Add a dashboard chart

Three touch points:

1. `dashboard/app.py` — compute the aggregate (e.g. another `value_counts()`) and pass it to `render_template(...)`.
2. `dashboard/templates/<page>.html` — add a `<canvas id="...">` inside a `chart-container` div.
3. `dashboard/static/js/dashboard.js` — render the chart with Chart.js against that canvas id (copy the pattern of the existing risk/attack charts).

Smoke it locally with `python dashboard/app.py`, then check the page still returns 200 — CI does exactly that (see below).

### 5. Retrain on new scan data

The normal path — scan a target you're authorized to test and let the pipeline do everything:

```bash
python run_pipeline.py https://your-target
```

Training happens automatically as part of the run. To retrain manually without scanning again (uses whatever is already in `data/latest_scan.json`):

```bash
python -m ml.alert_processor
python -m ml.train_hybrid_model
```

Both steps print their progress; metrics land in `models/training_metrics.json`. Training is deterministic (`random_state=42`), so the same input data always produces the same model and the same metrics. If the dataset has only one risk class, the classifier is skipped but the anomaly detector still trains — that's a handled case, not an error.

### 6. Rotate the AI provider

The AI analyst speaks the OpenAI chat-completions dialect, so the provider is just three lines in `.env`:

```bash
cp .env.example .env
# then set:
# AI_API_KEY=<key>
# AI_BASE_URL=<provider base url>
# AI_MODEL=<model name>
```

`AI_BASE_URL` examples (also documented in `.env.example`): OpenAI `https://api.openai.com/v1`, Groq `https://api.groq.com/openai/v1`, OpenRouter `https://openrouter.ai/api/v1`, a local Ollama server `http://localhost:11434/v1`. Never commit the `.env` itself — it's gitignored.

Verify the switch without re-running the whole pipeline:

```bash
python -m ml.ai_analyst
```

It prints who generated the summary (`LLM (<model>)` or the rule-based engine) and writes `data/ai_summary.json`. If the API call fails for any reason, it falls back to the rule-based engine instead of crashing — that's by design.

## 🌿 Git workflow

How I keep the history clean on this repo (see `git log` — the v2 commits follow this style):

```bash
# 1. Branch off main (or off v2-upgrade while that PR is still open)
git checkout -b fix/risk-escalation-threshold

# 2. Make changes, then commit small and atomic — one logical change per commit
git add ml/threat_intelligence.py tests/test_pipeline.py
git commit -m "Adjust hybrid escalation threshold and update tests"

# 3. Push and open a PR
git push -u origin fix/risk-escalation-threshold
# then open the PR on github.com/Kaif-Kenwey/OWASP-ML
```

Commit message style: short imperative subject, conventional prefixes (`Add ...`, `Fix ...`, `Update ...`, `Remove ...`), one concern per commit. If a change updates code and its tests, they go in the same commit. Generated files (`data/`, `models/`) are gitignored — don't `git add` them.

After the PR is reviewed, squash-merge or merge into `main`, delete the branch, and CI runs on the merge. That's the whole loop.

## 🤖 CI explanation

`.github/workflows/ci.yml` runs on every PR and every push to `main`, on Python 3.11:

1. **Install dependencies** — `pip install -r requirements.txt`, with pip caching. Proves the requirements file is complete.
2. **Unit tests** — `pytest tests/ -q`. Fast, deterministic checks of the pure logic: CWE mapping, the `risk`-field regression fix, fixed encodings, escalation rules, one-hot features, sample-data integrity. No ZAP, no Flask, no models needed.
3. **Smoke test — full demo pipeline** — `python run_pipeline.py --demo`. Runs the entire flow (including training) on the bundled scan. If this passes, a fresh clone genuinely works end to end.
4. **Smoke test — dashboard boots** — imports the Flask app and asserts `/`, `/ml-insights`, `/reports` all return 200. Catches template and route breakage that unit tests can't see.

Reading a failing run: open the **Actions** tab → click the failed run → the red step tells you which layer broke. A red "Unit tests" step prints the failing assertion with the test name (run the same `pytest` locally to reproduce). A red demo step means a pipeline regression — usually a schema change in one stage that a later stage doesn't accept; reproduce with `python run_pipeline.py --demo` and read the printed step headers to see where it died. A red dashboard step means a route or template regression; reproduce with the same snippet from `ci.yml`. Re-running a failed job without a code change rarely helps — the tests are deterministic.

## 📦 Demo data note

`data/sample/latest_scan.json` is committed **on purpose**. It is a real ZAP scan (193 alerts from testasp.vulnweb.com) that makes the demo work with zero setup, and `tests/test_pipeline.py::test_bundled_sample_data_is_valid_and_labeled` guards its integrity — if the file goes missing or its risk labels come out empty, CI fails.

To regenerate a fresh sample from a real scan (a target you're authorized to test):

```bash
python run_pipeline.py https://your-target     # writes data/latest_scan.json
cp data/latest_scan.json data/sample/latest_scan.json
git add data/sample/latest_scan.json
git commit -m "Update bundled demo scan data"
python -m pytest tests/ -q                     # the integrity test must pass
```

Keep it one representative scan. If the new scan has different hosts, update the "Tested On" section of the README and the training-data section of `MODEL_CARD.md` so the docs stay truthful.

## ✅ Release checklist

Before publishing a release (or merging a big change):

- [ ] `python -m pytest tests/ -q` — all green
- [ ] `python run_pipeline.py --demo` — completes, prints sane risk distribution
- [ ] `python dashboard/app.py` — all three pages load with data
- [ ] Docs still truthful: README commands, `MODEL_CARD.md` metrics (quote the fresh `models/training_metrics.json`), this guide
- [ ] README badges still accurate (Python version, CI status)
- [ ] `git status` clean of generated files (`data/`, `models/` are gitignored — nothing from them should ever be staged)
- [ ] Bump notes in the PR description: what changed, why, and any metric movement

---

*Maintained by Mohammad Kaif — B.Tech CSE (Data Science), Cybersecurity & AI Enthusiast.*
