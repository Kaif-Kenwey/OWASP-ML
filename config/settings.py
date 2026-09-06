"""
Pipeline-wide settings: thresholds, weights and reproducibility seeds.

Centralizing these means a single, reviewable place for the numbers that
govern detection, scoring and escalation. They are intentionally NOT split
across ml/hybrid_predict.py, ml/threat_intelligence.py and detection/*.
"""

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
RANDOM_STATE = 42           # every sklearn model + train_test_split
TEST_SIZE = 0.25            # holdout fraction
MIN_CLASS_SAMPLES = 2      # below this, stratify is skipped (single sample / class)

# ---------------------------------------------------------------------------
# Hybrid ML scoring weights (must sum to 1.0)
# ---------------------------------------------------------------------------
# hybrid_score = W_CLF * classifier_confidence
#              + W_ANOMALY * anomaly_score
#              + W_STATIC * static_risk_weight
#
# NOTE: this score is a RISK PRIORITIZATION score, NOT a calibrated probability.
# It is displayed as the "Hybrid Threat Score" and never as "ML confidence %".
HYBRID_WEIGHTS = {
    "classifier": 0.6,
    "anomaly": 0.3,
    "static_risk": 0.1,
}

# Fallback weights used when no classifier could be trained (single-class data).
# Rescaled to the same 0..1 range so the score stays comparable.
HYBRID_WEIGHTS_FALLBACK = {
    "classifier": 0.0,
    "anomaly": 0.9,
    "static_risk": 0.1,
}

# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------
ANOMALY_CONTAMINATION = 0.1     # expected fraction of anomalies (IsolationForest)
ANOMALY_SCORE_THRESHOLD = 0.55  # a finding above this is "anomalous" for RULE-006

# ---------------------------------------------------------------------------
# Risk escalation
# ---------------------------------------------------------------------------
# Final risk = max(scanner_risk, ml_predicted_risk), then escalate one level
# if hybrid_score >= ESCALATION_HYBRID_THRESHOLD, capped at Critical.
# Detection-rule and correlation signals can also escalate (see ml/threat_intelligence).
ESCALATION_HYBRID_THRESHOLD = 0.75

# A detection rule tagged High/Critical escalates the finding's final risk
# to at least this level (conservative: rule says High -> at least High).
DETECTION_SEVERITY_FLOOR = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Informational",
}

# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------
# Transparent, capped correlation score. Formula (documented):
#   correlation_score = related_findings_count
#                     + severity_weight   (max risk index among members, 0..4)
#                     + confidence_weight (0 if all Low confidence, 1 otherwise)
# Capped at CORRELATION_MAX_SCORE so a single noisy endpoint cannot dominate.
CORRELATION_MAX_SCORE = 10
# Minimum related findings required to form a correlated event.
CORRELATION_MIN_FINDINGS = 2
# Risk escalation applied to a correlated event (bumps member findings at
# least one level, capped at Critical) -- only for events whose correlation
# score crosses CORRELATION_ESCALATION_SCORE.
CORRELATION_ESCALATION_SCORE = 3
CORRELATION_ESCALATION_STEP = 1

# ---------------------------------------------------------------------------
# Dashboard / pipeline
# ---------------------------------------------------------------------------
REPORT_ROW_CAP = 500           # max rows rendered in the findings table
DEMO_TOTAL_STEPS = 8          # the [1/8]..[8/8] pipeline stepper
