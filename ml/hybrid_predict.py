"""
Hybrid ML threat scoring.

Returns FOUR separated signals per finding so the dashboard can show the
score's composition (explainability), not just a single opaque number:

  classifier_confidence  -- max class probability from the RandomForest
  anomaly_score           -- normalized IsolationForest anomaly score
  static_risk_weight      -- baseline weight of the predicted risk class
  hybrid_threat_score     -- the weighted combination

IMPORTANT naming policy (academic honesty):
The combined number is a RISK PRIORITIZATION score, not a calibrated
probability. It is therefore exposed as "hybrid_threat_score" and rendered
in the UI as "Hybrid Threat Score" -- never as "ML confidence %".
"""

import joblib
import os
import numpy as np
import pandas as pd

from config.settings import (
    HYBRID_WEIGHTS,
    HYBRID_WEIGHTS_FALLBACK,
)
from config.risks import risk_weight, normalize_risk

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

# Models are loaded lazily so importing this module never crashes
# when models have not been trained yet (fresh clone / CI).
_models = None


def _load_models():
    global _models
    if _models is not None:
        return _models

    clf_path = os.path.join(MODEL_DIR, "risk_classifier.pkl")
    iso_path = os.path.join(MODEL_DIR, "anomaly_detector.pkl")

    if not os.path.exists(iso_path):
        raise FileNotFoundError(
            "Models not found. Train them first: python run_pipeline.py --demo"
        )

    iso = joblib.load(iso_path)

    clf = None
    if os.path.exists(clf_path):
        clf = joblib.load(clf_path)
        # joblib keeps None when the classifier could not be trained
        if clf is None:
            clf = None

    _models = {"clf": clf, "iso": iso}
    return _models


def hybrid_predict(sample_dict, feature_cols=None):
    """
    Hybrid threat score for a single engineered alert.

    Combines three signals (weights live in config/settings.py):
      W_CLF     * classifier_confidence  (how sure the RF classifier is)
      W_ANOMALY * anomaly_score          (IsolationForest "how unusual is this")
      W_STATIC  * static_risk_weight      (baseline severity of predicted class)

    If the classifier is unavailable (single-class training data), the
    score falls back to anomaly + risk-weight signals only, rescaled to
    the same 0-1 range. The four components are returned separately so the
    dashboard can render the score's composition.
    """
    models = _load_models()
    clf, iso = models["clf"], models["iso"]

    df = pd.DataFrame([sample_dict])

    if feature_cols is None:
        fc_path = os.path.join(MODEL_DIR, "feature_columns.pkl")
        feature_cols = joblib.load(fc_path)

    df = df.reindex(columns=feature_cols, fill_value=0)

    # Anomaly score (IsolationForest) normalized to 0-1.
    # decision_function returns higher = more normal, so we negate it.
    raw_anomaly = -float(iso.decision_function(df)[0])
    anomaly_score = float(min(max(raw_anomaly, 0.0), 1.0))

    w = HYBRID_WEIGHTS

    if clf is not None:
        class_probs = clf.predict_proba(df)[0]
        predicted_class_index = int(np.argmax(class_probs))
        classifier_confidence = float(class_probs[predicted_class_index])

        le_path = os.path.join(MODEL_DIR, "label_encoder.pkl")
        le = joblib.load(le_path)
        predicted_risk = le.inverse_transform([predicted_class_index])[0]
        predicted_risk = normalize_risk(predicted_risk)

        static_risk_weight = risk_weight(predicted_risk)

        hybrid_threat_score = (
            w["classifier"] * classifier_confidence
            + w["anomaly"] * anomaly_score
            + w["static_risk"] * static_risk_weight
        )
    else:
        # Fallback: no classifier trained (single-class data).
        wf = HYBRID_WEIGHTS_FALLBACK
        predicted_risk = "Unknown"
        classifier_confidence = 0.0
        static_risk_weight = risk_weight("Informational")

        hybrid_threat_score = (
            wf["anomaly"] * anomaly_score
            + wf["static_risk"] * static_risk_weight
        )

    return {
        "predicted_risk": predicted_risk,
        "classifier_confidence": round(float(classifier_confidence), 4),
        "anomaly_score": round(float(anomaly_score), 4),
        "static_risk_weight": round(float(static_risk_weight), 4),
        "hybrid_threat_score": round(float(hybrid_threat_score), 4),
    }


# Backward-compatible alias: older code called `hybrid_predict` and read
# `hybrid_threat_score`. That key is unchanged. The old `hybrid_score` key
# is kept as an alias so any lingering caller still works.
def _legacy_alias(result):
    result["hybrid_score"] = result["hybrid_threat_score"]
    return result
