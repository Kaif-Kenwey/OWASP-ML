import joblib
import os
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

RISK_WEIGHT = {
    "Informational": 0.1,
    "Low": 0.3,
    "Medium": 0.6,
    "High": 0.9
}

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

    Combines three signals:
      0.6 * classifier confidence  (how sure the RF classifier is)
      0.3 * anomaly score          (IsolationForest "how unusual is this")
      0.1 * static risk weight     (baseline severity of predicted class)

    If the classifier is unavailable (single-class training data), the
    score falls back to anomaly + risk-weight signals only, rescaled to
    the same 0-1 range.
    """
    models = _load_models()
    clf, iso = models["clf"], models["iso"]

    df = pd.DataFrame([sample_dict])

    if feature_cols is None:
        fc_path = os.path.join(MODEL_DIR, "feature_columns.pkl")
        feature_cols = joblib.load(fc_path)

    df = df.reindex(columns=feature_cols, fill_value=0)

    # Anomaly score (IsolationForest) normalized to 0-1
    anomaly_score = -iso.decision_function(df)[0]
    anomaly_score = float(min(max(anomaly_score, 0), 1))

    if clf is not None:
        class_probs = clf.predict_proba(df)[0]
        predicted_class_index = int(np.argmax(class_probs))
        max_prob = float(class_probs[predicted_class_index])

        le_path = os.path.join(MODEL_DIR, "label_encoder.pkl")
        le = joblib.load(le_path)
        predicted_risk = le.inverse_transform([predicted_class_index])[0]

        final_score = 0.6 * max_prob + 0.3 * anomaly_score + 0.1 * RISK_WEIGHT.get(predicted_risk, 0.1)
    else:
        # Fallback: no classifier trained (single-class data)
        predicted_risk = "Unknown"
        final_score = 0.7 * anomaly_score + 0.1 * RISK_WEIGHT.get("Informational", 0.1)

    return {
        "predicted_risk": predicted_risk,
        "hybrid_threat_score": round(float(final_score), 4)
    }
