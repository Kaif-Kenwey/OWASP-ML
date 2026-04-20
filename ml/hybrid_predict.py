import joblib
import os
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

# Load models
clf = joblib.load(os.path.join(MODEL_DIR, "risk_classifier.pkl"))
iso = joblib.load(os.path.join(MODEL_DIR, "anomaly_detector.pkl"))
le = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
feature_cols = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))

RISK_WEIGHT = {
    "Informational": 0.1,
    "Low": 0.3,
    "Medium": 0.6,
    "High": 0.9
}

def hybrid_predict(sample_dict):

    df = pd.DataFrame([sample_dict])

    # Ensure correct column order
    df = df[feature_cols]

    # Classifier probability
    class_probs = clf.predict_proba(df)[0]
    predicted_class_index = np.argmax(class_probs)
    predicted_risk = le.inverse_transform([predicted_class_index])[0]

    max_prob = class_probs[predicted_class_index]

    # Anomaly score (IsolationForest)
    anomaly_score = -iso.decision_function(df)[0]

    # Normalize anomaly score between 0–1
    anomaly_score = min(max(anomaly_score, 0), 1)

    # Risk weight
    risk_weight = RISK_WEIGHT.get(predicted_risk, 0.1)

    # Final hybrid score
    final_score = (
        0.6 * max_prob +
        0.3 * anomaly_score +
        0.1 * risk_weight
    )

    return {
        "predicted_risk": predicted_risk,
        "hybrid_threat_score": round(final_score, 4)
    }
