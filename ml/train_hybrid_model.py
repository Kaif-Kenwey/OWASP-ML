import pandas as pd
import os
import json
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

from ml.features import build_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "processed_latest.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")


MIN_CLASS_SAMPLES = 2


def train_hybrid():
    """
    Train the hybrid model (RandomForest classifier + IsolationForest
    anomaly detector) on engineered alert features.
    """
    print("\n===== HYBRID ML TRAINING STARTED =====")

    if not os.path.exists(DATA_PATH):
        print("No processed data found. Run the preprocessing step first")
        print("(python run_pipeline.py --demo, or scan a target first).")
        return False

    df = pd.read_csv(DATA_PATH)

    if df.empty:
        print("Processed dataset is empty — nothing to train on.")
        return False

    print("Dataset shape:", df.shape)

    # ----------- LABEL ENCODING -----------
    le = LabelEncoder()
    df["risk_encoded"] = le.fit_transform(df["risk"])

    class_counts = df["risk_encoded"].value_counts()
    print("Class distribution:", class_counts.to_dict())

    if len(class_counts) < 2:
        print("Only one risk class present — classifier training skipped,")
        print("but the anomaly detector is still trained and models saved.")
        clf = None
        report = {"note": "single-class dataset, classifier not trained"}
        cm = []
    else:
        joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.pkl"))

        # ----------- FEATURE SELECTION -----------
        X = build_features(df)
        y = df["risk_encoded"]

        feature_cols = list(X.columns)
        joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_columns.pkl"))

        print("Features used:", feature_cols)

        # ----------- TRAIN TEST SPLIT -----------
        can_stratify = class_counts.min() >= MIN_CLASS_SAMPLES
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25,
            random_state=42,
            stratify=y if can_stratify else None
        )

        print("Training samples:", len(X_train))
        print("Testing samples:", len(X_test))

        # ----------- TRAIN CLASSIFIER -----------
        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            random_state=42,
            n_jobs=-1
        )

        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        print("\n--- CLASSIFIER EVALUATION ---")
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        print(classification_report(y_test, y_pred, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()
        print("Confusion Matrix:\n", cm)

    # ----------- TRAIN ANOMALY DETECTOR -----------
    print("\n--- TRAINING ANOMALY DETECTOR ---")

    X_all = build_features(df)
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.1,
        random_state=42
    )
    iso.fit(X_all)

    # ----------- SAVE MODELS -----------
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(MODEL_DIR, "risk_classifier.pkl"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "anomaly_detector.pkl"))

    # ----------- PERSIST METRICS -----------
    metrics = {
        "dataset_rows": int(len(df)),
        "class_distribution": {str(k): int(v) for k, v in class_counts.items()},
        "features": list(X_all.columns),
        "classifier_trained": clf is not None,
        "classification_report": report,
        "confusion_matrix": cm,
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print("\nMetrics saved to:", METRICS_PATH)
    print("Models saved successfully.")
    print("===== HYBRID TRAINING COMPLETE =====\n")
    return True


if __name__ == "__main__":
    train_hybrid()
