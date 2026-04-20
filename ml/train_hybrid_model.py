import pandas as pd
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "processed_latest.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")

def train_hybrid():

    print("\n===== HYBRID ML TRAINING STARTED =====")

    df = pd.read_csv(DATA_PATH)

    print("Dataset shape:", df.shape)

    # ----------- LABEL ENCODING -----------
    le = LabelEncoder()
    df["risk_encoded"] = le.fit_transform(df["risk"])

    # Save label encoder
    joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.pkl"))

    # ----------- FEATURE SELECTION -----------
    feature_cols = [
        "confidence_encoded",
        "method_encoded",
        "cwe_numeric",
        "url_length",
        "param_length",
        "has_query_params",
        "path_depth",
        "description_length",
        "solution_length",
        "reference_count"
    ]

    X = df[feature_cols]
    y = df["risk_encoded"]

    print("Features used:", feature_cols)

    # Save feature list
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_columns.pkl"))

    # ----------- TRAIN TEST SPLIT -----------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print("Training samples:", len(X_train))
    print("Testing samples:", len(X_test))

    # ----------- TRAIN CLASSIFIER -----------
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42
    )

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n--- CLASSIFIER EVALUATION ---")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    # ----------- TRAIN ANOMALY DETECTOR -----------
    print("\n--- TRAINING ANOMALY DETECTOR ---")

    iso = IsolationForest(
        n_estimators=200,
        contamination=0.1,
        random_state=42
    )

    iso.fit(X)

    # ----------- SAVE MODELS -----------
    joblib.dump(clf, os.path.join(MODEL_DIR, "risk_classifier.pkl"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "anomaly_detector.pkl"))

    print("\nModels saved successfully.")
    print("===== HYBRID TRAINING COMPLETE =====\n")


if __name__ == "__main__":
    train_hybrid()
