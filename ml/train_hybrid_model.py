import pandas as pd
import os
import json
import joblib
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)

from ml.features import build_features
from config.settings import RANDOM_STATE, TEST_SIZE, MIN_CLASS_SAMPLES, ANOMALY_CONTAMINATION
from config.owasp_mapping import ATTACK_TYPES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "processed_latest.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
METRICS_PATH = os.path.join(MODEL_DIR, "training_metrics.json")


# ---------------------------------------------------------------------------
# Honest evaluation helpers
# ---------------------------------------------------------------------------

def _safe_metric(fn, y_true, y_pred, **kwargs):
    """Wrap a sklearn metric so a computation failure never breaks training."""
    try:
        return float(fn(y_true, y_pred, **kwargs))
    except Exception as exc:
        print(f"[metrics] {fn.__name__} failed: {exc}")
        return None


def _try_roc_auc(clf, X_test, y_test, class_labels):
    """Compute weighted one-vs-rest ROC-AUC, only when statistically sensible.

    Requirements (documented): >= 2 classes present in the test set AND
    >= 5 test samples per class on average. Below that the estimate is
    too noisy to report as a metric, so we return None and a reason.
    """
    n_classes = len(set(y_test))
    n_samples = len(y_test)
    if n_classes < 2 or n_samples < 20:
        return None, "skipped: fewer than 2 classes or < 20 test samples"
    try:
        proba = clf.predict_proba(X_test)
        return float(roc_auc_score(y_test, proba, multi_class="ovr",
                                   average="weighted", labels=class_labels)), None
    except Exception as exc:
        return None, f"skipped: {exc}"


def _host_of(url):
    try:
        return urlparse(url).netloc
    except Exception:
        return "(unknown)"


def _cross_target_validation(df, X, y, le):
    """Leave-one-host-out evaluation when the dataset spans multiple hosts.

    This is the honest generalization check the spec asks for: train on
    host(s) A, test on host B. With the bundled scan (2 hosts: testasp and
    testaspnet) this is small but real. We document the limitation rather
    than fabricate a robust number.
    """
    if "url" not in df.columns:
        return {"available": False, "reason": "no url column -> cannot group by host"}

    hosts = df["url"].apply(_host_of)
    host_counts = hosts.value_counts()
    eligible = host_counts[host_counts >= 10]   # need enough per host to be meaningful

    if len(eligible) < 2:
        return {
            "available": False,
            "reason": (
                "cross-target validation requires >= 2 hosts with >= 10 findings each; "
                f"found {len(host_counts)} host(s): {host_counts.to_dict()}"
            ),
            "host_distribution": host_counts.to_dict(),
        }

    results = []
    for holdout_host in eligible.index:
        train_mask = hosts != holdout_host
        test_mask = hosts == holdout_host
        if train_mask.sum() == 0 or test_mask.sum() == 0:
            continue

        X_tr, y_tr = X[train_mask], y[train_mask]
        X_te, y_te = X[test_mask], y[test_mask]

        # need >= 2 classes in the train set to train a classifier
        if len(set(y_tr)) < 2:
            results.append({
                "held_out_host": holdout_host,
                "train_samples": int(train_mask.sum()),
                "test_samples": int(test_mask.sum()),
                "status": "skipped (single train class)",
            })
            continue

        clf_cv = RandomForestClassifier(
            n_estimators=200, max_depth=12, random_state=RANDOM_STATE, n_jobs=-1
        )
        clf_cv.fit(X_tr, y_tr)
        y_pred = clf_cv.predict(X_te)

        # only classes seen at train time can be predicted; restrict the
        # scoring to the intersection to avoid sklearn errors
        present = sorted(set(y_te) & set(y_pred))
        if not present:
            results.append({
                "held_out_host": holdout_host,
                "train_samples": int(train_mask.sum()),
                "test_samples": int(test_mask.sum()),
                "status": "skipped (no class overlap train/test)",
            })
            continue

        results.append({
            "held_out_host": holdout_host,
            "train_samples": int(train_mask.sum()),
            "test_samples": int(test_mask.sum()),
            "test_classes_present": [le.inverse_transform([c])[0] for c in present],
            "accuracy": float(accuracy_score(y_te, y_pred)),
            "weighted_f1": float(f1_score(y_te, y_pred, average="weighted",
                                          labels=present, zero_division=0)),
            "macro_f1": float(f1_score(y_te, y_pred, average="macro",
                                        labels=present, zero_division=0)),
        })

    return {
        "available": True,
        "host_distribution": {str(k): int(v) for k, v in host_counts.to_dict().items()},
        "folds": results,
        "note": (
            "Cross-target (leave-one-host-out) evaluation. With only 2 hosts "
            "in the bundled scan these numbers are indicative, not statistically "
            "robust -- they exist to demonstrate the methodology, not to claim "
            "generalization."
        ),
    }


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_hybrid():
    """
    Train the hybrid model (RandomForest classifier + IsolationForest
    anomaly detector) on engineered alert features.

    Persists:
      models/risk_classifier.pkl
      models/anomaly_detector.pkl
      models/label_encoder.pkl
      models/feature_columns.pkl
      models/training_metrics.json   (all metrics + cross-target framework)
    """
    print("\n===== HYBRID ML TRAINING STARTED =====")

    if not os.path.exists(DATA_PATH):
        print("No processed data found. Run the preprocessing step first")
        print("(python run_pipeline.py --demo, or scan a target first).")
        return False

    df = pd.read_csv(DATA_PATH)

    if df.empty:
        print("Processed dataset is empty -- nothing to train on.")
        return False

    print("Dataset shape:", df.shape)

    os.makedirs(MODEL_DIR, exist_ok=True)

    # ----------- LABEL ENCODING -----------
    le = LabelEncoder()
    df["risk_encoded"] = le.fit_transform(df["risk"])

    class_counts = df["risk_encoded"].value_counts()
    print("Class distribution:", class_counts.to_dict())

    # build the feature matrix once (used by both classifier + anomaly)
    X_all = build_features(df)
    feature_cols = list(X_all.columns)
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_columns.pkl"))

    y_all = df["risk_encoded"]

    if len(class_counts) < 2:
        print("Only one risk class present -- classifier training skipped,")
        print("but the anomaly detector is still trained and models saved.")
        clf = None
        report = {"note": "single-class dataset, classifier not trained"}
        cm = []
        headline_metrics = {}
        feature_importance = []
        stratified_flag = False
    else:
        joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.pkl"))

        # ----------- TRAIN TEST SPLIT -----------
        can_stratify = class_counts.min() >= MIN_CLASS_SAMPLES
        X_train, X_test, y_train, y_test = train_test_split(
            X_all, y_all, test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y_all if can_stratify else None
        )

        print("Training samples:", len(X_train))
        print("Testing samples:", len(X_test))
        print("Stratified:", can_stratify)

        # ----------- TRAIN CLASSIFIER -----------
        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            random_state=RANDOM_STATE,
            n_jobs=-1
        )
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        # ----------- EVALUATION (honest, multi-metric) -----------
        print("\n--- CLASSIFIER EVALUATION ---")
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        print(classification_report(y_test, y_pred, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()
        print("Confusion Matrix:\n", cm)

        class_labels = sorted(set(y_test))
        roc_auc, roc_auc_note = _try_roc_auc(clf, X_test, y_test, class_labels)

        headline_metrics = {
            "accuracy": _safe_metric(accuracy_score, y_test, y_pred),
            "precision_weighted": _safe_metric(
                precision_score, y_test, y_pred, average="weighted",
                zero_division=0, labels=class_labels),
            "recall_weighted": _safe_metric(
                recall_score, y_test, y_pred, average="weighted",
                zero_division=0, labels=class_labels),
            "f1_macro": _safe_metric(
                f1_score, y_test, y_pred, average="macro",
                zero_division=0, labels=class_labels),
            "f1_weighted": _safe_metric(
                f1_score, y_test, y_pred, average="weighted",
                zero_division=0, labels=class_labels),
            "roc_auc_weighted": roc_auc,
            "roc_auc_note": roc_auc_note,
        }
        print("Headline metrics:", headline_metrics)

        # ----------- FEATURE IMPORTANCE -----------
        try:
            importances = clf.feature_importances_
            feature_importance = sorted(
                [{"feature": str(f), "importance": float(v)}
                 for f, v in zip(feature_cols, importances)],
                key=lambda d: d["importance"], reverse=True
            )
        except Exception as exc:
            print("[feature_importance] failed:", exc)
            feature_importance = []

        stratified_flag = bool(len(class_counts) >= 2 and class_counts.min() >= MIN_CLASS_SAMPLES)

    # ----------- TRAIN ANOMALY DETECTOR -----------
    print("\n--- TRAINING ANOMALY DETECTOR ---")
    iso = IsolationForest(
        n_estimators=200,
        contamination=ANOMALY_CONTAMINATION,
        random_state=RANDOM_STATE
    )
    iso.fit(X_all)

    # ----------- CROSS-TARGET VALIDATION FRAMEWORK -----------
    print("\n--- CROSS-TARGET VALIDATION ---")
    cross_target = _cross_target_validation(df, X_all, y_all, le)
    if cross_target.get("available"):
        for fold in cross_target.get("folds", []):
            print(f"  hold-out {fold.get('held_out_host')}: "
                  f"train={fold.get('train_samples')} "
                  f"test={fold.get('test_samples')} "
                  f"acc={fold.get('accuracy')} "
                  f"weighted_f1={fold.get('weighted_f1')}")
    else:
        print("  ", cross_target.get("reason"))

    # ----------- SAVE MODELS -----------
    joblib.dump(clf, os.path.join(MODEL_DIR, "risk_classifier.pkl"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "anomaly_detector.pkl"))

    # ----------- PERSIST METRICS -----------
    metrics = {
        "dataset_rows": int(len(df)),
        "class_distribution": {str(k): int(v) for k, v in class_counts.items()},
        "features": feature_cols,
        "feature_importance": feature_importance,
        "classifier_trained": clf is not None,
        "classification_report": report,
        "confusion_matrix": cm,
        "headline_metrics": headline_metrics,
        "evaluation_methodology": {
            "split": f"{1 - TEST_SIZE:.0%} train / {TEST_SIZE:.0%} test",
            "stratified": stratified_flag,
            "random_state": RANDOM_STATE,
            "roc_auc_policy": (
                "ROC-AUC computed only when >= 2 classes and >= 20 test "
                "samples; otherwise reported as None with a reason."
            ),
        },
        "cross_target_validation": cross_target,
        "disclaimer": (
            "The current model is a proof-of-concept risk-prioritization model "
            "trained using scanner-labelled vulnerability findings. Its evaluation "
            "does NOT establish broad real-world vulnerability detection accuracy. "
            "Metrics reflect agreement with the scanner's own risk labels on a small "
            "single-scan holdout, not independent ground truth."
        ),
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print("\nMetrics saved to:", METRICS_PATH)
    print("Models saved successfully.")
    print("===== HYBRID TRAINING COMPLETE =====\n")
    return True


if __name__ == "__main__":
    train_hybrid()
