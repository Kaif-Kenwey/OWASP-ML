"""
Shared feature construction for training AND inference.

Both ml/train_hybrid_model.py and ml/scan_and_predict.py build features
through this module, so the feature space is guaranteed to be identical
at train time and prediction time (the one-hot attack columns in
particular — building them in two places caused silent mismatches).
"""

ATTACK_TYPES = [
    "SQL Injection",
    "Cross Site Scripting (XSS)",
    "Command Injection",
    "CSRF",
    "Path Traversal",
    "Broken Authentication",
    "Sensitive Data Exposure",
    "Insecure Deserialization",
    "SSRF",
    "Security Misconfiguration",
    "Other",
]

BASE_FEATURES = [
    "confidence_encoded",
    "method_encoded",
    "url_length",
    "param_length",
    "has_query_params",
    "path_depth",
    "description_length",
    "solution_length",
    "reference_count",
]


def build_sample_features(sample_dict):
    """
    One engineered alert (dict) -> one model feature row (dict).

    Why not raw cwe_numeric? CWE ids are identifiers, not quantities —
    a model would learn a fake ordering (CWE-918 > CWE-22). The derived
    attack_type is one-hot encoded instead, carrying the same meaning
    without the false ordinality.
    """
    features = {key: sample_dict.get(key, 0) for key in BASE_FEATURES}

    attack = sample_dict.get("attack_type", "Other")
    for attack_name in ATTACK_TYPES:
        features[f"attack_{attack_name}"] = 1 if attack == attack_name else 0

    return features


def build_features(df):
    """DataFrame of engineered alerts -> feature matrix for sklearn."""
    import pandas as pd

    rows = [build_sample_features(row) for _, row in df.iterrows()]
    return pd.DataFrame(rows)
