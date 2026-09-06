"""
Shared feature construction for training AND inference.

Both ml/train_hybrid_model.py and ml/scan_and_predict.py build features
through this module, so the feature space is guaranteed to be identical
at train time and prediction time (the one-hot attack columns in
particular -- building them in two places caused silent mismatches).

The canonical ATTACK_TYPES list is owned by config/owasp_mapping.py so a
new attack family only has to be added once.
"""

import hashlib
from urllib.parse import urlparse

from config.owasp_mapping import ATTACK_TYPES

# Base numeric features derived per-alert (see ml/alert_processor.py).
# Order is stable so the one-hot columns always come out in the same order.
BASE_FEATURES = [
    "confidence_encoded",
    "method_encoded",
    "url_length",
    "param_length",
    "param_count",
    "has_query_params",
    "path_depth",
    "hostname_length",
    "https_indicator",
    "special_char_count",
    "description_length",
    "solution_length",
    "reference_count",
]


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_len(value):
    return len(str(value)) if value is not None else 0


def _count_special_chars(url: str) -> int:
    """Count chars that commonly appear in injection / traversal payloads.

    A lightweight proxy for 'how attack-shaped is this URL'. Not a security
    verdict -- just a feature. Returns 0 for empty/missing URLs.
    """
    if not isinstance(url, str) or not url:
        return 0
    special = set("'\"<>{}|;&$`\\%*?")
    return sum(1 for ch in url if ch in special)


def _signature(finding: dict) -> str:
    """Stable signature for an alert (used for finding_id + correlation)."""
    raw = "|".join([
        str(finding.get("url", "")).strip(),
        str(finding.get("alert_name") or finding.get("alert", "")).strip(),
        str(finding.get("cweid", "")).strip(),
        str(finding.get("method", "")).strip().upper(),
        str(finding.get("param", "")).strip(),
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def build_sample_features(sample_dict):
    """
    One engineered alert (dict) -> one model feature row (dict).

    Why not raw cwe_numeric? CWE ids are identifiers, not quantities --
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
