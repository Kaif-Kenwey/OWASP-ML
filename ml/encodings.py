"""
Shared, fixed encoding maps used by BOTH training and inference.

Why this file exists:
Earlier versions used pandas `cat.codes`, which re-assigns category codes
alphabetically per dataset. That means the model could be trained with
confidence "High" -> 0 but receive "High" -> 2 at inference time.

Risk ordering / weights now live in config/risks.py (single source of truth).
This module keeps the confidence + HTTP-method encoding maps and re-exports
the risk helpers so existing `from ml.encodings import risk_index` imports
keep working.
"""

# ZAP alert confidence values (from the JSON API: "confidence" field)
CONFIDENCE_LEVELS = ["Low", "Medium", "High"]

# HTTP methods we care about; anything else is bucketed as OTHER
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "OTHER"]

CONFIDENCE_MAP = {name: idx for idx, name in enumerate(CONFIDENCE_LEVELS)}
METHOD_MAP = {name: idx for idx, name in enumerate(HTTP_METHODS)}

# Risk scale + weights are owned by config/risks.py -- re-export for callers
# that still import them from here.
from config.risks import (  # noqa: E402  (re-export)
    RISK_ORDER,
    RISK_MAP,
    RISK_WEIGHT,
    RISK_FALLBACK,
    risk_index,
    risk_from_index,
    risk_weight,
    normalize_risk,
    is_higher_or_equal,
    max_risk,
)


def encode_confidence(value):
    """Fixed encoding for ZAP confidence strings. Unknown -> 0 (Low)."""
    return CONFIDENCE_MAP.get(str(value).strip(), 0)


def encode_method(value):
    """Fixed encoding for HTTP method strings. Unknown -> OTHER bucket."""
    value = str(value).strip().upper()
    if value not in METHOD_MAP:
        value = "OTHER"
    return METHOD_MAP[value]
