"""
Shared, fixed encoding maps used by BOTH training and inference.

Why this file exists:
Earlier versions used pandas `cat.codes`, which re-assigns category codes
alphabetically per dataset. That means the model could be trained with
confidence "High" -> 0 but receive "High" -> 2 at inference time.

By defining one fixed universe of categories here and importing it
everywhere, train-time and inference-time encodings can never drift apart.
"""

# ZAP alert confidence values (from the JSON API: "confidence" field)
CONFIDENCE_LEVELS = ["Low", "Medium", "High"]

# HTTP methods we care about; anything else is bucketed as OTHER
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "OTHER"]

# ZAP risk scale, ordered from least to most severe
RISK_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

CONFIDENCE_MAP = {name: idx for idx, name in enumerate(CONFIDENCE_LEVELS)}
METHOD_MAP = {name: idx for idx, name in enumerate(HTTP_METHODS)}
RISK_MAP = {name: idx for idx, name in enumerate(RISK_ORDER)}


def encode_confidence(value):
    """Fixed encoding for ZAP confidence strings. Unknown -> 0 (Low)."""
    return CONFIDENCE_MAP.get(str(value).strip(), 0)


def encode_method(value):
    """Fixed encoding for HTTP method strings. Unknown -> OTHER bucket."""
    value = str(value).strip().upper()
    if value not in METHOD_MAP:
        value = "OTHER"
    return METHOD_MAP[value]


def risk_index(value):
    """Numeric position of a risk label on the ZAP scale. Unknown -> 0."""
    return RISK_MAP.get(str(value).strip(), 0)


def risk_from_index(index):
    """Inverse of risk_index(), safe on out-of-range values."""
    if 0 <= int(index) < len(RISK_ORDER):
        return RISK_ORDER[int(index)]
    return RISK_ORDER[0]
