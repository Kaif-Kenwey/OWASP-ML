"""
Centralized risk model.

The ZAP risk scale, ordered from least to most severe. Every module that
compares, escalates or normalizes a risk label MUST go through these helpers
so the ordering is defined in exactly one place.

`ml/encodings.py` re-exports risk_index / risk_from_index from here for
backward compatibility with older imports.
"""

# The canonical risk scale. Order matters -- index == severity position.
RISK_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

RISK_MAP = {name: idx for idx, name in enumerate(RISK_ORDER)}

# Numeric weight per risk label, used by the hybrid scorer as the static
# "baseline severity of the predicted class" signal (the 0.1 term).
# Critical is included so a Critical prediction contributes the full weight.
RISK_WEIGHT = {
    "Informational": 0.1,
    "Low": 0.3,
    "Medium": 0.6,
    "High": 0.9,
    "Critical": 1.0,
}

# Honest floor: any unparseable / missing / unknown risk label resolves to
# Informational. We NEVER silently inflate a missing value into High/Critical.
RISK_FALLBACK = "Informational"

# Display labels used by badges/chips in the dashboard, in severity order.
SEVERITY_BADGES = {
    "Critical": "crit",
    "High": "high",
    "Medium": "med",
    "Low": "low",
    "Informational": "info",
    "Unknown": "unknown",
}


def risk_index(value):
    """Numeric position of a risk label on the ZAP scale. Unknown -> 0."""
    if value is None:
        return 0
    return RISK_MAP.get(str(value).strip(), 0)


def risk_from_index(index):
    """Inverse of risk_index(), safe on out-of-range values."""
    if index is None:
        return RISK_FALLBACK
    try:
        i = int(index)
    except (TypeError, ValueError):
        return RISK_FALLBACK
    if 0 <= i < len(RISK_ORDER):
        return RISK_ORDER[i]
    return RISK_ORDER[0]


def risk_weight(value):
    """Static scoring weight for a risk label. Unknown -> Informational weight."""
    return RISK_WEIGHT.get(normalize_risk(value), RISK_WEIGHT[RISK_FALLBACK])


def normalize_risk(value):
    """
    Canonicalize a risk label for display / comparison.

    Handles:
      - None / NaN-ish values
      - the literal strings "nan", "none", "" (case-insensitive)
      - whitespace
      - numeric ids (0..4) coming from the encoded model output

    Anything not on the RISK_ORDER scale resolves to RISK_FALLBACK
    ("Informational") -- the honest floor. We never inflate a missing
    value into High or Critical.
    """
    if value is None:
        return RISK_FALLBACK
    s = str(value).strip()
    if s == "" or s.lower() in {"nan", "none", "null", "undefined", "na", "n/a"}:
        return RISK_FALLBACK
    # numeric id (model-encoded integers)
    if s.lstrip("-").isdigit():
        return risk_from_index(int(s))
    # case-insensitive match against known labels
    for label in RISK_ORDER:
        if s.lower() == label.lower():
            return label
    return RISK_FALLBACK


def is_higher_or_equal(a, b):
    """True if risk a is at least as severe as risk b (after normalization)."""
    return risk_index(normalize_risk(a)) >= risk_index(normalize_risk(b))


def max_risk(*labels):
    """Most severe of the given risk labels (Unknown -> Informational floor)."""
    if not labels:
        return RISK_FALLBACK
    return risk_from_index(max(risk_index(normalize_risk(l)) for l in labels))
