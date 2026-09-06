"""
OWASP-ML configuration package.

Single source of truth for the parts of the pipeline that used to be
scattered as inline dicts across ml/alert_processor.py, ml/threat_intelligence.py
and ml/hybrid_predict.py:

  config/risks.py            -> risk ordering, weights, normalization
  config/owasp_mapping.py    -> CWE -> attack, attack -> OWASP, descriptions
  config/detection_rules.py  -> detection rule definitions (RULE-001..N)
  config/settings.py         -> thresholds, weights, reproducibility seeds

Everything that needs these values imports from here, so adding a new
CWE mapping or detection rule is a one-file change instead of a hunt
across the codebase (see docs/MAINTENANCE_GUIDE.md -> "Adding a rule").
"""
