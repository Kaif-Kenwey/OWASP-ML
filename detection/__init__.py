"""
OWASP-ML detection-engineering layer.

  detection/engine.py        -> evaluate normalized findings against RULE-001..N
  detection/correlation.py   -> group related findings into correlated events

This is intentionally a lightweight, transparent layer -- NOT a full SIEM.
It demonstrates SIEM-style reasoning (rule evaluation + event correlation)
on top of normalized findings, and every decision is auditable from the
evidence string attached to each detection.
"""
