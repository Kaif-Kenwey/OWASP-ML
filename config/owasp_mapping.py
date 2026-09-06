"""
Centralized OWASP / CWE mapping.

Previously the CWE->attack table lived in ml/alert_processor.py and the
attack->OWASP table lived in ml/threat_intelligence.py. They are now both
here, together with human-readable descriptions, so:

  - adding a new CWE only touches this file
  - the OWASP Top 10 (2021) taxonomy is stated once, correctly
  - the dashboard / AI analyst can show the same attack / OWASP descriptions
    as the report without re-defining them

IMPORTANT classification note (academic honesty):
This mapping is RULE-BASED enrichment, not an ML prediction. The classifier
never sees these labels as targets -- it learns the scanner's `risk` field.
The OWASP category shown in the dashboard is derived deterministically from
the CWE id of each alert, so it should never be presented as model output.
"""

# ---------------------------------------------------------------------------
# CWE id -> attack family
# ---------------------------------------------------------------------------
# Whole-id matching only: "189" must NOT match "89" (handled in map_cwe_to_attack).
# Source: https://cwe.mitre.org/ + OWASP Top 10 (2021) mapping.
CWE_TO_ATTACK = {
    "89": "SQL Injection",
    "79": "Cross Site Scripting (XSS)",
    "78": "Command Injection",
    "352": "CSRF",
    "22": "Path Traversal",
    "23": "Path Traversal",
    "35": "Path Traversal",
    "287": "Broken Authentication",
    "285": "Broken Authentication",
    "306": "Broken Authentication",
    "862": "Broken Access Control",
    "639": "Broken Access Control",
    "200": "Sensitive Data Exposure",
    "201": "Sensitive Data Exposure",
    "209": "Sensitive Data Exposure",
    "532": "Sensitive Data Exposure",
    "502": "Insecure Deserialization",
    "918": "SSRF",
    "693": "Security Misconfiguration",
    "16": "Security Misconfiguration",
    "611": "Security Misconfiguration",
    "1004": "Security Misconfiguration",
    "1021": "Security Misconfiguration",
    "311": "Security Misconfiguration",
    "497": "Security Misconfiguration",
    "550": "Security Misconfiguration",
    "615": "Security Misconfiguration",
    "601": "Security Misconfiguration",
    "1295": "Security Misconfiguration",
    "933": "Security Misconfiguration",
}

# Attack families the pipeline recognizes. The order is stable so one-hot
# columns always come out in the same order at train and inference time
# (this list is re-exported by ml/features.py as the canonical source).
ATTACK_TYPES = [
    "SQL Injection",
    "Cross Site Scripting (XSS)",
    "Command Injection",
    "CSRF",
    "Path Traversal",
    "Broken Authentication",
    "Broken Access Control",
    "Sensitive Data Exposure",
    "Insecure Deserialization",
    "SSRF",
    "Security Misconfiguration",
    "Other",
]

# ---------------------------------------------------------------------------
# Attack family -> OWASP Top 10 (2021) category
# ---------------------------------------------------------------------------
# Reference: https://owasp.org/Top10/
ATTACK_TO_OWASP = {
    "SQL Injection": "A03 - Injection",
    "Cross Site Scripting (XSS)": "A03 - Injection",
    "Command Injection": "A03 - Injection",
    "CSRF": "A01 - Broken Access Control",
    "Path Traversal": "A01 - Broken Access Control",
    "Broken Authentication": "A07 - Identification & Authentication Failures",
    "Broken Access Control": "A01 - Broken Access Control",
    "Sensitive Data Exposure": "A02 - Cryptographic Failures",
    "Insecure Deserialization": "A08 - Software & Data Integrity Failures",
    "SSRF": "A10 - Server-Side Request Forgery",
    "Security Misconfiguration": "A05 - Security Misconfiguration",
    "Other": "Uncategorized",
}

OWASP_CATEGORY_FALLBACK = "Uncategorized"

# Short, factual description per OWASP category. Used by the AI analyst and
# the dashboard tooltips so the OWASP mapping is self-documenting.
OWASP_CATEGORY_DESCRIPTIONS = {
    "A01 - Broken Access Control": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
    "A02 - Cryptographic Failures": "Failures related to cryptography that often lead to exposure of sensitive data.",
    "A03 - Injection": "User-supplied data is interpreted as code or query, leading to injection flaws.",
    "A04 - Insecure Design": "Missing or ineffective control design (not referenced by this mapping).",
    "A05 - Security Misconfiguration": "Missing hardening, default accounts, verbose errors, or outdated configurations.",
    "A06 - Vulnerable & Outdated Components": "Using libraries / frameworks with known vulnerabilities.",
    "A07 - Identification & Authentication Failures": "Weak credential handling, session management, or identity controls.",
    "A08 - Software & Data Integrity Failures": "Code or data whose integrity cannot be trusted (e.g. deserialization).",
    "A09 - Security Logging & Monitoring Failures": "Insufficient logging and alerting (not referenced by this mapping).",
    "A10 - Server-Side Request Forgery": "Server fetches a remote resource without validating the destination URL.",
    OWASP_CATEGORY_FALLBACK: "The CWE did not map to a known attack family; classify manually.",
}

# Short, factual description per attack family (for explainability panels).
ATTACK_DESCRIPTIONS = {
    "SQL Injection": "Untrusted input is concatenated into a SQL query, letting an attacker alter query logic.",
    "Cross Site Scripting (XSS)": "Untrusted input is reflected or stored and rendered as HTML/JS in a victim browser.",
    "Command Injection": "Untrusted input is passed to an OS shell, allowing arbitrary command execution.",
    "CSRF": "A trusted authenticated session is abused to perform an unwanted state-changing action.",
    "Path Traversal": "File path input is not validated, allowing access outside the intended directory.",
    "Broken Authentication": "Credential storage, session, or login flow lets attackers assume identities.",
    "Broken Access Control": "Authorization checks are missing or bypassable, exposing unauthorized data/functions.",
    "Sensitive Data Exposure": "Sensitive data is transmitted or stored without adequate protection.",
    "Insecure Deserialization": "Untrusted serialized data is deserialized, enabling object/code injection.",
    "SSRF": "The server can be tricked into making outbound requests to unintended destinations.",
    "Security Misconfiguration": "Default configs, verbose errors, or missing headers weaken the application.",
    "Other": "CWE did not map to a tracked attack family; manual classification recommended.",
}


def map_cwe_to_attack(cwe):
    """Whole-id CWE -> attack family mapping. Unknown / empty -> 'Other'.

    Handles comma/space separated CWE lists (some ZAP responses), and the
    ZAP sentinel 'cweid' values '0' and '-1' which mean 'no CWE assigned'.
    """
    if not cwe:
        return "Other"
    cwe_str = str(cwe).strip()
    if cwe_str in {"", "0", "-1"}:
        return "Other"
    ids = [c.strip() for c in __import__("re").split(r"[,\s]+", cwe_str) if c.strip()]
    for cwe_id in ids:
        if cwe_id in CWE_TO_ATTACK:
            return CWE_TO_ATTACK[cwe_id]
    return "Other"


def map_attack_to_owasp(attack_type):
    """Attack family -> OWASP Top 10 (2021) category. Unknown -> 'Uncategorized'."""
    return ATTACK_TO_OWASP.get(attack_type, OWASP_CATEGORY_FALLBACK)


def owasp_description(owasp_category):
    """Short factual description of an OWASP category (for tooltips / analyst)."""
    return OWASP_CATEGORY_DESCRIPTIONS.get(owasp_category, OWASP_CATEGORY_DESCRIPTIONS[OWASP_CATEGORY_FALLBACK])


def attack_description(attack_type):
    """Short factual description of an attack family (for tooltips / analyst)."""
    return ATTACK_DESCRIPTIONS.get(attack_type, ATTACK_DESCRIPTIONS["Other"])
