"""
Remediation engine.

Structured, deterministic fix guidance keyed by attack family (not alert
name). Every entry carries four sections so the dashboard detail drawer
can render them consistently:

  why_it_matters    - the security concept behind the finding
  impact            - what an attacker could do if it is exploited
  fix               - the concrete remediation steps
  best_practice     - the durable defensive practice to adopt

Unknown attack families get an honest fallback, never a fabricated fix.
"""

from config.clean import safe_str

# ---------------------------------------------------------------------------
# Structured remediation knowledge base (keyed by attack_type)
# ---------------------------------------------------------------------------
REMEDIATION_KB = {
    "SQL Injection": {
        "why_it_matters": (
            "Untrusted input is concatenated into a SQL query, letting an "
            "attacker alter query logic or extract/modify data."
        ),
        "impact": (
            "Authentication bypass, full database read/write, data exfiltration, "
            "and in some configurations remote code execution via xp_cmdshell / "
            "INTO OUTFILE."
        ),
        "fix": (
            "1) Parameterize the query with bound parameters / prepared statements.\n"
            "2) Use an ORM with parameter binding (never string-concatenation).\n"
            "3) Validate input type/length against an allowlist.\n"
            "4) Apply least privilege: the DB account should not own tables or "
            "have DDL/admin rights."
        ),
        "best_practice": "Treat all input as hostile; separate code from data.",
    },
    "Cross Site Scripting (XSS)": {
        "why_it_matters": (
            "Untrusted input is reflected or stored and rendered as HTML/JS in "
            "a victim's browser, executing attacker code in the app's origin."
        ),
        "impact": (
            "Session/token theft, credential phishing via UI spoofing, browser "
            "keylogging, and pivots into other same-origin services."
        ),
        "fix": (
            "1) Context-aware output encoding (HTML, attribute, JS, URL).\n"
            "2) Use a templating engine that escapes by default.\n"
            "3) Sanitize any stored HTML through an allowlist sanitizer.\n"
            "4) Deploy a strict Content Security Policy (CSP)."
        ),
        "best_practice": "Never trust input that will reach the DOM; encode by context.",
    },
    "Command Injection": {
        "why_it_matters": (
            "Untrusted input is passed to an OS shell, allowing arbitrary "
            "command execution on the host."
        ),
        "impact": (
            "Full host compromise, lateral movement, data theft, and "
            "persistence. Often the fastest path to total system control."
        ),
        "fix": (
            "1) Avoid shelling out -- use the language's native libraries.\n"
            "2) If a shell is unavoidable, pass args as a list (no shell=True).\n"
            "3) Validate input against a strict allowlist.\n"
            "4) Run the process under a least-privilege, sandboxed account."
        ),
        "best_practice": "Code, don't shell. If you must shell, never interpolate input.",
    },
    "CSRF": {
        "why_it_matters": (
            "A state-changing request can be forced from a victim's "
            "authenticated session without their consent."
        ),
        "impact": (
            "Unauthorized fund transfers, account changes, privilege grants, "
            "and any action the victim is authorized to perform."
        ),
        "fix": (
            "1) Require an anti-CSRF token on every state-changing request.\n"
            "2) Validate the token server-side, bound to the session.\n"
            "3) Set SameSite=Lax/Strict on session cookies.\n"
            "4) Verify the Origin / Referer header."
        ),
        "best_practice": "State changes need proof of intent, not just authentication.",
    },
    "Path Traversal": {
        "why_it_matters": (
            "File path input is not validated, allowing access outside the "
            "intended directory."
        ),
        "impact": (
            "Reading sensitive files (/etc/passwd, configs, source code), and "
            "in write-capable flows, overwriting binaries or configs."
        ),
        "fix": (
            "1) Canonicalize the path and verify it stays inside the base dir.\n"
            "2) Use an allowlist of permitted filenames.\n"
            "3) Map user input to a key, never to a raw path.\n"
            "4) Run the service with least filesystem privileges."
        ),
        "best_practice": "Treat a filename as data, not as a path component.",
    },
    "Broken Authentication": {
        "why_it_matters": (
            "Credential storage, session management, or login flow lets "
            "attackers assume another user's identity."
        ),
        "impact": (
            "Account takeover, privilege escalation, and full session hijack. "
            "Often the entry point for broader compromise."
        ),
        "fix": (
            "1) Hash passwords with a slow KDF (bcrypt/scrypt/argon2).\n"
            "2) Rotate session ids after login and use secure cookie flags.\n"
            "3) Enforce MFA on sensitive actions.\n"
            "4) Rate-limit and monitor failed login attempts."
        ),
        "best_practice": "Identity is the new perimeter; defend it in depth.",
    },
    "Broken Access Control": {
        "why_it_matters": (
            "Authorization checks are missing or bypassable, exposing data "
            "or functions a user is not entitled to."
        ),
        "impact": (
            "Horizontal privilege escalation (other users' data), vertical "
            "escalation (admin functions), and data breaches."
        ),
        "fix": (
            "1) Enforce authorization on every object access, not just the route.\n"
            "2) Deny by default; require an explicit allow.\n"
            "3) Use indirect object references (map a user-scoped id to a real id).\n"
            "4) Log and alert on access-control failures."
        ),
        "best_practice": "Never trust the client to tell you what it can do.",
    },
    "Sensitive Data Exposure": {
        "why_it_matters": (
            "Sensitive data is transmitted or stored without adequate "
            "protection, exposing it to interception or theft."
        ),
        "impact": (
            "PII/credential/secret leakage, regulatory exposure (GDPR/HIPAA), "
            "and reputational damage."
        ),
        "fix": (
            "1) Enforce TLS everywhere (HSTS, modern ciphers, no downgrade).\n"
            "2) Classify data and encrypt sensitive fields at rest.\n"
            "3) Do not return secrets in responses or logs.\n"
            "4) Mask sensitive fields in UI/logs."
        ),
        "best_practice": "Encrypt in transit and at rest; minimize what you store.",
    },
    "Insecure Deserialization": {
        "why_it_matters": (
            "Untrusted serialized data is deserialized, enabling object or "
            "code injection into the application's runtime."
        ),
        "impact": (
            "Remote code execution, privilege escalation, and logic bypass -- "
            "frequently a full compromise primitive."
        ),
        "fix": (
            "1) Do not deserialize untrusted data; use JSON / a data-only format.\n"
            "2) If unavoidable, use an allowlist of permitted classes.\n"
            "3) Sign or integrity-protect serialized payloads.\n"
            "4) Run deserialization in a low-privilege sandbox."
        ),
        "best_practice": "Deserialization is code execution by another name.",
    },
    "SSRF": {
        "why_it_matters": (
            "The server can be tricked into making outbound requests to "
            "attacker-chosen destinations."
        ),
        "impact": (
            "Access to internal services/metadata endpoints, cloud credential "
            "theft (169.254.169.254), and pivoting into the internal network."
        ),
        "fix": (
            "1) Validate and allowlist destination hosts/schemes.\n"
            "2) Block requests to link-local / RFC1918 ranges.\n"
            "3) Disable unused URL schemes (file://, gopher://, ...).\n"
            "4) Egress through a hardened forward proxy."
        ),
        "best_practice": "A server that fetches URLs is a proxy -- harden it like one.",
    },
    "Security Misconfiguration": {
        "why_it_matters": (
            "Default configurations, verbose errors, or missing security "
            "headers weaken the application's defensive baseline."
        ),
        "impact": (
            "Information leakage that aids further attacks, missing protections "
            "(no CSP, no HSTS), and exposure of admin/debug surfaces."
        ),
        "fix": (
            "1) Disable default accounts and debug endpoints in production.\n"
            "2) Suppress verbose error pages; return generic errors to clients.\n"
            "3) Add security headers (CSP, HSTS, X-Frame-Options, "
            "X-Content-Type-Options, Referrer-Policy).\n"
            "4) Patch and remove unused components/features."
        ),
        "best_practice": "Harden by default; configurations are code, review them.",
    },
    "Other": {
        "why_it_matters": (
            "This finding's CWE did not map to a tracked attack family, so "
            "it requires manual classification before remediation."
        ),
        "impact": (
            "Varies. Without classification, risk cannot be reliably triaged."
        ),
        "fix": (
            "1) Read the CWE description and the alert evidence.\n"
            "2) Map it to the correct attack family in config/owasp_mapping.py.\n"
            "3) Re-run the pipeline so the remediation engine applies the "
            "right guidance."
        ),
        "best_practice": "Classify findings before triaging them.",
    },
}


FALLBACK = {
    "why_it_matters": "No structured remediation is available for this finding class.",
    "impact": "Treat as Unknown until classified manually.",
    "fix": "Refer to OWASP testing guidance for the relevant CWE and verify manually.",
    "best_practice": "Classify the finding so the remediation engine can advise.",
}


def get_remediation_dict(attack_type):
    """Return the structured remediation {why, impact, fix, best_practice}."""
    key = safe_str(attack_type, "Other") or "Other"
    return dict(REMEDIATION_KB.get(key, FALLBACK))


def get_remediation(attack_type):
    """Flat, multi-section string for the CSV 'Remediation' column.

    Format:
      Why it matters: ...
      Impact: ...
      Fix: ...
      Best practice: ...
    """
    r = get_remediation_dict(attack_type)
    return (
        f"Why it matters: {r['why_it_matters']}\n"
        f"Impact: {r['impact']}\n"
        f"Fix: {r['fix']}\n"
        f"Best practice: {r['best_practice']}"
    )
