def get_remediation(alert_name):
    fixes = {
        "SQL Injection": "Use parameterized queries and prepared statements.",
        "Cross Site Scripting (XSS)": "Sanitize and validate user input. Use Content Security Policy (CSP).",
        "Server Leaks Version Information": "Disable server version disclosure in headers.",
        "Directory Browsing": "Disable directory listing on web server.",
        "Content Security Policy (CSP) Header Not Set": "Implement proper CSP headers."
    }

    return fixes.get(alert_name, "Refer to OWASP guidelines for remediation.")
