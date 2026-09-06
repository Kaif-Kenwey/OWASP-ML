"""
AI Analyst — turns the threat intelligence report into a readable
executive security summary with prioritized recommendations.

Two operating modes:

1. AI mode (needs API key):
   Calls ANY OpenAI-compatible chat completions endpoint. Configure with
   environment variables (see .env.example):
     AI_API_KEY   - your API key
     AI_BASE_URL  - default: https://api.openai.com/v1
                    (works with OpenAI, Groq, OpenRouter, local LLM servers...)
     AI_MODEL     - default: gpt-4o-mini

2. Rule-based mode (no key needed):
   Builds the same summary deterministically from the report statistics.
   This keeps the dashboard fully functional in demo/offline settings.

Output: data/ai_summary.json — consumed by the Flask dashboard.
"""

import os
import json
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PATH = os.path.join(BASE_DIR, "data", "threat_report.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "ai_summary.json")

AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
AI_MODEL = os.environ.get("AI_MODEL", "gpt-4o-mini")
REQUEST_TIMEOUT = 60


# -----------------------------
# REPORT DIGEST
# -----------------------------

def build_digest(df):
    """Compact statistical digest of the threat report for the analyst."""
    digest = {
        "total_findings": int(len(df)),
        "final_risk_distribution": df["Final_Risk"].value_counts().to_dict(),
        "scanner_risk_distribution": df["risk"].value_counts().to_dict(),
        "top_attack_types": df["attack_type"].value_counts().head(5).to_dict(),
        "owasp_categories": df["OWASP_Category"].value_counts().head(5).to_dict(),
        "top_cwe_ids": {str(k): int(v) for k, v in
                        df["cwe_numeric"].value_counts().head(5).items()},
        "average_ml_confidence": round(float(df["ML_Confidence_%"].mean()), 2),
    }

    if "url" in df.columns:
        digest["most_affected_paths"] = (
            df[df["Final_Risk"].isin(["High", "Critical"])]["url"]
            .value_counts().head(5).to_dict()
        )

    return digest


def _digest_lines(digest):
    lines = []
    for key, value in digest.items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


# -----------------------------
# AI MODE
# -----------------------------

SYSTEM_PROMPT = (
    "You are a senior application security analyst writing for a "
    "vulnerability triage report. Given a statistical digest of automated "
    "scan findings (OWASP ZAP + ML risk scoring), produce:\n"
    "1. A 4-6 sentence executive summary in plain English.\n"
    "2. Exactly 3 prioritized recommendations, each one concrete and "
    "actionable, ordered by impact.\n"
    "Be factual: only reference what the digest shows. Do not invent "
    "findings. Keep a professional but direct tone."
)


def generate_ai_summary(digest):
    """Call an OpenAI-compatible endpoint; returns dict or raises."""
    import requests

    user_prompt = (
        "Threat report digest:\n"
        f"{_digest_lines(digest)}\n\n"
        "Respond with STRICT JSON only, no markdown fences, using this shape:\n"
        '{"executive_summary": "...", "recommendations": ["...", "...", "..."]}'
    )

    resp = requests.post(
        f"{AI_BASE_URL}/chat/completions",
        headers={
            "Authorization": f"Bearer {AI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": AI_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()

    content = resp.json()["choices"][0]["message"]["content"].strip()
    # tolerate models that wrap JSON in fences despite instructions
    if content.startswith("```"):
        content = content.strip("`")
        if content.startswith("json"):
            content = content[4:]
    parsed = json.loads(content)

    return {
        "generated_by": f"LLM ({AI_MODEL})",
        "executive_summary": parsed.get("executive_summary", "").strip(),
        "recommendations": [r for r in parsed.get("recommendations", []) if r],
    }


# -----------------------------
# RULE-BASED FALLBACK
# -----------------------------

def generate_rule_based_summary(digest):
    """Deterministic analyst summary built from the digest statistics."""

    dist = digest["final_risk_distribution"]
    total = digest["total_findings"]
    critical = dist.get("Critical", 0)
    high = dist.get("High", 0)
    medium = dist.get("Medium", 0)
    low = dist.get("Low", 0)

    urgent = critical + high
    urgent_pct = round(100 * urgent / total, 1) if total else 0.0

    top_attacks = list(digest["top_attack_types"].items())
    named_attacks = [(k, v) for k, v in top_attacks if k != "Other"]
    other_count = digest["top_attack_types"].get("Other", 0)
    top_categories = list(digest["owasp_categories"].items())

    summary_parts = [
        f"The scan produced {total} findings, of which {urgent} "
        f"({urgent_pct}%) are High or Critical severity after ML-assisted "
        f"risk escalation.",
    ]

    if critical:
        summary_parts.append(
            f"{critical} finding(s) reached Critical priority and should be "
            f"triaged before any routine work."
        )

    if named_attacks:
        name, count = named_attacks[0]
        summary_parts.append(
            f"The dominant weakness class is {name} ({count} findings)"
            + (
                f", concentrated under {top_categories[0][0]}."
                if top_categories else "."
            )
        )
        if other_count:
            summary_parts.append(
                f"A further {other_count} findings are unclassified and "
                f"worth a manual review."
            )
    elif other_count:
        summary_parts.append(
            f"Most findings ({other_count}) fall outside the standard CWE "
            f"attack mapping and deserve a manual classification pass."
        )

    if digest.get("average_ml_confidence") is not None:
        summary_parts.append(
            f"Average ML confidence across findings is "
            f"{digest['average_ml_confidence']}%."
        )

    recommendations = []

    if named_attacks:
        name, _ = named_attacks[0]
        if "Injection" in name:
            recommendations.append(
                f"Prioritize parameterized queries / output encoding to close "
                f"the {name} findings — they dominate this report."
            )
        elif "Misconfiguration" in name:
            recommendations.append(
                "Harden default configurations (headers, error pages, "
                "debug endpoints) — misconfiguration is the largest class here."
            )
        else:
            recommendations.append(
                f"Remediate the {name} class first ({named_attacks[0][1]} "
                f"findings); it is the largest single weakness in this scan."
            )
    else:
        recommendations.append(
            "Extend the CWE-to-attack mapping so the largest finding classes "
            "get proper OWASP categorization."
        )

    if digest.get("most_affected_paths"):
        worst = list(digest["most_affected_paths"].keys())[0]
        recommendations.append(
            f"Review and fix the most affected endpoint first: {worst}"
        )

    recommendations.append(
        "Re-run the scan after fixes to confirm the risk distribution shifts "
        "toward Low/Informational."
    )

    return {
        "generated_by": "Rule-based engine (no AI API key configured)",
        "executive_summary": " ".join(summary_parts),
        "recommendations": recommendations[:3],
    }


# -----------------------------
# MAIN
# -----------------------------

def generate_summary():
    if not os.path.exists(REPORT_PATH):
        print("Threat report not found at:", REPORT_PATH)
        print("Run the pipeline first: python run_pipeline.py --demo")
        return None

    df = pd.read_csv(REPORT_PATH)
    digest = build_digest(df)

    result = None

    if AI_API_KEY:
        try:
            result = generate_ai_summary(digest)
            print("AI summary generated by:", result["generated_by"])
        except Exception as e:
            print("AI call failed, falling back to rule-based engine:", str(e))
            result = None

    if result is None:
        result = generate_rule_based_summary(digest)
        print("Summary generated by:", result["generated_by"])

    result["digest"] = digest

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(result, f, indent=2)

    print("AI summary saved to:", OUTPUT_PATH)
    print("\n" + result["executive_summary"])
    for i, rec in enumerate(result["recommendations"], 1):
        print(f"  {i}. {rec}")

    return result


if __name__ == "__main__":
    generate_summary()
