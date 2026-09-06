"""
AI Analyst -- turns the threat intelligence report into a readable
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

Architectural rule (IMPORTANT):
The AI is an EXPLANATION layer. It summarizes evidence the deterministic
pipeline already produced (scanner -> detection -> ML -> risk engine).
It CANNOT override the Final_Risk of any finding -- that is computed
deterministically in ml/threat_intelligence.py.

Output: data/ai_summary.json -- consumed by the Flask dashboard.
"""

import os
import json
import pandas as pd

# optional .env support for standalone runs (run_pipeline.py loads it too)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except ImportError:
    pass

from config.risks import normalize_risk, risk_index
from config.owasp_mapping import map_attack_to_owasp
from config.clean import safe_str

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PATH = os.path.join(BASE_DIR, "data", "threat_report.csv")
DETECTIONS_PATH = os.path.join(BASE_DIR, "data", "detections.csv")
CORRELATIONS_PATH = os.path.join(BASE_DIR, "data", "correlations.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "ai_summary.json")

AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
AI_MODEL = os.environ.get("AI_MODEL", "gpt-4o-mini")
REQUEST_TIMEOUT = 60


# -----------------------------
# REPORT DIGEST
# -----------------------------

def _safe_value_counts(series):
    """value_counts that tolerates missing columns / empty frames."""
    try:
        return series.value_counts(dropna=False).to_dict()
    except Exception:
        return {}


def build_digest(df, detections_df=None, correlations_df=None):
    """Compact statistical digest of the threat report for the analyst."""
    total = int(len(df)) if not df.empty else 0

    digest = {
        "total_findings": total,
        "final_risk_distribution": _safe_value_counts(df.get("Final_Risk")) if not df.empty else {},
        "scanner_risk_distribution": _safe_value_counts(df.get("original_risk")) if not df.empty else {},
        "top_attack_types": _safe_value_counts(df.get("attack_type")) if not df.empty else {},
        "owasp_categories": _safe_value_counts(df.get("OWASP_Category")) if not df.empty else {},
    }

    # average Hybrid Threat Score (renamed from "ML confidence")
    if not df.empty and "Hybrid_Threat_Score" in df.columns:
        scores = pd.to_numeric(df["Hybrid_Threat_Score"], errors="coerce").dropna()
        digest["average_hybrid_threat_score"] = round(float(scores.mean()), 3) if len(scores) else None
    # legacy alias for older readers
    digest["average_ml_confidence"] = None
    if "average_hybrid_threat_score" in digest and digest["average_hybrid_threat_score"] is not None:
        digest["average_ml_confidence"] = round(digest["average_hybrid_threat_score"] * 100, 2)

    # most-affected High/Critical endpoints
    if not df.empty and "url" in df.columns:
        hot = df[df["Final_Risk"].isin(["High", "Critical"])]
        if not hot.empty:
            digest["most_affected_paths"] = (
                hot["url"].value_counts().head(5).to_dict()
            )

    # dominant NAMED attack type (excluding "Other") and its OWASP category
    if not df.empty and "attack_type" in df.columns:
        named = df[df["attack_type"] != "Other"]["attack_type"]
        if not named.empty:
            dominant_attack = named.value_counts().index[0]
            digest["dominant_named_attack"] = dominant_attack
            digest["dominant_named_attack_count"] = int(named.value_counts().iloc[0])
            digest["dominant_named_attack_owasp"] = map_attack_to_owasp(dominant_attack)
        other_count = int((df["attack_type"] == "Other").sum())
        digest["unclassified_count"] = other_count

    # detection summary
    if detections_df is not None and not detections_df.empty:
        digest["detection_summary"] = {
            "total_detections": int(len(detections_df)),
            "by_rule": _safe_value_counts(detections_df.get("rule_id")),
            "by_severity": _safe_value_counts(detections_df.get("severity")),
        }
    else:
        digest["detection_summary"] = {"total_detections": 0, "by_rule": {}, "by_severity": {}}

    # correlation summary
    if correlations_df is not None and not correlations_df.empty:
        digest["correlation_summary"] = {
            "total_events": int(len(correlations_df)),
            "by_severity": _safe_value_counts(correlations_df.get("severity")),
        }
        # top correlated endpoint by score
        try:
            top = correlations_df.sort_values("correlation_score", ascending=False).head(1)
            if not top.empty:
                row = top.iloc[0]
                digest["top_correlated_event"] = {
                    "correlation_id": safe_str(row.get("correlation_id")),
                    "endpoint": safe_str(row.get("endpoint")),
                    "score": int(row.get("correlation_score", 0)) if pd.notna(row.get("correlation_score")) else 0,
                    "severity": safe_str(row.get("severity")),
                }
        except Exception:
            digest["top_correlated_event"] = None
    else:
        digest["correlation_summary"] = {"total_events": 0, "by_severity": {}}

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
    "scan findings (OWASP ZAP + detection rules + ML risk scoring), produce:\n"
    "1. A 4-6 sentence executive summary in plain English.\n"
    "2. Exactly 3 prioritized recommendations, each one concrete and "
    "actionable, ordered by impact, referencing specific endpoints / attack "
    "classes / detection rules where the digest shows them.\n"
    "Be factual: only reference what the digest shows. Do not invent "
    "findings. Keep a professional but direct tone. The numeric score is a "
    "'Hybrid Threat Score' (a risk prioritization score, NOT a probability)."
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
    """Deterministic analyst summary built from the digest statistics.

    Fixes the v2 contradiction where the dominant NAMED attack (e.g.
    Security Misconfiguration) was reported as 'concentrated under
    Uncategorized' -- the OWASP category now comes from the dominant
    attack itself, not from the overall most-common category.
    """

    dist = digest.get("final_risk_distribution", {})
    total = digest.get("total_findings", 0)
    critical = dist.get("Critical", 0)
    high = dist.get("High", 0)
    medium = dist.get("Medium", 0)
    low = dist.get("Low", 0)

    urgent = critical + high
    urgent_pct = round(100 * urgent / total, 1) if total else 0.0

    dominant_attack = digest.get("dominant_named_attack")
    dominant_count = digest.get("dominant_named_attack_count", 0)
    dominant_owasp = digest.get("dominant_named_attack_owasp")
    other_count = digest.get("unclassified_count", 0)
    avg_score = digest.get("average_hybrid_threat_score")

    summary_parts = [
        f"The scan produced {total} findings, of which {urgent} "
        f"({urgent_pct}%) are High or Critical severity after ML-assisted "
        f"risk escalation."
    ]

    if critical:
        summary_parts.append(
            f"{critical} finding(s) reached Critical priority and should be "
            f"triaged before any routine work."
        )

    # dominant named attack + its OWN owasp category (the v2 contradiction fix)
    if dominant_attack:
        summary_parts.append(
            f"The dominant classified weakness is {dominant_attack} "
            f"({dominant_count} findings), mapped to the OWASP Top 10 "
            f"category {dominant_owasp}."
        )
        if other_count:
            summary_parts.append(
                f"A further {other_count} findings are unclassified "
                f"(attack_type 'Other') and deserve a manual classification pass."
            )
    elif other_count:
        summary_parts.append(
            f"Most findings ({other_count}) fall outside the standard CWE "
            f"attack mapping and deserve a manual classification pass."
        )

    # detection + correlation evidence
    det = digest.get("detection_summary", {})
    corr = digest.get("correlation_summary", {})
    if det.get("total_detections"):
        summary_parts.append(
            f"The detection engine fired {det['total_detections']} rule(s)."
        )
    if corr.get("total_events"):
        summary_parts.append(
            f"The correlation engine grouped findings into "
            f"{corr['total_events']} correlated event(s) on shared endpoints."
        )

    if avg_score is not None:
        summary_parts.append(
            f"Average Hybrid Threat Score across findings is {avg_score} "
            f"(on a 0..1 risk-prioritization scale, not a probability)."
        )

    # ---- prioritized recommendations (concrete, evidence-backed) ----
    recommendations = []

    if critical:
        # find the worst endpoint from the digest if available
        worst = None
        if digest.get("most_affected_paths"):
            worst = list(digest["most_affected_paths"].keys())[0]
        if worst:
            recommendations.append(
                f"Triage the {critical} Critical finding(s) first -- "
                f"the most affected High/Critical endpoint is {worst}."
            )
        else:
            recommendations.append(
                f"Triage the {critical} Critical finding(s) before any routine work."
            )

    if dominant_attack:
        if "Injection" in dominant_attack or dominant_attack == "SQL Injection" \
                or "XSS" in dominant_attack:
            recommendations.append(
                f"Close the {dominant_attack} class first ({dominant_count} "
                f"findings under {dominant_owasp}) using parameterized queries / "
                f"context-aware output encoding."
            )
        elif "Misconfiguration" in dominant_attack:
            recommendations.append(
                f"Harden default configurations ({dominant_count} {dominant_attack} "
                f"findings): security headers, verbose errors, debug endpoints, "
                f"and default accounts."
            )
        elif "Authentication" in dominant_attack or "Access Control" in dominant_attack:
            recommendations.append(
                f"Audit authorization and session handling for the "
                f"{dominant_attack} findings ({dominant_count} under {dominant_owasp})."
            )
        else:
            recommendations.append(
                f"Remediate the {dominant_attack} class first ({dominant_count} "
                f"findings under {dominant_owasp}); it is the largest single "
                f"weakness in this scan."
            )

    # detection-driven recommendation
    by_rule = det.get("by_rule", {})
    if "RULE-002" in by_rule or "RULE-005" in by_rule:
        recommendations.append(
            "Prioritize endpoints flagged by RULE-002 (injection chain) and "
            "RULE-005 (repeated high-risk endpoint) -- a focused fix pass there "
            "closes multiple findings at once."
        )
    elif "RULE-006" in by_rule:
        recommendations.append(
            f"Manually review the {by_rule.get('RULE-006', 0)} anomalous findings "
            f"(RULE-006) -- anomaly flags unusualness, not exploitability; "
            f"confirm or dismiss each with evidence."
        )

    if not recommendations:
        recommendations.append(
            "No Critical/High findings detected -- verify the scan had adequate "
            "coverage and re-run after any code change."
        )

    recommendations.append(
        "Re-run the pipeline after fixes to confirm the risk distribution shifts "
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
    detections_df = pd.read_csv(DETECTIONS_PATH) if os.path.exists(DETECTIONS_PATH) else None
    correlations_df = pd.read_csv(CORRELATIONS_PATH) if os.path.exists(CORRELATIONS_PATH) else None

    digest = build_digest(df, detections_df, correlations_df)

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
