"""
case_file_engine.py — Rule-based Investigation Brief Generator
Zero external API calls. Generates case files purely from:
  - The user's behavioral feature values
  - Statistical thresholds computed from the training data itself
  - Risk scoring logic from detection_engine.py
"""

import json
import numpy as np
import pandas as pd
from config import OUTPUT_DIR, TOP_THREATS_FOR_CASE_FILES


# ── THRESHOLD CALCULATOR ─────────────────────────────────────────────────────

def compute_population_thresholds(df: pd.DataFrame) -> dict:
    """
    Compute mean + std for every behavioral feature across ALL users.
    These become the baselines — deviation = suspicious.
    """
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    exclude      = ["risk_score", "is_flagged", "is_insider", "anomaly_raw"]
    feature_cols = [c for c in numeric_cols if c not in exclude]

    thresholds = {}
    for col in feature_cols:
        thresholds[col] = {
            "mean": round(float(df[col].mean()), 4),
            "std" : round(float(df[col].std()),  4),
            "p75" : round(float(df[col].quantile(0.75)), 4),
            "p90" : round(float(df[col].quantile(0.90)), 4),
            "p95" : round(float(df[col].quantile(0.95)), 4),
            "max" : round(float(df[col].max()), 4),
        }
    return thresholds


def z_score(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0
    return round((value - mean) / std, 2)


# ── INDICATOR DETECTOR ───────────────────────────────────────────────────────

def detect_indicators(row: pd.Series, thresholds: dict) -> list:
    """
    Compare user values against population thresholds.
    Returns sorted list of (severity_score, indicator_text).
    """
    indicators = []

    def check(col, label, is_ratio=False, suffix=""):
        if col not in row.index or col not in thresholds:
            return
        val = float(row[col])
        t   = thresholds[col]
        z   = z_score(val, t["mean"], t["std"])

        if   z >= 3.0: severity, tag = 3, "CRITICAL"
        elif z >= 2.0: severity, tag = 2, "HIGH"
        elif z >= 1.5: severity, tag = 1, "ELEVATED"
        else:          return

        if is_ratio:
            val_str = f"{val*100:.1f}%"
            avg_str = f"{t['mean']*100:.1f}%"
        else:
            val_str = f"{val:.0f}{suffix}"
            avg_str = f"{t['mean']:.1f}{suffix}"

        indicators.append((
            severity,
            f"[{tag}] {label}: {val_str} "
            f"(population avg: {avg_str}, z={z:+.1f}σ)"
        ))

    # Login
    check("after_hours_logon_ratio", "After-hours login ratio",           is_ratio=True)
    check("weekend_logon_ratio",     "Weekend login ratio",               is_ratio=True)
    check("unique_pcs",              "Unique workstations accessed",      suffix=" PCs")
    check("logon_time_entropy",      "Login time irregularity (entropy)")
    check("std_logon_hour",          "Login hour variance",               suffix="h")
    # USB
    check("usb_total",               "USB connection events",             suffix=" events")
    check("usb_after_hours_ratio",   "After-hours USB ratio",             is_ratio=True)
    # File
    check("file_copy_ratio",         "File copy ratio",                   is_ratio=True)
    check("file_after_hours_ratio",  "After-hours file ops ratio",        is_ratio=True)
    check("file_suspicious_ext",     "Suspicious file types accessed",    suffix=" files")
    check("file_deletes",            "File deletion events",              suffix=" files")
    # Email
    check("external_email_ratio",    "External email ratio",              is_ratio=True)
    check("attachment_ratio",        "Email attachment ratio",            is_ratio=True)
    check("emails_sent",             "Total emails sent",                 suffix=" emails")
    # HTTP
    check("malicious_url_ratio",     "Malicious URL visits (Safe Browsing verified)", is_ratio=True)
    check("concerning_browse_ratio", "Concerning category browsing",      is_ratio=True)

    indicators.sort(key=lambda x: x[0], reverse=True)
    return indicators


# ── SCENARIO CLASSIFIER ──────────────────────────────────────────────────────

def classify_threat_scenario(row: pd.Series) -> str:
    usb_high    = row.get("usb_total", 0) > 5 or row.get("usb_after_hours_ratio", 0) > 0.3
    file_high   = row.get("file_copy_ratio", 0) > 0.3 or row.get("file_suspicious_ext", 0) > 2
    email_high  = row.get("external_email_ratio", 0) > 0.4 or row.get("attachment_ratio", 0) > 0.5
    web_high    = row.get("malicious_url_ratio", 0) > 0.05
    ah_high     = row.get("after_hours_logon_ratio", 0) > 0.25
    delete_high = row.get("file_deletes", 0) > 10
    multi_pc    = row.get("unique_pcs", 0) > 3

    if usb_high and file_high and ah_high:
        return ("DATA EXFILTRATION via removable media — elevated USB activity combined "
                "with high file copy ratio and after-hours access strongly suggests "
                "deliberate data staging and extraction")
    elif email_high and file_high:
        return ("DATA EXFILTRATION via email — unusual external emails with attachments "
                "combined with file copy activity indicates possible leakage via email channel")
    elif web_high and file_high:
        return ("MALWARE / EXTERNAL COORDINATION — confirmed malicious URL visits combined "
                "with file operations suggest possible malware download or threat actor contact")
    elif delete_high and ah_high:
        return ("SABOTAGE / EVIDENCE DESTRUCTION — abnormal file deletions during after-hours "
                "periods is consistent with sabotage or pre-resignation evidence cleanup")
    elif ah_high and multi_pc:
        return ("UNAUTHORIZED ACCESS — after-hours logins across multiple workstations "
                "suggests credential misuse or lateral movement")
    elif email_high:
        return ("POLICY VIOLATION — excessive external communication with attachments "
                "may indicate unauthorized data sharing or job-search activity")
    else:
        return ("ANOMALOUS BEHAVIORAL PATTERN — multi-vector deviation from established "
                "baseline across login, file, and communication channels")


# ── PSYCHOMETRIC INTERPRETER ─────────────────────────────────────────────────

def interpret_psychometric(row: pd.Series) -> str:
    C = float(row.get("C", 0.5))
    N = float(row.get("N", 0.5))
    A = float(row.get("A", 0.5))
    O = float(row.get("O", 0.5))

    notes = []
    if C < 0.35: notes.append("low conscientiousness (impulsive, rule-bending tendencies)")
    if N > 0.65: notes.append("high neuroticism (emotional instability, stress-reactive)")
    if A < 0.35: notes.append("low agreeableness (antagonistic, non-cooperative)")
    if O > 0.75 and C < 0.4:
        notes.append("high openness with low conscientiousness (risk-taking without accountability)")

    if not notes:
        return ("Psychometric profile does not independently elevate risk; "
                "behavioral signals are primary concern.")
    return "Psychometric profile shows " + "; ".join(notes) + " — consistent with insider threat literature."


# ── RECOMMENDED ACTION ───────────────────────────────────────────────────────

def recommend_action(row: pd.Series) -> str:
    level = row.get("risk_level", "High")
    if level == "Critical":
        return ("Immediately escalate to CISO. Suspend remote access pending review. "
                "Preserve all activity logs with write-lock. Do not alert the employee.")
    elif level == "High":
        return ("Initiate privileged access review within 24 hours. "
                "Flag account for enhanced monitoring. "
                "Schedule confidential HR interview.")
    else:
        return ("Add to 30-day enhanced monitoring watchlist. "
                "Review access permissions against job role requirements.")


# ── CASE FILE BUILDER ─────────────────────────────────────────────────────────

def _percentile_label(score: float) -> str:
    if score >= 90: return "1%"
    elif score >= 80: return "5%"
    elif score >= 70: return "10%"
    else: return "20%"


def generate_case_file(row: pd.Series, thresholds: dict) -> str:
    indicators = detect_indicators(row, thresholds)
    scenario   = classify_threat_scenario(row)
    psycho     = interpret_psychometric(row)
    action     = recommend_action(row)
    top_inds   = indicators[:5] if indicators else [(1, "Overall pattern deviates from peer baseline")]

    lines = [
        f"THREAT LEVEL : {str(row.get('risk_level','HIGH')).upper()}",
        f"RISK SCORE   : {float(row.get('risk_score', 0)):.1f} / 100",
        f"EMPLOYEE ID  : {row.get('user_hash','UNKNOWN')}",
        f"DEPARTMENT   : {row.get('department', 'Unknown')}",
        f"ROLE         : {row.get('role', 'Unknown')}",
        "",
        "EXECUTIVE SUMMARY:",
        f"  {scenario}.",
        f"  Anomaly detected across {len(indicators)} behavioral dimensions.",
        f"  Composite risk score {float(row.get('risk_score',0)):.1f}/100 places this employee",
        f"  in the top {_percentile_label(float(row.get('risk_score',0)))} of all monitored users.",
        "",
        "KEY INDICATORS:",
    ]
    for _, text in top_inds:
        lines.append(f"  • {text}")

    lines += [
        "",
        "BEHAVIORAL SNAPSHOT:",
        f"  After-hours logins   : {float(row.get('after_hours_logon_ratio',0))*100:.1f}%"
        f"   |   Weekend logins      : {float(row.get('weekend_logon_ratio',0))*100:.1f}%",
        f"  USB events           : {int(row.get('usb_total',0))}"
        f"   |   File copy ratio     : {float(row.get('file_copy_ratio',0))*100:.1f}%",
        f"  External emails      : {float(row.get('external_email_ratio',0))*100:.1f}%"
        f"   |   Malicious URLs      : {float(row.get('malicious_url_ratio',0))*100:.1f}%",
        f"  Active days          : {int(row.get('active_days',0))}"
        f"   |   Unique workstations : {int(row.get('unique_pcs',0))}",
        "",
        "PSYCHOMETRIC RISK FACTORS:",
        f"  {psycho}",
        "",
        "RECOMMENDED ACTION:",
        f"  {action}",
        "",
        "─" * 60,
        "Generated by Obscura Detection Engine v1.0",
        "All identifiers are SHA-256 anonymized. No API calls used.",
    ]
    return "\n".join(lines)


# ── BATCH GENERATOR ──────────────────────────────────────────────────────────

def generate_all_case_files(results_df: pd.DataFrame) -> dict:
    print("\n⚙️  Computing population thresholds from training data...")
    thresholds = compute_population_thresholds(results_df)

    top = (
        results_df[results_df["is_flagged"] == 1]
        .sort_values("risk_score", ascending=False)
        .head(TOP_THREATS_FOR_CASE_FILES)
    )

    print(f"📝 Generating Case Files for top {len(top)} threats...\n")
    case_files = {}

    for i, (_, row) in enumerate(top.iterrows(), 1):
        uid = row["user_hash"]
        print(f"  [{i:>2}/{len(top)}] {uid}  (score: {row['risk_score']:.1f})", end=" ")
        brief = generate_case_file(row, thresholds)
        case_files[uid] = brief
        print("✅")

    path = f"{OUTPUT_DIR}/case_files.json"
    with open(path, "w") as f:
        json.dump(case_files, f, indent=2)
    print(f"\n💾 Saved: {path}")
    return case_files


if __name__ == "__main__":
    results = pd.read_csv(f"{OUTPUT_DIR}/results.csv")
    generate_all_case_files(results)
