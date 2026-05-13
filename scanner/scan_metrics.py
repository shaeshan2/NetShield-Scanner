"""
Scan run metrics and qualitative risk score for defensive reporting.

The risk score is a simple weighted sum of finding severities, capped at 10.
It is not CVSS and does not imply exploitation or validation of vulnerabilities.
"""

from __future__ import annotations

from typing import Any

from scanner.risk_checker import Finding


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.severity
        if sev in counts:
            counts[sev] += 1
    return counts


def compute_risk_assessment(findings: list[Finding]) -> dict[str, Any]:
    """
    Overall posture score out of 10 from finding severities only.

    High = 3, Medium = 2, Low = 1 per finding; sum capped at 10.
    Band labels describe aggregate posture, not individual finding severity names.
    """
    raw = 0
    for f in findings:
        if f.severity == "High":
            raw += 3
        elif f.severity == "Medium":
            raw += 2
        elif f.severity == "Low":
            raw += 1

    score = min(raw, 10)
    if score <= 3:
        band = "Low"
    elif score <= 6:
        band = "Medium"
    else:
        band = "High"

    return {
        "raw_points": raw,
        "score": score,
        "max_score": 10,
        "posture_band": band,
        "method": "weighted_severity_sum_capped",
        "weights": {"High": 3, "Medium": 2, "Low": 1},
    }


def build_scan_metrics(
    *,
    duration_seconds: float,
    hosts: list[str],
    ports_scanned: list[int],
    results_by_host: dict[str, dict[str, Any]],
    findings: list[Finding],
) -> dict[str, Any]:
    n_hosts = len(hosts)
    n_ports = len(ports_scanned)
    total_probes = n_hosts * n_ports
    open_ports_found = sum(len(data.get("open_ports") or []) for data in results_by_host.values())
    sev = severity_counts(findings)

    return {
        "duration_seconds": round(duration_seconds, 3),
        "hosts_scanned": n_hosts,
        "ports_scanned_per_host": n_ports,
        "total_probes_attempted": total_probes,
        "open_ports_found": open_ports_found,
        "findings_generated": len(findings),
        "severity_counts": sev,
    }
