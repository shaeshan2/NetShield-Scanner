"""
Persistence + presentation: JSON/HTML/CSV on disk and Rich-friendly structures.
"""

from __future__ import annotations

import csv
import io
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.risk_checker import Finding


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _reports_dir() -> Path:
    d = _project_root() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _utc_stamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def build_scan_payload(
    *,
    targets: list[str],
    ports_scanned: list[int],
    results_by_host: dict[str, dict[str, Any]],
    findings: list[Finding],
    metadata: dict[str, Any],
    scan_metrics: dict[str, Any],
    risk_assessment: dict[str, Any],
) -> dict[str, Any]:
    """Assemble one JSON-serializable document describing the entire run."""

    return {
        "scanner": metadata,
        "targets": targets,
        "ports_scanned": ports_scanned,
        "hosts": results_by_host,
        "findings": [f.to_dict() for f in findings],
        "scan_metrics": scan_metrics,
        "risk_assessment": risk_assessment,
    }


def save_json(payload: dict[str, Any], *, file_stamp: str | None = None) -> Path:
    """Write ``payload`` pretty-printed to ``reports/*.json``. Returns file path."""

    slug = file_stamp or _utc_stamp_slug()
    path = _reports_dir() / f"netshield_scan_{slug}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    return path


def _banner_for_finding(
    results_by_host: dict[str, dict[str, Any]],
    host: str,
    port: int | None,
) -> str:
    if port is None:
        return ""
    data = results_by_host.get(host) or {}
    banners = data.get("banners") or {}
    b = banners.get(str(port), banners.get(port, ""))
    return b if isinstance(b, str) else str(b)


def save_csv(payload: dict[str, Any], *, file_stamp: str | None = None) -> Path:
    """
    Write findings and scan context to ``reports/*.csv``.

    One row per finding; repeated scan-level columns help spreadsheet imports.
    """

    slug = file_stamp or _utc_stamp_slug()
    path = _reports_dir() / f"netshield_scan_{slug}.csv"
    hosts = payload.get("hosts") or {}
    findings_raw = payload.get("findings") or []
    metrics = payload.get("scan_metrics") or {}
    risk = payload.get("risk_assessment") or {}

    duration = metrics.get("duration_seconds", "")
    hosts_n = metrics.get("hosts_scanned", "")
    ports_ph = metrics.get("ports_scanned_per_host", "")
    probes = metrics.get("total_probes_attempted", "")
    opens = metrics.get("open_ports_found", "")
    fc = metrics.get("findings_generated", "")
    rscore = risk.get("score", "")
    rband = risk.get("posture_band", "")

    fieldnames = [
        "host",
        "port",
        "service_or_banner",
        "finding_title",
        "severity",
        "explanation",
        "recommendation",
        "scan_duration_sec",
        "hosts_scanned",
        "ports_per_host",
        "total_probes_attempted",
        "open_ports_found",
        "findings_count",
        "risk_score",
        "posture_band",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()

        def row_common() -> dict[str, Any]:
            return {
                "scan_duration_sec": duration,
                "hosts_scanned": hosts_n,
                "ports_per_host": ports_ph,
                "total_probes_attempted": probes,
                "open_ports_found": opens,
                "findings_count": fc,
                "risk_score": rscore,
                "posture_band": rband,
            }

        if not findings_raw:
            w.writerow(
                {
                    "host": "",
                    "port": "",
                    "service_or_banner": "",
                    "finding_title": "No defensive findings generated for this run",
                    "severity": "",
                    "explanation": "",
                    "recommendation": "",
                    **row_common(),
                }
            )
        else:
            for fd in findings_raw:
                host = str(fd.get("affected_host") or "")
                port_val = fd.get("affected_port")
                port_str = "" if port_val is None else str(port_val)
                banner = _banner_for_finding(hosts, host, port_val if isinstance(port_val, int) else None)
                w.writerow(
                    {
                        "host": host,
                        "port": port_str,
                        "service_or_banner": banner,
                        "finding_title": str(fd.get("title") or ""),
                        "severity": str(fd.get("severity") or ""),
                        "explanation": str(fd.get("explanation") or ""),
                        "recommendation": str(fd.get("recommendation") or ""),
                        **row_common(),
                    }
                )

    return path


def save_html(payload: dict[str, Any], *, file_stamp: str | None = None) -> Path:
    """
    Merge ``payload`` into ``templates/report.html`` and write HTML under reports/.

    Uses simple ``str.replace`` placeholders to avoid extra dependencies.
    """

    slug = file_stamp or _utc_stamp_slug()
    template_path = _project_root() / "templates" / "report.html"
    template_text = template_path.read_text(encoding="utf-8")

    findings_rows = ""
    severity_class = {"Low": "sev-low", "Medium": "sev-medium", "High": "sev-high"}

    for fdict in payload.get("findings", []):
        sev = fdict.get("severity", "")
        badge = severity_class.get(sev, "sev-low")
        port = fdict.get("affected_port")
        port_txt = "-" if port is None else str(port)
        findings_rows += (
            "<tr>"
            f'<td><span class="badge {badge}">{escape_html(sev)}</span></td>'
            f"<td>{escape_html(str(fdict.get('title','')))}</td>"
            f"<td><code>{escape_html(str(fdict.get('affected_host','')))}</code></td>"
            f"<td><code>{escape_html(port_txt)}</code></td>"
            f"<td>{escape_html(str(fdict.get('explanation','')))}</td>"
            f"<td>{escape_html(str(fdict.get('recommendation','')))}</td>"
            "</tr>\n"
        )

    matrix_rows = ""
    for fdict in payload.get("findings", []):
        sev = str(fdict.get("severity", ""))
        badge = severity_class.get(sev, "sev-low")
        port = fdict.get("affected_port")
        port_txt = "-" if port is None else str(port)
        matrix_rows += (
            "<tr>"
            f"<td><code>{escape_html(str(fdict.get('affected_host','')))}</code></td>"
            f"<td><code>{escape_html(port_txt)}</code></td>"
            f'<td><span class="badge {badge}">{escape_html(sev)}</span></td>'
            f"<td>{escape_html(str(fdict.get('title','')))}</td>"
            "</tr>\n"
        )

    hosts_rows = ""
    for host, data in (payload.get("hosts") or {}).items():
        open_ports = data.get("open_ports") or []
        open_txt = ", ".join(str(p) for p in open_ports) if open_ports else "(none)"

        banners = data.get("banners") or {}
        banner_chunks = []
        for p in open_ports:
            key_candidates = (p, str(p))
            b = ""
            for k in key_candidates:
                if k in banners:
                    b = banners[k]
                    break
            if not isinstance(b, str):
                b = str(b)
            banner_chunks.append(f"{p}: {b or '[no banner]'}")

        banner_txt = " | ".join(banner_chunks) if banner_chunks else "-"

        hosts_rows += (
            "<tr>"
            f"<td><code>{escape_html(host)}</code></td>"
            f"<td>{escape_html(open_txt)}</td>"
            f"<td>{escape_html(banner_txt)}</td>"
            "</tr>\n"
        )

    metrics = payload.get("scan_metrics") or {}
    risk = payload.get("risk_assessment") or {}
    sev_counts = metrics.get("severity_counts") or {}

    metrics_rows = ""
    metric_pairs = [
        ("Scan duration (seconds)", str(metrics.get("duration_seconds", ""))),
        ("Hosts scanned", str(metrics.get("hosts_scanned", ""))),
        ("Ports per host", str(metrics.get("ports_scanned_per_host", ""))),
        ("Total probes attempted", str(metrics.get("total_probes_attempted", ""))),
        ("Open ports found", str(metrics.get("open_ports_found", ""))),
        ("Findings generated", str(metrics.get("findings_generated", ""))),
    ]
    for label, val in metric_pairs:
        metrics_rows += f"<tr><th>{escape_html(label)}</th><td>{escape_html(val)}</td></tr>\n"

    sev_break_rows = ""
    for label, key in [("High", "High"), ("Medium", "Medium"), ("Low", "Low")]:
        sev_break_rows += (
            f"<tr><td><span class=\"badge {severity_class.get(label, 'sev-low')}\">"
            f"{escape_html(label)}</span></td>"
            f"<td>{escape_html(str(sev_counts.get(key, 0)))}</td></tr>\n"
        )

    findings_list = payload.get("findings") or []
    seen_rec: set[str] = set()
    remediation_items = ""
    for fd in findings_list:
        rec = str(fd.get("recommendation") or "").strip()
        if rec and rec not in seen_rec:
            seen_rec.add(rec)
            remediation_items += f"<li>{escape_html(rec)}</li>\n"

    if not remediation_items:
        remediation_items = "<li>No actionable recommendations (no findings).</li>"

    score = risk.get("score", 0)
    band = str(risk.get("posture_band", ""))
    raw_pts = risk.get("raw_points", 0)
    exec_summary = _build_executive_summary_html(payload, metrics, risk)

    overview = escape_html(json.dumps(payload.get("scanner") or {}, indent=2))

    risk_badge_class = {"Low": "sev-low", "Medium": "sev-medium", "High": "sev-high"}.get(band, "sev-low")

    replacements = {
        "{{TITLE}}": "NetShield Scanner — Report",
        "{{GENERATED_AT}}": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "{{TARGET_LIST}}": escape_html(", ".join(payload.get("targets") or [])),
        "{{PORTS_LIST}}": escape_html(", ".join(str(p) for p in (payload.get("ports_scanned") or []))),
        "{{FINDINGS_COUNT}}": str(len(payload.get("findings") or [])),
        "{{FINDINGS_TABLE_ROWS}}": findings_rows if findings_rows else "<tr><td colspan='6'>No findings.</td></tr>",
        "{{HOSTS_TABLE_ROWS}}": hosts_rows if hosts_rows else "<tr><td colspan='3'>No reachable hosts scanned.</td></tr>",
        "{{JSON_OVERVIEW}}": f"<pre>{overview}</pre>",
        "{{EXEC_SUMMARY}}": exec_summary,
        "{{SCAN_METRICS_ROWS}}": metrics_rows,
        "{{SEVERITY_BREAKDOWN_ROWS}}": sev_break_rows,
        "{{RISK_SCORE}}": escape_html(str(score)),
        "{{RISK_BAND}}": escape_html(band),
        "{{RISK_BADGE_CLASS}}": risk_badge_class,
        "{{RISK_RAW_POINTS}}": escape_html(str(raw_pts)),
        "{{REMEDIATION_ITEMS}}": remediation_items,
        "{{FINDINGS_MATRIX_ROWS}}": matrix_rows
        if matrix_rows
        else "<tr><td colspan='4'>No findings.</td></tr>",
    }

    html = template_text
    for key, val in replacements.items():
        html = html.replace(key, val)

    out_path = _reports_dir() / f"netshield_report_{slug}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


def _build_executive_summary_html(
    payload: dict[str, Any],
    metrics: dict[str, Any],
    risk: dict[str, Any],
) -> str:
    targets = payload.get("targets") or []
    n_hosts = metrics.get("hosts_scanned", 0)
    n_ports = metrics.get("ports_scanned_per_host", 0)
    dur = metrics.get("duration_seconds", 0)
    opens = metrics.get("open_ports_found", 0)
    nf = metrics.get("findings_generated", 0)
    band = risk.get("posture_band", "Low")
    score = risk.get("score", 0)

    t_preview = ", ".join(str(t) for t in targets[:5])
    if len(targets) > 5:
        t_preview += f" (+{len(targets) - 5} more)"

    parts = [
        f"This defensive inventory assessed <strong>{escape_html(str(n_hosts))}</strong> host(s) "
        f"across <strong>{escape_html(str(n_ports))}</strong> TCP port(s) per host in "
        f"<strong>{escape_html(str(dur))}</strong> seconds (authorized scope only). "
        f"<strong>{escape_html(str(opens))}</strong> open port(s) were observed; "
        f"<strong>{escape_html(str(nf))}</strong> posture finding(s) were recorded. "
        f"Aggregate posture band is <strong>{escape_html(str(band))}</strong> "
        f"(qualitative score <strong>{escape_html(str(score))}</strong> out of 10, "
        "derived from finding severities, not from exploitation or CVSS). "
        f"Targets included: <code>{escape_html(t_preview or 'n/a')}</code>."
    ]
    return "<p>" + "".join(parts) + "</p>"


def escape_html(text: str) -> str:
    """Minimal escaping for MVP HTML embedding."""

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def print_rich_summary(
    *,
    payload: dict[str, Any],
    json_path: Path,
    html_path: Path,
    csv_path: Path,
    console: Console | None = None,
) -> None:
    """Emit a concise, colorful summary to stdout."""

    console = console or Console()

    meta = payload.get("scanner") or {}
    scanner_name = meta.get("name", "NetShield Scanner")
    version = meta.get("version", "")
    title = scanner_name + (f" v{version}" if version else "")

    findings = payload.get("findings") or []
    metrics = payload.get("scan_metrics") or {}
    risk = payload.get("risk_assessment") or {}

    bucket: dict[str, int] = defaultdict(int)
    for f in findings:
        sev = str(f.get("severity") or "Unknown")
        if sev not in {"Low", "Medium", "High"}:
            sev = "Other"
        bucket[sev] += 1

    order_and_style = [
        ("High", "bold red"),
        ("Medium", "yellow"),
        ("Low", "green"),
        ("Other", "magenta"),
    ]

    sev_tbl = Table(title="Findings by severity", show_lines=False)
    sev_tbl.add_column("Severity", style="cyan", no_wrap=True)
    sev_tbl.add_column("Count", justify="right")

    for label, sty in order_and_style:
        n = bucket.get(label, 0)
        if n <= 0:
            continue
        sev_tbl.add_row(f"[{sty}]{label}[/{sty}]", str(n))

    metrics_tbl = Table(title="Scan metrics", show_lines=False)
    metrics_tbl.add_column("Metric", style="cyan")
    metrics_tbl.add_column("Value", justify="right")
    metrics_tbl.add_row("Duration (s)", str(metrics.get("duration_seconds", "")))
    metrics_tbl.add_row("Hosts scanned", str(metrics.get("hosts_scanned", "")))
    metrics_tbl.add_row("Ports per host", str(metrics.get("ports_scanned_per_host", "")))
    metrics_tbl.add_row("Total probes", str(metrics.get("total_probes_attempted", "")))
    metrics_tbl.add_row("Open ports found", str(metrics.get("open_ports_found", "")))
    metrics_tbl.add_row("Findings generated", str(metrics.get("findings_generated", "")))

    risk_band = str(risk.get("posture_band", ""))
    risk_score = str(risk.get("score", ""))
    risk_raw = str(risk.get("raw_points", ""))
    risk_panel = (
        f"[bold]Posture score (out of 10):[/bold] {risk_score}\n"
        f"[bold]Posture band:[/bold] {risk_band}\n"
        f"[dim]Raw weighted points (before cap): {risk_raw} "
        "(High=3, Medium=2, Low=1 per finding)[/dim]"
    )

    findings_tbl = Table(title="Detailed findings", show_lines=True, expand=True)
    findings_tbl.add_column("Severity", width=10)
    findings_tbl.add_column("Title", ratio=2)
    findings_tbl.add_column("Host")
    findings_tbl.add_column("Port", justify="right", width=6)
    findings_tbl.add_column("Summary", ratio=3)

    for f in findings:
        sev = str(f.get("severity") or "")
        sty = {"High": "red", "Medium": "yellow", "Low": "green"}.get(sev, "white")

        port = f.get("affected_port")
        port_txt = "-" if port is None else str(port)

        explanation = str(f.get("explanation") or "")
        clipped = explanation if len(explanation) <= 200 else explanation[:197] + "..."

        findings_tbl.add_row(
            f"[{sty}]{sev}[/{sty}]",
            str(f.get("title") or ""),
            str(f.get("affected_host") or ""),
            port_txt,
            clipped,
        )

    hosts_tbl = Table(title="Open ports per host", show_lines=False)
    hosts_tbl.add_column("Host")
    hosts_tbl.add_column("Open TCP ports")

    hosts = payload.get("hosts") or {}
    any_open = False
    for host, data in hosts.items():
        open_ports = data.get("open_ports") or []
        if open_ports:
            any_open = True
        txt = ", ".join(str(p) for p in open_ports) if open_ports else "(none observed)"
        hosts_tbl.add_row(host, txt)

    console.print(Panel.fit(f"[bold]{title}[/bold]\nAuthorized defensive assessment only.", title="NetShield"))

    console.print(metrics_tbl)
    console.print()
    console.print(Panel.fit(risk_panel, title="Risk posture (qualitative)"))

    if findings:
        console.print()
        console.print(sev_tbl)
        console.print()
        console.print(findings_tbl)
    else:
        console.print("[green]No risk findings emitted for this run.[/green]")

    console.print()

    console.print(hosts_tbl)

    if not any_open and hosts:
        console.print(
            "\n[yellow]"
            "All probed hosts had every listed port closed or unreachable from this machine."
            "[/yellow]"
        )

    console.print(f"\n[bold]JSON report:[/bold] {json_path}")
    console.print(f"[bold]HTML report:[/bold] {html_path}")
    console.print(f"[bold]CSV report:[/bold] {csv_path}")
