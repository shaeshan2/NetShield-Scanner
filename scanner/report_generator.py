"""
Persistence + presentation: JSON/HTML on disk and Rich-friendly structures.
"""

from __future__ import annotations

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
) -> dict[str, Any]:
    """Assemble one JSON-serializable document describing the entire run."""

    return {
        "scanner": metadata,
        "targets": targets,
        "ports_scanned": ports_scanned,
        "hosts": results_by_host,
        "findings": [f.to_dict() for f in findings],
    }


def save_json(payload: dict[str, Any]) -> Path:
    """Write ``payload`` pretty-printed to ``reports/*.json``. Returns file path."""

    path = _reports_dir() / f"netshield_scan_{_utc_stamp_slug()}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    return path


def save_html(payload: dict[str, Any]) -> Path:
    """
    Merge ``payload`` into ``templates/report.html`` and write HTML under reports/.

    Uses simple ``str.replace`` placeholders to avoid extra dependencies.
    """

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

    overview = escape_html(json.dumps(payload.get("scanner") or {}, indent=2))

    replacements = {
        "{{TITLE}}": "NetShield Scanner — Report",
        "{{GENERATED_AT}}": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "{{TARGET_LIST}}": escape_html(", ".join(payload.get("targets") or [])),
        "{{PORTS_LIST}}": escape_html(", ".join(str(p) for p in (payload.get("ports_scanned") or []))),
        "{{FINDINGS_COUNT}}": str(len(payload.get("findings") or [])),
        "{{FINDINGS_TABLE_ROWS}}": findings_rows if findings_rows else "<tr><td colspan='6'>No findings.</td></tr>",
        "{{HOSTS_TABLE_ROWS}}": hosts_rows if hosts_rows else "<tr><td colspan='3'>No reachable hosts scanned.</td></tr>",
        "{{JSON_OVERVIEW}}": f"<pre>{overview}</pre>",
    }

    html = template_text
    for key, val in replacements.items():
        html = html.replace(key, val)

    out_path = _reports_dir() / f"netshield_report_{_utc_stamp_slug()}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


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
    console: Console | None = None,
) -> None:
    """Emit a concise, colorful summary to stdout."""

    console = console or Console()

    meta = payload.get("scanner") or {}
    scanner_name = meta.get("name", "NetShield Scanner")
    version = meta.get("version", "")
    title = scanner_name + (f" v{version}" if version else "")

    findings = payload.get("findings") or []

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

    if findings:
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
