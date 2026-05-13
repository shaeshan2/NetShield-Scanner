#!/usr/bin/env python3
"""
NetShield Scanner — entry point.

Defensive TCP connect scanner for AUTHORIZED assessments only.

This program does not implement exploitation, brute forcing, stealth/evasion scans,
credential attacks, or any other offensive tooling. Use only where you hold
explicit permission per README and SECURITY guidelines.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Running `python main.py` should resolve the local `scanner` package without PYTHONPATH tweaks.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from rich.console import Console

from scanner import __version__
from scanner.banner_grabber import banners_for_open_ports
from scanner.port_scanner import DEFAULT_CONNECT_TIMEOUT, DEFAULT_PORTS, flatten_targets, scan_host_ports_multithreaded
from scanner.report_generator import build_scan_payload, print_rich_summary, save_csv, save_html, save_json
from scanner.risk_checker import Finding, analyze_host
from scanner.scan_metrics import build_scan_metrics, compute_risk_assessment


def _parse_ports(csv: str) -> list[int]:
    """Turn a comma-separated list into sorted unique integers."""

    parts = [part.strip() for part in csv.split(",") if part.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("At least one port is required.")

    ports: list[int] = []
    for p in parts:
        try:
            n = int(p, 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid port literal: {p!r}") from exc
        if not (1 <= n <= 65535):
            raise argparse.ArgumentTypeError(f"Port must be between 1 and 65535: {n}")
        ports.append(n)

    return sorted(set(ports))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description=(
            "NetShield Scanner — defensive IPv4 TCP connect inventory for AUTHORIZED scopes only. "
            "No exploitation/brute-force/stealth/credential tooling."
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        help='Single IPv4 host (example: "127.0.0.1") or IPv4 CIDR (example: "192.168.1.0/24").',
    )
    parser.add_argument(
        "--ports",
        default=None,
        help=(
            "Comma-separated TCP ports overriding the checklist "
            f'(default checklist: {",".join(str(p) for p in DEFAULT_PORTS)}). Example: 22,80,443'
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=120,
        help="Concurrent socket workers per host (bounded). Default: 120",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help=f"TCP connect timeout in seconds per port. Default: {DEFAULT_CONNECT_TIMEOUT}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    console = Console()

    try:
        expanded = flatten_targets([args.target])
    except ValueError as exc:
        console.print(f"[red]Bad target:[/red] {exc}")
        return 2

    ports = _parse_ports(args.ports) if args.ports else list(DEFAULT_PORTS)
    scanned_set = set(ports)

    if args.timeout <= 0:
        console.print("[red]timeout must be positive[/red]")
        return 2

    workers = max(1, min(args.workers, 256))

    results_by_host: dict[str, dict] = {}
    all_findings: list[Finding] = []
    t0 = time.monotonic()

    console.print("[bold cyan]Starting NetShield scan...[/bold cyan]")
    console.print(
        f"Hosts to probe: [white]{len(expanded)}[/white] — checklist ports/host: [white]{len(ports)}[/white]"
    )

    for host_index, host in enumerate(expanded, start=1):
        console.print()
        console.print(f"Host [{host_index}/{len(expanded)}]: [yellow]{host}[/yellow]")

        probe_results = scan_host_ports_multithreaded(
            host,
            ports,
            max_workers=min(workers, max(len(ports), 1)),
            timeout=args.timeout,
        )

        open_ports = sorted({r.port for r in probe_results if r.open})

        # Optional breadcrumbs for learners (never fatal). Most closed ports only return errno codes.
        errors_by_port: dict[int, str] = {}
        for r in probe_results:
            if r.open or not r.error:
                continue
            if r.error == "connect_ex errno 11":  # EAGAIN on some platforms — skip noise
                continue
            errors_by_port[r.port] = r.error

        banner_map_numeric: dict[int, str] = {}
        if open_ports:
            try:
                banner_map_numeric = banners_for_open_ports(
                    host,
                    open_ports,
                    max_workers=min(32, max(len(open_ports), 1)),
                )
            except Exception as exc:  # noqa: BLE001 — banner stage must never crash the scan
                banner_map_numeric = {}
                console.print(f"[yellow]Banner stage soft-failed:[/yellow] {exc}")

        banners_out: dict[str, str] = {str(p): banner_map_numeric.get(p, "") for p in open_ports}

        results_by_host[host] = {
            "open_ports": open_ports,
            "banners": banners_out,
            "closed_port_errors": errors_by_port,
        }

        if open_ports:
            console.print(
                f"[green bold]Probe complete[/green bold] — open TCP: {', '.join(str(p) for p in open_ports)}"
            )
        else:
            console.print("[green bold]Probe complete[/green bold] — no open checklist ports detected here")

        try:
            findings = analyze_host(
                host,
                open_ports=set(open_ports),
                banners=banner_map_numeric,
                scanned_ports=scanned_set,
            )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Risk analysis skipped for[/red] {host}: {exc}")
            findings = []

        all_findings.extend(findings)

    elapsed = max(0.0, time.monotonic() - t0)
    scan_metrics = build_scan_metrics(
        duration_seconds=elapsed,
        hosts=expanded,
        ports_scanned=ports,
        results_by_host=results_by_host,
        findings=all_findings,
    )
    risk_assessment = compute_risk_assessment(all_findings)

    metadata = {
        "name": "NetShield Scanner",
        "version": __version__,
        "ethical_posture": "defensive-tcp-connect-only",
        "workers": workers,
        "timeout_seconds": args.timeout,
    }

    payload = build_scan_payload(
        targets=expanded,
        ports_scanned=ports,
        results_by_host=results_by_host,
        findings=all_findings,
        metadata=metadata,
        scan_metrics=scan_metrics,
        risk_assessment=risk_assessment,
    )

    try:
        file_stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_path = save_json(payload, file_stamp=file_stamp)
        html_path = save_html(payload, file_stamp=file_stamp)
        csv_path = save_csv(payload, file_stamp=file_stamp)
    except OSError as exc:
        console.print(f"[red]Could not write reports:[/red] {exc}")
        return 1

    print_rich_summary(
        payload=payload,
        json_path=json_path,
        html_path=html_path,
        csv_path=csv_path,
        console=console,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
