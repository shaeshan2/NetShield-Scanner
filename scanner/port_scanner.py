"""
TCP connect-based port probing using only the standard `socket` API (full handshake).

Authorized defensive inventories—not SYN half-open stealth, spoofing,
fragmentation tricks, rate-based evasion, or any offensive phase.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

# Seconds to wait before considering a port closed / filtered from our perspective.
DEFAULT_CONNECT_TIMEOUT = 1.5

# Default checklist of ports commonly audited on internal/external perimeters.
DEFAULT_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    8080,
)


@dataclass(frozen=True)
class PortScanResult:
    """Outcome of probing a single TCP port on one host."""

    host: str
    port: int
    open: bool
    error: str | None = None


def parse_target(target: str) -> list[str]:
    """
    Turn a CLI target string into a list of IPv4 addresses.

    Accepts:

        - Single host: ``127.0.0.1`` (normalized to ``/32`` internally)
        - CIDR prefix: ``192.168.1.0/24``

    Raises ValueError if parsing fails or IPv6 is supplied.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target must not be empty.")

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError(
            f"Could not parse IPv4 target or CIDR: {target!r}. "
            f"Examples: 127.0.0.1 or 192.168.10.0/28"
        ) from exc

    if isinstance(network, ipaddress.IPv6Network):
        raise ValueError("IPv6 is not supported in this beginner-safe build.")

    return [str(ip) for ip in network.hosts()]


def scan_tcp_port(host: str, port: int, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> PortScanResult:
    """
    Try a TCP connection to ``host``:``port``.

    Unknown hosts or firewalls returning no SYN-ACK surface as closed from our view,
    never as an uncaught exception to the caller.
    """
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result_code = sock.connect_ex((host, port))
        is_open = result_code == 0
        err = None if is_open else f"connect_ex errno {result_code}"
        return PortScanResult(host=host, port=port, open=is_open, error=err)
    except OSError as exc:
        return PortScanResult(host=host, port=port, open=False, error=str(exc))
    except Exception as exc:  # noqa: BLE001 — defensive UX; never crash the scan runner
        return PortScanResult(host=host, port=port, open=False, error=f"unexpected: {exc!s}")
    finally:
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass


def scan_host_ports_multithreaded(
    host: str,
    ports: Sequence[int],
    *,
    max_workers: int = 100,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    progress_hook: Callable[[PortScanResult], None] | None = None,
) -> list[PortScanResult]:
    """
    Scan all ``ports`` on ``host`` using a thread pool.

    ``progress_hook`` is optional and called once per finished probe (may be noisy).
    """
    results: list[PortScanResult] = []

    # Cap workers for very small port lists to avoid pointless thread churn.
    workers = min(max_workers, max(len(ports), 1))

    def _worker(p: int) -> PortScanResult:
        res = scan_tcp_port(host, p, timeout=timeout)
        if progress_hook:
            progress_hook(res)
        return res

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(_worker, p): p for p in ports}
        for future in as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001 — never fail the batch
                port = future_map.get(future, -1)
                results.append(
                    PortScanResult(host=host, port=port, open=False, error=f"executor: {exc!s}")
                )

    results.sort(key=lambda r: r.port)
    return results


def flatten_targets(targets: Iterable[str]) -> list[str]:
    """Expand multiple target strings into a de-duplicated, stable-ordered IPv4 list."""
    seen: set[str] = set()
    ordered: list[str] = []
    for t in targets:
        for ip in parse_target(t):
            if ip not in seen:
                seen.add(ip)
                ordered.append(ip)
    return ordered
