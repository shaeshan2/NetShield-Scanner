"""
Best-effort TCP banner grabbing for open ports.

This does not exploit services; it only reads what peers send after accept
(or what we probe with harmless literals for SMTP-style greeters).
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


# How long we wait per banner attempt (quick fail keeps scans responsive).
DEFAULT_BANNER_TIMEOUT = 2.0

# Largest chunk to read — keeps memory predictable on chatty protocols.
MAX_BANNER_BYTES = 4096


def _sanitize_banner(raw: bytes) -> str:
    """Reduce binary noise to a short printable-ish string safe for logs and HTML."""
    if not raw:
        return ""

    decoded = ""
    try:
        decoded = raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        decoded = ""

    decoded = decoded.replace("\r", " ").replace("\n", " ").strip()

    decoded = re.sub(r"[^\x09\x20-\x7E]", "", decoded)

    if len(decoded) > 512:
        decoded = decoded[:509] + "..."
    return decoded


def grab_banner_tcp(host: str, port: int, timeout: float = DEFAULT_BANNER_TIMEOUT) -> str:
    """
    Connect to ``host``:``port`` and try to read an initial greeting / banner.

    Returns an empty string if nothing useful is returned.
    Never raises — failures become empty banners.
    """
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        peek = b""

        # Lightweight protocol hints — no credential exchange, only literal probes
        # that many daemons tolerate for banner display only.
        if port in {80, 8080}:
            try:
                request = (
                    b"HEAD / HTTP/1.1\r\n"
                    b"Host: " + host.encode("ascii", errors="ignore") + b"\r\n"
                    b"Connection: close\r\n\r\n"
                )
                sock.sendall(request)
            except OSError:
                pass

        try:
            peek = sock.recv(MAX_BANNER_BYTES)
        except OSError:
            peek = b""

        return _sanitize_banner(peek)

    except OSError:
        return ""
    except Exception:  # noqa: BLE001
        return ""
    finally:
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass


def banners_for_open_ports(
    host: str,
    open_ports: list[int],
    *,
    max_workers: int = 32,
    timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> dict[int, str]:
    """
    Run banner grabs concurrently for ``open_ports`` only.

    Returns a map port -> banner string (possibly empty).
    """
    out: dict[int, str] = {}

    if not open_ports:
        return out

    workers = min(max_workers, len(open_ports))

    def _one(p: int) -> tuple[int, str]:
        return p, grab_banner_tcp(host, p, timeout=timeout)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, p) for p in open_ports]
        for future in as_completed(futures):
            try:
                port, banner = future.result()
                out[port] = banner
            except Exception:  # noqa: BLE001
                continue

    return out
