"""
Defensive risk heuristics from open ports and banners.

These are simple posture checks, not exploit validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Finding:
    """One human-readable security observation from the scan."""

    title: str
    severity: str  # "Low" | "Medium" | "High"
    affected_host: str
    affected_port: int | None
    explanation: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "affected_host": self.affected_host,
            "affected_port": self.affected_port,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
        }


# Ports we treat as "database listener" for the portfolio heuristic.
DATABASE_PORTS = {3306, 5432}


def _has_meaningful_banner(banner: str | None) -> bool:
    if banner is None:
        return False
    return len(banner.strip()) >= 3


def analyze_host(
    host: str,
    open_ports: set[int],
    banners: dict[int, str],
    scanned_ports: set[int],
) -> list[Finding]:
    """
    Build a list of findings for a single host.

    ``open_ports`` should include only ports that answered to our TCP connect scan.
    ``banners`` maps port -> best-effort banner text.
    """
    findings: list[Finding] = []

    if not open_ports:
        return findings

    if 21 in open_ports:
        findings.append(
            Finding(
                title="FTP service exposed (TCP 21)",
                severity="Medium",
                affected_host=host,
                affected_port=21,
                explanation=(
                    "File Transfer Protocol (FTP) often transfers credentials "
                    "in cleartext and expands your attack surface. "
                    "Even when patched, FTP is uncommon on modern hardened perimeters."
                ),
                recommendation=(
                    "Prefer SFTP or HTTPS-based file exchange. Disable anonymous FTP "
                    "if FTP must remain, restrict by firewall and VLAN, enforce TLS where supported."
                ),
            )
        )

    if 23 in open_ports:
        findings.append(
            Finding(
                title="Telnet service exposed (TCP 23)",
                severity="High",
                affected_host=host,
                affected_port=23,
                explanation=(
                    "Telnet is almost always cleartext. Anyone on-path can sniff "
                    "session data. This typically fails basic compliance checks."
                ),
                recommendation=(
                    "Disable Telnet. Use SSH for remote administration "
                    "(with key-based auth and patching discipline)."
                ),
            )
        )

    if {139, 445} & open_ports:
        smb_ports = sorted({139, 445} & open_ports)
        primary = smb_ports[0]
        findings.append(
            Finding(
                title="SMB / Windows File Sharing reachable",
                severity="High",
                affected_host=host,
                affected_port=primary,
                explanation=(
                    f"SMB-related ports responded: {smb_ports}. "
                    "Internet-exposed SMB is a frequent ransomware entry path."
                ),
                recommendation=(
                    "Block SMB from untrusted networks. Require VPN or private links. "
                    "Patch SMB stacks, disable legacy SMBv1 where safe, audit shares and auth."
                ),
            )
        )

    if 3389 in open_ports:
        findings.append(
            Finding(
                title="Remote Desktop (RDP) exposed (TCP 3389)",
                severity="High",
                affected_host=host,
                affected_port=3389,
                explanation=(
                    "Remote Desktop listens for interactive logins. When exposed broadly, "
                    "it invites password guessing and exploits against the RDP stack."
                ),
                recommendation=(
                    "Require VPN / Zero Trust access, enforce MFA/RD Gateway, aggressive lockout/"
                    "auditing where policy allows, and keep systems patched."
                ),
            )
        )

    db_hits = sorted(open_ports & DATABASE_PORTS)
    if db_hits:
        findings.append(
            Finding(
                title="Database listener exposed on network",
                severity="High",
                affected_host=host,
                affected_port=db_hits[0],
                explanation=(
                    "Database protocols (examples: common MySQL/PostgreSQL ports) "
                    f"answered on: {db_hits}. These should rarely be reachable from broad subnets."
                ),
                recommendation=(
                    "Bind listeners to localhost or internal interfaces only where possible; "
                    "use firewall ACLs / security groups / private networking; rotate credentials;"
                    "require TLS between app and DB if supported."
                ),
            )
        )

    http_without_https = (
        (80 in open_ports)
        and (443 in scanned_ports)
        and (443 not in open_ports)
    )
    if http_without_https:
        findings.append(
            Finding(
                title="HTTP without companion HTTPS observed",
                severity="Medium",
                affected_host=host,
                affected_port=80,
                explanation=(
                    "Port 80 is open while 443 is not in the scanned set. Users or scripts "
                    "may send sensitive data over cleartext HTTP if no redirect exists."
                ),
                recommendation=(
                    "Serve HTTPS on 443, redirect HTTP to HTTPS with HSTS on the HTTPS site, "
                    "and avoid mixed content in production apps."
                ),
            )
        )

    for port in sorted(open_ports):
        banner = banners.get(port, "")
        if not _has_meaningful_banner(banner):
            findings.append(
                Finding(
                    title="Missing or minimal banner / service fingerprint",
                    severity="Low",
                    affected_host=host,
                    affected_port=port,
                    explanation=(
                        "We could not retrieve a useful application banner for this open port. "
                        "That makes remote inventory harder and can hide outdated software."
                    ),
                    recommendation=(
                        "During change windows, identify the service via local process lists "
                        "or config management. Ensure only intended daemons listen and versions are tracked."
                    ),
                )
            )

    return findings
