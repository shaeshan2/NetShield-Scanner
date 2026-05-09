# NetShield Scanner

**NetShield Scanner** is a **defensive** network posture tool for **authorized testing only**. It inventories which common TCP ports accept connections using **explicit TCP connects** (`socket`), performs **non-destructive banner reads**, applies a simple **risk rubric** for defenders, and exports **JSON**, **HTML**, plus a terminal summary via **Rich**.

**Out of scope (not included nor intended):** exploitation, brute forcing, stealth scanning, evasion tactics, credential attacks (or any spraying/guessing), or other offensive tooling. Networking is confined to benign connect-time behavior comparable to **`telnet` / `nc` checks** — automated with threading and timeouts only.

---

## Features

- **IPv4 host or CIDR input** — expand `192.168.1.0/24` safely with the standard library `ipaddress` module.
- **Default defensive port checklist** — `21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080` (override via `--ports`).
- **Multithreaded TCP probes** using `concurrent.futures.ThreadPoolExecutor`.
- **Banner grabbing** via short, read-only socket operations (plus a harmless `HEAD` probe for HTTP-ish ports).
- **Risk checker** with curated findings (FTP/Telnet/SMB/RDP/DB exposure patterns, HTTP/`HTTPS` posture hint, missing banners).
- **Reports** — timestamped files in `reports/` for JSON + HTML, styled terminal output via **Rich**.
- **Resilient core** — malformed targets are rejected with a message; offline hosts do not crash the run.

---

## Ethical use disclaimer

NetShield Scanner produces **network traffic** (TCP connection attempts). Direct it **only**:

- Toward hosts and networks inside **scopes you own** or are **contractually permitted** to assess, **and**
- In ways consistent with applicable laws and organizational policies.

**Unauthorized scanning is unethical and illegal in many jurisdictions.** If you need practice, prefer **explicitly sanctioned** environments (labs, VMs you control, deliberate vulnerable practice ranges with permission).

Nothing here helps you bypass firewalls covertly or attack third parties—you are responsible for lawful, authorized use only.

---

## Legal notice (not legal advice)

This repository distributes **portfolio / instructional code** related to benign TCP probing. Reading this section is **not** a substitute for professional legal counsel where you operate.

- **No warranty.** The maintainers disclaim warranties to the fullest extent permitted— software is shipped **“AS IS.”** Bugs, misconfigurations, and environment differences are yours to validate.
- **Your compliance.** You alone are responsible for complying with criminal law, contracts, ISP/campus/cloud acceptable-use rules, workplace policy, export controls (if relevant), etc.
- **Third-party forks and misuse.** This project teaches defensive inventory patterns. Anyone who repurposes code for unlawful access or unauthorized probing acts on their own. **That misuse is outside the authors’ reasonable control**, just as with spreadsheets, compilers, or any general-purpose tooling.
- **Scan artifacts.** Logs and HTML/JSON reports can contain banners or IPs; keep them internal (`.gitignore` helps keep them **out** of Git—double-check before every `push`).

If you need definitive answers—for employment, coursework, penetration-test contracts, international travel, or regulatory regimes—consult a lawyer qualified in **your jurisdiction**.

---

## License

This repository is licensed under the [MIT License](LICENSE). Dependencies (currently **[Rich](https://github.com/Textualize/rich)**) carry their own terms on PyPI.

---

## Installation

Requirements: **Python 3.10+** (uses modern union types like `list[str]`).

```bash
cd netshield-scanner
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
# .venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
```

No third-party binaries are required—the scanner uses `socket` from the Python standard library and `rich` for prettier terminal output only.

---

## Usage

Always run commands from inside the **`netshield-scanner/`** folder so `scanner/` and `main.py` resolve correctly.

### Scan a single host with the default checklist

```bash
python main.py --target 127.0.0.1
```

### Scan an entire private /24 prefix

```bash
python main.py --target 192.168.1.0/24
```

> Larger ranges mean **more probes** (`hosts × ports`). Exercise patience and restraint on shared networks.

### Override TCP ports explicitly

```bash
python main.py --target 127.0.0.1 --ports 22,80,443
```

### Optional knobs

```bash
# Increase concurrent workers per host (default 120)
python main.py --target 127.0.0.1 --workers 180

# Tighten/loosen per-port timeouts (seconds, default ~1.5)
python main.py --target 127.0.0.1 --timeout 1.2
```

### Outputs

Every successful run emits:

| Output | Location |
|--------|----------|
| JSON machine-readable results | `reports/netshield_scan_YYYYMMDD_HHMMSS.json` |
| HTML human-readable narrative | `reports/netshield_report_YYYYMMDD_HHMMSS.html` |
| Styled terminal digest | Printed to stdout (Rich tables + panels) |

Open the `.html` file in any browser. Use the `.json` file for ingestion into ticketing systems or Grafana/Splunk demos.

---

## Sample terminal output

```
Starting NetShield scan...
Hosts to probe: 1 — checklist ports/host: 15

Host [1/1]: 127.0.0.1

Probe complete — open TCP: 443

╭──────────────────────────── NetShield ─────────────────────────────╮
│ NetShield Scanner v1.0.0                                            │
│ Authorized defensive assessment only.                               │
╰────────────────────────────────────────────────────────────────────╯

... Rich tables summarize severities & hosts ...

JSON report: /path/to/netshield-scanner/reports/netshield_scan_20260501_120000.json
HTML report: /path/to/netshield-scanner/reports/netshield_report_20260501_120000.html
```

Your exact wording will mirror whatever services were reachable from your workstation.

---

## Publishing to GitHub (first time)

From the `netshield-scanner/` directory:

1. Confirm only source + templates are staged (reports and `.venv` must stay ignored):

   ```bash
   git status
   ```

2. Initialize the repo once (skip if `.git/` already exists):

   ```bash
   git init
   git branch -M main
   ```

3. Add the remote once and publish:

   ```bash
   git remote add origin https://github.com/shaeshan2/NetShield-Scanner.git
   git push -u origin main
   ```

   If `origin` already exists with another URL:

   ```bash
   git remote set-url origin https://github.com/shaeshan2/NetShield-Scanner.git
   git push -u origin main
   ```

`reports/` stays empty except for `.gitkeep` in Git; JSON/HTML artifacts from your VM tests should never be committed—they may contain sensitive hostnames or banners.

Continuous integration (`.github/workflows/ci.yml`) runs on pushes/PRs to `main`: compile check, `--help`, and a fast localhost probe.

---

## Project layout recap

```
netshield-scanner/
├── scanner/
│   ├── __init__.py           # Package metadata/version
│   ├── port_scanner.py       # Target parsing + threaded TCP probing
│   ├── banner_grabber.py     # Read-only banners & HTTP HEAD helper
│   ├── risk_checker.py       # Severity-tagged posture findings model
│   └── report_generator.py   # Rich summary + disk writers
├── reports/                  # JSON/HTML artifacts (.gitignored; .gitkeep tracked)
├── templates/
│   └── report.html           # Lightweight HTML scaffold w/ placeholders
├── .github/workflows/ci.yml  # Smoke CI on Ubuntu (Python 3.10 / 3.13)
├── main.py                   # argparse driver + orchestration glue
├── requirements.txt          # pinned third-party deps (currently Rich)
├── README.md
├── SECURITY.md               # Responsibility + vuln-reporting posture
├── LICENSE                   # MIT
└── .gitignore
```

---

## Risk checker logic (overview)

Every finding includes **title**, **severity** (`Low`, `Medium`, `High`), **affected host**, **affected port** (nullable), **plain-language explanation**, and **recommended hardening**:

| Observation | Severity (typical) |
|-------------|---------------------|
| TCP 21 reachable | Medium |
| TCP 23 reachable | High |
| TCP 139/445 reachable together | High |
| TCP 3389 reachable | High |
| Known DB ports reachable (`3306`, `5432` in checklist) | High |
| Port 80 open while **443 was part of your scan scope** yet remains closed | Medium |
| Open port lacked a recognizable banner fingerprint | Low |

Interpret severities **qualitatively**—they summarize attack-surface commonsense rather than validating active exploitation.

---

## Future improvements

Curated ideas aligned with defensive goals:

1. IPv6 equivalents with parallel address expansion controls.
2. Optional TLS-aware metadata (certificate expiry, SAN coverage) strictly over normal TLS handshakes.
3. Pluggable Nessus-compatible JSON or SARIF exporters for SOC demos.
4. Asyncio rewrite for gigantic host sets while respecting rate caps.
5. Configuration file presets for compliance frameworks (PCI, CIS) expressed as declarative YAML.

---

## Resume bullet ideas

Adapt these to truthful statements about **your contribution**:

- Implemented a threaded Python TCP perimeter inventory tool with JSON/HTML outputs suitable for auditors.
- Authored heuristic risk classifications for legacy cleartext services (FTP, Telnet), SMB/RDP exposure, database listeners, HTTP/TLS imbalance, and missing service banners.
- Hardened control flow against offline hosts/timeouts via defensive exception handling plus structured logging for portfolio demonstrations.

---

## Support & ethos

Issues in this educational repository boil down to two categories:

1. **Bugs/defects** in parsing, threading, reporting, or documentation—PRs/issues welcome in personal forks.
2. **Requests for offensive tooling**—out of scope; maintain aligned defensive enhancements only.

Lead with empathy, cite authorization, mentor newer analysts transparently—**that** is how this portfolio piece demonstrates professional maturity alongside technical skill.
