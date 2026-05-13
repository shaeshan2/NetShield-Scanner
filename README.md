# NetShield Scanner

**NetShield Scanner** is a **defensive** network posture tool for **authorized testing only**. It inventories which common TCP ports accept connections using **explicit TCP connects** (`socket`), performs banner reads that **do not change remote service state**, applies a simple **risk rubric** for defenders, and exports **JSON**, **HTML**, **CSV**, plus a terminal summary via **Rich** with **scan metrics** and a **qualitative posture score**.

**Out of scope (not included nor intended):** exploitation, brute forcing, stealth scanning, evasion tactics, credential attacks (or any spraying or guessing), or other offensive tooling. Networking stays at benign connect time behavior comparable to **`telnet` / `nc` checks**, automated with threading and timeouts only.

---

## Features

- **IPv4 host or CIDR input:** expand `192.168.1.0/24` safely with the standard library `ipaddress` module.
- **Default defensive port checklist:** `21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080` (override via `--ports`).
- **Multithreaded TCP probes** using `concurrent.futures.ThreadPoolExecutor`.
- **Banner grabbing** via short, read only socket operations (plus a harmless `HEAD` probe for HTTP style ports).
- **Risk checker** with curated findings (FTP/Telnet/SMB/RDP/DB exposure patterns, HTTP/`HTTPS` posture hint, missing banners).
- **Reports:** timestamped **JSON**, **HTML**, and **CSV** under `reports/` (shared timestamp per run), Rich terminal summary including **scan metrics** and a **qualitative posture score**.
- **Resilient core:** malformed targets are rejected with a message; offline hosts do not crash the run.

---

## Enterprise use cases

Use NetShield Scanner only with **written authorization** and on **assets you may assess**. Typical defensive workflows:

- **Perimeter or segment inventory** before a change freeze: confirm which checklist ports answer on approved hosts.
- **Lab and golden image validation** after builds: compare listeners to an expected baseline.
- **Evidence for hardening tickets** export JSON, HTML, or CSV into GRC or ITSM tools your organization allows.
- **Dockerized CI or jump host runs** repeat the same scan with pinned images and volume mounted `reports/` for audit trails.

---

## Scan metrics

Each run records **duration**, **hosts scanned**, **ports per host**, **total probes** (hosts × ports), **open ports found**, **findings count**, and **severity counts** (High, Medium, Low). These appear in the terminal summary, in `scan_metrics` inside the JSON payload, in the HTML **Scan metrics** table, and as repeated columns on CSV rows for spreadsheet pivots.

---

## Risk scoring

The tool computes a **posture score from 0 to 10** by summing **3 points per High**, **2 per Medium**, and **1 per Low** finding, then **capping at 10**. The **posture band** is **Low** for scores 0–3, **Medium** for 4–6, and **High** for 7–10. This is a **qualitative rubric** for triage and reporting; it is **not** CVSS, not exploit proof, and not a substitute for a full risk program.

---

## Security findings matrix

The HTML report includes a **findings matrix** (host, port, severity, title) for quick triage, plus the full **defensive posture notes** table with explanations and recommendations. The JSON `findings` array remains the machine readable source of truth for integrations.

---

## CSV export

`reports/netshield_scan_YYYYMMDD_HHMMSS.csv` lists one row per finding with **host**, **port**, **service or banner** (best effort from the scan), **finding title**, **severity**, **explanation**, **recommendation**, and repeated **scan level** columns (duration, probe counts, posture score and band). If no findings are emitted, a single summary row explains that case. The terminal footer prints the CSV path next to JSON and HTML.

---

## Ethical use disclaimer

NetShield Scanner produces **network traffic** (TCP connection attempts). Direct it **only**:

- Toward hosts and networks inside **scopes you own** or are **contractually permitted** to assess, **and**
- In ways consistent with applicable laws and organizational policies.

**Unauthorized scanning is unethical and illegal in many jurisdictions.** If you need practice, prefer **explicitly sanctioned** environments (labs, VMs you control, deliberate vulnerable practice ranges with permission).

Nothing here helps you bypass firewalls covertly or attack third parties. You are responsible for lawful, authorized use only.

---

## Legal notice (not legal advice)

This repository distributes **portfolio / instructional code** related to benign TCP probing. Reading this section is **not** a substitute for professional legal counsel where you operate.

- **No warranty.** The maintainers disclaim warranties to the fullest extent permitted; software is shipped **“AS IS.”** Bugs, misconfigurations, and environment differences are yours to validate.
- **Your compliance.** You alone are responsible for complying with criminal law, contracts, ISP or campus or cloud acceptable use rules, workplace policy, export controls (if relevant), etc.
- **Third party forks and misuse.** This project teaches defensive inventory patterns. Anyone who repurposes code for unlawful access or unauthorized probing acts on their own. **That misuse is outside the authors’ reasonable control**, just as with spreadsheets, compilers, or any general purpose tooling.
- **Scan artifacts.** Logs and HTML and JSON reports can contain banners or IPs; keep them internal (`.gitignore` helps keep them **out** of Git; recheck before every `push`).

If you need definitive answers for employment, coursework, penetration test contracts, international travel, or regulatory regimes, consult a lawyer qualified in **your jurisdiction**.

---

## License

This repository is licensed under the [MIT License](LICENSE). Dependencies (currently **[Rich](https://github.com/Textualize/rich)**) carry their own terms on PyPI.

---

## Installation

Requirements: **Python 3.10+** (uses modern union types like `list[str]`).

```bash
cd /path/to/your-clone
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
# .venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
```

No third party binaries are required; the scanner uses `socket` from the Python standard library and `rich` for prettier terminal output only.

---

## Docker usage

The image is based on **`python:3.12-slim-bookworm`** with dependencies from **`requirements.txt`**. The process runs **without root privileges** (`netshield` user). Use Docker **only** for **authorized** defensive inventories; the same [**Ethical use disclaimer**](#ethical-use-disclaimer) applies.

From the repository root:

```bash
docker build -t netshield-scanner .
```

```bash
mkdir -p reports
docker run --rm -v "$(pwd)/reports:/app/reports" netshield-scanner --target 127.0.0.1
```

```bash
mkdir -p reports
docker compose run --rm scanner --target 127.0.0.1
```

Optional flags (`--ports`, `--workers`, `--timeout`) work the same as native Python. Artifacts (**JSON**, **HTML**, **CSV**) land in `./reports/` on the host. If writes fail with **Permission denied**, make `reports/` writable for UID **65532** or use `chmod go+w reports` for local labs.

**Networking note:** `--target 127.0.0.1` from a default bridge container probes **inside the container**, not your physical host. To inventory the **Docker host**, use an explicit reachable IP for a lab or LAN you control, or on **Linux** add `--network host` to reach host listeners (**authorized** targets only).

---

## Docker validation

Docker support was checked by building the image successfully, running NetShield Scanner inside a container, persisting **JSON**, **HTML**, and **CSV** to the host `reports/` directory through a mounted volume, and invoking the scanner with Docker Compose. All checks were done in a defensive, authorized context.

![Docker build success](docs/screenshots/docker-build-success.png)

![Docker image created](docs/screenshots/docker-image-created.png)

![Docker run basic](docs/screenshots/docker-run-basic.png)

![Docker volume reports](docs/screenshots/docker-volume-reports.png)

![Docker Compose run](docs/screenshots/docker-compose-run.png)

---

## Usage

Always run commands from the repository root (the folder that contains `scanner/` and `main.py`).

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

# Tighten or loosen per port timeouts (seconds, default ~1.5)
python main.py --target 127.0.0.1 --timeout 1.2
```

### Outputs

Every successful run emits:

- **JSON:** `reports/netshield_scan_YYYYMMDD_HHMMSS.json` (includes `scan_metrics` and `risk_assessment`)
- **HTML:** `reports/netshield_report_YYYYMMDD_HHMMSS.html` (executive summary, metrics, matrix, remediation checklist)
- **CSV:** `reports/netshield_scan_YYYYMMDD_HHMMSS.csv` (findings plus scan context columns; same timestamp stem as JSON)
- **Terminal digest:** Rich tables (metrics, posture score, findings, paths)

Open the `.html` file in any browser. Use `.json` for automation and `.csv` for spreadsheets your policy allows.

---

## Sample terminal output

```
Starting NetShield scan...
Hosts to probe: 1; checklist ports per host: 15

Host [1/1]: 127.0.0.1

Probe complete: open TCP: 443

********************************************************************
  NetShield Scanner v1.0.0
  Authorized defensive assessment only.
********************************************************************

... Rich tables summarize severities & hosts ...

JSON report: /path/to/your-clone/reports/netshield_scan_20260501_120000.json
HTML report: /path/to/your-clone/reports/netshield_report_20260501_120000.html
CSV report: /path/to/your-clone/reports/netshield_scan_20260501_120000.csv
```

Your exact wording will mirror whatever services were reachable from your workstation.

---

## Lab validation

NetShield Scanner was exercised in an **authorized Ubuntu lab VM** (UTM on macOS) against **`127.0.0.1`**, with services correlated using **`sudo ss -tulnp`**. Screenshots and measured numbers live under **Measured results** and **Screenshots** below. This validation proves defensive inventory behavior only, not exploitation.

---

## Measured results (lab snapshot)

Representative validated run against **`127.0.0.1`** with the default **15 port** checklist:

- **Hosts scanned:** 1 (`127.0.0.1`)
- **TCP ports in checklist:** 15
- **Open checklist ports detected:** 5
- **Listening services (identifiers):** FTP (21), SSH (22), Telnet (23), HTTP (80), MySQL (3306)
- **Generated findings:** 5 (`2 × High`, `2 × Medium`, `1 × Low`)
- **Report formats:** JSON, HTML, and CSV
- **OS validation command:** `sudo ss -tulnp`

These numbers reflect **that lab snapshot** only; repeat runs depend on what is genuinely listening.

---

## Screenshots

Evidence images live under **`docs/screenshots/`**. Omit committing raw scan reports if they contain banners or fingerprints you prefer not to share.

### 1. Ubuntu services / environment

Listening services, network context (`ip a`), or tooling such as **`sudo ss -tulnp`** showing expected daemons consistent with scanner output.

![IP of VM](docs/screenshots/ip-of-vm.png)

### 2. Targeted scan (terminal)

Example: run with **`--ports`** narrowed to confirm specific services (narrow scope, faster iterations).

![Targeted Scan Terminal](docs/screenshots/targeted-scan-terminal.png)

### 3. Full default checklist scan (terminal)

Default **15 port** run against **`127.0.0.1`** including Rich severity summary and report paths under `reports/`.

![Open ports on VM](docs/screenshots/open-ports-on-vm.png)

### 4. HTML report

Browser view of `reports/netshield_report_*.html` (open ports, banners snapshot, defensive notes).

![HTML Report](docs/screenshots/html-report.png)

### 5. JSON report

Structured artifact `reports/netshield_scan_*.json` (scanner metadata, ports, banners, findings).

![JSON Report](docs/screenshots/json-report.png)

---

## Resume highlights

Bullets you can adapt; keep them truthful to what you ran and shipped:

- Delivered a **defensive** TCP inventory CLI with **JSON, HTML, and CSV** exports, **scan metrics**, and a **capped posture score** for stakeholder ready summaries, validated in an **authorized lab** (UTM Ubuntu, `127.0.0.1`, `ss` correlation).
- Extended reporting with an **executive summary**, **findings matrix**, **remediation checklist**, and **Docker** packaging for repeatable, non root container runs with **volume mounted** `reports/`.

---

## Project layout recap

```
project/
  docs/
    screenshots/           (optional README evidence images)
  scanner/
    __init__.py
    port_scanner.py
    banner_grabber.py
    risk_checker.py
    scan_metrics.py
    report_generator.py
  reports/                 (JSON and HTML artifacts; gitignored except .gitkeep)
  templates/
    report.html
  Dockerfile
  docker-compose.yml
  .dockerignore
  .github/workflows/ci.yml
  main.py
  requirements.txt
  README.md
  SECURITY.md
  LICENSE
  .gitignore
```

---

## Risk checker logic (overview)

Every finding includes **title**, **severity** (`Low`, `Medium`, `High`), **affected host**, **affected port** (nullable), **plain language explanation**, and **recommended hardening**:

- TCP 21 reachable: **Medium** (typical)
- TCP 23 reachable: **High**
- TCP 139 and 445 reachable together: **High**
- TCP 3389 reachable: **High**
- Known DB ports reachable (`3306`, `5432` in checklist): **High**
- Port 80 open while **443 was part of your scan scope** yet stays closed: **Medium**
- Open port lacked a recognizable banner fingerprint: **Low**

Interpret severities **qualitatively**; they summarize attack surface sense rather than validating active exploitation.

---

## Support and ethos

Issues in this educational repository boil down to two categories:

1. **Bugs or defects** in parsing, threading, reporting, or documentation (PRs and issues welcome in personal forks).
2. **Requests for offensive tooling:** out of scope; maintain aligned defensive enhancements only.

Lead with empathy, cite authorization, mentor newer analysts transparently. **That** is how this portfolio piece demonstrates professional maturity alongside technical skill.
