# NetShield Scanner

**Defensive TCP posture inventory for authorized scopes only.** Python **3.10+** tool: expand **IPv4** hosts or **CIDR**, probe a configurable checklist with **threaded TCP connects** (`socket`), collect **non-destructive** banners, classify posture with a **severity rubric**, and emit **JSON**, **HTML**, **CSV**, plus a **Rich** terminal summary with **scan metrics** and a **qualitative score (0–10)**.

**Not in scope:** exploitation, brute forcing, stealth or evasion scanning, credential attacks, payloads, or offensive workflows. Traffic is comparable to manual **`telnet` / `nc`** style checks, automated with timeouts and concurrency caps.

---

## Ethical use disclaimer

NetShield Scanner produces **network traffic** (TCP connection attempts). Use it **only** on hosts and networks you **own** or are **contractually permitted** to assess, in line with law and policy.

**Unauthorized scanning is unethical and illegal in many jurisdictions.** For practice, use labs, VMs you control, or ranges where you have **explicit permission**.

This software does not help bypass controls or target third parties without authorization. **You** are responsible for lawful use.

---

## At a glance

| Topic | Detail |
|--------|--------|
| **Default checklist** | 15 TCP ports: `21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080` (override with `--ports`) |
| **Artifacts** | `reports/netshield_scan_*.json`, `netshield_report_*.html`, `netshield_scan_*.csv` (same run timestamp) |
| **Scan metrics** | Duration, hosts scanned, ports per host, total probes, open ports found, findings count, severity counts (`scan_metrics` in JSON; tables in HTML and terminal; repeated columns in CSV) |
| **Posture score** | Sum **3** (High) + **2** (Medium) + **1** (Low) per finding, **cap 10**; band **Low** 0–3, **Medium** 4–6, **High** 7–10. **Not** CVSS or exploit validation. |
| **HTML report** | Executive summary, metrics, severity breakdown, risk card, findings matrix, detailed findings, deduplicated remediation list |

**CSV:** one row per finding (host, port, banner, title, severity, explanation, recommendation) plus repeated scan level columns for spreadsheets. **JSON:** full `hosts`, `findings`, `scan_metrics`, `risk_assessment`.

---

## Enterprise use cases

With **written authorization** only: perimeter or segment inventory before change windows; golden image or lab VM checks against an expected listener set; export **JSON / HTML / CSV** into GRC or ITSM where policy allows; repeatable **Docker** runs with bind mounted `reports/` for audit trails.

---

## Quick start

```bash
cd /path/to/your-clone
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

```bash
python main.py --target 127.0.0.1
python main.py --target 192.168.1.0/24
python main.py --target 10.0.0.5 --ports 22,80,443 --workers 120 --timeout 1.5
```

Larger CIDR ranges multiply probes (**hosts × ports**). Use restraint on shared networks.

---

## Docker

Image: **`python:3.12-slim-bookworm`**, non root **`netshield`** user (UID **65532**). Same CLI flags as local Python. Mount **`./reports`** so JSON, HTML, and CSV persist on the host. If writes fail, `chmod go+w reports` or align ownership with UID **65532** for lab use.

```bash
docker build -t netshield-scanner .
docker run --rm -v "$(pwd)/reports:/app/reports" netshield-scanner --target 127.0.0.1
docker compose run --rm scanner --target 127.0.0.1
```

**Bridge networking:** `--target 127.0.0.1` inside a default bridge container hits the **container** loopback, not the physical host. For the Docker host or LAN assets you control, use a reachable IP or, on Linux, **`--network host`** (still **authorized** targets only).

---

## Lab validation

Validated in an **authorized Ubuntu VM** (UTM on macOS) against **`127.0.0.1`**, with listeners cross checked using **`sudo ss -tulnp`**. Representative snapshot: **15** checklist ports, **5** opens (FTP **21**, SSH **22**, Telnet **23**, HTTP **80**, MySQL **3306**), **5** findings (**2** High, **2** Medium, **1** Low), all three report formats plus metrics and posture score. Reproducibility depends on what is actually listening; this documents **defensive inventory**, not exploitation.

---

## Evidence gallery

Screenshots under **`docs/screenshots/`** (omit sensitive banners from public commits).

![HTML report](docs/screenshots/html-report.png)

![Open ports on VM](docs/screenshots/open-ports-on-vm.png)

![JSON report](docs/screenshots/json-report.png)

![Docker Compose run](docs/screenshots/docker-compose-run.png)

![IP of VM](docs/screenshots/ip-of-vm.png)

---

## Risk checker rubric (summary)

Findings carry **title**, **severity**, **host**, **port** (optional), **explanation**, **recommendation**. Typical mapping: cleartext legacy services and exposed DB or RDP listeners trend **High**; FTP and HTTP without HTTPS in scope trend **Medium**; weak or missing banners trend **Low**. Severities are **qualitative** posture hints, not proof of compromise.

---

## Legal notice (not legal advice)

Portfolio code for benign TCP probing. **No warranty** (software **as is**). **Your** duty: laws, contracts, acceptable use, workplace rules, export controls as applicable. **Misuse** by third parties is outside reasonable maintainer control. **Scan artifacts** may contain sensitive data; keep them internal and out of Git (see `.gitignore`). For binding guidance, consult counsel in **your jurisdiction**.

---

## License

[MIT License](LICENSE). Third party deps (e.g. **[Rich](https://github.com/Textualize/rich)**) follow their own licenses.

Continuous integration (`.github/workflows/ci.yml`) runs **compileall**, **`--help`**, and a minimal localhost probe on Ubuntu. See **[SECURITY.md](SECURITY.md)** for vulnerability reporting expectations.

---

## Project layout

```
project/
  scanner/          port_scanner, banner_grabber, risk_checker, scan_metrics, report_generator
  templates/        report.html
  reports/          generated artifacts (gitignored except .gitkeep)
  main.py
  Dockerfile, docker-compose.yml, .dockerignore
  .github/workflows/ci.yml
  requirements.txt, README.md, SECURITY.md, LICENSE
```

---

## Support and ethos

**Bugs / docs improvements:** welcome in forks via issues or PRs. **Requests for offensive features:** out of scope. Prefer clear authorization, proportionate tooling, and transparent mentoring when sharing defensive practice.
