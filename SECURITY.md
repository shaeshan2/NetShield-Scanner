# Security considerations

NetShield Scanner is **defensive** tooling for **explicitly authorized** inventories.

**In-scope behavior:** benign IPv4 TCP `connect()` probing, bounded-time reads for
possible banners / HTTP `HEAD` hints, heuristic risk summaries, reporting.

**Explicitly out of scope (upstream will not pursue):**

- Exploitation, weaponized payloads, or post-exploit tooling
- Credential guessing, brute forcing, spraying, stuffing, cracking, MFA bypass themes
- Stealth SYN / half-open / spoofed-origin scanning, fragmentation tricks, covert channels
- Evasion tactics against IDS/IPS/WAF/logging (rate shaping to hide probes, malformed packets to confuse sensors, etc.)
- Denial-of-service or abusive resource exhaustion workflows

Anything that repurposes forks for the above stays outside maintainers’ endorsement.

## Using this responsibly

Use it **only** on systems and networks where you have **explicit permission**
(written authorization, lab policy, cloud tenant you administer, VM you own, etc.)

If someone misuses forks or clones against third parties without authorization:

- That conduct violates **law** or **computer-use policies** independently of anything written here or in the README.
- Automated probes can produce **SOC** / firewall evidence even when payloads are benign.

Maintainership of **this upstream repository does not supervise downstream users.** Security reports here should focus on vulnerabilities **in NetShield Scanner’s own code**.

## Reporting vulnerabilities **in NetShield Scanner itself**

Found a flaw in **this codebase** that could materially harm users (e.g. unsafe deserialization,
dangerous subprocess use, unintended remote behavior)? Email the maintainer or open an issue
according to repo policy describing:

- Steps to reproduce
- Severity / impact hypothesis
- Suggested mitigation (optional)

Avoid posting working exploit harnesses publicly before a coordinated fix unless you have no safer channel.
