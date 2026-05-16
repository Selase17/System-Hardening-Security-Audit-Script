# Linux System Hardening & Security Audit Script

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25.svg?logo=gnubash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624.svg?logo=linux&logoColor=black)
![Status](https://img.shields.io/badge/Status-Stable-success.svg)

A Bash script that audits a Linux system against common security hardening checks and produces a scored report.

## What It Checks

| # | Check | Tool/File |
|---|-------|-----------|
| 1 | SSH hardening (root login, password auth, port) | `/etc/ssh/sshd_config` |
| 2 | Firewall status | `ufw` / `iptables` |
| 3 | SUID / SGID file count | `find` |
| 4 | World-writable files | `find` |
| 5 | Automatic security updates | `unattended-upgrades` |
| 6 | Accounts with empty passwords | `/etc/shadow` |

## Usage

```bash
sudo bash security_audit.sh
```

> Root privileges are required for `/etc/shadow` and full filesystem scans.

## Output

- Colour-coded terminal output — `[PASS]`, `[FAIL]`, `[WARN]`
- A plain-text report saved as `security_audit_YYYYMMDD.txt`
- A final security score (`PASS / TOTAL * 100`)

## Requirements

- Debian/Ubuntu-based Linux (uses `dpkg`, `ufw`)
- `bash`, `awk`, `find`, `bc`


## What I Learned

Writing this audit tool pushed me deeper into the practical mechanics of Linux security configuration:

- **Security audits live or die by their scoring rubric.** Listing 50 findings without prioritisation just produces noise. Designing a weighted scoring system — where a wide-open SSH config costs more points than a missing motd banner — taught me that the *interpretation* of findings is what makes an audit useful, not the raw checks themselves.

- **`/etc/ssh/sshd_config` parsing is fiddlier than it looks.** Directives can be commented, duplicated, or overridden by `Match` blocks. Reading the file line-by-line with `grep` misses the override semantics — I had to think about which directive *actually wins* at runtime, not which one appears in the file.

- **File permission auditing requires real care.** A 644 on `/etc/shadow` is critical; a 644 on `/etc/passwd` is fine. The same number means different things on different files. Encoding that context into the check logic forced me to actually understand the Linux permission model rather than just check raw octal values.

- **Idempotent checks are essential.** The script should produce the same report on identical systems, regardless of when or how often it's run. That meant being careful with anything time-sensitive (last login dates, package age) and surfacing those as informational rather than scored findings.

- **Reports must be both human- and machine-readable.** A colour-coded summary is great for an admin running it interactively, but if you want to wire this into CI or central log aggregation, it needs structured output too. Designing for both audiences upfront was cheaper than retrofitting.

- **The biggest security wins are usually configuration, not patching.** Most of the high-severity findings I wrote checks for aren't "outdated software" — they're misconfigurations that ship by default. That changed how I think about security work generally: lock down what you have before chasing CVEs.


## Production Hardening Checklist

This tool is a focused single-host audit. For production-grade security tooling, the following would need to be added:

- [ ] Structured output mode (JSON or SARIF) for ingestion into SIEM platforms or CI pipelines
- [ ] Differential mode — compare two audit runs and report only changes (useful for drift detection)
- [ ] Fleet mode — run audits across many hosts via SSH or pulled from a central server
- [ ] Configurable rule severity per organisation (what's critical to one team may not be to another)
- [ ] Whitelist / exemption mechanism for accepted risks, with justification recorded
- [ ] Integration with established standards (CIS Benchmarks, STIGs, ISO 27001 control mappings)
- [ ] Auto-remediation mode for low-risk findings (with dry-run and rollback)
- [ ] Continuous mode — run as a systemd timer or cron, ship reports to central storage
- [ ] At fleet scale, this pattern is replaced by tools like OpenSCAP, Lynis, or Wazuh — which is the right call for serious compliance work