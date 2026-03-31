# Linux System Hardening & Security Audit Script

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
