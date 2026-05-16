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

Full audit (recommended):

```bash
sudo bash security_audit.sh
```

Partial audit without root:

```bash
bash security_audit.sh
```

When run without root, the script detects insufficient privilege at startup and gracefully skips checks that require it (UFW status, `/etc/shadow` read). These appear as `[SKIP]` entries in the report with a clear explanation, rather than misleading failures. Run with `sudo` for full coverage.


## Output

- Colour-coded terminal output — `[PASS]`, `[FAIL]`, `[WARN]`
- A plain-text report saved as `security_audit_YYYYMMDD.txt`
- A final security score (`PASS / TOTAL * 100`)

## Requirements

- Debian/Ubuntu-based Linux (uses `dpkg`, `ufw`)
- `bash`, `awk`, `find`, `bc`


## What I Learned

Writing — and then actually running — this audit tool pushed me through several lessons that surprised me:

- **Audit tools need three result states, not two.** The first version had only PASS/FAIL. When I ran it without root, the firewall check reported a misleading FAIL because `ufw status` requires root and returned nothing. Adding an explicit SKIP state (with privilege detection at startup) means the tool can now honestly say *"I couldn't verify this"* rather than guessing wrong. That distinction matters in security work.

- **The same finding has different severity on different systems.** Running the tool on my own machine surfaced "world-writable files" findings — but some were real (Minikube installed certs with 777 perms; I fixed with `chmod 600/644`), and others were false positives from WSL exposing Windows-mounted paths as POSIX-777. Taught me that audit findings need context, not just counts.

- **Idempotency in output files is non-trivial.** The first version used `>> "$REPORT"` everywhere, which meant repeated runs in the same day appended to the existing file forever. Fixing this took only one character change (`>` instead of `>>` at the start), but discovering the bug required actually running the tool repeatedly and watching the file grow. *Use your own tools.*

- **Filter known false positives explicitly, with comments.** I added `/init`, `/mnt`, `/proc`, `/sys`, and `/run` to the world-writable scan exclusion list, each with a comment explaining why. A tool that flags `/init` as a security issue on every WSL system trains its user to ignore findings — and a security tool whose findings get ignored is worse than no tool at all.

- **Reports must be self-contained.** The summary was originally only printed to terminal — never written to the report file. Anyone reading the saved report would see findings but no totals or score. Writing the summary block to both terminal and file made the saved report usable as a standalone artefact for someone reviewing later.

- **The biggest security wins are usually configuration, not patching.** Most of the high-severity findings this tool checks for aren't "outdated software" — they're misconfigurations that ship by default. That reframed how I think about security work: lock down what you already have before chasing CVEs.


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