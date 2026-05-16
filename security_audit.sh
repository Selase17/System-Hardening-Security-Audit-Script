#!/bin/bash
# security_audit.sh — Linux Security Hardening Audit

# ── COLOURS for readable output ──────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'   # No Color — resets to default

PASS=0
FAIL=0
WARN=0
SKIPPED=0
REPORT="security_audit_$(date +%Y%m%d).txt"

# ── Detect privilege level ──────────────────────────────
# Some checks (UFW status, /etc/shadow read, full /etc/ssh access) require root.
# We don't refuse to run as a non-root user — that would block partial audits.
# Instead we set a flag and skip privileged checks gracefully with a clear note.
if [ "$(id -u)" -eq 0 ]; then
    RUN_AS_ROOT=true
else
    RUN_AS_ROOT=false
fi

# ── Initialise report file ───────────────────────────────
# Truncate (or create) the report file at the start of each run.
# Using a single `>` here resets the file. All subsequent writes use `>>`
# which appends to *this* run's report, not stale ones.
HOSTNAME_LABEL="$(hostname 2>/dev/null || echo unknown-host)"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

if [ "$RUN_AS_ROOT" = true ]; then
    PRIVILEGE_LABEL='root'
else
    PRIVILEGE_LABEL='non-root (partial audit)'
fi

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  System Hardening & Security Audit Report"
    echo "  Generated: $TIMESTAMP  ·  Host: $HOSTNAME_LABEL"
    echo "  Privilege: $PRIVILEGE_LABEL"
    echo "═══════════════════════════════════════════════════════════════"
} > "$REPORT"

# ── Helper Functions ─────────────────────────────────────
pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "[PASS] $1" >> "$REPORT"
    ((PASS++))
}
fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "[FAIL] $1" >> "$REPORT"
    ((FAIL++))
}
warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[WARN] $1" >> "$REPORT"
    ((WARN++))
}
skip() {
    # SKIP is used when a check can't run due to insufficient privilege.
    # It's distinct from WARN because the *system* hasn't necessarily failed —
    # we just couldn't verify. Surfacing this honestly is more useful than guessing.
    echo -e "${BLUE}[SKIP]${NC} $1"
    echo "[SKIP] $1" >> "$REPORT"
    ((SKIPPED++))
}
section() {
    echo -e "\n${BLUE}══ $1 ══${NC}"
    echo "" >> "$REPORT"
    echo "══ $1 ══" >> "$REPORT"
}

# ── Warn at start if running without root ────────────────
if [ "$RUN_AS_ROOT" = false ]; then
    echo -e "${YELLOW}WARNING:${NC} Running as non-root user."
    echo "         Privileged checks (UFW, /etc/shadow) will be skipped."
    echo "         For a full audit, run: sudo bash $0"
    echo ""
fi

# ── Check 1: SSH Hardening ────────────────────────────────
section 'SSH Configuration'
SSH_CONFIG="/etc/ssh/sshd_config"

# /etc/ssh/sshd_config is world-readable on most systems, so non-root can audit it.
# But we still check the file exists before parsing.
if [ ! -r "$SSH_CONFIG" ]; then
    skip "SSH config not readable at $SSH_CONFIG"
else
    # Root should NEVER be able to SSH in directly
    # If root is compromised, attackers get full control immediately
    if grep -qE '^PermitRootLogin (no|prohibit-password)' "$SSH_CONFIG"; then
        pass 'Root SSH login is disabled'
    else
        fail 'Root SSH login is ENABLED — run: echo "PermitRootLogin no" >> /etc/ssh/sshd_config'
    fi

    # Password auth should be off — SSH keys are far more secure
    if grep -qE '^PasswordAuthentication no' "$SSH_CONFIG"; then
        pass 'SSH password authentication is disabled (keys only)'
    else
        warn 'SSH password authentication is enabled — consider disabling it'
    fi

    # SSH should not run on default port 22 — reduces automated attack traffic
    SSH_PORT=$(grep -E '^Port' "$SSH_CONFIG" | awk '{print $2}')
    if [ -z "$SSH_PORT" ] || [ "$SSH_PORT" = '22' ]; then
        warn 'SSH is on default port 22 — consider changing it to reduce scan noise'
    else
        pass "SSH is running on non-default port: $SSH_PORT"
    fi
fi

# ── Check 2: Firewall ─────────────────────────────────────
section 'Firewall'

# UFW status requires root — ufw refuses to report state to non-root users.
# Without this guard, the script reports a misleading [FAIL] when run as a normal user.
if [ "$RUN_AS_ROOT" = false ]; then
    skip 'Firewall status check requires root privilege'
elif command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status | head -1 | awk '{print $2}')
    if [ "$UFW_STATUS" = 'active' ]; then
        pass 'UFW firewall is active'
    else
        fail 'UFW firewall is INACTIVE — run: ufw enable'
    fi
else
    warn 'UFW not installed — checking iptables'
    RULES=$(iptables -L 2>/dev/null | wc -l)
    if [ "$RULES" -gt 8 ]; then
        pass 'iptables rules are configured'
    else
        fail 'No firewall rules found'
    fi
fi

# ── Check 3: SUID/SGID Files ─────────────────────────────
section 'SUID / SGID Files'

# SUID (Set User ID) means the file runs as its OWNER, not the user running it.
# /bin/sudo is SUID — it runs as root even when a normal user calls it.
# Unexpected SUID files are a major attack vector — attackers plant them.
# `find / -perm -4000` works for normal users on world-readable directories,
# but will miss SUID files in directories only root can read.
# We note this caveat when running without root.
if [ "$RUN_AS_ROOT" = false ]; then
    warn 'Running without root — SUID scan may miss files in restricted directories'
fi

SUID_FILES=$(find / -xdev -type f -perm -4000 2>/dev/null | sort)
SUID_COUNT=$(echo "$SUID_FILES" | grep -c .)

# A safe baseline has around 10-20 SUID files
if [ "$SUID_COUNT" -lt 30 ]; then
    pass "SUID files count is reasonable: $SUID_COUNT files"
else
    warn "High number of SUID files: $SUID_COUNT — review them"
fi

echo '  SUID files found:' >> "$REPORT"
echo "$SUID_FILES" | while read -r f; do
    [ -n "$f" ] && echo "    $f" >> "$REPORT"
done

# ── Check 4: World-Writable Files ────────────────────────
section 'World-Writable Files'

# World-writable = any user on the system can modify the file
# This is dangerous — an attacker could modify scripts or configs.
# Exclude virtual/system paths that always appear world-writable due to filesystem
# semantics rather than real permissions issues:
#   /proc, /sys   — kernel virtual filesystems
#   /init         — WSL kernel-userspace bridge file
#   /mnt          — Windows drives mounted in WSL (NTFS doesn't model POSIX perms)
#   /run          — runtime tmpfs, recreated each boot
WW_FILES=$(find / -xdev -type f -perm -002 2>/dev/null \
    | grep -Ev '^(/proc|/sys|/init|/mnt|/run)')
WW_COUNT=$(echo "$WW_FILES" | grep -c . || true)

if [ "$WW_COUNT" -eq 0 ]; then
    pass 'No unexpected world-writable files found'
else
    fail "$WW_COUNT world-writable file(s) found — review immediately"
    echo "$WW_FILES" | head -20 | while read -r f; do
        [ -n "$f" ] && echo "  → $f" >> "$REPORT"
    done
fi

# ── Check 5: Unattended Upgrades ─────────────────────────
section 'Security Updates'

# Unpatched systems are the #1 cause of breaches.
# unattended-upgrades automatically installs security patches.
# `dpkg -l` is readable by anyone, so this check works without root.
if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    pass 'unattended-upgrades is installed'
else
    fail 'unattended-upgrades not installed — run: apt install unattended-upgrades'
fi

# ── Check 6: Empty Passwords ─────────────────────────────
section 'Password Security'

# /etc/shadow is mode 0640 and owned by root — non-root cannot read it.
# This is the single most privilege-sensitive check in the audit.
if [ "$RUN_AS_ROOT" = false ]; then
    skip '/etc/shadow not readable — empty password check requires root'
else
    EMPTY_PASS=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | grep -v '^$')
    if [ -z "$EMPTY_PASS" ]; then
        pass 'No accounts with empty/locked passwords found'
    else
        fail 'Accounts with empty/locked passwords:'
        echo "$EMPTY_PASS" | while read -r u; do
            echo "    $u" | tee -a "$REPORT"
        done
    fi
fi

# ── Final Score ───────────────────────────────────────────
TOTAL=$((PASS + FAIL + WARN))

# Guard against division by zero (would only happen if zero checks ran)
if [ "$TOTAL" -gt 0 ]; then
    SCORE=$(echo "scale=0; $PASS * 100 / $TOTAL" | bc)
else
    SCORE=0
fi

# Print to terminal AND append to report file using a single block.
{
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  AUDIT SUMMARY"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  [PASS]    $PASS"
    echo "  [WARN]    $WARN"
    echo "  [FAIL]    $FAIL"
    if [ "$SKIPPED" -gt 0 ]; then
        echo "  [SKIP]    $SKIPPED  (run as root for full coverage)"
    fi
    echo "  ─────────────────"
    echo "  Score     $SCORE / 100"
    echo "═══════════════════════════════════════════════════════════════"
} >> "$REPORT"

# Terminal output (with colours)
echo ""
echo -e "${BLUE}══ AUDIT COMPLETE ══${NC}"
echo "──────────────────────"
echo -e "${GREEN}PASS:  $PASS${NC}"
echo -e "${YELLOW}WARN:  $WARN${NC}"
echo -e "${RED}FAIL:  $FAIL${NC}"
if [ "$SKIPPED" -gt 0 ]; then
    echo -e "${BLUE}SKIP:  $SKIPPED${NC}  (run as root for full coverage)"
fi
echo "──────────────────────"
echo "Security Score: $SCORE / 100"
echo ""
echo "Full report saved to: $REPORT"