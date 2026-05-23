#!/usr/bin/env bash

set -euo pipefail

# --Configuration-------------------------------------------------------------
NT_HOME="/var/lib/network-telescope"
DATA_DIR="${NT_HOME}/data"
RAW_DIR="${DATA_DIR}/raw"
CONF_DIR="/etc/network-telescope"
ENV_FILE="${CONF_DIR}/capturing-node.env"

NT_USER="nt-capture"
NT_GROUP="nt-capture"

# --Helpers-------------------------------------------------------------------
log()  { echo "[*] $*"; }
warn() { echo -e "\033[1;33m[i]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
err()  { echo -e "\033[1;31m[x]\033[0m $*"; }
require_root() {
    if [[ $EUID -ne 0 ]]; then
       err "This script must be run as root (use sudo)."
       exit 1
    fi
 }
require_root

ERRORS=0

check_or_start_service() {
    local svc="$1"
    if systemctl is-active --quiet "${svc}"; then
        ok "${svc} is running"
    else
        warn "${svc} is not running - starting..."
        systemctl start "${svc}" && ok "${svc} started" || { err "Could not start ${svc}"; ERRORS=$(( ERRORS + 1 )); }
    fi
}

# --env file------------------------------------------------------------------
log "Capturing Node Check"
echo ""

if [[ -f "${ENV_FILE}" ]]; then
    ok "Environment file found: ${ENV_FILE}"
    set -a; source "${ENV_FILE}"; set +a
else
    err "Environment file missing: ${ENV_FILE} - run setup.sh first"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Capture directory---------------------------------------------------------
if [[ -d "${RAW_DIR}" ]]; then
    AVAIL_KB=$(df -k "${RAW_DIR}" | awk 'NR==2 {print $4}')
    AVAIL_GB=$(( AVAIL_KB / 1024 / 1024 ))
    if [[ ${AVAIL_GB} -lt 5 ]]; then
        err "Low disk space: ${AVAIL_GB}GB available in ${RAW_DIR}"
        ERRORS=$(( ERRORS + 1 ))
    else
        ok "Disk space OK: ${AVAIL_GB}GB available"
    fi
else
    err "Capture directory missing: ${RAW_DIR}"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Interface-----------------------------------------------------------------
IFACE="${INTERFACE:-UNSET}"
if [[ "${IFACE}" == "UNSET" || "${IFACE}" == "CHANGE_ME" ]]; then
    err "INTERFACE not set in ${ENV_FILE}"
    ERRORS=$(( ERRORS + 1 ))
elif ip link show "${IFACE}" &>/dev/null; then
    STATE=$(ip link show "${IFACE}" | grep -oP '(?<=state )\w+' || echo "UNKNOWN")
    ok "Interface ${IFACE} exists (state: ${STATE})"
else
    err "Interface ${IFACE} not found on this machine"
    ERRORS=$(( ERRORS + 1 ))
fi

# --SSH connectivity----------------------------------------------------------
REMOTE="${REMOTE_HOST:-}"
if [[ -n "${REMOTE}" && "${REMOTE}" != "CHANGE_ME" ]]; then
    SSH_KEY="${SSH_KEY_PATH:-/var/lib/network-telescope/.ssh/id_ed25519}"
    if ssh -i "${SSH_KEY}" -o ConnectTimeout=5 -o BatchMode=yes \
           "${REMOTE_USER:-telescope}@${REMOTE}" "echo ok" &>/dev/null; then
        ok "SSH to processing node (${REMOTE}) OK"
    else
        err "Cannot SSH to processing node (${REMOTE}) - check key and REMOTE_HOST"
        ERRORS=$(( ERRORS + 1 ))
    fi
else
    warn "REMOTE_HOST not set - skipping SSH check (local mode?)"
fi

# --Services------------------------------------------------------------------
echo ""
check_or_start_service nt-capture
check_or_start_service nt-file-detector
check_or_start_service prometheus-node-exporter

# --dumpcap process check-----------------------------------------------------
if pgrep -x dumpcap &>/dev/null; then
    PCAP_PID=$(pgrep -x dumpcap)
    ok "dumpcap is running (PID: ${PCAP_PID})"
    # Check recent file creation
    LATEST=$(find "${RAW_DIR}" -name "*.pcap" -newer "${RAW_DIR}" -printf '%T@ %p\n' 2>/dev/null \
             | sort -n | tail -1 | awk '{print $2}')
    if [[ -n "${LATEST}" ]]; then
        ok "Latest pcap: $(basename "${LATEST}")"
    else
        warn "No .pcap files found yet in ${RAW_DIR}"
    fi
else
    err "dumpcap process not found"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Summary-------------------------------------------------------------------
echo ""
if [[ ${ERRORS} -eq 0 ]]; then
    ok "All checks passed. Node is healthy and running."
else
    err "${ERRORS} check(s) errored. Review errors above."
fi