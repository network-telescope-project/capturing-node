#!/usr/bin/env bash

set -euo pipefail

# --Configuration-------------------------------------------------------------
NT_HOME="/var/lib/network-telescope"
DATA_DIR="${NT_HOME}/data"
RAW_DIR="${DATA_DIR}/raw"
CONF_DIR="/etc/network-telescope"
ENV_FILE="${CONF_DIR}/capturing-node.env"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
HELPERS_DIR="$(dirname "${SCRIPT_DIR}")/helpers"

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
    if ! systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
        err "${svc} is not enabled (would not come back after a reboot): systemctl enable ${svc}"
        ERRORS=$(( ERRORS + 1 ))
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

# --Clock---------------------------------------------------------------------
if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]]; then
    ok "Clock synchronised: $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
else
    warn "Clock is not synchronised by NTP and will slowly drift: $(date -u '+%Y-%m-%d %H:%M:%S') UTC (setup.sh sets it once)"
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

    RING="${RING_BUFFER_SIZE:-24}"
    if [[ "${RING}" -gt 0 ]]; then
        warn "Ring buffer: only the last ${RING} PCAP files are kept (1 per ${DURATION:-3600}s); older ones are deleted even if not yet transferred (if file transfer fails)."
        warn "  Set RING_BUFFER_SIZE in ${ENV_FILE} from this node's disk (${AVAIL_GB}GB free) and the expected MB per file."
    else
        warn "Ring buffer disabled (RING_BUFFER_SIZE=0): no file limit, the disk can fill up if transfers fail."
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

    # --Darknet destinations--------------------------------------------------
    if [[ -z "${DARKNET_NETS:-}" ]]; then
        if [[ "${TRANSFER_MODE:-local}" == "remote" ]]; then
            err "DARKNET_NETS is empty in ${ENV_FILE}: capture will not start (re-run setup.sh or set it by hand)"
            ERRORS=$(( ERRORS + 1 ))
        fi
    elif UNCOVERED=$(python3 "${HELPERS_DIR}/darknet.py" missing "${IFACE}" "${DARKNET_NETS}"); then
        ok "Capturing traffic to: ${DARKNET_NETS}"
        [[ -z "${UNCOVERED}" ]] || warn "Public address(es) on ${IFACE} not covered by DARKNET_NETS (not captured): ${UNCOVERED}"
    else
        err "DARKNET_NETS is invalid: ${DARKNET_NETS}"
        ERRORS=$(( ERRORS + 1 ))
    fi

    # --Packet merging (GRO/LRO)----------------------------------------------
    MERGING=$(ethtool -k "${IFACE}" 2>/dev/null | awk '$1 ~ /^(generic-receive-offload|large-receive-offload|rx-gro-hw):$/ && $2 == "on" {printf "%s ", $1}') || true
    if [[ -z "${MERGING}" ]]; then
        ok "Packet merging (GRO/LRO) is off on ${IFACE}"
    else
        warn "${IFACE} still merges packets before the capture, ${MERGING//:/} is on (systemctl restart nt-nic-tuning; journalctl -u nt-nic-tuning)"
    fi
else
    err "Interface ${IFACE} not found on this machine"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Management address and branches-------------------------------------------
BRANCHES_OK=0
if [[ -n "${DARKNET_NETS:-}" ]]; then
    [[ -n "${MGMT_ADDR:-}" ]] || warn "MGMT_ADDR is not set in ${ENV_FILE}: this node's own traffic is not kept out of the capture (re-run setup.sh)"
    if SUMMARY=$(python3 "${HELPERS_DIR}/branches.py" check "${DARKNET_NETS}" --mgmt "${MGMT_ADDR:-}" \
                     --irregular "${R_IRREGULAR_ADDRS:-}" --regular "${R_REGULAR_ADDRS:-}" 2>&1); then
        ok "Branches: ${SUMMARY}"
        BRANCHES_OK=1
        if [[ -n "${BRANCH_NETS:-}" ]] && ! python3 "${HELPERS_DIR}/darknet.py" same "${BRANCH_NETS}" "${DARKNET_NETS}"; then
            warn "DARKNET_NETS changed since the branches were drawn (for ${BRANCH_NETS}): any new address is passive"
        fi
    else
        err "Branches in ${ENV_FILE} are invalid: ${SUMMARY}"
        ERRORS=$(( ERRORS + 1 ))
    fi
fi

# --Tunnel to the processing node---------------------------------------------
WG_IF="wg-nt"
HANDSHAKE_MAX_AGE=180       # keepalive every 25 s; WireGuard renews the handshake every 2 min
REMOTE="${WG_REMOTE_ADDR:-}"
if [[ "${TRANSFER_MODE:-local}" == "remote" ]]; then
    if [[ -z "${REMOTE}" || -z "${WG_ADDR:-}" ]]; then
        err "Tunnel to the processing node not configured (WG_ADDR / WG_REMOTE_ADDR in ${ENV_FILE}) - re-run setup.sh"
        ERRORS=$(( ERRORS + 1 ))
    else
        echo ""
        if [[ "${WG_WRAPPER:-tcp}" == "tcp" ]]; then
            check_or_start_service nt-wstunnel
        fi
        check_or_start_service "wg-quick@${WG_IF}"
        LAST=$(wg show "${WG_IF}" latest-handshakes 2>/dev/null | awk '{print $2; exit}') || true
        for _ in $(seq 1 15); do       # just (re)started: give it a moment
            [[ "${LAST:-0}" -gt 0 ]] && break
            sleep 1
            LAST=$(wg show "${WG_IF}" latest-handshakes 2>/dev/null | awk '{print $2; exit}') || true
        done
        AGE=$(( $(date +%s) - ${LAST:-0} ))
        if [[ "${LAST:-0}" -eq 0 ]]; then
            HINT="'wg show ${WG_IF}'"
            [[ "${WG_WRAPPER:-tcp}" != "tcp" ]] || HINT="journalctl -u nt-wstunnel and ${HINT}"
            err "Tunnel: no handshake with the processing node (wrapper: ${WG_WRAPPER:-tcp}) - check ${HINT}"
            ERRORS=$(( ERRORS + 1 ))
        elif [[ ${AGE} -gt ${HANDSHAKE_MAX_AGE} ]]; then
            err "Tunnel: last handshake ${AGE} s ago - the processing node or the path to it is down"
            ERRORS=$(( ERRORS + 1 ))
        else
            ok "Tunnel: ${WG_ADDR} <-> ${REMOTE} up (handshake ${AGE} s ago, wrapper: ${WG_WRAPPER:-tcp})"
        fi
    fi
fi

# --SSH connectivity (through the tunnel)-------------------------------------
if [[ -n "${REMOTE}" ]]; then
    SSH_KEY="${SSH_KEY_PATH:-/var/lib/network-telescope/.ssh/id_ed25519}"
    KNOWN_HOSTS="${SSH_KEY%/*}/known_hosts"
    PORT="${REMOTE_PORT:-8500}"
    if ! ssh-keygen -F "[${REMOTE}]:${PORT}" -f "${KNOWN_HOSTS}" &>/dev/null; then
        err "Processing node host key is not pinned in ${KNOWN_HOSTS} - re-run setup.sh once the node is registered there"
        ERRORS=$(( ERRORS + 1 ))
    elif sudo -u ${NT_USER} rsync -rn --exclude='*' \
           -e "ssh -i ${SSH_KEY} -p ${PORT} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${KNOWN_HOSTS} -o ConnectTimeout=5" \
           "${RAW_DIR}/" "${REMOTE_USER:-telescope}@${REMOTE}:." &>/dev/null; then
        ok "Delivery to processing node (${REMOTE}:${PORT}) OK"
    else
        err "Cannot deliver to processing node (${REMOTE}:${PORT}) - is the tunnel up and was add-sensor.sh run there with this node's keys?"
        ERRORS=$(( ERRORS + 1 ))
    fi
else
    warn "No tunnel configured - skipping the delivery check (local mode?)"
fi

# --Services------------------------------------------------------------------
echo ""
check_or_start_service nt-nic-tuning
check_or_start_service nt-file-detector
check_or_start_service nt-capture
check_or_start_service nt-sweep.timer
check_or_start_service nt-metrics.timer
check_or_start_service prometheus-node-exporter

systemctl start nt-metrics.service || true
if [[ "$(curl -s --max-time 5 http://127.0.0.1:9100/metrics)" == *nt_capture_running* ]]; then
    ok "node-exporter answers, with this node's own metrics"
else
    err "node-exporter (port 9100) does not answer or has no nt_* metrics - journalctl -u nt-metrics -u prometheus-node-exporter"
    ERRORS=$(( ERRORS + 1 ))
fi

# --Firewall------------------------------------------------------------------
if [[ "${TRANSFER_MODE:-local}" == "remote" ]]; then
    if [[ "$(ufw status 2>/dev/null)" == "Status: active"* ]]; then
        ok "Firewall active"
    else
        err "Firewall is not active - run setup.sh"
        ERRORS=$(( ERRORS + 1 ))
    fi
fi

# --Branch assignment for the processing node---------------------------------
if [[ ${BRANCHES_OK} -eq 1 && "${TRANSFER_MODE:-local}" == "remote" && -d "${RAW_DIR}" ]]; then
    if MANIFEST=$(python3 "${HELPERS_DIR}/branches.py" manifest "${DARKNET_NETS}" --mgmt "${MGMT_ADDR:-}" \
                      --irregular "${R_IRREGULAR_ADDRS:-}" --regular "${R_REGULAR_ADDRS:-}" --seed "${BRANCH_SEED:-0}" --out-dir "${RAW_DIR}"); then
        chown "${NT_USER}:${NT_GROUP}" "${MANIFEST}" 2>/dev/null || true
        ok "Branch assignment queued for the processing node: $(basename "${MANIFEST}")"
    else
        err "Could not write the branch assignment to ${RAW_DIR}"
        ERRORS=$(( ERRORS + 1 ))
    fi
fi

# --dumpcap process check-----------------------------------------------------
DUMPCAP_RUNNING=0
for _ in $(seq 1 5); do
    pgrep -x dumpcap &>/dev/null && { DUMPCAP_RUNNING=1; break; }
    sleep 1
done
mapfile -t PCAPS < <(find "${RAW_DIR}" -maxdepth 1 -name '*.pcap' -printf '%Ts %f\n' 2>/dev/null | sort -rn)
if [[ ${DUMPCAP_RUNNING} -eq 1 ]]; then
    ok "dumpcap is running (PID: $(pgrep -x dumpcap | tr '\n' ' '))"
    if [[ ${#PCAPS[@]} -eq 0 ]]; then
        warn "No .pcap files yet in ${RAW_DIR}"
    else
        AGE=$(( $(date +%s) - ${PCAPS[0]%% *} ))
        # dumpcap starts a new file every DURATION even without any traffic
        if [[ ${AGE} -gt $(( ${DURATION:-3600} + 120 )) ]]; then
            err "Newest pcap ${PCAPS[0]#* } was last written ${AGE} s ago, longer than one rotation (${DURATION:-3600} s) - is dumpcap stuck?"
            ERRORS=$(( ERRORS + 1 ))
        else
            ok "Newest pcap: ${PCAPS[0]#* } (last written ${AGE} s ago)"
        fi
    fi
    UNSENT=("${PCAPS[@]:1}")    # the newest one is still being written
else
    err "dumpcap process not found"
    ERRORS=$(( ERRORS + 1 ))
    UNSENT=("${PCAPS[@]}")
fi

# --Files waiting for the transfer--------------------------------------------
if [[ "${TRANSFER_MODE:-local}" == "remote" ]]; then
    RING="${RING_BUFFER_SIZE:-24}"
    if [[ ${#UNSENT[@]} -eq 0 ]]; then
        ok "No files waiting for the transfer"
    else
        AGE=$(( $(date +%s) - ${UNSENT[-1]%% *} ))
        MSG="${#UNSENT[@]} file(s) waiting for the transfer, the oldest for $(( AGE / 60 )) min"
        [[ ${RING} -gt 0 ]] && MSG+=" (dumpcap deletes the oldest when there are more than ${RING})"
        if [[ ${RING} -gt 0 && ${#UNSENT[@]} -ge $(( RING * 3 / 4 )) ]]; then
            err "${MSG}"
            ERRORS=$(( ERRORS + 1 ))
        else
            warn "${MSG}"
        fi
    fi
fi

# --Summary-------------------------------------------------------------------
echo ""
if [[ ${ERRORS} -eq 0 ]]; then
    ok "All checks passed. Node is healthy and running."
else
    err "${ERRORS} check(s) errored. Review errors above."
    exit 1
fi