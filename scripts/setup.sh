#!/usr/bin/env bash

set -euo pipefail

# --Configuration-------------------------------------------------------------
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")

NT_USER="nt-capture"
NT_GROUP="nt-capture"

NT_HOME="/var/lib/network-telescope"
DATA_DIR="${NT_HOME}/data/raw"
SSH_DIR="${NT_HOME}/.ssh"
CONF_DIR="/etc/network-telescope"
ENV_FILE="${CONF_DIR}/capturing-node.env"

# WireGuard tunnel to the processing node (the transfer and the metrics go through it)
WG_IF="wg-nt"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
WG_KEY="/etc/wireguard/${WG_IF}.key"
WG_MTU=1280                         # leaves room for the WireGuard and the TCP wrapper headers
WG_WRAPPER_LISTEN="127.0.0.1:51820" # the local end of the wstunnel client (nt-wstunnel.service), WireGuard's Endpoint

# wstunnel (carries WireGuard over TCP): pinned release and the checksums published with it
WSTUNNEL_VERSION="11.1.0"
declare -A WSTUNNEL_SHA256=(
    [amd64]="512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23"
    [arm64]="148895f957a68be39e2b65d28c5f2065b9c58c4a0cfd48c560b2b3267f398464"
)
WSTUNNEL_BIN="/usr/local/bin/wstunnel"

# --Helpers-------------------------------------------------------------------
log()  { echo "[*] $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[i]\033[0m $*"; }
err()  { echo -e "\033[1;31m[!]\033[0m ERROR: $*" >&2; }
env_value() { grep "^$1=" "${ENV_FILE}" | tail -1 | cut -d= -f2- | tr -d "\"' " || true; }
set_env() {
    if grep -q "^$1=" "${ENV_FILE}"; then
        sed -i "s|^$1=.*|$1=$2|" "${ENV_FILE}"
    else
        [[ -z "$(tail -c1 "${ENV_FILE}")" ]] || echo >> "${ENV_FILE}"
        echo "$1=$2" >> "${ENV_FILE}"
    fi
}
require_root() {
    if [[ $EUID -ne 0 ]]; then
       err "This script must be run as root (use sudo)."
       exit 1
    fi
 }

 is_valid_ip() {
    local ip=$1
    local stat=1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
           ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

install_wstunnel() {
    if [[ "$("${WSTUNNEL_BIN}" --version 2>/dev/null)" == "wstunnel-cli ${WSTUNNEL_VERSION}" ]]; then
        ok "wstunnel ${WSTUNNEL_VERSION} installed."
        return
    fi
    local arch sha tmp
    arch=$(dpkg --print-architecture)
    sha="${WSTUNNEL_SHA256[${arch}]:-}"
    [[ -n "${sha}" ]] || { err "No pinned wstunnel build for architecture '${arch}'."; exit 1; }
    tmp=$(mktemp -d)
    log "Installing wstunnel ${WSTUNNEL_VERSION} (${arch})..."
    if ! curl -fsSL --retry 3 -o "${tmp}/wstunnel.tar.gz" \
            "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/wstunnel_${WSTUNNEL_VERSION}_linux_${arch}.tar.gz" \
        || ! echo "${sha}  ${tmp}/wstunnel.tar.gz" | sha256sum -c --quiet; then
        rm -rf "${tmp}"
        err "wstunnel download failed or its checksum does not match - not installed."
        exit 1
    fi
    tar -xzf "${tmp}/wstunnel.tar.gz" -C "${tmp}" wstunnel
    install -m 755 -o root -g root "${tmp}/wstunnel" "${WSTUNNEL_BIN}"
    rm -rf "${tmp}"
    ok "wstunnel ${WSTUNNEL_VERSION} installed: ${WSTUNNEL_BIN}"
}

# Time sync
sync_clock() {
    timedatectl set-ntp true 2>/dev/null || true
    for _ in $(seq 1 20); do
        if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]]; then
            ok "Clock synchronised (NTP): $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
            return
        fi
        sleep 1
    done

    local host before after header server offsets=()
    for host in www.debian.org www.google.com www.cloudflare.com www.wikipedia.org; do
        before=$(date +%s%3N)
        header=$(curl -sI --max-time 5 "https://${host}" 2>/dev/null | tr -d '\r' | sed -n 's/^[Dd]ate: //p' | head -1) || true
        after=$(date +%s%3N)
        [[ -n "${header}" ]] && server=$(date -d "${header}" +%s 2>/dev/null) || continue
        offsets+=($(( server * 1000 + 500 - (before + after) / 2 )))
        [[ ${#offsets[@]} -eq 3 ]] && break
    done
    if [[ ${#offsets[@]} -lt 3 ]]; then
        warn "Clock NOT verified: NTP does not answer and neither do enough web servers. Set it by hand (date -u -s '...')."
        return
    fi
    local sorted diff
    mapfile -t sorted < <(printf '%s\n' "${offsets[@]}" | sort -n)
    diff=${sorted[1]}
    if (( sorted[2] - diff > 2000 && diff - sorted[0] > 2000 )); then
        warn "Clock NOT verified: the web servers disagree (offsets ${sorted[*]} ms). Check it by hand: $(date -u)"
    elif (( diff >= -2000 && diff <= 2000 )); then
        ok "Clock OK: within 2 s of the web servers (no NTP)"
    elif systemctl is-active --quiet nt-capture 2>/dev/null; then
        warn "Clock is off by $(( diff / 1000 )) s, but not changed while nt-capture runs: stop it and re-run setup.sh."
    else
        date -s "@$(( ($(date +%s%3N) + diff) / 1000 ))" > /dev/null
        ok "Clock was off by $(( diff / 1000 )) s, set from the web servers (no NTP): $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
    fi
}

# --Pre flight----------------------------------------------------------------
require_root

REDRAW_BRANCHES=0
if [[ "${1:-}" == "--redraw-branches" ]]; then
    REDRAW_BRANCHES=1
elif [[ $# -gt 0 ]]; then
    err "usage: sudo $0 [--redraw-branches]"
    exit 1
fi

OS=$(. /etc/os-release && echo "${ID}")
if [[ ! "${OS}" =~ ^(ubuntu|debian)$ ]]; then
    err "Only Ubuntu/Debian supported."
    exit 1
fi

if [[ "${PROJECT_ROOT}" == /home/* || "${PROJECT_ROOT}" == /root/* ]]; then
    err "The repo is in ${PROJECT_ROOT}, which user '${NT_USER}' cannot read."
    err "Clone it to /opt/network-telescope and run scripts/setup.sh from there."
    exit 1
fi

# --Dependencies--------------------------------------------------------------
SYSTEM_DEPS=("wireshark-common" "python3" "inotify-tools" "psmisc" "prometheus-node-exporter" "openssh-client" "rsync" "ethtool" "util-linux" "cpufrequtils" "net-tools" "procps" "curl" "jq" "ufw" "wireguard-tools")
MISSING_DEPS=()

log "Auditing CAPTURE node dependencies..."

for pkg in "${SYSTEM_DEPS[@]}"; do
    if [[ "$(dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null)" != "installed" ]]; then
        MISSING_DEPS+=("$pkg")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    warn "Missing: ${MISSING_DEPS[*]}"
    log "Updating package lists and installing missing dependencies..."
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING_DEPS[@]}"
else
    ok "Capture dependencies satisfied."
fi

# --Clock--------------------------------------------------------------------
timedatectl set-timezone UTC || warn "Could not set the timezone to UTC."
sync_clock

# --User and directories-----------------------------------------------------
log "Creating user and directories"
if ! getent group "${NT_GROUP}" &>/dev/null; then
    groupadd --system "${NT_GROUP}"
    ok "Created group '${NT_GROUP}'."
fi

if ! id "${NT_USER}" &>/dev/null; then
    useradd --system --no-create-home -d "${NT_HOME}" --shell /usr/sbin/nologin \
        -g "${NT_GROUP}" --comment "Network Telescope capture daemon" "${NT_USER}"
    ok "Created user '${NT_USER}'."
fi

# Make dumpcap accessible to nt-capture user
if ! getent group wireshark &>/dev/null; then
    groupadd wireshark
fi
usermod -aG wireshark "${NT_USER}" 2>/dev/null || true
chmod 750 /usr/bin/dumpcap
chgrp wireshark /usr/bin/dumpcap
setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

log "Setting up directories and permissions..."
mkdir -p "${DATA_DIR}" "${SSH_DIR}" "${CONF_DIR}"
chown -R "${NT_USER}:${NT_GROUP}" "${NT_HOME}"
chown root:"${NT_GROUP}" "${CONF_DIR}"
chmod 750 "${NT_HOME}"
chmod 700 "${SSH_DIR}"
chmod 750 "${DATA_DIR}"

# --Environment file--------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
    log "Creating environment file: ${ENV_FILE}"
    cp "${PROJECT_ROOT}/.env.example" "${ENV_FILE}"
    sed -i "s|^PROJECT_ROOT=.*|PROJECT_ROOT=${PROJECT_ROOT}|" "${ENV_FILE}"
    sed -i "s|^DATA_DIR=.*|DATA_DIR=${DATA_DIR}|" "${ENV_FILE}"
    sed -i "s|^NT_HOME=.*|NT_HOME=${NT_HOME}|" "${ENV_FILE}"
    sed -i "s|^SSH_KEY_PATH=.*|SSH_KEY_PATH=${SSH_DIR}/id_ed25519|" "${ENV_FILE}"

    # Try to ask user for remote host IP
    echo ""
    while true; do
        read -p "Enter the Processing node IP (IPv4) [or 'x' to skip]: " REMOTE_HOST

        if [[ "$REMOTE_HOST" == "x" ]]; then
            sed -i "s|^REMOTE_HOST=.*|REMOTE_HOST=CHANGE_ME|" "${ENV_FILE}"
            warn "Skipping IP setup. Remember to manually set REMOTE_HOST in $ENV_FILE later."
            break
        fi

        if is_valid_ip "$REMOTE_HOST"; then
            sed -i "s|^REMOTE_HOST=.*|REMOTE_HOST=${REMOTE_HOST}|" "${ENV_FILE}"
            ok "Processing node IP set: $REMOTE_HOST"
            break
        else
            err "Invalid format. Please enter a valid IPv4 (e.g., 192.168.1.1)."
        fi
    done

    chmod 640 "${ENV_FILE}"
    chown root:"${NT_GROUP}" "${ENV_FILE}"
else
    warn "Environment file already exists, not overwriting: ${ENV_FILE}"
fi

# --CPU Pinning------------------------------------------------------------
log "Configuring CPU pinning..."
TOTAL_CORES=$(nproc)
log "Detected ${TOTAL_CORES} logical CPUs."

if [[ ${TOTAL_CORES} -le 2 ]]; then
    MGMT_CPUS="0"
    CAPTURE_CPUS="0-$((TOTAL_CORES - 1))"
    warn "Only ${TOTAL_CORES} cores - management and capture share all cores."
elif [[ ${TOTAL_CORES} -le 4 ]]; then
    MGMT_CPUS="0"
    CAPTURE_CPUS="1-$((TOTAL_CORES - 1))"
else
    MGMT_CPUS="0-1"
    CAPTURE_CPUS="2-$((TOTAL_CORES - 1))"
fi

log "Management CPUs (OS, SSH, Prometheus, detector): ${MGMT_CPUS}"
log "Capture CPUs (dumpcap + NIC interrupts): ${CAPTURE_CPUS}"

# Patch env file
sed -i "s|^CAPTURE_CPUS=.*|CAPTURE_CPUS=${CAPTURE_CPUS}|" "${ENV_FILE}"
sed -i "s|^DETECTOR_CPUS=.*|DETECTOR_CPUS=${MGMT_CPUS}|" "${ENV_FILE}"

# Isolate capture CPUs at kernel level
GRUB_FILE="/etc/default/grub"
ISOLCPUS_PARAM="isolcpus=${CAPTURE_CPUS} nohz_full=${CAPTURE_CPUS} rcu_nocbs=${CAPTURE_CPUS}"
if grep -q "isolcpus" "${GRUB_FILE}"; then
    warn "isolcpus already in GRUB config - not modifying. Current: $(grep isolcpus "${GRUB_FILE}")"
else
    log "Adding isolcpus to GRUB: ${ISOLCPUS_PARAM}"
    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"|GRUB_CMDLINE_LINUX_DEFAULT=\"\1 ${ISOLCPUS_PARAM}\"|" "${GRUB_FILE}"
    update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg
    warn "GRUB updated. A reboot is required for CPU isolation to take effect."
fi

# --System tuning----------------------------------------------------------
log "Applying system tuning..."

# CPU governor → performance
if command -v cpupower &>/dev/null; then
    cpupower frequency-set -g performance || warn "Could not set CPU governor (may not be available)."
elif command -v cpufreq-set &>/dev/null; then
    for cpu in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
        echo performance > "${cpu}" 2>/dev/null || true
    done
fi

# Persist CPU governor via systemd
cat > /etc/systemd/system/nt-cpu-governor.service <<'EOF'
[Unit]
Description=Set CPU governor to performance for Network Telescope
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $f 2>/dev/null || true; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now nt-cpu-governor.service

# Sysctl tuning
cat > /etc/sysctl.d/90-nt-capture.conf <<EOF
# Network Telescope - capturing node tuning
# Increase socket receive buffer sizes
net.core.rmem_max = 268435456
net.core.rmem_default = 67108864
net.core.netdev_max_backlog = 1000000
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 8000

# Disable unnecessary packet processing to reduce CPU load
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
sysctl --system -q

# --Interface lookup-------------------------------------------------------
DETECTED_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}') || true
if [ -z "$DETECTED_IFACE" ]; then  # local routing table fallback
    DETECTED_IFACE=$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' | head -n 1) || true
fi

ENV_IFACE=$(grep "^INTERFACE=" "${ENV_FILE}" | cut -d= -f2- | tr -d '"'\'' ' | xargs 2>/dev/null) || true
if [[ -n "${ENV_IFACE}" && "${ENV_IFACE}" != "lo" ]]; then
    IFACE="${ENV_IFACE}"
    log "Using interface configured in .env: ${IFACE}"

    if [[ -n "${DETECTED_IFACE}" && "${IFACE}" != "${DETECTED_IFACE}" ]]; then
        warn "  Note: Configured interface (${IFACE}) differs from detected internet route (${DETECTED_IFACE})"
    fi
elif [ -n "$DETECTED_IFACE" ]; then
    IFACE="${DETECTED_IFACE}"
    log "Auto-detected primary internet interface: ${IFACE}"
    sed -i "s|^INTERFACE=.*|INTERFACE=${IFACE}|" "${ENV_FILE}"
else
    err "No internet-facing interface could be determined automatically or via .env"
    exit 1
fi

if ! ip link show "${IFACE}" 2>/dev/null | grep -q "state UP"; then
    warn "Interface '${IFACE}' is not currently in an UP operational state!"
fi

# --NIC tuning-------------------------------------------------------------
# Receive ring, no packet merging, the NIC's interrupts on the capture CPUs
log "Tuning NIC: ${IFACE}"
chmod +x "${PROJECT_ROOT}/capture/nic_tuning.sh"
sed "s|@PROJECT_ROOT@|${PROJECT_ROOT}|g" "${PROJECT_ROOT}/capture/nt-nic-tuning.service" > /etc/systemd/system/nt-nic-tuning.service
systemctl daemon-reload
systemctl enable nt-nic-tuning > /dev/null 2>&1
systemctl restart nt-nic-tuning || warn "NIC tuning failed: journalctl -u nt-nic-tuning"
journalctl -q -u nt-nic-tuning --no-pager -o cat -n 6 --since "-1 min" 2>/dev/null | grep nic_tuning || true

# --Darknet destinations---------------------------------------------------
# Prefixes routed to the node but not configured on it cannot be detected and has to be appended manually
grep -q "^DARKNET_NETS=" "${ENV_FILE}" || echo -e "\nDARKNET_NETS=" >> "${ENV_FILE}"
CURRENT_NETS=$(grep "^DARKNET_NETS=" "${ENV_FILE}" | cut -d= -f2- | tr -d '"' | xargs || true)
if ip link show "${IFACE}" &>/dev/null; then
    if [[ -z "${CURRENT_NETS}" ]]; then
        DETECTED=$(python3 "${PROJECT_ROOT}/helpers/darknet.py" detect "${IFACE}")
        if [[ -n "${DETECTED}" ]]; then
            sed -i "s|^DARKNET_NETS=.*|DARKNET_NETS=${DETECTED}|" "${ENV_FILE}"
            ok "DARKNET_NETS set from the public addresses of ${IFACE}: ${DETECTED}"
            warn "  Prefixes routed to this node that are not configured on it must be added by hand in ${ENV_FILE}."
        else
            warn "No public address found on ${IFACE}: set DARKNET_NETS in ${ENV_FILE} by hand (capture will not start without it)."
        fi
    else
        UNCOVERED=$(python3 "${PROJECT_ROOT}/helpers/darknet.py" missing "${IFACE}" "${CURRENT_NETS}")
        ok "DARKNET_NETS already set: ${CURRENT_NETS}"
        [[ -z "${UNCOVERED}" ]] || warn "  Public address(es) on ${IFACE} not covered by it (not captured): ${UNCOVERED}"
    fi
else
    warn "Interface '${IFACE}' not found: DARKNET_NETS not detected. Fix INTERFACE in ${ENV_FILE} and re-run setup.sh."
fi

# --Management address-----------------------------------------------------
MGMT_ADDR=$(env_value MGMT_ADDR)
if [[ -z "${MGMT_ADDR}" ]]; then
    MGMT_ADDR=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}') || true
    if is_valid_ip "${MGMT_ADDR}"; then
        set_env MGMT_ADDR "${MGMT_ADDR}"
    else
        MGMT_ADDR=""
        warn "Could not detect this node's own address: set MGMT_ADDR in ${ENV_FILE} by hand and re-run setup.sh."
    fi
fi
[[ -z "${MGMT_ADDR}" ]] || ok "Management address: ${MGMT_ADDR}"

SSH_PORTS=$(ss -ltnpH | awk '/"sshd"/ {n=split($4, a, ":"); print a[n]}' | sort -u)
if [[ -n "${SSH_PORTS}" ]]; then
    set_env MGMT_PORTS "$(echo ${SSH_PORTS} 9100 | tr ' ' ',')"     # sshd + node-exporter
elif [[ -z "$(env_value MGMT_PORTS)" ]]; then
    set_env MGMT_PORTS "22,9100"
    warn "Could not find the port sshd listens on: assuming 22 for MGMT_PORTS in ${ENV_FILE}."
fi

# --Branches---------------------------------------------------------------
NETS=$(env_value DARKNET_NETS)
if [[ -n "${NETS}" ]]; then
    branches() { python3 "${PROJECT_ROOT}/helpers/branches.py" "$@"; }
    if [[ -z "$(env_value BRANCH_SEED)" || ${REDRAW_BRANCHES} -eq 1 ]]; then
        rc=0
        DRAWN=$(branches draw "${NETS}" --mgmt "${MGMT_ADDR}") || rc=$?
        if [[ ${rc} -eq 3 ]]; then
            DRAWN=$'BRANCH_SEED=\nBRANCH_NETS=\nR_IRREGULAR_ADDRS=\nR_REGULAR_ADDRS='
            warn "Too few addresses in DARKNET_NETS to answer on any: all stay passive. The branches are drawn once setup.sh runs with more."
        elif [[ ${rc} -ne 0 ]]; then
            err "Could not draw the branches for DARKNET_NETS=${NETS}"
            exit 1
        fi
        while IFS='=' read -r key value; do
            set_env "${key}" "${value}"
        done <<< "${DRAWN}"
        [[ ${rc} -ne 0 ]] || ok "Branches drawn at random (seed $(env_value BRANCH_SEED)) and written to ${ENV_FILE}"
    elif ! python3 "${PROJECT_ROOT}/helpers/darknet.py" same "$(env_value BRANCH_NETS)" "${NETS}"; then
        warn "DARKNET_NETS changed since the branches were drawn (for $(env_value BRANCH_NETS)): the answered addresses stay"
        warn "  as they are and any new address is passive. To draw again: sudo $0 --redraw-branches"
    fi
    if SUMMARY=$(branches check "${NETS}" --mgmt "${MGMT_ADDR}" --irregular "$(env_value R_IRREGULAR_ADDRS)" --regular "$(env_value R_REGULAR_ADDRS)" 2>&1); then
        ok "Branches: ${SUMMARY}"
    else
        err "Branches in ${ENV_FILE} are invalid: ${SUMMARY}"
        exit 1
    fi
fi

# --Prometheus node exporter tuning----------------------------------------
log "Configuring prometheus-node-exporter..."
PROM_OVERRIDE_DIR="/etc/systemd/system/prometheus-node-exporter.service.d"
mkdir -p "${PROM_OVERRIDE_DIR}"

cat > "${PROM_OVERRIDE_DIR}/nt-collectors.conf" <<EOF
[Service]
# Only enable collectors relevant to the telescope
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter \\
  --collector.disable-defaults \\
  --collector.cpu \\
  --collector.meminfo \\
  --collector.netdev \\
  --collector.softnet \\
  --collector.filesystem \\
  --collector.diskstats \\
  --collector.timex \\
  --collector.textfile \\
  --collector.textfile.directory=/run/nt-metrics \\
  --web.listen-address=":9100"

# Pin to management CPUs
CPUAffinity=${MGMT_CPUS}
EOF

systemctl daemon-reload
systemctl enable prometheus-node-exporter
systemctl restart prometheus-node-exporter

# --SSH Key setup----------------------------------------------------------
log "Setting up SSH key for transfer to processing node..."

if [[ ! -f "${SSH_DIR}/id_ed25519" ]]; then
    ssh-keygen -t ed25519 -f "${SSH_DIR}/id_ed25519" -N "" -C "nt-capture@$(hostname)"
    chown -R "${NT_USER}:${NT_GROUP}" "${SSH_DIR}"
    chmod 700 "${SSH_DIR}"
    chmod 600 "${SSH_DIR}/id_ed25519"
    chmod 644 "${SSH_DIR}/id_ed25519.pub"
    log "SSH key generated: ${SSH_DIR}/id_ed25519.pub"
else
    warn "SSH key already exists: ${SSH_DIR}/id_ed25519"
fi

# --WireGuard key----------------------------------------------------------
install -d -m 700 /etc/wireguard
if [[ ! -f "${WG_KEY}" ]]; then
    (umask 077 && wg genkey > "${WG_KEY}")
    log "WireGuard key generated: ${WG_KEY}"
fi
WG_PUBKEY=$(wg pubkey < "${WG_KEY}")

# --Systemd services-------------------------------------------------------
log "Installing systemd unit files..."
UNIT_FILES=(
    capture/nt-capture.service
    transfer/nt-file-detector.service
    transfer/nt-sweep.service
    transfer/nt-sweep.timer
    monitoring/nt-metrics.service
    monitoring/nt-metrics.timer
)

chmod +x "${PROJECT_ROOT}/capture/capture.sh" "${PROJECT_ROOT}"/transfer/{file_detector,sweep}.sh "${PROJECT_ROOT}/monitoring/node_metrics.sh" "${SCRIPT_DIR}/start.sh"

# Patch CPU affinity into unit files
for unit_file in "${UNIT_FILES[@]}"; do
    src="${PROJECT_ROOT}/${unit_file}"
    dest="/etc/systemd/system/$(basename "${unit_file}")"

    if [[ -f "${dest}" ]]; then
        warn "Systemd unit file '$dest' already exists - overwriting."
    fi
    sed "s|@PROJECT_ROOT@|${PROJECT_ROOT}|g" "$src" > "${dest}"
    ok "Installed systemd unit file '$dest'."
done

# Patch capture CPUs
sed -i "s|^# CPUAffinity=2-7|CPUAffinity=${CAPTURE_CPUS}|" /etc/systemd/system/nt-capture.service
sed -i "s|^# CPUAffinity=0-1|CPUAffinity=${MGMT_CPUS}|" /etc/systemd/system/nt-file-detector.service
sed -i "s|^# CPUAffinity=0-1|CPUAffinity=${MGMT_CPUS}|" /etc/systemd/system/nt-sweep.service
sed -i "s|^# CPUAffinity=0-1|CPUAffinity=${MGMT_CPUS}|" /etc/systemd/system/nt-metrics.service

systemctl daemon-reload
systemctl enable nt-capture nt-file-detector nt-sweep.timer nt-metrics.timer
systemctl try-restart nt-sweep.timer
systemctl restart nt-metrics.timer

for unit in nt-file-detector nt-capture; do
    if systemctl is-active --quiet "${unit}"; then
        warn "${unit} is already running - restart it to apply the updated unit file/scripts: systemctl restart ${unit}"
    fi
done

# --Registration on the processing node----------------------------------
REMOTE_HOST=$(env_value REMOTE_HOST)
REMOTE_PORT=$(env_value REMOTE_PORT)
REMOTE_PORT="${REMOTE_PORT:-8500}"
KNOWN_HOSTS="${SSH_DIR}/known_hosts"
TUNNEL_LINE='^nt-tunnel addr=([0-9.]+) server=([0-9.]+) key=([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=) port=([0-9]{1,5}) wrapper=(tcp|none)$'

if ! is_valid_ip "${REMOTE_HOST}"; then
    warn "REMOTE_HOST is not set in ${ENV_FILE}: skipping registration and firewall. Set it and re-run setup.sh"
else
    NODE_IP=$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)
    is_valid_ip "${NODE_IP}" || { warn "Could not detect this node's public IPv4: replace <NODE_IP> in the command below."; NODE_IP="<NODE_IP>"; }

    NETS=$(env_value DARKNET_NETS)
    [[ -n "${NETS}" ]] || warn "DARKNET_NETS is empty: replace <DARKNET_NETS> in the command below (comma separated)."
    REGISTER_CMD="sudo ./scripts/add-sensor.sh ${NODE_IP} \"${NETS:-<DARKNET_NETS>}\" \"$(cat "${SSH_DIR}/id_ed25519.pub")\" \"${WG_PUBKEY}\""

    if [[ -z "$(env_value WG_ADDR)" || -z "$(env_value WG_REMOTE_ADDR)" || -z "$(env_value WG_REMOTE_PUBKEY)" ]]; then
        echo ""
        warn "Register this node (run on the processing node, in its repository):"
        echo "  ${REGISTER_CMD}"
        echo ""
        while true; do
            read -r -p "Paste the 'nt-tunnel ...' line it printed (or type 's' to skip and re-run setup.sh later): " LINE
            LINE=$(sed -e 's/\r//g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<< "${LINE}")
            [[ "${LINE}" == "s" ]] && break
            if [[ "${LINE}" =~ ${TUNNEL_LINE} ]]; then
                T_ADDR="${BASH_REMATCH[1]}"; T_SERVER="${BASH_REMATCH[2]}"; T_KEY="${BASH_REMATCH[3]}"
                T_PORT="${BASH_REMATCH[4]}"; T_WRAPPER="${BASH_REMATCH[5]}"
                if is_valid_ip "${T_ADDR}" && is_valid_ip "${T_SERVER}"; then
                    set_env WG_ADDR "${T_ADDR}"
                    set_env WG_REMOTE_ADDR "${T_SERVER}"
                    set_env WG_REMOTE_PUBKEY "${T_KEY}"
                    set_env WG_PORT "${T_PORT}"
                    set_env WG_WRAPPER "${T_WRAPPER}"
                    ok "Tunnel settings written to ${ENV_FILE}"
                    break
                fi
            fi
            err "That is not the 'nt-tunnel addr=... server=... key=... port=... wrapper=...' line - try again."
        done
    else
        ok "Registered on the processing node (tunnel address $(env_value WG_ADDR))."
        log "  Only if this node's public address or keys changed, run there again: ${REGISTER_CMD}"
    fi

    WG_ADDR=$(env_value WG_ADDR)
    WG_REMOTE_ADDR=$(env_value WG_REMOTE_ADDR)
    WG_REMOTE_PUBKEY=$(env_value WG_REMOTE_PUBKEY)
    WG_PORT=$(env_value WG_PORT)
    WG_WRAPPER=$(env_value WG_WRAPPER)
    if [[ -n "${WG_ADDR}" && -n "${WG_REMOTE_ADDR}" && -n "${WG_REMOTE_PUBKEY}" ]]; then
        if [[ ! "${WG_WRAPPER}" =~ ^(tcp|none)$ || ! "${WG_PORT}" =~ ^[0-9]+$ ]]; then
            err "WG_WRAPPER must be tcp or none and WG_PORT a port number (${ENV_FILE})."
            exit 1
        fi

        # The wrapper: WireGuard sends to the local wstunnel client, which carries it over TCP
        if [[ "${WG_WRAPPER}" == "tcp" ]]; then
            install_wstunnel
            install -m 644 "${PROJECT_ROOT}/transfer/nt-wstunnel.service" /etc/systemd/system/nt-wstunnel.service
            systemctl daemon-reload
            systemctl enable nt-wstunnel > /dev/null 2>&1
            systemctl restart nt-wstunnel
            ENDPOINT="${WG_WRAPPER_LISTEN}"
            ok "wstunnel client up: WireGuard goes over TCP to ${REMOTE_HOST}:${WG_PORT}"
        else
            if [[ -f /etc/systemd/system/nt-wstunnel.service ]]; then
                systemctl disable --now nt-wstunnel > /dev/null 2>&1 || true
                rm -f /etc/systemd/system/nt-wstunnel.service
                systemctl daemon-reload
            fi
            ENDPOINT="${REMOTE_HOST}:${WG_PORT}"
        fi

        (umask 077 && cat > "${WG_CONF}" <<EOF
# Written by setup.sh from the WG_* settings in ${ENV_FILE}: change those and re-run setup.sh
[Interface]
Address = ${WG_ADDR}/32
MTU = ${WG_MTU}
PostUp = wg set %i private-key ${WG_KEY}

[Peer]
PublicKey = ${WG_REMOTE_PUBKEY}
AllowedIPs = ${WG_REMOTE_ADDR}/32
Endpoint = ${ENDPOINT}
PersistentKeepalive = 25
EOF
        )
        systemctl enable "wg-quick@${WG_IF}" > /dev/null 2>&1
        systemctl restart "wg-quick@${WG_IF}"
        log "Waiting for the tunnel to the processing node..."
        HANDSHAKE=0
        for _ in $(seq 1 30); do
            HANDSHAKE=$(wg show "${WG_IF}" latest-handshakes 2>/dev/null | awk '{print $2; exit}') || true
            [[ "${HANDSHAKE:-0}" -gt 0 ]] && break
            sleep 1
        done
        if [[ "${HANDSHAKE:-0}" -gt 0 ]]; then
            ok "Tunnel up: ${WG_ADDR} <-> ${WG_REMOTE_ADDR} (wrapper: ${WG_WRAPPER})"
        else
            warn "No answer through the tunnel yet: is this node registered there with this WireGuard key, and does"
            warn "  WG_WRAPPER match the processing node's? (journalctl -u nt-wstunnel; wg show ${WG_IF})"
        fi

        # Pin the processing node's host key, as seen through the tunnel
        if ssh-keygen -F "[${WG_REMOTE_ADDR}]:${REMOTE_PORT}" -f "${KNOWN_HOSTS}" &>/dev/null; then
            ok "Processing node host key already pinned."
        else
            HOST_KEY=$(ssh-keyscan -T 10 -p "${REMOTE_PORT}" -t ed25519 "${WG_REMOTE_ADDR}" 2>/dev/null || true)
            if [[ -z "${HOST_KEY}" ]]; then
                warn "No answer from ${WG_REMOTE_ADDR}:${REMOTE_PORT} through the tunnel: re-run setup.sh to pin its host key."
            else
                echo "SSH host key offered by ${WG_REMOTE_ADDR}:${REMOTE_PORT}:"
                ssh-keygen -lf /dev/stdin <<< "${HOST_KEY}"
                read -r -p "Does it match the fingerprint printed at the end of setup.sh on the processing node? [y/N] " ANSWER
                if [[ "${ANSWER}" =~ ^[Yy]$ ]]; then
                    echo "${HOST_KEY}" >> "${KNOWN_HOSTS}"
                    chown "${NT_USER}:${NT_GROUP}" "${KNOWN_HOSTS}"
                    chmod 644 "${KNOWN_HOSTS}"
                    ok "Host key pinned in ${KNOWN_HOSTS}"
                else
                    err "Host key NOT pinned - fingerprint differs."
                fi
            fi
        fi
    else
        warn "Tunnel not configured yet: re-run setup.sh after registering this node."
    fi

    # --Firewall---------------------------------------------------------------
    if [[ -z "${SSH_PORTS}" ]]; then
        warn "Could not find the port sshd listens on: not enabling the firewall."
    else
        ufw logging off > /dev/null   # scans of the darknet would flood the log
        ufw default deny incoming > /dev/null
        ufw default allow outgoing > /dev/null
        # No ping replies: passive addresses must not look alive (ufw lets pings through and has its own sysctl file)
        # TODO figure out whether this is what we really want (also if it wont damage our cause)
        sed -i '/^net\/ipv4\/icmp_echo_ignore_all=/d' /etc/ufw/sysctl.conf
        echo "net/ipv4/icmp_echo_ignore_all=1" >> /etc/ufw/sysctl.conf
        sysctl -q -w net.ipv4.icmp_echo_ignore_all=1
        for port in ${SSH_PORTS}; do
            if [[ -n "${MGMT_ADDR}" ]]; then
                ufw allow proto tcp to "${MGMT_ADDR}" port "${port}" comment "nt-ssh" > /dev/null
            else
                ufw allow "${port}/tcp" comment "nt-ssh" > /dev/null
            fi
        done
        if [[ -n "${WG_REMOTE_ADDR}" ]]; then
            # node-exporter: scraped by the processing node through the tunnel only
            ufw allow in on "${WG_IF}" proto tcp from "${WG_REMOTE_ADDR}" to any port 9100 comment "nt-prometheus" > /dev/null
        fi

        # Not "ufw status | grep -q": with pipefail, grep stopping early can make an active firewall look inactive
        if [[ "$(ufw status 2>/dev/null)" == "Status: active"* ]]; then
            ok "Firewall already active - rules updated."
        else
            systemd-run --quiet --unit=nt-ufw-rollback /bin/sh -c 'sleep 300; /usr/sbin/ufw disable'
            ufw --force enable > /dev/null
            warn "Firewall enabled (ssh port(s): ${SSH_PORTS//$'\n'/ }); it disables itself in 5 minutes unless you confirm."
            warn "Open a NEW ssh session to this node now (keep this one open), then answer here."
            read -r -p "Does the new session work? [y/N] " ANSWER
            systemctl stop nt-ufw-rollback 2>/dev/null || true
            if [[ "${ANSWER}" =~ ^[Yy]$ && "$(ufw status 2>/dev/null)" == "Status: active"* ]]; then
                ok "Firewall confirmed."
            elif [[ "${ANSWER}" =~ ^[Yy]$ ]]; then
                err "The 5 minutes had already passed and the firewall disabled itself - re-run setup.sh."
            else
                ufw disable > /dev/null
                err "Firewall disabled again. Check the ssh port and re-run setup.sh."
            fi
        fi
    fi
fi

echo ""
ok "Capture node setup is done."
echo ""
echo -e "\033[1;33mNext steps:\033[0m"
echo -e "\033[1;33m   1. Edit ${ENV_FILE}\033[0m"
echo -e "\033[1;33m   2. If you skipped the registration: re-run setup.sh once REMOTE_HOST is set, and paste the line add-sensor.sh prints\033[0m"
echo -e "\033[1;33m   3. Run: sudo ./scripts/start.sh\033[0m"
echo ""
warn "RING_BUFFER_SIZE (default 24) = max PCAP files kept on this node, one per DURATION (default 1 h)."
warn "  If more pile up (e.g. processing node unreachable) the oldest are deleted untransferred."
warn "  Set it in ${ENV_FILE} from this node's disk size and the expected MB per file (0 = no limit, disk can fill)."
echo ""
warn "A reboot is recommended."