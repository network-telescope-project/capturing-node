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

# --Helpers-------------------------------------------------------------------
log()  { echo "[*] $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[i]\033[0m $*"; }
err()  { echo -e "\033[1;31m[!]\033[0m ERROR: $*" >&2; }
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

# --Pre flight----------------------------------------------------------------
require_root

OS=$(. /etc/os-release && echo "${ID}")
if [[ ! "${OS}" =~ ^(ubuntu|debian)$ ]]; then
    err "Only Ubuntu/Debian supported."
    exit 1
fi

# --Dependencies--------------------------------------------------------------
SYSTEM_DEPS=("wireshark-common" "inotify-tools" "prometheus-node-exporter" "openssh-client" "rsync" "ethtool" "util-linux" "cpufrequtils" "net-tools" "procps" "curl" "jq")
MISSING_DEPS=()

log "Auditing CAPTURE node dependencies..."

for pkg in "${SYSTEM_DEPS[@]}"; do
    if ! dpkg -l | grep -q "ii  $pkg "; then
        MISSING_DEPS+=("$pkg")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    warn "Missing: ${MISSING_DEPS[*]}"
    log "Updating package lists and installing missing dependencies..."
    apt-get update -qq && apt-get install -y -qq "${MISSING_DEPS[@]}"
else
    ok "Capture dependencies satisfied."
fi

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

# --NIC tuning-------------------------------------------------------------
IFACE=$(grep "^INTERFACE" "${ENV_FILE}" | cut -d= -f2 | tr -d '"' | xargs)
if [[ -n "${IFACE}" && "${IFACE}" != "lo" ]]; then
    log "Tuning NIC: ${IFACE}"
    # Maximize ring buffer
    ethtool -G "${IFACE}" rx 4096 tx 4096 2>/dev/null || warn "Could not set ring buffer on ${IFACE}"
    # Disable offloads that can cause issues with packet capture
    ethtool -K "${IFACE}" gro off lro off 2>/dev/null || warn "Could not disable GRO/LRO on ${IFACE}"

    # IRQ affinity: pin NIC interrupts to capture CPUs
    log "Setting NIC IRQ affinity to capture CPUs (${CAPTURE_CPUS})..."
    # Convert cpu range to hex bitmask
    AFFINITY_MASK=$(python3 -c "
import sys
r = '${CAPTURE_CPUS}'
bits = 0
for part in r.split(','):
    if '-' in part:
        s,e = map(int,part.split('-'))
        for i in range(s,e+1): bits |= (1<<i)
    else:
        bits |= (1<<int(part))
print(hex(bits)[2:])
")
    for irq_dir in /proc/irq/*/; do
        smp_affinity="${irq_dir}smp_affinity"
        [[ -f "${smp_affinity}" ]] || continue
        echo "${AFFINITY_MASK}" > "${smp_affinity}" 2>/dev/null || true
    done
else
    warn "INTERFACE is 'lo' or unset - skipping NIC tuning."
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
  --collector.netstat \\
  --collector.netstat.fields="^(TcpExt:(TCPSynRetrans|TCPFastRetrans)|Tcp:(RetransSegs|InErrs)|Udp:(RcvbufErrors|InErrors))$" \\
  --collector.hwmon \\
  --collector.ethtool \\
  --collector.ethtool.metrics-include="rx_dropped|rx_missed_errors|rx_fifo_errors" \\
  --collector.filesystem \\
  --collector.diskstats \\
  --collector.processes \\
  --collector.cpu \\
  --web.listen-address=":9100"



# Pin to management CPUs
CPUAffinity=${MGMT_CPUS}
EOF

systemctl daemon-reload
systemctl enable --now prometheus-node-exporter

# --SSH Key setup----------------------------------------------------------
log "Setting up SSH key for transfer to processing node..."

if [[ ! -f "${SSH_DIR}/id_ed25519" ]]; then
    ssh-keygen -t ed25519 -f "${SSH_DIR}/id_ed25519" -N "" -C "nt-capture@$(hostname)"
    chown -R "${NT_USER}:${NT_GROUP}" "${SSH_DIR}"
    chmod 700 "${SSH_DIR}"
    chmod 600 "${SSH_DIR}/id_ed25519"
    chmod 644 "${SSH_DIR}/id_ed25519.pub"
    log "SSH key generated: ${SSH_DIR}/id_ed25519.pub"
    warn "Copy this public key to processing node"
    cat "${SSH_DIR}/id_ed25519.pub"
    echo "telescope@<PROCESSING_NODE_IP>"
    echo ""
else
    warn "SSH key already exists: ${SSH_DIR}/id_ed25519"
fi

# --Systemd services-------------------------------------------------------
log "Installing systemd unit files..."
UNIT_SRC="${SCRIPT_DIR}/systemd_unit_files"

# Patch CPU affinity into unit files
for unit in nt-capture nt-file-detector; do
    src="${UNIT_SRC}/${unit}.service"
    dest="/etc/systemd/system/${unit}.service"

    # Replace placeholders in original unit files
    sed "s|@PROJECT_ROOT@|${PROJECT_ROOT}|g" "$src" > "${src}.temp"

    if [[ ! -f "${dest}" ]]; then
        mv "${src}.temp" "${dest}"
        ok "Created systemd unit file '$dest'."
    else
        warn "Systemd unit file '$dest' already exists."
    fi
done

# Patch capture CPUs
sed -i "s|^# CPUAffinity=2-7|CPUAffinity=${CAPTURE_CPUS}|" /etc/systemd/system/nt-capture.service
sed -i "s|^# CPUAffinity=0-1|CPUAffinity=${MGMT_CPUS}|" /etc/systemd/system/nt-file-detector.service

systemctl daemon-reload
systemctl enable nt-capture nt-file-detector

echo ""
ok "Capture node setup is done."
echo ""
echo -e "\033[1;33mNext steps:\033[0m"
echo -e "\033[1;33m   1. Edit ${ENV_FILE}\033[0m"
echo -e "\033[1;33m   2. Copy SSH public key to processing node\033[0m"
echo -e "\033[1;33m   3. Run: sudo ./scripts/start.sh\033[0m"
echo ""
warn "A reboot is recommended."