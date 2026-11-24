#!/usr/bin/env bash

set -uo pipefail

IFACE="${INTERFACE:-}"
CPUS="${CAPTURE_CPUS:-}"

log_warn() { echo "<4>[nic_tuning] $*"; }
log_info() { echo "<6>[nic_tuning] $*"; }

if [[ -z "${IFACE}" || "${IFACE}" == "lo" || ! -d "/sys/class/net/${IFACE}" ]]; then
    log_warn "INTERFACE '${IFACE}' is unset, lo or missing - nothing to tune"
    exit 0
fi

# --Receive ring: as large as the NIC allows----------------------------------
mapfile -t rx < <(ethtool -g "${IFACE}" 2>/dev/null | awk '/^RX:/ {print $2}')     # maximum, current
if [[ "${rx[0]:-}" =~ ^[0-9]+$ && "${rx[1]:-}" =~ ^[0-9]+$ ]]; then
    if [[ "${rx[0]}" -eq "${rx[1]}" ]]; then
        log_info "${IFACE}: receive ring already at its maximum (${rx[0]})"
    elif ethtool -G "${IFACE}" rx "${rx[0]}" 2>/dev/null; then
        log_info "${IFACE}: receive ring ${rx[1]} -> ${rx[0]}"
    else
        log_warn "${IFACE}: could not enlarge the receive ring"
    fi
else
    log_warn "${IFACE}: the receive ring cannot be changed on this NIC"
fi

# --Offloads that merge packets before they are captured----------------------
for feature in gro lro rx-gro-hw; do
    ethtool -K "${IFACE}" "${feature}" off &>/dev/null || true
done
merging=$(ethtool -k "${IFACE}" 2>/dev/null | awk '$1 ~ /^(generic-receive-offload|large-receive-offload|rx-gro-hw):$/ && $2 == "on" {printf "%s ", $1}')
if [[ -z "${merging}" ]]; then
    log_info "${IFACE}: packet merging (GRO/LRO) is off"
else
    log_warn "${IFACE}: still merging packets, could not turn off: ${merging}"
fi

# --Interrupts of this NIC on the capture CPUs--------------------------------
nic_irqs() {
    local device
    device=$(readlink -f "/sys/class/net/${IFACE}/device" 2>/dev/null) || return 0
    [[ -n "${device}" && -d "${device}" ]] || return 0      # virtual interface
    [[ "$(basename "${device}")" != virtio* ]] || device=$(dirname "${device}")     # of a virtio NIC: its PCI device
    if [[ -d "${device}/msi_irqs" ]]; then
        ls "${device}/msi_irqs"
    elif [[ -f "${device}/irq" ]]; then
        cat "${device}/irq"
    fi
}

if [[ -n "${CPUS}" ]]; then
    pinned=0
    for irq in $(nic_irqs); do
        if echo "${CPUS}" 2>/dev/null > "/proc/irq/${irq}/smp_affinity_list"; then
            pinned=$(( pinned + 1 ))
        fi
    done 2>/dev/null
    log_info "${IFACE}: ${pinned} interrupt(s) pinned to CPU ${CPUS}"
    if systemctl is-active --quiet irqbalance 2>/dev/null; then
        log_warn "irqbalance is running and may move the interrupts again"
    fi
fi
exit 0
