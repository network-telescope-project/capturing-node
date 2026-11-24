#!/usr/bin/env bash
# Node's own metrics for prometheus-node-exporter (its textfile collector reads the file written here)
# Run every minute by nt-metrics.timer

set -uo pipefail

METRICS_DIR="${METRICS_DIR:-/run/nt-metrics}"
DATA_DIR="${DATA_DIR:-/var/lib/network-telescope/data/raw}"
RING_BUFFER_SIZE="${RING_BUFFER_SIZE:-24}"
OUT="${METRICS_DIR}/nt.prom"

metric() {      # metric <name> <gauge|counter> <value> [help]
    printf '# HELP %s %s\n# TYPE %s %s\n%s %s\n' "$1" "${4:-}" "$1" "$2" "$1" "$3"
}

# --Services------------------------------------------------------------------
services() {
    local units=(nt-capture.service nt-file-detector.service nt-sweep.timer)
    local unit active
    if [[ "${TRANSFER_MODE:-local}" == "remote" ]]; then
        units+=(wg-quick@wg-nt.service)
        [[ "${WG_WRAPPER:-tcp}" == "tcp" ]] && units+=(nt-wstunnel.service)
    fi
    echo "# HELP nt_unit_active Whether the service is running"
    echo "# TYPE nt_unit_active gauge"
    for unit in "${units[@]}"; do
        active=0
        systemctl is-active --quiet "${unit}" && active=1
        echo "nt_unit_active{unit=\"${unit}\"} ${active}"
    done
}

# --dumpcap-------------------------------------------------------------------
dumpcap() {
    local cpu line
    pgrep -x dumpcap >/dev/null && running=1 || running=0
    metric nt_capture_running gauge "${running}" "Whether dumpcap is running"

    cpu=$(systemctl show -p CPUUsageNSec --value nt-capture.service 2>/dev/null)
    if [[ "${running}" -eq 1 && "${cpu}" =~ ^[0-9]{1,18}$ ]]; then
        metric nt_capture_cpu_seconds_total counter "$(awk -v n="${cpu}" 'BEGIN {printf "%.3f", n / 1e9}')" "CPU time of the capture service"
    fi

    # dumpcap says how many packets it lost only when it stops: the last such line
    local lost_at=0 lost=0
    line=$(journalctl -q -u nt-capture.service --since "-7 days" --no-pager -o short-unix --grep 'Packets received/dropped on interface .*: [0-9]+/[1-9]' -n 1 2>/dev/null)
    if [[ "${line}" =~ ^([0-9]+)\.[0-9]+\ .*:\ [0-9]+/([0-9]+)\ \( ]]; then
        lost_at="${BASH_REMATCH[1]}"
        lost="${BASH_REMATCH[2]}"
    fi
    metric nt_capture_last_loss_seconds gauge "${lost_at}" "When a capture that lost packets last ended (unix time, 0 = not in the last 7 days)"
    metric nt_capture_last_loss_packets gauge "${lost}" "Packets it lost"
}

# --Files waiting for the transfer--------------------------------------------
files() {
    local now newest_mtime=0 oldest=0 count=0 total=0 mtime
    now=$(date +%s)
    # The newest file is the one dumpcap is writing to
    while read -r mtime; do
        total=$(( total + 1 ))
        if [[ ${total} -eq 1 ]]; then
            newest_mtime="${mtime}"
            [[ "${running}" -eq 1 ]] && continue
        fi
        count=$(( count + 1 ))
        oldest=$(( now - mtime ))
    done < <(find "${DATA_DIR}" -maxdepth 1 -type f -name '*.pcap' -printf '%Ts\n' 2>/dev/null | sort -rn)
    metric nt_unsent_files gauge "${count}" "Closed PCAP files not yet transferred"
    metric nt_unsent_oldest_seconds gauge "${oldest}" "Age of the oldest of them"
    metric nt_ring_limit_files gauge "${RING_BUFFER_SIZE}" "PCAP files kept before the oldest is deleted (0 = no limit)"
    if [[ ${total} -gt 0 ]]; then
        metric nt_newest_file_seconds gauge "$(( now - newest_mtime ))" "Seconds since the newest PCAP file was written to"
    fi
}

running=0
tmp=$(mktemp "${METRICS_DIR}/.nt.prom.XXXXXX") || exit 1
trap 'rm -f "${tmp}"' EXIT
{
    services
    dumpcap
    files
} > "${tmp}"
chmod 644 "${tmp}"
mv "${tmp}" "${OUT}"
