#!/usr/bin/env bash

set -euo pipefail

INTERFACE="${INTERFACE:-lo}"
DATA_DIR="${DATA_DIR:-/var/lib/network-telescope/data/raw}"
DURATION="${DURATION:-3600}"
RING_BUFFER_SIZE="${RING_BUFFER_SIZE:-24}"
CAPTURE_CPUS="${CAPTURE_CPUS:-}"
TRANSFER_MODE="${TRANSFER_MODE:-local}"
DARKNET_NETS="${DARKNET_NETS:-}"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
HELPERS_DIR="$(dirname "${SCRIPT_DIR}")/helpers"

if [[ -n "${DARKNET_NETS}" ]]; then
    DARKNET_FILTER="$(python3 "${HELPERS_DIR}/darknet.py" filter "${DARKNET_NETS}")"
elif [[ "${TRANSFER_MODE}" == "remote" ]]; then
    echo "[capture] ERROR: DARKNET_NETS is empty - set it in the .env file" >&2
    exit 1
else
    echo "[capture] WARNING: DARKNET_NETS is empty - not filtering on the destination (local mode only)"
    DARKNET_FILTER=""
fi

EXCLUDE_SRC="not (src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16 or src net 169.254.0.0/16 or src net 127.0.0.0/8)"
if ip -6 addr show "$INTERFACE" scope global >/dev/null 2>&1; then
    EXCLUDE_SRC="$EXCLUDE_SRC and not (src net fc00::/7 or src net ::1/128)"
fi
PROTO_FILTER="tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0"

# Optimized clause order building to utilize BPF filter's short-circuit evaluation
FILTER="(${PROTO_FILTER})"
if [[ -n "${DARKNET_FILTER}" ]]; then
    FILTER="${FILTER} and ${DARKNET_FILTER}"
fi
FILTER="${FILTER} and (${EXCLUDE_SRC})"

mkdir -p "${DATA_DIR}"

echo "[capture] Starting on interface=${INTERFACE}, dir=${DATA_DIR}"
echo "[capture] Rotation: every ${DURATION}s"

DUMPCAP_ARGS=(
    -i "${INTERFACE}"
    -w "${DATA_DIR}/capture.pcap"
    -b "duration:${DURATION}"
    -B 128
    -n
    -q
)

if [[ -n "${RING_BUFFER_SIZE}" && "${RING_BUFFER_SIZE}" -gt 0 ]]; then
    DUMPCAP_ARGS+=(-b "files:${RING_BUFFER_SIZE}")
fi

if [[ -n "${FILTER}" ]]; then
    echo "[capture] filter=${FILTER}"
    DUMPCAP_ARGS+=(-f "${FILTER}")
fi

CMD=("dumpcap" "${DUMPCAP_ARGS[@]}")

if [[ -n "${CAPTURE_CPUS}" ]]; then
    echo "[capture] Pinning to CPUs: ${CAPTURE_CPUS}"
    CMD=("taskset" "-c" "${CAPTURE_CPUS}" "${CMD[@]}")
fi

echo "[capture] Running: ${CMD[*]}"
exec "${CMD[@]}"
