#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (use sudo)."
   exit 1
fi

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
RAW_DIR="$PROJECT_ROOT/data/raw"
if [ ! -d "$RAW_DIR" ]; then
    mkdir -p "$RAW_DIR"
fi

DURATION=3600
RING_BUFFER_SIZE=24

INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')

IP_FILTER="not (src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16 or src net 169.254.0.0/16 or src net 127.0.0.0/8)"
if ip -6 addr show "$INTERFACE" scope global >/dev/null 2>&1; then
    IP_FILTER="$IP_FILTER and not (src net fc00::/7 or src net ::1/128)"
fi
PROTO_FILTER="tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0"
FILTER="$IP_FILTER and ($PROTO_FILTER)"

echo "[*] Starting capture on $INTERFACE"
echo "[*] Files saving into: $RAW_DIR"

sudo dumpcap -i "$INTERFACE" -f "$FILTER" -B 128 -b duration:"$DURATION" -b files:"$RING_BUFFER_SIZE" -n -q -w "$RAW_DIR/capture.pcap"
