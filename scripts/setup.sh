#!/usr/bin/env bash
set -e

SYSTEM_DEPS=("wireshark-common" "inotify-tools" "prometheus-node-exporter")
MISSING_DEPS=()

echo "[*] Auditing CAPTURE node dependencies..."

for pkg in "${SYSTEM_DEPS[@]}"; do
    if ! dpkg -l | grep -q "ii  $pkg "; then
        MISSING_DEPS+=("$pkg")
    fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "[!] Missing: ${MISSING_DEPS[*]}"
    echo "[*] Updating package lists and installing missing dependencies..."
    sudo apt update && sudo apt install -y "${MISSING_DEPS[@]}"
else
    echo "[+] Capture dependencies satisfied."
fi

# Optimization: Ensure dumpcap can be run by non-root users if needed
# sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' $(which dumpcap)

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
mkdir -p "$PROJECT_ROOT/data/raw"

echo -e "\n[DONE] Capture node setup is done."