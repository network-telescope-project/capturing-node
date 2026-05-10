#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
RAW_DIR="$PROJECT_ROOT/data/raw"
if [ ! -d "$RAW_DIR" ]; then
    mkdir -p "$RAW_DIR"
fi

echo "[*] Watching '$RAW_DIR' for closed PCAP files..."

inotifywait -m "$RAW_DIR" -e close_write | while read -r path action file; do
    if [[ "$file" == *.pcap* ]]; then
        NEW_NAME=$(date +"%Y-%m-%d_%H-%M-%S").pcap

        # TODO how can we make sure the remote path is correct (??/processing-node/data/queue)?
        # TODO maybe some transfer monitoring or alert (ideally without increasing the possibility of packet drops - so maybe on the processing node)
        echo "[*] Transferring $file to processing node..."
        rsync --remove-source-files -avz "$path/$file" user@processing-node-ip:/opt/nt-processing/data/queue/$NEW_NAME.part

        # Atomically remove the temporary suffix after transfer
        ssh user@processing-node "mv /opt/nt-processing/data/queue/$NEW_NAME.part /opt/nt-processing/data/queue/$NEW_NAME"
        echo "[+] File $NEW_NAME handoff complete."
    fi
done
