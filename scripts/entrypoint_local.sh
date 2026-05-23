#!/usr/bin/env bash

set -euo pipefail

cleanup() {
    echo "[entrypoint] Shutting down..."
    kill "${CAPTURE_PID}" "${DETECTOR_PID}" 2>/dev/null || true
    wait
}
trap cleanup EXIT INT TERM

echo "[entrypoint] Starting capture..."
/scripts/capture.sh &
CAPTURE_PID=$!

# Give dumpcap a moment to start writing before we watch
sleep 2

echo "[entrypoint] Starting file_detector..."
/scripts/file_detector.sh &
DETECTOR_PID=$!

# Wait for either process to exit; if one dies, the trap kills the other
wait -n "${CAPTURE_PID}" "${DETECTOR_PID}"
EXIT_CODE=$?
echo "[entrypoint] A child process exited with code ${EXIT_CODE}"
exit "${EXIT_CODE}"
