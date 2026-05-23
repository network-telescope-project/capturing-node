#!/usr/bin/env bash

set -euo pipefail

DATA_DIR="${DATA_DIR:-/var/lib/network-telescope/data/raw}"
TRANSFER_MODE="${TRANSFER_MODE:-local}"
REMOTE_USER="${REMOTE_USER:-telescope}"
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/network-telescope/data/queue}"
SSH_KEY_PATH="${SSH_KEY_PATH:-/var/lib/network-telescope/.ssh/id_ed25519}"
DETECTOR_CPUS="${DETECTOR_CPUS:-}"

LOCK_FILE="/tmp/nt-file-detector.lock"
MAX_RETRIES=5
RETRY_DELAY=60

log_err() { echo "<3>[file_detector] [$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_info() { echo "<6>[file_detector] [$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

transfer_file() {
    local filepath="$1"
    local filename
    filename="$(basename "${filepath}")"

    if [[ "${TRANSFER_MODE}" == "local" ]]; then
        log_info "LOCAL mode - file ready for processing: ${filename}"
        echo "${filepath}" >> "${DATA_DIR}/.ready_files"
        return 0
    fi

    if [[ -z "${REMOTE_HOST}" ]]; then
        log_err "ERROR: REMOTE_HOST not set but TRANSFER_MODE=remote"
        return 1
    fi

    local attempt=0
    while [[ ${attempt} -lt ${MAX_RETRIES} ]]; do
        attempt=$(( attempt + 1 ))
        log_info "Transferring ${filename} to ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR} (attempt ${attempt})"

        if rsync -az --checksum \
            -e "ssh -i ${SSH_KEY_PATH} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10" \
            "${filepath}" \
            "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"; then

            log_info "Transfer OK: ${filename}"

            rm -f "${filepath}"
            return 0
        fi

        log_err "Transfer failed (attempt ${attempt}/${MAX_RETRIES}), retrying in ${RETRY_DELAY}s..."
        sleep "${RETRY_DELAY}"
    done

    log_err "ERROR: All ${MAX_RETRIES} transfer attempts failed for ${filename}"
    return 1
}

if [[ -e "${LOCK_FILE}" ]]; then
    existing_pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "")
    if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" 2>/dev/null; then
        log_info "Already running (PID ${existing_pid}). Exiting."
        exit 0
    fi
fi
echo $$ > "${LOCK_FILE}"
trap 'rm -f "${LOCK_FILE}"; log_info "Stopped."' EXIT

mkdir -p "${DATA_DIR}"

log_info "Watching '${DATA_DIR}' for closed PCAP files (mode=${TRANSFER_MODE})"
[[ "${TRANSFER_MODE}" == "remote" ]] && log_info "Remote target: ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"

INOTIFY_CMD=(inotifywait -m -e close_write -q --format '%w%f' "${DATA_DIR}")
if [[ -n "${DETECTOR_CPUS}" ]]; then
    log_info "CPU pinning: ${DETECTOR_CPUS}"
    INOTIFY_CMD=(taskset -c "${DETECTOR_CPUS}" "${INOTIFY_CMD[@]}")
fi

"${INOTIFY_CMD[@]}" | while IFS= read -r filepath; do
    [[ "${filepath}" == *.pcap ]] || continue

    log_info "Closed: ${filepath}"
    transfer_file "${filepath}" || log_err "ERROR: transfer_file failed for ${filepath}"
done
