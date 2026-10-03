#!/usr/bin/env bash
# Safety net for file_detector.sh: transfers closed PCAPs the detector never handled
# (e.g. the last file of a capture session, whose close event arrives after the detector
# has already been stopped). Run periodically by nt-sweep.timer.
#
# Never touches a file that is still being written:
#   - a file held open by any process (fuser) is skipped; if it has also not been modified
#     for 2x DURATION it is only reported (dumpcap hung?), never moved
#   - while dumpcap runs, the newest file is skipped even if fuser reports it closed
#   - files modified less than SWEEP_MIN_AGE seconds ago are skipped

set -euo pipefail

DATA_DIR="${DATA_DIR:-/var/lib/network-telescope/data/raw}"
TRANSFER_MODE="${TRANSFER_MODE:-local}"
REMOTE_USER="${REMOTE_USER:-telescope}"
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/network-telescope/data/queue}"
SSH_KEY_PATH="${SSH_KEY_PATH:-/var/lib/network-telescope/.ssh/id_ed25519}"
DURATION="${DURATION:-3600}"

MIN_AGE="${SWEEP_MIN_AGE:-600}"
STALE_AFTER=$(( 2 * DURATION ))
LOCK_WAIT=300
TRANSFER_LOCK="${DATA_DIR}/.transfer.lock"

log_err() { echo "<3>[sweep] [$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_info() { echo "<6>[sweep] [$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

if [[ "${TRANSFER_MODE}" != "remote" ]]; then
    log_info "TRANSFER_MODE=${TRANSFER_MODE}, nothing to do"
    exit 0
fi
if [[ -z "${REMOTE_HOST}" ]]; then
    log_err "ERROR: REMOTE_HOST not set but TRANSFER_MODE=remote"
    exit 1
fi
if ! command -v fuser >/dev/null; then
    log_err "ERROR: 'fuser' (package psmisc) is required to tell open PCAPs from closed ones"
    exit 1
fi

send_file() {
    local filepath="$1"
    local filename="${filepath##*/}"
    local rc=0

    (
        flock -w "${LOCK_WAIT}" 9 || exit 3
        # The detector may have sent it while we waited for the lock
        [[ -f "${filepath}" ]] || exit 2

        rsync -az --checksum \
            -e "ssh -i ${SSH_KEY_PATH} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10" \
            "${filepath}" \
            "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/" || exit 1

        rm -f "${filepath}"
    ) 9>"${TRANSFER_LOCK}" || rc=$?

    case ${rc} in
        0) log_info "Transfer OK: ${filename}" ;;
        2) log_info "Already transferred by the detector: ${filename}"; rc=0 ;;
        3) log_err "Could not get the transfer lock within ${LOCK_WAIT}s, trying again next run" ;;
        *) log_err "ERROR: Transfer failed for ${filename}" ;;
    esac
    return "${rc}"
}

mapfile -t files < <(find "${DATA_DIR}" -maxdepth 1 -type f -name '*.pcap' -printf '%T@ %p\n' | sort -n | cut -d' ' -f2-)

if [[ ${#files[@]} -eq 0 ]]; then
    log_info "No PCAP files in ${DATA_DIR}"
    exit 0
fi

newest="${files[-1]}"
dumpcap_running=0
pgrep -x dumpcap >/dev/null && dumpcap_running=1

now=$(date +%s)
sent=0
status=0

for filepath in "${files[@]}"; do
    filename="${filepath##*/}"
    mtime=$(stat -c %Y "${filepath}" 2>/dev/null) || continue
    age=$(( now - mtime ))

    if fuser -s "${filepath}" 2>/dev/null; then
        if [[ ${age} -gt ${STALE_AFTER} ]]; then
            log_err "ERROR: ${filename} is held open but was not modified for ${age}s (> ${STALE_AFTER}s): is dumpcap hung? Not touching it"
        fi
        continue
    fi

    if [[ ${dumpcap_running} -eq 1 && "${filepath}" == "${newest}" ]]; then
        continue
    fi

    if [[ ${age} -lt ${MIN_AGE} ]]; then
        continue
    fi

    log_info "Unsent closed file ${filename} (not modified for ${age}s)"
    rc=0
    send_file "${filepath}" || rc=$?
    if [[ ${rc} -eq 0 ]]; then
        sent=$(( sent + 1 ))
    else
        # Processing node down or lock busy (remaining files would fail the same way)
        status=1
        break
    fi
done

log_info "Done: ${sent} file(s) sent"
exit "${status}"
