#!/usr/bin/env bash
# Builds the static nt-responder binary in Docker and copies it to responder/bin/ (the node needs no compiler).

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
IMAGE="nt-responder-build"
OUT_DIR="${SCRIPT_DIR}/bin"

docker build -t "${IMAGE}" "${SCRIPT_DIR}"

mkdir -p "${OUT_DIR}"
CID="$(docker create "${IMAGE}")"
trap 'docker rm -f "${CID}" >/dev/null' EXIT
docker cp "${CID}:/out/nt-responder" "${OUT_DIR}/nt-responder"

echo "[build] ${OUT_DIR}/nt-responder"
file "${OUT_DIR}/nt-responder" 2>/dev/null || true
