#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-.}"
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM}"
FORMAT="${TRIVY_FORMAT:-table}"
STAMP="$(date +%Y%m%d-%H%M%S)"

usage() {
  echo "Usage: $0 [target_path_within_repo]"
  echo "Example: $0 ."
  echo "Example: TRIVY_SEVERITY=CRITICAL,HIGH $0 config"
}

if [[ "${TARGET}" == "-h" || "${TARGET}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ! -e "${ROOT_DIR}/${TARGET}" ]]; then
  echo "[ERROR] Target does not exist inside repository: ${TARGET}" >&2
  exit 1
fi

ROOT_ABS="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$ROOT_DIR")"
TARGET_ABS="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${ROOT_DIR}/${TARGET}")"

case "$TARGET_ABS" in
  "$ROOT_ABS"|"$ROOT_ABS"/*) ;;
  *)
    echo "[ERROR] Target must be inside repository: ${TARGET}" >&2
    exit 1
    ;;
esac

TARGET_IN_CONTAINER="/workspace${TARGET_ABS#$ROOT_ABS}"
REPORT_DIR="${ROOT_DIR}/reports/trivy"
REPORT_PATH="${REPORT_DIR}/filesystem-${STAMP}.${FORMAT}"

mkdir -p "$REPORT_DIR"

echo "[INFO] Running Trivy filesystem scan"
echo "[INFO] Target: ${TARGET_IN_CONTAINER}"
echo "[INFO] Severity: ${SEVERITY}"
echo "[INFO] Report: ${REPORT_PATH}"

cd "$ROOT_DIR"
docker compose --profile scanner run --rm trivy \
  filesystem \
  --cache-dir /trivy-cache \
  --format "$FORMAT" \
  --severity "$SEVERITY" \
  "$TARGET_IN_CONTAINER" | tee "$REPORT_PATH"

echo "[INFO] Saved report to ${REPORT_PATH}"