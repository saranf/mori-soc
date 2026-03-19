#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_REF="${1:-grafana/grafana-oss:11.5.2}"
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM}"
FORMAT="${TRIVY_FORMAT:-table}"
STAMP="$(date +%Y%m%d-%H%M%S)"
SAFE_NAME="$(printf '%s' "$IMAGE_REF" | tr '/:@' '---')"
REPORT_DIR="${ROOT_DIR}/reports/trivy"
REPORT_PATH="${REPORT_DIR}/image-${SAFE_NAME}-${STAMP}.${FORMAT}"

usage() {
  echo "Usage: $0 [image_ref]"
  echo "Example: $0 grafana/grafana-oss:11.5.2"
  echo "Example: TRIVY_SEVERITY=CRITICAL,HIGH $0 zabbix/zabbix-web-nginx-pgsql:alpine-7.4-latest"
}

if [[ "${IMAGE_REF}" == "-h" || "${IMAGE_REF}" == "--help" ]]; then
  usage
  exit 0
fi

mkdir -p "$REPORT_DIR"

echo "[INFO] Running Trivy image scan"
echo "[INFO] Image: ${IMAGE_REF}"
echo "[INFO] Severity: ${SEVERITY}"
echo "[INFO] Report: ${REPORT_PATH}"

cd "$ROOT_DIR"
docker compose --profile scanner run --rm trivy \
  image \
  --cache-dir /trivy-cache \
  --format "$FORMAT" \
  --severity "$SEVERITY" \
  "$IMAGE_REF" | tee "$REPORT_PATH"

echo "[INFO] Saved report to ${REPORT_PATH}"