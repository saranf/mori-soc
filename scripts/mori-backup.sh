#!/usr/bin/env bash
# ============================================================================
# MORI SOC — PostgreSQL 백업 스크립트
#
# 사용법:
#   ./scripts/mori-backup.sh                       # backups/mori-soc-YYYYMMDD-HHMMSS.sql.gz 생성
#   ./scripts/mori-backup.sh /custom/path/dump.sql # 사용자 지정 경로
#   BACKUP_DIR=/var/backups ./scripts/mori-backup.sh
#
# 동작:
#   1) soc-postgres 컨테이너에서 pg_dump 실행 (custom format → 압축률·복원 유연성)
#   2) 로컬 호스트의 backups/ 디렉토리(또는 BACKUP_DIR)로 저장
#   3) 파일명 형식: mori-soc-YYYYMMDD-HHMMSS.dump
#
# 환경변수 (옵션):
#   BACKUP_DIR              백업 저장 경로 (기본: ./backups)
#   MORI_DB_NAME            DB명 (기본: mori_soc, .env에서 자동 로드)
#   MORI_DB_USER            DB 사용자 (기본: mori, .env에서 자동 로드)
#   COMPOSE_SERVICE         Postgres 서비스 이름 (기본: soc-postgres)
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# .env 로드 (있으면)
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

DB_NAME="${MORI_DB_NAME:-mori_soc}"
DB_USER="${MORI_DB_USER:-mori}"
SERVICE="${COMPOSE_SERVICE:-soc-postgres}"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# 출력 경로 결정
if [ "$#" -ge 1 ]; then
  OUT_PATH="$1"
else
  mkdir -p "$BACKUP_DIR"
  OUT_PATH="$BACKUP_DIR/mori-soc-${TIMESTAMP}.dump"
fi

echo "💾 MORI SOC Backup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   DB:      ${DB_NAME} (user: ${DB_USER})"
echo "   Service: ${SERVICE}"
echo "   Output:  ${OUT_PATH}"
echo ""

# 컨테이너 실행 여부 확인
if ! docker compose ps "$SERVICE" --format json 2>/dev/null | grep -q '"State":"running"'; then
  echo "❌ Service '$SERVICE' is not running."
  echo "   Start it first: docker compose up -d $SERVICE"
  exit 1
fi

echo "📦 Running pg_dump (custom format)..."
docker compose exec -T "$SERVICE" \
  pg_dump -U "$DB_USER" -d "$DB_NAME" -F c --no-owner --no-acl > "$OUT_PATH"

SIZE="$(du -h "$OUT_PATH" | awk '{print $1}')"
echo ""
echo "✅ Backup complete"
echo "   File: ${OUT_PATH}"
echo "   Size: ${SIZE}"
echo ""
echo "   Restore with: ./scripts/mori-restore.sh ${OUT_PATH}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
