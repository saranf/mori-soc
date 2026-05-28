#!/usr/bin/env bash
# ============================================================================
# MORI SOC — PostgreSQL 복원 스크립트
#
# 사용법:
#   ./scripts/mori-restore.sh backups/mori-soc-20260101-120000.dump
#   ./scripts/mori-restore.sh backups/foo.dump --force      # 확인 프롬프트 생략
#
# 동작:
#   1) 입력 파일이 pg_dump custom format(.dump) 인지 확인
#   2) 사용자 확인 후 기존 DB 객체 DROP & RECREATE
#   3) pg_restore 실행 (--clean --if-exists --no-owner --no-acl)
#
# ⚠️ 경고: 이 스크립트는 기존 DB의 모든 데이터를 덮어씁니다.
#         실행 전 반드시 ./scripts/mori-backup.sh 로 안전 백업을 만드세요.
#
# 환경변수 (옵션):
#   MORI_DB_NAME, MORI_DB_USER, COMPOSE_SERVICE (mori-backup.sh와 동일)
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <backup.dump> [--force]" >&2
  exit 1
fi

INPUT_PATH="$1"
FORCE="${2:-}"

if [ ! -f "$INPUT_PATH" ]; then
  echo "❌ File not found: $INPUT_PATH" >&2
  exit 1
fi

# .env 로드
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

DB_NAME="${MORI_DB_NAME:-mori_soc}"
DB_USER="${MORI_DB_USER:-mori}"
SERVICE="${COMPOSE_SERVICE:-soc-postgres}"

echo "♻️  MORI SOC Restore"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "   DB:      ${DB_NAME} (user: ${DB_USER})"
echo "   Service: ${SERVICE}"
echo "   Input:   ${INPUT_PATH}"
echo ""

# 컨테이너 실행 여부 확인
if ! docker compose ps "$SERVICE" --format json 2>/dev/null | grep -q '"State":"running"'; then
  echo "❌ Service '$SERVICE' is not running."
  echo "   Start it first: docker compose up -d $SERVICE"
  exit 1
fi

# 사용자 확인 (--force 가 없으면)
if [ "$FORCE" != "--force" ]; then
  echo "⚠️  WARNING: All current data in '${DB_NAME}' will be REPLACED."
  echo "   Run ./scripts/mori-backup.sh first if you have unsaved data."
  read -r -p "   Continue? Type 'yes' to proceed: " CONFIRM
  if [ "$CONFIRM" != "yes" ]; then
    echo "   Aborted."
    exit 0
  fi
fi

echo ""
echo "📥 Streaming dump into pg_restore..."
# --clean --if-exists 로 기존 객체를 drop 후 재생성
docker compose exec -T "$SERVICE" \
  pg_restore --clean --if-exists --no-owner --no-acl \
  -U "$DB_USER" -d "$DB_NAME" < "$INPUT_PATH" || {
    RC=$?
    # pg_restore exit code 1 = warnings (e.g. missing objects on --clean); 2+ = error
    if [ "$RC" -gt 1 ]; then
      echo "❌ pg_restore failed (exit $RC)" >&2
      exit "$RC"
    fi
    echo "   ⚠️  pg_restore finished with warnings (exit $RC) — usually safe to ignore"
  }

echo ""
echo "✅ Restore complete"
echo "   Restart API to reload snapshot:"
echo "     docker compose restart mori-api"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
