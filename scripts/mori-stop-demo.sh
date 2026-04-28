#!/usr/bin/env bash
# ============================================================================
# MORI SOC — 데모 모드 정지 + 샘플 데이터 정리
#
# 사용법:
#   ./scripts/mori-stop-demo.sh           # 데모 데이터만 삭제 + 컨테이너 정지
#   ./scripts/mori-stop-demo.sh --keep    # 데모 데이터만 삭제 (컨테이너 유지)
#   ./scripts/mori-stop-demo.sh --purge   # 데모 데이터 + 컨테이너 + 볼륨 모두 삭제
#
# mori-seed-sample-data.sh 가 삽입한 ID 만 정확히 매칭해 삭제하므로,
# 폴러가 실제로 수집한 데이터는 보존됩니다.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

MODE="${1:-stop}"

if [ -f .env ]; then
  set -a; source .env; set +a
fi
DB_NAME="${MORI_DB_NAME:-mori_soc}"
DB_USER="${MORI_DB_USER:-mori}"

run_sql() {
  docker compose exec -T soc-postgres psql -U "$DB_USER" -d "$DB_NAME" -q <<< "$1"
}

echo "🧹 MORI SOC Demo Stop"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# --purge 시 컨테이너+볼륨 통째로 제거 (데이터 전부 손실)
if [ "$MODE" = "--purge" ]; then
  echo "⚠️  --purge: 컨테이너 + 볼륨 모두 삭제합니다 (모든 데이터 손실)"
  docker compose down -v
  echo "   ✅ All containers and volumes removed."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 0
fi

# DB 가 떠 있는지 확인 (없으면 데이터 정리 스킵)
if ! docker compose ps --status running --services 2>/dev/null | grep -q '^soc-postgres$'; then
  echo "ℹ️  soc-postgres 가 실행 중이 아닙니다. 데이터 정리를 건너뜁니다."
else
  echo "🗑  Removing demo seed rows from $DB_NAME..."

  # 1) Source-syncs (데모용 4개 소스, 폴러가 같은 source 키를 덮어쓰므로 신중히)
  #    → 실제 폴러가 돌고 있다면 records_collected 등이 바뀌었을 것이므로
  #      seed 가 넣은 정확한 값일 때만 지우는 건 어려움. 데모 4행은 그냥 보존.

  # 2) 자식 테이블부터 삭제 (FK 의존성)
  run_sql "
  DELETE FROM group_memberships WHERE membership_id IN
    ('gm-01','gm-02','gm-03','gm-04','gm-05','gm-06','gm-07','gm-08');
  DELETE FROM privilege_bindings WHERE binding_id IN
    ('pb-01','pb-02','pb-03','pb-04','pb-05','pb-06');
  DELETE FROM directory_accounts WHERE account_id IN
    ('acct-admin','acct-sec01','acct-dev01','acct-dev02','acct-ops01','acct-dba01','acct-ext01');
  DELETE FROM control_check_results WHERE check_id IN
    ('cc-01','cc-02','cc-03','cc-04','cc-05','cc-06','cc-07','cc-08','cc-09','cc-10','cc-11','cc-12');
  DELETE FROM host_observations WHERE observation_id IN
    ('obs-01','obs-02','obs-03','obs-04','obs-05','obs-06','obs-07','obs-08','obs-09');
  DELETE FROM vulnerabilities WHERE vuln_id IN
    ('v-01','v-02','v-03','v-04','v-05','v-06','v-07','v-08');
  DELETE FROM alerts WHERE alert_id IN
    ('al-01','al-02','al-03','al-04','al-05','al-06','al-07','al-08');
  DELETE FROM host_aliases WHERE alias_id IN
    ('a-z-01','a-z-02','a-z-03','a-z-04','a-z-05','a-z-06','a-z-07',
     'a-f-01','a-f-02','a-f-03','a-t-01','a-t-02','a-t-03');
  DELETE FROM hosts WHERE host_id IN
    ('h-web-01','h-web-02','h-db-01','h-db-02','h-app-01',
     'h-pc-01','h-pc-02','h-pc-03','h-fw-01','h-vpn-01');
  " 2>&1 | grep -E '^DELETE' || true

  echo "   ✅ Demo seed rows deleted (실제 수집 데이터는 보존)."
fi

# --keep 이면 컨테이너 정지 안 함
if [ "$MODE" = "--keep" ]; then
  echo ""
  echo "ℹ️  --keep: 컨테이너는 그대로 유지합니다."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  exit 0
fi

# 기본: 컨테이너 정지 (볼륨 보존)
echo ""
echo "⏹  Stopping containers (volumes preserved)..."
docker compose stop
echo "   ✅ Containers stopped. Restart with: ./scripts/mori-start-demo.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
