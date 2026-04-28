#!/usr/bin/env bash
# ============================================================================
# MORI SOC — 원커맨드 데모 실행
#
# 사용법:
#   ./scripts/mori-start-demo.sh
#
# .env 파일이 없으면 .env.example 을 복사하여 자동 생성합니다.
# 핵심 서비스(DB, API, Worker)만 기동하고, 샘플 데이터를 시딩합니다.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🚀 MORI SOC Demo Start"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1) .env 확인
if [ ! -f .env ]; then
  echo "📄 .env not found — copying from .env.example"
  cp .env.example .env
  echo "   ✅ .env created (edit passwords for production)"
fi

# 2) Build & start core services
echo ""
echo "🔧 Building & starting core services..."
docker compose up -d --build soc-postgres openldap mori-api

echo ""
echo "⏳ Waiting for mori-api to be healthy..."
for i in $(seq 1 30); do
  if docker compose exec -T mori-api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" 2>/dev/null; then
    echo "   ✅ mori-api is healthy"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "   ❌ mori-api failed to become healthy after 30 attempts"
    echo "   Check logs: docker compose logs mori-api"
    exit 1
  fi
  sleep 2
done

# 4) Seed sample data
echo ""
echo "🌱 Seeding sample data..."
bash "$SCRIPT_DIR/mori-seed-sample-data.sh"

# 4-1) Seed demo incidents (in-memory store, requires running API)
echo ""
echo "📋 Creating demo incidents..."
MORI_PORT="${MORI_API_PORT:-18000}"
post_incident() {
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:${MORI_PORT}/incidents" \
    -H "Content-Type: application/json" -d "$1" || echo "000"
}
codes=()
codes+=( "$(post_incident '{"title":"SSH brute force on web-server-01","hostname":"web-server-01","analyst":"security","alert_ids":["al-01"]}')" )
codes+=( "$(post_incident '{"title":"Rootkit detection requires forensic review","hostname":"web-server-01","analyst":"security","alert_ids":["al-02"]}')" )
codes+=( "$(post_incident '{"title":"db-primary disk usage critical","hostname":"db-primary","analyst":"monitor","alert_ids":["al-03"]}')" )
ok_count=0
for c in "${codes[@]}"; do [ "$c" = "200" ] && ok_count=$((ok_count+1)); done
echo "   ✅ ${ok_count}/3 demo incidents created (in-memory; reset on API restart)"

# 5) Start worker (background, optional — mori-api uses same image)
echo ""
echo "🔄 Starting worker (if available)..."
docker compose up -d mori-worker 2>/dev/null || echo "   ⚠️  Worker skipped (dependency not ready — OK for demo mode)"

# 6) Summary
MORI_PORT="${MORI_API_PORT:-18000}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ MORI SOC Demo is running!"
echo ""
echo "   🌐 Dashboard:  http://localhost:${MORI_PORT}/ui"
echo "   🔑 API:        http://localhost:${MORI_PORT}/docs"
echo "   📊 Health:     http://localhost:${MORI_PORT}/health"
echo ""
echo "   Default login: admin / 1234"
echo ""
echo "   Stop demo (preserve real data):  ./scripts/mori-stop-demo.sh"
echo "   Stop containers only:            ./scripts/mori-stop-demo.sh --keep"
echo "   Wipe everything (volumes too):   ./scripts/mori-stop-demo.sh --purge"
echo "   Logs:                            docker compose logs -f mori-api"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

