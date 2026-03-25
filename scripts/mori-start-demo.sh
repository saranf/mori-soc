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
docker compose up -d --build soc-postgres mori-api

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

# 3) Seed sample data
echo ""
echo "🌱 Seeding sample data..."
bash "$SCRIPT_DIR/mori-seed-sample-data.sh"

# 4) Start worker (background)
echo ""
echo "🔄 Starting worker..."
docker compose up -d mori-worker

# 5) Summary
MORI_PORT="${MORI_API_PORT:-18000}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ MORI SOC Demo is running!"
echo ""
echo "   🌐 Dashboard:  http://localhost:${MORI_PORT}/ui"
echo "   🔑 API:        http://localhost:${MORI_PORT}/docs"
echo "   📊 Health:     http://localhost:${MORI_PORT}/health"
echo ""
echo "   Default login: admin / admin"
echo ""
echo "   Stop:  docker compose down"
echo "   Logs:  docker compose logs -f mori-api"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

