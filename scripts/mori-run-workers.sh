#!/usr/bin/env bash
# ============================================================================
# MORI SOC — Worker 실행/관리 스크립트
#
# 사용법:
#   ./scripts/mori-run-workers.sh              # 통합 워커 시작
#   ./scripts/mori-run-workers.sh status       # 워커 상태 확인
#   ./scripts/mori-run-workers.sh restart      # 워커 재시작
#   ./scripts/mori-run-workers.sh logs         # 워커 로그 확인
#   ./scripts/mori-run-workers.sh cycle        # 수동 1회 수집 사이클 실행
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

ACTION="${1:-start}"

case "$ACTION" in
  start)
    echo "🔄 Starting MORI unified worker..."
    docker compose up -d mori-worker
    echo "   ✅ Worker started"
    echo "   📋 Logs: docker compose logs -f mori-worker"
    echo ""
    echo "   Enabled pollers (from .env):"
    grep -E '^MORI_ENABLE_' .env 2>/dev/null | while IFS='=' read -r key val; do
      icon="❌"
      [ "$val" = "true" ] && icon="✅"
      poller="${key#MORI_ENABLE_}"
      echo "     $icon $poller"
    done || echo "     (check .env for MORI_ENABLE_* settings)"
    ;;

  status)
    echo "📊 Worker status:"
    docker compose ps mori-worker 2>/dev/null || echo "   Worker is not running"
    echo ""
    echo "🔍 Latest sync status from API:"
    MORI_PORT="${MORI_API_PORT:-18000}"
    curl -s "http://localhost:${MORI_PORT}/dashboard/summary" 2>/dev/null | \
      python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    syncs = data.get('source_syncs', [])
    if not syncs:
        print('   No sync data available')
    else:
        for s in syncs:
            icon = '✅' if s.get('status') == 'success' else '❌'
            print(f\"   {icon} {s['source']:10s}  {s.get('status','?'):8s}  last: {s.get('last_sync_at','N/A')}\")
except Exception:
    print('   Could not fetch sync status')
" 2>/dev/null || echo "   Could not connect to API"
    ;;

  restart)
    echo "🔄 Restarting worker..."
    docker compose restart mori-worker
    echo "   ✅ Worker restarted"
    ;;

  logs)
    echo "📋 Worker logs (Ctrl+C to exit):"
    docker compose logs -f --tail=100 mori-worker
    ;;

  cycle)
    echo "⚡ Running one-shot collection cycle..."
    docker compose exec -T mori-api python -c "
from mori_soc.worker import build_pollers_from_env, run_ingestion_cycle
from mori_soc.repositories import create_repository_from_env
from mori_soc.services.normalization import EnvelopeEntityMapper

repo = create_repository_from_env()
pollers = build_pollers_from_env()
mapper = EnvelopeEntityMapper()
print(f'Found {len(pollers)} enabled pollers')
for p in pollers:
    print(f'  Running: {p.__class__.__name__}')
results = run_ingestion_cycle(repo, pollers, mapper=mapper)
for r in results:
    print(f'  ✅ {r.source}: collected={r.records_collected} saved={r.entities_saved}')
print('Done!')
" 2>/dev/null || echo "   ❌ Cycle execution failed. Is mori-api running?"
    ;;

  stop)
    echo "⏹ Stopping worker..."
    docker compose stop mori-worker
    echo "   ✅ Worker stopped"
    ;;

  *)
    echo "Usage: $0 {start|status|restart|logs|cycle|stop}"
    exit 1
    ;;
esac

