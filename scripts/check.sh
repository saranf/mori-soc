#!/usr/bin/env bash
# 커밋/푸시 전 빠른 품질 게이트(R2) — CI 반복 실패(ruff·팔레트·JS 붕괴) 재발 방지.
#
# 전체 postgres 스위트·trivy·headless 는 CI 가 담당하고, 여기선 "빠르고 자주 깨지던" 것만
# 로컬에서 선제 차단한다: ruff(import 정렬 등) · JS 문법 · 6색 팔레트 · 핵심 순수 테스트.
# 실행: bash scripts/check.sh   (또는 make check)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== [1/3] ruff (lint · import 정렬) =="
docker run --rm -v "$PWD:/w" -w /w python:3.12-slim sh -c "pip install -q ruff && ruff check src tests"

echo "== [2/3] JS 문법 (console · dashboard) =="
for f in console dashboard; do
  docker run --rm -v "$PWD/src/mori_soc/api/static/js/$f.js:/x.js:ro" node:20-alpine node --check /x.js
  echo "  $f.js OK"
done

echo "== [3/3] 팔레트(6색) + 핵심 순수 테스트 (memory) =="
docker compose run --rm --no-deps -v "$PWD/src:/app/src" -v "$PWD/tests:/app/tests" \
  -e PYTHONPATH=/app/src:/app -e MORI_QUERY_BACKEND=memory -e MORI_ADMIN_PASSWORD=1234 -e MORI_DEMO_MODE=true \
  mori-api python -m unittest \
    tests.test_toss_palette tests.test_onboarding tests.test_secure_boot \
    tests.test_session_store tests.test_query_cache 2>&1 | tail -3

echo ""
echo "ALL CHECKS PASSED — 푸시해도 CI ruff/팔레트에서 안 막힙니다."
echo "(전체 postgres 스위트·trivy·headless 는 CI 에서 최종 확인)"
