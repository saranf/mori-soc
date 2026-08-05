# MORI SOC — 개발 편의 타깃(R2). 커밋/푸시 전 로컬 품질 게이트.
.PHONY: check headless install-hooks

# 빠른 게이트: ruff · JS 문법 · 6색 팔레트 · 핵심 순수 테스트 (CI 반복 실패 재발 방지).
check:
	@bash scripts/check.sh

# 프론트 런타임 가드(pageerror==0) — dashboard/console 을 chromium(headless)으로 로드.
headless:
	docker run --rm -v "$(CURDIR)":/app -w /app -e PYTHONPATH=src \
	  mcr.microsoft.com/playwright/python:v1.47.0-jammy \
	  bash -c 'pip install -q playwright==1.47.0; python scripts/dashboard_headless_check.py && python scripts/console_headless_check.py'

# pre-push 훅 설치(옵트인) — 푸시 전 `make check` 자동 실행.
install-hooks:
	@bash scripts/install-git-hooks.sh
