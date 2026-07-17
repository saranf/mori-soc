"""MORI 단일 버전 출처(single source of truth).

pyproject(빌드 메타데이터)·FastAPI 앱 버전·CHANGELOG 헤더가 모두 이 값을 참조한다.
이전에는 pyproject 0.6.0 / FastAPI 0.2.0 / CHANGELOG v0.18.x 로 3중 불일치였다 — 신뢰 훼손.
릴리스 시 이 파일 한 곳만 올린다.
"""
from __future__ import annotations

__version__ = "0.6.0"
