"""Org-settings routes — currently the risk DoA (수용가능 위험 기준) threshold.

DoA (Degree of Acceptance) is a single org-wide score on the 1~9 risk scale
(impact × likelihood). Any vulnerability whose risk score is at or below the DoA
is treated as **기본 수용가능(auto-acceptable)** unless a stricter treatment was
explicitly recorded. Admin sets it from the dashboard; it persists via the
shared settings store (``ctx.settings`` + ``ctx.persist_setting``).
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.routes.context import RouteContext

RISK_DOA_KEY = "risk_doa"
RISK_DOA_DEFAULT = 4  # 1~9 중 4점 이하(중간 이하) 자동 수용이 기본
RISK_DOA_MIN = 1
RISK_DOA_MAX = 9


def read_risk_doa(settings: dict[str, str]) -> int:
    """Read the DoA threshold from the settings map, clamped to 1..9."""
    raw = (settings or {}).get(RISK_DOA_KEY, "")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return RISK_DOA_DEFAULT
    return max(RISK_DOA_MIN, min(RISK_DOA_MAX, value))


def register_settings(ctx: RouteContext) -> None:
    app = ctx.app
    settings = ctx.settings
    sessions = ctx.sessions

    def _username(request: Request) -> str:
        # 공용 RouteContext.session_username 로 위임(공통화 C3).
        return ctx.session_username(request)

    @app.get("/settings/risk", tags=["Settings"])
    def get_risk_settings() -> dict[str, Any]:
        """현재 위험 DoA 기준을 반환(읽기는 모든 로그인 사용자 허용)."""
        return {
            "doa": read_risk_doa(settings),
            "default": RISK_DOA_DEFAULT,
            "min": RISK_DOA_MIN,
            "max": RISK_DOA_MAX,
        }

    @app.put("/settings/risk", tags=["Settings"])
    def put_risk_settings(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """위험 DoA 기준 저장 — admin 전용."""
        ctx.require_role(request, {"admin"}, detail="risk settings require admin role")
        raw = payload.get("doa")
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="doa must be an integer 1..9") from None
        if not (RISK_DOA_MIN <= value <= RISK_DOA_MAX):
            raise HTTPException(status_code=400, detail="doa must be in 1..9")
        settings[RISK_DOA_KEY] = str(value)
        if ctx.persist_setting:
            ctx.persist_setting(RISK_DOA_KEY, _username(request))
        return {"doa": value}


__all__ = ["register_settings", "read_risk_doa", "RISK_DOA_KEY", "RISK_DOA_DEFAULT"]
