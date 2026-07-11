"""Guide routes (Task J-4b3).

Registers ``GET /guides``, ``GET /guides/{guide_id}`` and ``PUT /guides/{guide_id}``
on ``ctx.app``. Handler bodies are verbatim from the original ``create_app``
closures; only the unpacking preamble (binding ``ctx.guides``) is new.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext


def _resolve_lang(request: Request) -> str:
    """요청 언어 결정: ?lang= 우선, 없으면 mori_lang 쿠키, 기본 ko."""
    lang = (request.query_params.get("lang") or request.cookies.get("mori_lang") or "ko").lower()
    return "en" if lang == "en" else "ko"


def _localize(guide: dict[str, Any], lang: str) -> dict[str, Any]:
    """lang=en 이면 title_en/content_en 을 title/content 로 노출(없으면 한글 폴백).

    관리자가 저장한 커스텀 내용(title/content)이 있으면 그것을 우선한다:
    ``updated_at`` 이 설정돼 있으면 사용자가 편집한 것이므로 언어 치환하지 않는다.
    """
    if lang != "en" or guide.get("updated_at"):
        return guide
    out = dict(guide)
    if guide.get("title_en"):
        out["title"] = guide["title_en"]
    if guide.get("content_en"):
        out["content"] = guide["content_en"]
    return out


def register_guides(ctx: RouteContext) -> None:
    app = ctx.app
    guides = ctx.guides

    @app.get("/guides")
    def guides_list(request: Request) -> Any:
        lang = _resolve_lang(request)
        return {"guides": [_localize(g, lang) for g in guides.values()]}

    @app.get("/guides/{guide_id}")
    def guide_get(guide_id: str, request: Request) -> Any:
        if guide_id not in guides:
            raise HTTPException(status_code=404, detail="guide not found")
        return _localize(guides[guide_id], _resolve_lang(request))

    @app.put("/guides/{guide_id}")
    def guide_upsert(guide_id: str, payload: dict[str, Any]) -> Any:
        existing = guides.get(guide_id, {"id": guide_id})
        entry = {
            **existing,
            "title": str(payload.get("title", existing.get("title", guide_id))).strip(),
            "content": str(payload.get("content", existing.get("content", ""))),
            "updated_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        guides[guide_id] = entry
        return entry


__all__ = ["register_guides"]
