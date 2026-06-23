"""Guide routes (Task J-4b3).

Registers ``GET /guides``, ``GET /guides/{guide_id}`` and ``PUT /guides/{guide_id}``
on ``ctx.app``. Handler bodies are verbatim from the original ``create_app``
closures; only the unpacking preamble (binding ``ctx.guides``) is new.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext


def register_guides(ctx: RouteContext) -> None:
    app = ctx.app
    guides = ctx.guides

    @app.get("/guides")
    def guides_list() -> Any:
        return {"guides": list(guides.values())}

    @app.get("/guides/{guide_id}")
    def guide_get(guide_id: str) -> Any:
        if guide_id not in guides:
            raise HTTPException(status_code=404, detail="guide not found")
        return guides[guide_id]

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
