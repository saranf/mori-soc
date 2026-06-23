"""Slack webhook management routes (Task J-4b1).

Registers the ``/webhooks`` CRUD + test endpoints on ``ctx.app``. The handler
bodies are kept verbatim from the original ``create_app`` closures; the only
change is the unpacking preamble that binds ``webhooks`` from the shared
:class:`~mori_soc.api.routes.context.RouteContext`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from mori_soc.api.payloads import _isoformat, _send_slack_message
from mori_soc.api.routes.context import RouteContext


def register_webhooks(ctx: RouteContext) -> None:
    app = ctx.app
    webhooks = ctx.webhooks

    @app.get("/webhooks")
    def webhooks_list() -> dict[str, Any]:
        return {"webhooks": webhooks}

    @app.post("/webhooks")
    def webhooks_add(payload: dict[str, Any]) -> dict[str, Any]:
        name = str(payload.get("name", "")).strip()
        url = str(payload.get("url", "")).strip()
        if not url.startswith("https://hooks.slack.com/") and not url.startswith("http"):
            raise HTTPException(status_code=400, detail="url must be a valid webhook URL")
        entry: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "name": name or "Slack Webhook",
            "url": url,
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        webhooks.append(entry)
        return entry

    @app.delete("/webhooks/{webhook_id}")
    def webhooks_delete(webhook_id: str) -> dict[str, Any]:
        idx = next((i for i, w in enumerate(webhooks) if w["id"] == webhook_id), None)
        if idx is None:
            raise HTTPException(status_code=404, detail="webhook not found")
        removed = webhooks.pop(idx)
        return {"deleted": removed["id"]}

    @app.post("/webhooks/{webhook_id}/test")
    def webhooks_test(webhook_id: str) -> dict[str, Any]:
        wh = next((w for w in webhooks if w["id"] == webhook_id), None)
        if wh is None:
            raise HTTPException(status_code=404, detail="webhook not found")
        ok, err = _send_slack_message(wh["url"], ":white_check_mark: MORI SOC 알림 테스트 메시지입니다.")
        if not ok:
            raise HTTPException(status_code=502, detail=f"slack delivery failed: {err}")
        return {"ok": True}


__all__ = ["register_webhooks"]
