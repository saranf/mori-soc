"""Host-level action plan routes (Task J-4b5).

Registers ``GET /assets/plans/{host_id}`` and ``PUT /assets/plans/{host_id}`` on
``ctx.app``. Handler bodies are verbatim from the original ``create_app``
closures; only the unpacking preamble (binding ``ctx.action_plans``) is new.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext


def register_plans(ctx: RouteContext) -> None:
    app = ctx.app
    action_plans = ctx.action_plans

    @app.get("/assets/plans/{host_id}")
    def plan_get(host_id: str) -> Any:
        return action_plans.get(host_id, {"host_id": host_id, "text": "", "target_date": "", "updated_by": "", "updated_at": None})

    @app.put("/assets/plans/{host_id}")
    def plan_upsert(host_id: str, payload: dict[str, Any]) -> Any:
        entry = {
            "host_id": host_id,
            "text": str(payload.get("text", "")).strip(),
            "target_date": str(payload.get("target_date", "")).strip(),
            "updated_by": str(payload.get("updated_by", "")).strip() or "unknown",
            "updated_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        action_plans[host_id] = entry
        return entry


__all__ = ["register_plans"]
