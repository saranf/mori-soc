"""Per-vulnerability action routes (Task J-4b6).

Registers the vulnerability plan / exception endpoints on ``ctx.app``. Handler
bodies — and the four block-local helpers (``_vuln_action_default``,
``_vuln_exists``, ``_vuln_lookup``, ``_record_vuln_audit``) — are verbatim from
the original ``create_app`` closures; only the unpacking preamble (binding shared
stores + the ``get_query_service`` / ``get_session_username`` helpers from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext


def register_vulnerabilities(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    asset_audit_log = ctx.asset_audit_log
    vuln_actions = ctx.vuln_actions
    _get_session_username = ctx.get_session_username

    def _vuln_action_default(vuln_id: str) -> dict[str, Any]:
        return {
            "vuln_id": vuln_id,
            "plan_text": "", "plan_target_date": "", "plan_updated_by": "",
            "exception_until": "", "exception_reason": "", "exception_updated_by": "",
            "updated_at": None,
        }

    def _vuln_exists(vuln_id: str) -> bool:
        for v in get_query_service().store.vulnerabilities:
            if v.vuln_id == vuln_id:
                return True
        return False

    def _vuln_lookup(vuln_id: str) -> tuple[Any, str, str]:
        """vuln_id → (vuln_obj, hostname, cve_label) 반환. 없으면 (None, "", vuln_id)."""
        store_ = get_query_service().store
        for v in store_.vulnerabilities:
            if v.vuln_id == vuln_id:
                hostname = next((h.hostname for h in store_.hosts if h.host_id == v.host_id), v.host_id)
                return v, hostname, (v.cve or vuln_id)
        return None, "", vuln_id

    def _record_vuln_audit(
        hostname: str,
        cve_label: str,
        old_entry: dict[str, Any],
        new_entry: dict[str, Any],
        changed_by: str,
        now_str: str,
        fields: tuple[str, ...],
    ) -> None:
        """vuln_actions 변경분을 asset_audit_log에 기록한다."""
        if not hostname:
            return
        for fld in fields:
            old_val = old_entry.get(fld, "")
            new_val = new_entry.get(fld, "")
            if old_val == new_val:
                continue
            asset_audit_log.append({
                "log_id": str(uuid.uuid4()),
                "hostname": hostname,
                "field": f"vuln_{fld} [{cve_label}]",
                "old_value": old_val,
                "new_value": new_val,
                "changed_by": changed_by,
                "changed_at": now_str,
            })

    @app.get("/vulnerabilities/{vuln_id}/action", tags=["Vulnerabilities"])
    def vuln_action_get(vuln_id: str) -> Any:
        if not _vuln_exists(vuln_id):
            raise HTTPException(status_code=404, detail="vulnerability not found")
        return vuln_actions.get(vuln_id, _vuln_action_default(vuln_id))

    @app.put("/vulnerabilities/{vuln_id}/plan", tags=["Vulnerabilities"])
    def vuln_plan_upsert(vuln_id: str, payload: dict[str, Any], request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        old_entry = dict(vuln_actions.get(vuln_id, _vuln_action_default(vuln_id)))
        entry = old_entry | {"vuln_id": vuln_id}
        entry["plan_text"] = str(payload.get("plan_text", "")).strip()
        entry["plan_target_date"] = str(payload.get("plan_target_date", "")).strip()
        entry["plan_updated_by"] = str(payload.get("plan_updated_by", "")).strip() or "unknown"
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        vuln_actions[vuln_id] = entry
        changed_by = entry["plan_updated_by"] if entry["plan_updated_by"] != "unknown" else (_get_session_username(request) or "unknown")
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("plan_text", "plan_target_date"))
        return entry

    @app.put("/vulnerabilities/{vuln_id}/exception", tags=["Vulnerabilities"])
    def vuln_exception_upsert(vuln_id: str, payload: dict[str, Any], request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        old_entry = dict(vuln_actions.get(vuln_id, _vuln_action_default(vuln_id)))
        entry = old_entry | {"vuln_id": vuln_id}
        entry["exception_until"] = str(payload.get("exception_until", "")).strip()
        entry["exception_reason"] = str(payload.get("exception_reason", "")).strip()
        entry["exception_updated_by"] = str(payload.get("exception_updated_by", "")).strip() or "unknown"
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        vuln_actions[vuln_id] = entry
        changed_by = entry["exception_updated_by"] if entry["exception_updated_by"] != "unknown" else (_get_session_username(request) or "unknown")
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("exception_until", "exception_reason"))
        return entry

    @app.delete("/vulnerabilities/{vuln_id}/exception", tags=["Vulnerabilities"])
    def vuln_exception_clear(vuln_id: str, request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        entry = vuln_actions.get(vuln_id)
        if entry is None:
            return {"ok": True}
        old_entry = dict(entry)
        entry["exception_until"] = ""
        entry["exception_reason"] = ""
        entry["exception_updated_by"] = ""
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        changed_by = _get_session_username(request) or "unknown"
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("exception_until", "exception_reason"))
        return {"ok": True, "vuln_id": vuln_id}


__all__ = ["register_vulnerabilities"]
