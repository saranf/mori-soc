"""Incident routes (Task J-4b7).

Registers the incident list / create / update / note endpoints on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures; only the
unpacking preamble (binding shared stores + the ``get_query_service`` /
``get_session_username`` helpers from :class:`RouteContext`) is new.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext


def register_incidents(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    incidents = ctx.incidents
    asset_owners = ctx.asset_owners
    _get_session_username = ctx.get_session_username
    _persist_incident = ctx.persist_incident

    @app.get("/incidents", tags=["Incidents"])
    def incidents_list(date_from: str = "", date_to: str = "", search: str = "", format: str = "json") -> Any:
        import csv as csv_mod
        import io
        all_items = list(incidents.values())
        # Date filtering on created_at
        if date_from:
            try:
                from_dt = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
                if from_dt.tzinfo is None:
                    from_dt = from_dt.replace(tzinfo=timezone.utc)
                all_items = [i for i in all_items if i.get("created_at", "") >= _isoformat(from_dt)]
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="date_from must be ISO format (YYYY-MM-DD)") from exc
        if date_to:
            try:
                to_dt = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
                if to_dt.tzinfo is None:
                    to_dt = to_dt.replace(tzinfo=timezone.utc)
                # Include the whole day
                to_dt = to_dt.replace(hour=23, minute=59, second=59)
                all_items = [i for i in all_items if i.get("created_at", "") <= _isoformat(to_dt)]
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="date_to must be ISO format (YYYY-MM-DD)") from exc
        # Text search: title, analyst, status
        if search:
            kw = search.lower()
            all_items = [
                i for i in all_items
                if kw in i.get("title", "").lower()
                or kw in i.get("analyst", "").lower()
                or kw in i.get("status", "").lower()
            ]
        if format == "csv":
            buf = io.StringIO()
            fieldnames = ["인시던트ID", "제목", "상태", "생성일시", "수정일시", "상태변경일시", "경보수", "노트수"]
            writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for inc in all_items:
                writer.writerow({
                    "인시던트ID": inc.get("incident_id", ""),
                    "제목": inc.get("title", ""),
                    "상태": inc.get("status", ""),
                    "생성일시": inc.get("created_at", ""),
                    "수정일시": inc.get("updated_at", ""),
                    "상태변경일시": inc.get("status_updated_at", ""),
                    "경보수": len(inc.get("alert_ids", [])),
                    "노트수": len(inc.get("notes", [])),
                })
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-incidents-{timestamp}.csv"'},
            )
        # Enrich incidents with related host/owner info
        try:
            store = get_query_service().store
            hostnames_map = {host.host_id: host.hostname for host in store.hosts}
            alert_map = {a.alert_id: a for a in store.alerts}
        except Exception:
            hostnames_map = {}
            alert_map = {}
        enriched = []
        for inc in all_items:
            item = dict(inc)
            # Resolve related hostnames/owners from alert_ids
            related_hosts: list[str] = []
            for aid in inc.get("alert_ids", []):
                alert_obj = alert_map.get(aid)
                if alert_obj:
                    hn = hostnames_map.get(alert_obj.host_id or "", alert_obj.host_id or "")
                    if hn and hn not in related_hosts:
                        related_hosts.append(hn)
            item["related_hosts"] = related_hosts
            owners_list = []
            for hn in related_hosts:
                owner_entry = asset_owners.get(hn, {})
                label = " / ".join(p for p in [owner_entry.get("owner", ""), owner_entry.get("team", "")] if p)
                if label and label not in owners_list:
                    owners_list.append(label)
            item["related_owners"] = owners_list
            enriched.append(item)
        return {"incidents": enriched}

    @app.post("/incidents", tags=["Incidents"])
    def incidents_create(payload: dict[str, Any]) -> dict[str, Any]:
        title = str(payload.get("title", "")).strip()
        if not title:
            raise HTTPException(status_code=400, detail="title is required")
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        analyst = str(payload.get("analyst", "")).strip() or "unknown"
        handler = str(payload.get("handler", "")).strip()
        hostname = str(payload.get("hostname", "")).strip()
        incident: dict[str, Any] = {
            "incident_id": str(uuid.uuid4()),
            "title": title,
            "status": "open",
            "status_updated_at": now_str,
            "hostname": hostname,
            "analyst": analyst,
            "handler": handler or analyst,
            "alert_ids": list(payload.get("alert_ids") or []),
            "notes": [],
            "history": [{"event": "created", "to_status": "open", "analyst": analyst, "changed_at": now_str}],
            "created_at": now_str,
            "updated_at": now_str,
        }
        incidents[incident["incident_id"]] = incident
        _persist_incident(incident["incident_id"])
        return incident

    @app.patch("/incidents/{incident_id}", tags=["Incidents"])
    def incidents_update(incident_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        incident = incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        valid_statuses = {"open", "investigating", "resolved", "closed"}
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        actor = str(payload.get("actor", "")).strip() or _get_session_username(request) or "unknown"
        if "status" in payload:
            new_status = payload["status"]
            if new_status not in valid_statuses:
                raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(sorted(valid_statuses))}")
            prev_status = incident.get("status", "open")
            if new_status != prev_status:
                incident.setdefault("history", []).append({
                    "event": "status_changed",
                    "from_status": prev_status,
                    "to_status": new_status,
                    "analyst": actor,
                    "changed_at": now_str,
                })
                incident["status_updated_at"] = now_str
            incident["status"] = new_status
        if "analyst" in payload:
            new_analyst = str(payload["analyst"]).strip()
            prev_analyst = incident.get("analyst", "")
            if new_analyst and new_analyst != prev_analyst:
                incident.setdefault("history", []).append({
                    "event": "analyst_changed",
                    "from_analyst": prev_analyst,
                    "to_analyst": new_analyst,
                    "analyst": actor,
                    "changed_at": now_str,
                })
                incident["analyst"] = new_analyst
        if "handler" in payload:
            new_handler = str(payload["handler"]).strip()
            prev_handler = incident.get("handler", "")
            if new_handler and new_handler != prev_handler:
                incident.setdefault("history", []).append({
                    "event": "handler_changed",
                    "from_handler": prev_handler,
                    "to_handler": new_handler,
                    "analyst": actor,
                    "changed_at": now_str,
                })
                incident["handler"] = new_handler
        if "title" in payload:
            incident["title"] = str(payload["title"]).strip()
        if "alert_ids" in payload:
            incident["alert_ids"] = list(payload["alert_ids"] or [])
        incident["updated_at"] = now_str
        _persist_incident(incident_id)
        return incident

    @app.post("/incidents/{incident_id}/notes", tags=["Incidents"])
    def incidents_add_note(incident_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        incident = incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        text = str(payload.get("text", "")).strip()
        if not text:
            raise HTTPException(status_code=400, detail="text is required")
        note: dict[str, Any] = {
            "note_id": str(uuid.uuid4()),
            "text": text,
            "analyst": str(payload.get("analyst", "")).strip() or "unknown",
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        incident["notes"].append(note)
        incident["updated_at"] = note["created_at"]
        _persist_incident(incident_id)
        return note


__all__ = ["register_incidents"]
