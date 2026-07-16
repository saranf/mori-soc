"""Asset routes (Task J-4b14).

Registers the asset collection board (``/assets`` + CSV export), the on-demand
refresh trigger (``/assets/refresh``), and the asset-owner CRUD endpoints
(``/assets/owners`` …) on ``ctx.app``. Handler bodies — including the lazy poller
imports inside ``/assets/refresh`` — are verbatim from the original ``create_app``
closures; only the unpacking preamble (binding shared stores + the
``get_query_service`` / ``get_session_username`` helpers from
:class:`RouteContext`) and the module-level ``logger`` are new.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from mori_soc.api.payloads import _assets_csv, _isoformat, build_assets_payload
from mori_soc.api.routes.context import RouteContext

logger = logging.getLogger("mori_soc.api")


def register_assets(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    asset_owners = ctx.asset_owners
    asset_audit_log = ctx.asset_audit_log
    action_plans = ctx.action_plans
    vuln_actions = ctx.vuln_actions
    _get_session_username = ctx.get_session_username
    _persist_asset_owner = ctx.persist_asset_owner
    _delete_asset_owner = ctx.delete_asset_owner
    _persist_asset_audit = ctx.persist_asset_audit

    # ── Asset Owners ─────────────────────────────────────────────────────────
    @app.get("/assets/owners", tags=["Assets"])
    def owners_list() -> Any:
        return {"owners": list(asset_owners.values())}

    def _upsert_owner(payload: dict[str, Any], changed_by: str) -> dict[str, Any]:
        """자산 담당자 1건 upsert(변경 감사 포함). 단건 API·CSV import 공통 사용."""
        hostname = str(payload.get("hostname", "")).strip()
        if not hostname:
            raise HTTPException(status_code=400, detail="hostname is required")
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        old_entry = asset_owners.get(hostname, {})
        entry = {
            "hostname": hostname,
            "owner": str(payload.get("owner", old_entry.get("owner", ""))).strip(),
            "category": str(payload.get("category", old_entry.get("category", ""))).strip(),
            "importance": str(payload.get("importance", old_entry.get("importance", ""))).strip(),
            "exception_until": str(payload.get("exception_until", old_entry.get("exception_until", ""))).strip(),
            "exception_reason": str(payload.get("exception_reason", old_entry.get("exception_reason", ""))).strip(),
            "email": str(payload.get("email", old_entry.get("email", ""))).strip(),
            "team": str(payload.get("team", old_entry.get("team", ""))).strip(),
            "updated_at": now_str,
        }
        for field in ("owner", "category", "importance", "exception_until", "exception_reason"):
            old_val = old_entry.get(field, "")
            if entry[field] != old_val:
                audit_entry = {
                    "log_id": str(uuid.uuid4()), "hostname": hostname, "field": field,
                    "old_value": old_val, "new_value": entry[field],
                    "changed_by": changed_by, "changed_at": now_str,
                }
                asset_audit_log.append(audit_entry)
                _persist_asset_audit(audit_entry)
        asset_owners[hostname] = entry
        _persist_asset_owner(hostname)
        return entry

    @app.post("/assets/owners")
    def owners_upsert(payload: dict[str, Any], request: Request) -> Any:
        return _upsert_owner(payload, _get_session_username(request) or "unknown")

    # 자산 담당자 CSV 가져오기 — export(openCsvPreview)와 짝. 헤더는 한/영 별칭 허용.
    _OWNER_ALIASES: dict[str, list[str]] = {
        "hostname": ["호스트명", "host", "호스트", "장비명", "서버명"],
        "owner": ["담당자", "담당", "관리자"],
        "team": ["팀", "부서", "소속"],
        "email": ["이메일", "메일"],
        "category": ["구분", "분류", "카테고리", "용도"],
        "importance": ["중요도", "등급"],
    }

    def _session_role(request: Request) -> str | None:
        token = request.cookies.get("mori_session", "") if hasattr(request, "cookies") else ""
        sess = ctx.sessions.get(token) if ctx.sessions else None
        return (sess or {}).get("role")

    @app.get("/assets/owners/import-template.csv", tags=["Assets"])
    def owners_import_template() -> StreamingResponse:
        """자산 담당자 가져오기 양식(헤더 + 예시 1행)."""
        from mori_soc.services.csv_import import sample_csv
        example = {"hostname": "web-01", "owner": "홍길동", "team": "인프라팀",
                   "email": "hong@example.com", "category": "웹서버", "importance": "상"}
        body = sample_csv(_OWNER_ALIASES, example)
        return StreamingResponse(
            iter(["﻿" + body]), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="mori-asset-owners-template.csv"'})

    @app.post("/assets/owners/import", tags=["Assets"])
    def owners_import(payload: dict[str, Any], request: Request) -> Any:
        """CSV 텍스트를 받아 자산 담당자를 일괄 upsert. admin·security 전용(대량 변경)."""
        if ctx.auth_enabled and _session_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="자산 일괄 가져오기는 admin·security 전용입니다.")
        from mori_soc.services.csv_import import parse_csv
        rows, errors = parse_csv(str(payload.get("csv", "")), _OWNER_ALIASES, required=["hostname"])
        changed_by = _get_session_username(request) or "unknown"
        imported = 0
        for row in rows:
            try:
                _upsert_owner(row, changed_by)
                imported += 1
            except HTTPException as exc:
                errors.append(f"{row.get('hostname', '?')}: {exc.detail}")
        return {"imported": imported, "rows": len(rows), "errors": errors}

    @app.delete("/assets/owners/{hostname}")
    def owners_delete(hostname: str) -> Any:
        if hostname not in asset_owners:
            raise HTTPException(status_code=404, detail="owner not found")
        asset_owners.pop(hostname)
        _delete_asset_owner(hostname)
        return {"deleted": hostname}

    # ── Asset Collection Board ───────────────────────────────────────────────
    @app.get("/assets", tags=["Assets"])
    def assets_get(format: str = "json", source: str = "all") -> Any:
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"assets unavailable: {exc}") from exc
        if format == "csv":
            valid_sources = {"fleet", "zabbix", "trivy"}
            if source not in valid_sources:
                raise HTTPException(status_code=400, detail=f"source must be one of: {', '.join(sorted(valid_sources))}")
            csv_content = _assets_csv(payload, source)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"mori-assets-{source}-{timestamp}.csv"
            return StreamingResponse(
                iter([csv_content]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        return payload

    # ── On-demand 수집 (사용자 새로고침 시 즉시 폴링) ──────────────────────
    @app.post("/assets/refresh", tags=["Assets"])
    def assets_refresh(payload: dict[str, Any], request: Request) -> Any:
        """사용자가 새로고침 버튼을 누르면 해당 소스를 on-demand 수집한다.

        요청: ``{"source": "zabbix"}`` 또는 ``{"source": "fleet"}``
        응답: 수집 결과 상태
        """
        source = str(payload.get("source", "")).strip().lower()
        valid_sources = {"zabbix", "fleet", "wazuh", "trivy"}
        if source not in valid_sources:
            raise HTTPException(status_code=400, detail=f"source must be one of: {', '.join(sorted(valid_sources))}")

        from mori_soc.pollers.fleet import FleetPoller
        from mori_soc.pollers.trivy import TrivyPoller
        from mori_soc.pollers.wazuh import WazuhPoller
        from mori_soc.pollers.zabbix import ZabbixPoller
        from mori_soc.services import EnvelopeEntityMapper as _EM

        poller_map: dict[str, type] = {
            "zabbix": ZabbixPoller,
            "fleet": FleetPoller,
            "wazuh": WazuhPoller,
            "trivy": TrivyPoller,
        }
        poller_cls = poller_map[source]
        poller = poller_cls()

        try:
            mapper = _EM()
            from mori_soc.pollers.base import _repository_from_env
            repository = _repository_from_env()
            result = poller.run_cycle(repository, mapper)
            username = _get_session_username(request) or "unknown"
            logger.info("[on-demand] %s refresh triggered by %s — %s", source, username, result.status)
            return {"status": result.status, "source": source, "message": result.message or "completed"}
        except Exception as exc:
            logger.error("[on-demand] %s refresh failed: %s", source, exc)
            return {"status": "error", "source": source, "message": str(exc)}


__all__ = ["register_assets"]
