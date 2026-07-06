"""Per-source asset routes (Task J-4b4).

Registers ``GET /fleet/hosts``, ``GET /zabbix/hosts`` and
``GET /trivy/vulnerabilities`` on ``ctx.app``. Handler bodies are verbatim from
the original ``create_app`` closures; only the unpacking preamble (binding shared
stores + the ``get_query_service`` helper from :class:`RouteContext`) is new.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from mori_soc.api.payloads import build_assets_payload
from mori_soc.api.routes.context import RouteContext


def register_sources(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    asset_owners = ctx.asset_owners
    action_plans = ctx.action_plans
    vuln_actions = ctx.vuln_actions

    # ── Fleet 전용 API ───────────────────────────────────────────────────────
    @app.get("/fleet/hosts", tags=["Fleet"])
    def fleet_hosts_get(format: str = "json") -> Any:
        """Fleet(PC 자산) 전용 호스트 목록 API."""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"fleet hosts unavailable: {exc}") from exc
        fleet_data = payload.get("fleet", {})
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            hosts = fleet_data.get("hosts", [])
            if hosts:
                _fleet_header_map = {"hostname": "호스트명", "asset_type": "자산유형", "platform": "플랫폼", "primary_ip": "IP주소", "status": "상태", "risk_score": "위험점수", "last_seen_at": "최종확인일시", "owner": "담당자", "team": "팀"}
                fieldnames = list(_fleet_header_map.keys())
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writerow(_fleet_header_map)
                writer.writerows(hosts)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-fleet-hosts-{timestamp}.csv"'},
            )
        return {"source": "fleet", **fleet_data}

    # ── Zabbix 전용 API ──────────────────────────────────────────────────────
    @app.get("/zabbix/hosts", tags=["Zabbix"])
    def zabbix_hosts_get(format: str = "json") -> Any:
        """Zabbix(서버 자산) 전용 호스트 목록 API."""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"zabbix hosts unavailable: {exc}") from exc
        zabbix_data = payload.get("zabbix", {})
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            hosts = zabbix_data.get("hosts", [])
            if hosts:
                _zabbix_header_map = {"hostname": "호스트명", "category": "분류", "importance": "중요도", "primary_ip": "IP주소", "status": "상태", "latest_metric": "최근메트릭", "latest_value": "최근값", "owner": "담당자", "team": "팀"}
                fieldnames = list(_zabbix_header_map.keys())
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writerow(_zabbix_header_map)
                writer.writerows(hosts)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-zabbix-hosts-{timestamp}.csv"'},
            )
        return {"source": "zabbix", **zabbix_data}

    # ── Trivy 전용 API ───────────────────────────────────────────────────────
    @app.get("/trivy/vulnerabilities", tags=["Trivy"])
    def trivy_vulnerabilities_get(format: str = "json", severity: str = "all") -> Any:
        """Trivy(취약점) 전용 취약점 목록 API. severity=critical|high|medium|low|all"""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"trivy vulnerabilities unavailable: {exc}") from exc
        trivy_data = payload.get("trivy", {})
        rows = trivy_data.get("by_host", [])
        valid_severities = {"critical", "high", "medium", "low", "all"}
        if severity not in valid_severities:
            raise HTTPException(status_code=400, detail=f"severity must be one of: {', '.join(sorted(valid_severities))}")
        if severity != "all":
            rows = [r for r in rows if (r.get(severity, 0) or 0) > 0]
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            if rows:
                _trivy_header_map = {"hostname": "호스트명", "critical": "심각", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보", "total": "합계", "latest_cve": "최근CVE", "action_plan": "조치계획", "action_target_date": "목표완료일"}
                fieldnames = list(_trivy_header_map.keys())
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writerow(_trivy_header_map)
                writer.writerows(rows)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-trivy-vulns-{timestamp}.csv"'},
            )
        return {"source": "trivy", "severity_filter": severity, "count": len(rows), "by_host": rows}

    # ── Trivy 리포트 HTTP 인제스트 (원격 엔드포인트 → MORI 자동 배송) ──────────
    @app.post("/ingest/trivy", tags=["Sources"])
    def ingest_trivy(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """원격 호스트가 Trivy JSON 리포트를 push → 정규화 → PostgreSQL 적재.

        인증: MORI_INGEST_TOKEN 이 설정돼 있으면 Authorization: Bearer / X-MORI-Token
        헤더 필요. 없으면 로그인 세션 필요. 적재는 postgres 백엔드에서만(라이브 조회).
        """
        import os as _os

        token_required = _os.getenv("MORI_INGEST_TOKEN", "").strip()
        if token_required:
            auth = request.headers.get("authorization", "")
            provided = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-mori-token", "").strip()
            if provided != token_required:
                raise HTTPException(status_code=401, detail="invalid ingest token")
        else:
            get_user = ctx.get_session_username
            if not (get_user and get_user(request)):
                raise HTTPException(status_code=401, detail="auth required (login or set MORI_INGEST_TOKEN)")

        db = _os.getenv("MORI_DATABASE_URL", "").strip()
        if not db:
            raise HTTPException(status_code=503, detail="ingest requires MORI_DATABASE_URL (postgres backend)")
        if not isinstance(payload, dict) or "Results" not in payload:
            raise HTTPException(status_code=400, detail="body must be a Trivy JSON report (with 'Results')")

        from mori_soc.collectors import TrivyCollector
        from mori_soc.models import SourceSync
        from mori_soc.repositories import PostgresRepository
        from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper

        repo = PostgresRepository(db)
        try:
            report = CollectorIngestionService(EnvelopeEntityMapper(), repo).ingest_collector(
                TrivyCollector(reports=[payload])
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Trivy ingest failed: {exc}") from exc

        now = datetime.now(tz=timezone.utc)
        try:
            repo.save(SourceSync(source="trivy", status="success", last_sync_at=now, last_success_at=now,
                                 message=f"http ingest: {report.records_collected} records",
                                 records_collected=report.records_collected,
                                 envelopes_normalized=report.envelopes_normalized,
                                 entities_saved=report.entities_saved))
        except Exception:
            pass
        return {"ok": True, "records_collected": report.records_collected,
                "entities_saved": report.entities_saved, "artifact": payload.get("ArtifactName")}


__all__ = ["register_sources"]
