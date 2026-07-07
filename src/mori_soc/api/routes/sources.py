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
    state_repo = ctx.state_repo
    sessions = ctx.sessions

    def _require_ingest_auth(request: Request) -> None:
        """토큰(Authorization: Bearer / X-MORI-Token) 또는 로그인 세션 요구.

        MORI_INGEST_TOKEN 이 설정돼 있으면 토큰 필수(에이전트/CSOP 무세션 push),
        없으면 로그인 세션으로 폴백. /ingest/trivy · /ingest/evidence 공통.
        """
        import os as _os

        token_required = _os.getenv("MORI_INGEST_TOKEN", "").strip()
        if token_required:
            auth = request.headers.get("authorization", "")
            provided = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-mori-token", "").strip()
            if provided != token_required:
                raise HTTPException(status_code=401, detail="invalid ingest token")
            return
        get_user = ctx.get_session_username
        if not (get_user and get_user(request)):
            raise HTTPException(status_code=401, detail="auth required (login or set MORI_INGEST_TOKEN)")

    def _session_role(request: Request) -> str | None:
        """현재 세션 롤(admin/security/...)을 반환. 미인증 시 None."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return sess.get("role") if sess else None

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
    def ingest_trivy(payload: dict[str, Any], request: Request, hostname: str | None = None) -> dict[str, Any]:
        """원격 호스트가 Trivy JSON 리포트를 push → 정규화 → PostgreSQL 적재.

        인증: MORI_INGEST_TOKEN 이 설정돼 있으면 Authorization: Bearer / X-MORI-Token
        헤더 필요. 없으면 로그인 세션 필요. 적재는 postgres 백엔드에서만(라이브 조회).

        Host↔Image 매핑: 이미지 스캔(ArtifactName=alpine:3.19 등)을 실제 Zabbix/Fleet
        호스트에 묶으려면 호스트명을 함께 실어준다. 우선순위:
        ``?hostname=`` 쿼리 → ``X-MORI-Hostname`` 헤더 → 리포트 본문의 ``hostname``/
        ``host_id``. 지정 시 정규화 host_id 가 ArtifactName 대신 그 호스트명이 된다.
        (미지정 시 기존 동작 유지 → ArtifactName 파생.)
        """
        import os as _os

        _require_ingest_auth(request)

        db = _os.getenv("MORI_DATABASE_URL", "").strip()
        if not db:
            raise HTTPException(status_code=503, detail="ingest requires MORI_DATABASE_URL (postgres backend)")
        if not isinstance(payload, dict) or "Results" not in payload:
            raise HTTPException(status_code=400, detail="body must be a Trivy JSON report (with 'Results')")

        resolved_host = (
            (hostname or "").strip()
            or request.headers.get("x-mori-hostname", "").strip()
            or str(payload.get("hostname") or payload.get("host_id") or "").strip()
        )
        raw_aliases = payload.get("host_aliases")
        host_aliases = [str(a).strip() for a in raw_aliases if str(a).strip()] if isinstance(raw_aliases, list) else []

        from mori_soc.collectors import TrivyCollector
        from mori_soc.models import SourceSync
        from mori_soc.repositories import PostgresRepository
        from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper

        repo = PostgresRepository(db)
        try:
            report = CollectorIngestionService(EnvelopeEntityMapper(), repo).ingest_collector(
                TrivyCollector(reports=[payload], hostname=resolved_host or None, host_aliases=host_aliases)
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
                "entities_saved": report.entities_saved, "artifact": payload.get("ArtifactName"),
                "host_id": resolved_host or payload.get("ArtifactName")}

    # ── CSOP 증적(evidence) HTTP 인제스트 — 조치 전/후 diff envelope 수신함 ────────
    @app.post("/ingest/evidence", tags=["Sources"])
    def ingest_evidence(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """CSOP/에이전트가 조치 전/후 diff envelope(delta_type new/fixed/reopened)를 push.

        /ingest/trivy 는 원본 Trivy 리포트만 받아 자체 정규화하므로 delta/before-after
        증적을 담지 못한다. 이 엔드포인트는 payload 를 원형(jsonb)으로 ui_evidence_events
        에 적재하고, 조회·필터용으로 host_id/artifact_name/delta_type/cve/summary 를 추출한다.

        인증은 /ingest/trivy 와 동일(토큰 또는 세션). 단건 envelope 또는
        ``{"events": [...]}`` 배열을 허용한다. 스키마에 유연 — 미지의 필드도 보존된다.
        """
        import hashlib as _hashlib

        _require_ingest_auth(request)
        if state_repo is None:
            raise HTTPException(status_code=503, detail="evidence ingest requires a configured state backend")
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")

        raw_events = payload.get("events")
        events = raw_events if isinstance(raw_events, list) else [payload]
        default_host = str(payload.get("hostname") or payload.get("host_id") or "").strip()
        now_iso = datetime.now(tz=timezone.utc).isoformat()

        saved = 0
        ids: list[str] = []
        for item in events:
            if not isinstance(item, dict):
                continue
            scan = item.get("scan") if isinstance(item.get("scan"), dict) else {}
            host_id = str(item.get("host_id") or item.get("hostname") or default_host or "").strip()
            artifact = str(item.get("artifact_name") or item.get("ArtifactName") or scan.get("target") or "").strip()
            delta_type = str(item.get("delta_type") or item.get("delta") or "").strip()
            cve = str(item.get("cve") or item.get("VulnerabilityID") or item.get("vuln_id") or "").strip()
            summary = str(item.get("summary") or item.get("title") or "").strip()
            source = str(item.get("source") or payload.get("source") or "csop").strip() or "csop"
            received_at = str(item.get("received_at") or item.get("completed_at") or scan.get("completed_at") or now_iso)

            event_id = str(item.get("id") or item.get("event_id") or "").strip()
            if not event_id:
                seed = "|".join([host_id, artifact, cve, delta_type, str(item.get("raw_ref") or "")])
                if not seed.strip("|"):
                    seed = f"{received_at}|{saved}"
                event_id = "evi-" + _hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]

            record = {"id": event_id, "host_id": host_id, "artifact_name": artifact,
                      "delta_type": delta_type, "cve": cve, "summary": summary, "source": source,
                      "envelope": item, "received_at": received_at}
            try:
                state_repo.save_evidence_event(event_id, record)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"evidence ingest failed: {exc}") from exc
            saved += 1
            ids.append(event_id)

        if saved == 0:
            raise HTTPException(status_code=400, detail="no evidence records found in payload")
        return {"ok": True, "saved": saved, "ids": ids}

    # ── 증적 조회 — admin·security 전용(위험성 평가와 동일 가시성 정책) ───────────
    @app.get("/evidence", tags=["Sources"])
    def evidence_list(request: Request, limit: int = 200, host: str | None = None,
                      delta: str | None = None) -> dict[str, Any]:
        """적재된 CSOP 증적 이벤트를 최신순 조회. admin·security 롤만 접근 가능."""
        if ctx.auth_enabled:
            role = _session_role(request)
            if role not in ("admin", "security"):
                raise HTTPException(status_code=403, detail="evidence access requires admin or security role")
        if state_repo is None:
            raise HTTPException(status_code=503, detail="evidence requires a configured state backend")

        capped = max(1, min(int(limit or 200), 1000))
        try:
            events = state_repo.load_evidence_events(limit=capped)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"evidence unavailable: {exc}") from exc
        if host:
            events = [e for e in events if e.get("host_id") == host]
        if delta:
            events = [e for e in events if e.get("delta_type") == delta]
        return {"source": "evidence", "count": len(events), "events": events}


__all__ = ["register_sources"]
