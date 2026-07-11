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


# GitHub OIDC JWKS(공개키) 프로세스 캐시 — kid 회전 시에만 재조회.
_OIDC_JWKS_CACHE: dict[str, Any] = {}


def _extract_code_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """코드 리뷰 인제스트 본문에서 finding dict 목록을 뽑는다.

    허용: (1) ``{"findings": [...]}`` (2) SARIF ``{"runs": [{"results": [...]}]}``
    (3) 단일 finding dict. SARIF result → MORI finding 형태로 평탄화한다.
    """
    if isinstance(payload.get("findings"), list):
        return [f for f in payload["findings"] if isinstance(f, dict)]
    if isinstance(payload.get("runs"), list):  # SARIF
        out: list[dict[str, Any]] = []
        for run in payload["runs"]:
            if not isinstance(run, dict):
                continue
            for r in run.get("results") or []:
                if not isinstance(r, dict):
                    continue
                msg = r.get("message") if isinstance(r.get("message"), dict) else {}
                locs = r.get("locations") if isinstance(r.get("locations"), list) else []
                phys = (locs[0].get("physicalLocation") if locs and isinstance(locs[0], dict) else {}) or {}
                art = phys.get("artifactLocation") if isinstance(phys.get("artifactLocation"), dict) else {}
                region = phys.get("region") if isinstance(phys.get("region"), dict) else {}
                out.append({
                    "id": r.get("guid") or r.get("correlationGuid"),
                    "rule_id": r.get("ruleId"),
                    "severity": r.get("level"),
                    "title": (msg.get("text") if isinstance(msg, dict) else None),
                    "message": (msg.get("text") if isinstance(msg, dict) else None),
                    "file": art.get("uri") if isinstance(art, dict) else None,
                    "line": region.get("startLine") if isinstance(region, dict) else None,
                })
        return out
    # 단일 finding fallback — 리뷰 finding 으로 볼 수 있는 필드가 있을 때만.
    if any(k in payload for k in ("rule_id", "ruleId", "title", "severity", "level")):
        return [payload]
    return []


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

    def _verify_oidc_header(request: Request) -> dict[str, Any] | None:
        """X-MORI-OIDC 헤더가 있으면 GitHub OIDC JWT 를 검증해 클레임 반환(없으면 None).

        헤더가 있으나 검증 실패면 401. 검증되면 repository·sha·run_id 가 GitHub 서명으로
        보증되므로 provenance 를 '검증됨'으로 승격할 수 있다.
        """
        import os as _os
        import time as _time

        token = request.headers.get("x-mori-oidc", "").strip()
        if not token:
            return None
        from mori_soc.services.oidc_verify import OidcError, fetch_github_jwks, verify_github_oidc

        audience = _os.getenv("MORI_OIDC_AUDIENCE", "mori-ingest").strip() or "mori-ingest"
        allowed = _os.getenv("MORI_OIDC_ALLOWED_REPOS", "").strip()
        allowed_repos = {r.strip() for r in allowed.split(",") if r.strip()} or None
        allowed_owner = _os.getenv("MORI_OIDC_ALLOWED_OWNER", "").strip() or None

        def _run(jwks: dict[str, Any]) -> dict[str, Any]:
            return verify_github_oidc(token, audience=audience, jwks=jwks, allowed_repos=allowed_repos,
                                      allowed_owner=allowed_owner, now=int(_time.time()))

        try:
            if not _OIDC_JWKS_CACHE.get("keys"):
                _OIDC_JWKS_CACHE.clear(); _OIDC_JWKS_CACHE.update(fetch_github_jwks())
            try:
                return _run(_OIDC_JWKS_CACHE)
            except OidcError as exc:
                if "no JWKS key" in str(exc):  # kid 회전 → 1회 재조회 후 재시도
                    _OIDC_JWKS_CACHE.clear(); _OIDC_JWKS_CACHE.update(fetch_github_jwks())
                    return _run(_OIDC_JWKS_CACHE)
                raise
        except OidcError as exc:
            raise HTTPException(status_code=401, detail=f"OIDC verification failed: {exc}") from exc
        except HTTPException:
            raise
        except Exception as exc:  # JWKS 조회 실패 등
            raise HTTPException(status_code=503, detail=f"OIDC verify unavailable: {exc}") from exc

    def _session_role(request: Request) -> str | None:
        """현재 세션 롤(admin/security/...)을 반환. 미인증 시 None."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return sess.get("role") if sess else None

    # ── Fleet 전용 API ───────────────────────────────────────────────────────
    @app.get("/fleet/hosts", tags=["Fleet"])
    def fleet_hosts_get() -> Any:
        """Fleet(PC 자산) 전용 호스트 목록 API (JSON). CSV 는 /assets?format=csv 로 일원화."""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"fleet hosts unavailable: {exc}") from exc
        return {"source": "fleet", **payload.get("fleet", {})}

    # ── Zabbix 전용 API ──────────────────────────────────────────────────────
    @app.get("/zabbix/hosts", tags=["Zabbix"])
    def zabbix_hosts_get() -> Any:
        """Zabbix(서버 자산) 전용 호스트 목록 API (JSON). CSV 는 /assets?format=csv 로 일원화."""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"zabbix hosts unavailable: {exc}") from exc
        return {"source": "zabbix", **payload.get("zabbix", {})}

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

    # ── Wazuh 경보 HTTP 인제스트 (Wazuh integrator → MORI Alert Triage) ──────────
    @app.post("/ingest/wazuh", tags=["Sources"])
    def ingest_wazuh(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """Wazuh 경보(alert)를 push → 정규화 → PostgreSQL alerts 적재 → Alert Triage.

        Wazuh 의 integrator/custom integration 이 보내는 alert JSON 을 받는다.
        본문은 단일 alert 객체 또는 ``{"alerts": [...]}`` 배치 모두 허용(각 alert 는
        ``rule`` 을 포함해야 함). 인증/백엔드 조건은 /ingest/trivy 와 동일.
        """
        import json as _json, os as _os

        _require_ingest_auth(request)

        db = _os.getenv("MORI_DATABASE_URL", "").strip()
        if not db:
            raise HTTPException(status_code=503, detail="ingest requires MORI_DATABASE_URL (postgres backend)")
        if isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
            alerts = payload["alerts"]
        elif isinstance(payload, dict):
            alerts = [payload]
        else:
            raise HTTPException(status_code=400, detail="body must be a Wazuh alert object or {alerts:[...]}")
        alert_lines = [_json.dumps(a) for a in alerts if isinstance(a, dict) and a.get("rule")]
        if not alert_lines:
            raise HTTPException(status_code=400, detail="no valid Wazuh alerts (each needs a 'rule')")

        from mori_soc.collectors import WazuhAlertCollector
        from mori_soc.models import SourceSync
        from mori_soc.repositories import PostgresRepository
        from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper

        repo = PostgresRepository(db)
        try:
            report = CollectorIngestionService(EnvelopeEntityMapper(), repo).ingest_collector(
                WazuhAlertCollector(alert_lines=alert_lines)
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Wazuh ingest failed: {exc}") from exc

        now = datetime.now(tz=timezone.utc)
        try:
            repo.save(SourceSync(source="wazuh", status="success", last_sync_at=now, last_success_at=now,
                                 message=f"http ingest: {report.records_collected} alerts",
                                 records_collected=report.records_collected,
                                 envelopes_normalized=report.envelopes_normalized,
                                 entities_saved=report.entities_saved))
        except Exception:
            pass
        return {"ok": True, "records_collected": report.records_collected,
                "entities_saved": report.entities_saved}

    # ── 코드 보안 리뷰 findings 인제스트 (claude-code-security-review → Alert Triage) ──
    @app.post("/ingest/code-review", tags=["Sources"])
    def ingest_code_review(payload: dict[str, Any], request: Request, repo: str | None = None,
                           commit: str | None = None, run_id: str | None = None,
                           run_url: str | None = None, pr: str | None = None) -> dict[str, Any]:
        """AI 코드 보안 리뷰 findings 를 push → 정규화 → alert(source=code_review) 적재.

        claude-code-security-review(GitHub Action)가 매 PR 리뷰 결과를 보낸다. MORI 는
        코드를 읽지 않고 finding 결과만 받아(Trivy 리포트 push 와 동형) 호스트에 묶이지
        않는 alert 로 적재 → Alert Triage 재사용 + 2.8 개발보안(ISO A.8.25~28) 증적.

        본문은 (1) MORI 네이티브 ``{"findings": [...]}``, (2) SARIF ``{"runs": [{"results": [...]}]}``,
        (3) 단일 finding dict 를 허용한다. 인증/백엔드 조건은 /ingest/wazuh 와 동일.
        """
        import os as _os

        # 인증: OIDC(X-MORI-OIDC) 우선 → 검증된 provenance. 없으면 정적 토큰/세션 폴백.
        oidc_claims = _verify_oidc_header(request)
        if oidc_claims is None:
            if _os.getenv("MORI_INGEST_REQUIRE_OIDC", "").strip().lower() in ("1", "true", "yes"):
                raise HTTPException(status_code=401, detail="OIDC required (X-MORI-OIDC) but not provided")
            _require_ingest_auth(request)

        db = _os.getenv("MORI_DATABASE_URL", "").strip()
        if not db:
            raise HTTPException(status_code=503, detail="ingest requires MORI_DATABASE_URL (postgres backend)")
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")

        findings = _extract_code_findings(payload)
        # {"findings": []} = 깨끗한 스캔(0건)도 유효 — "통제가 작동했다" 증적이 되므로 400 아님.
        is_scan_report = isinstance(payload.get("findings"), list) or isinstance(payload.get("runs"), list)
        if not findings and not is_scan_report:
            raise HTTPException(status_code=400, detail="no findings in payload ({findings:[...]} or SARIF {runs:[...]})")

        resolved_repo = (repo or "").strip() or str(payload.get("repo") or payload.get("repository") or "").strip() or None

        # ── provenance(출처) 캡처 — 어느 repo·commit·PR·run 에서 나온 증적인지 불변 기록 ──
        now = datetime.now(tz=timezone.utc)
        now_iso = now.isoformat()
        commit = (commit or "").strip() or str(payload.get("commit") or payload.get("sha") or "").strip()
        run_id = (run_id or "").strip() or str(payload.get("run_id") or "").strip()
        pr = (pr or "").strip() or str(payload.get("pr") or payload.get("pr_number") or "").strip()
        # OIDC 검증됨 → GitHub 서명 클레임이 자기신고 값을 이긴다(위조 불가 provenance).
        verified = False
        if oidc_claims:
            resolved_repo = str(oidc_claims.get("repository") or resolved_repo or "") or None
            commit = str(oidc_claims.get("sha") or commit or "")
            run_id = str(oidc_claims.get("run_id") or run_id or "")
            verified = True
        run_url = (run_url or "").strip() or str(payload.get("run_url") or "").strip() or (
            f"https://github.com/{resolved_repo}/actions/runs/{run_id}" if resolved_repo and run_id else "")
        provenance = {"repo": resolved_repo, "commit": commit or None, "pr": pr or None,
                      "run_id": run_id or None, "run_url": run_url or None,
                      "scan_time": now_iso, "verified": verified}
        for _f in findings:
            if isinstance(_f, dict):
                _f.setdefault("_provenance", provenance)

        from mori_soc.collectors import CodeReviewCollector
        from mori_soc.models import SourceSync
        from mori_soc.repositories import PostgresRepository
        from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper

        repo_db = PostgresRepository(db)
        try:
            report = CollectorIngestionService(EnvelopeEntityMapper(), repo_db).ingest_collector(
                CodeReviewCollector(findings=findings, repo=resolved_repo)
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"code-review ingest failed: {exc}") from exc

        # ── 스캔 런 자체를 증적으로 — 0건이어도 "이 repo@commit 를 언제 스캔했다"를 남긴다 ──
        scan_recorded = False
        if state_repo is not None:
            import hashlib as _hashlib
            seed = "|".join(x for x in [resolved_repo or "", commit, run_id] if x) or now_iso
            ev_id = "cr-scan-" + _hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]
            short = (commit or "HEAD")[:8]
            record = {"id": ev_id, "host_id": resolved_repo or "", "artifact_name": resolved_repo or "",
                      "delta_type": "code_review_scan", "cve": "",
                      "summary": f"코드 보안 리뷰 스캔: {resolved_repo or '?'}@{short} — findings {len(findings)}건",
                      "source": "code_review", "envelope": provenance, "received_at": now_iso}
            try:
                state_repo.save_evidence_event(ev_id, record)
                scan_recorded = True
            except Exception:
                scan_recorded = False

        try:
            repo_db.save(SourceSync(source="code_review", status="success", last_sync_at=now, last_success_at=now,
                                    message=f"http ingest: {report.records_collected} findings ({resolved_repo or '?'}@{(commit or 'HEAD')[:8]})",
                                    records_collected=report.records_collected,
                                    envelopes_normalized=report.envelopes_normalized,
                                    entities_saved=report.entities_saved))
        except Exception:
            pass
        return {"ok": True, "records_collected": report.records_collected,
                "entities_saved": report.entities_saved, "repo": resolved_repo,
                "commit": commit or None, "pr": pr or None, "run_url": run_url or None,
                "scan_recorded": scan_recorded, "provenance_verified": verified}

    # ── 고객 배포용 code-review-fullscan.yml 템플릿 (UI 도움말의 "파일 예시") ───────
    @app.get("/controls/code-review/workflow-template", tags=["Sources"])
    def code_review_workflow_template() -> dict[str, Any]:
        """고객이 자기 레포에 복붙할 fullscan 2파일(워크플로 + 스캐너 스크립트) 예시."""
        import os as _os
        from pathlib import Path as _Path

        from mori_soc.services.code_review_dispatch import workflow_template

        aud = _os.getenv("MORI_OIDC_AUDIENCE", "mori-ingest").strip() or "mori-ingest"
        # 스캐너 스크립트는 단일 소스(scripts/code_review_fullscan.py)에서 읽어 서빙.
        script_content = ""
        for cand in (
            _Path(__file__).resolve().parents[4] / "scripts" / "code_review_fullscan.py",
            _Path.cwd() / "scripts" / "code_review_fullscan.py",
        ):
            try:
                script_content = cand.read_text(encoding="utf-8")
                break
            except OSError:
                continue
        return {"filename": ".github/workflows/code-review-fullscan.yml",
                "content": workflow_template(aud),
                "script_filename": "scripts/code_review_fullscan.py",
                "script_content": script_content,
                "audience": aud, "public_url": _os.getenv("MORI_PUBLIC_URL", "").strip()}

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
