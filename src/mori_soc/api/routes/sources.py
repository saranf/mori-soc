"""Per-source asset routes (Task J-4b4).

Registers ``GET /fleet/hosts``, ``GET /zabbix/hosts`` and
``GET /trivy/vulnerabilities`` on ``ctx.app``. Handler bodies are verbatim from
the original ``create_app`` closures; only the unpacking preamble (binding shared
stores + the ``get_query_service`` helper from :class:`RouteContext`) is new.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from mori_soc.api.payloads import build_assets_payload
from mori_soc.api.routes.context import RouteContext

# 인제스트/증적 영속화 실패는 절대 조용히 삼키지 않는다(증적·개인정보 유실 은폐 방지).
_log = logging.getLogger("mori_soc.ingest")

# Ingest replay 방지(#11) — OIDC jti(토큰 1회성 ID) 를 본 적 있으면 재전송으로 간주.
# 단일 인스턴스 인메모리 TTL 캐시(다중 인스턴스는 공유 저장소 필요 — 백로그).
_INGEST_REPLAY_SEEN: dict[str, float] = {}


def _replay_window() -> int:
    try:
        return max(1, int(os.environ.get("MORI_INGEST_REPLAY_WINDOW", "86400")))
    except (ValueError, AttributeError):
        return 86400


def _is_replayed(oidc_claims: dict[str, Any] | None) -> bool:
    """OIDC jti 기반 replay 여부. jti 없으면(정적 토큰 경로) 결정적 id 멱등성에 맡기고 False."""
    if not oidc_claims:
        return False
    jti = str(oidc_claims.get("jti") or "").strip()
    if not jti:
        return False
    import time as _time
    now, window = _time.time(), _replay_window()
    # 오래된 항목 정리(무한 증가 방지)
    for k in [k for k, t in _INGEST_REPLAY_SEEN.items() if now - t > window]:
        _INGEST_REPLAY_SEEN.pop(k, None)
    if jti in _INGEST_REPLAY_SEEN and now - _INGEST_REPLAY_SEEN[jti] < window:
        return True
    _INGEST_REPLAY_SEEN[jti] = now
    return False

# GitHub OIDC JWKS(공개키) 프로세스 캐시 — kid 회전 시에만 재조회.
_OIDC_JWKS_CACHE: dict[str, Any] = {}


def _max_findings() -> int:
    """인제스트 1회 처리 findings 상한(#36 — resource exhaustion 방어). 기본 20000."""
    try:
        return int(os.environ.get("MORI_MAX_FINDINGS", "20000"))
    except ValueError:
        return 20000


def _cap_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """상한 초과 시 잘라내되 **조용히 버리지 않고** 로그로 남긴다(silent cap 금지)."""
    cap = _max_findings()
    if cap > 0 and len(findings) > cap:
        _log.warning("ingest findings %d건이 상한 %d 초과 — 초과분 잘림(silent 아님)", len(findings), cap)
        return findings[:cap]
    return findings


def _extract_code_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """코드 리뷰 인제스트 본문에서 finding dict 목록을 뽑는다.

    허용: (1) ``{"findings": [...]}`` (2) SARIF ``{"runs": [{"results": [...]}]}``
    (3) 단일 finding dict. SARIF result → MORI finding 형태로 평탄화한다.
    상한(#36)을 넘으면 초과분을 잘라 resource exhaustion 을 막고 그 사실을 로그로 남긴다.
    """
    if isinstance(payload.get("findings"), list):
        return _cap_findings([f for f in payload["findings"] if isinstance(f, dict)])
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
                snip = region.get("snippet") if isinstance(region.get("snippet"), dict) else {}
                out.append({
                    "id": r.get("guid") or r.get("correlationGuid"),
                    "rule_id": r.get("ruleId"),
                    "severity": r.get("level"),
                    "title": (msg.get("text") if isinstance(msg, dict) else None),
                    "message": (msg.get("text") if isinstance(msg, dict) else None),
                    "file": art.get("uri") if isinstance(art, dict) else None,
                    "line": region.get("startLine") if isinstance(region, dict) else None,
                    "snippet": (snip.get("text") if isinstance(snip, dict) else None),
                })
        return _cap_findings(out)
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
        from mori_soc.services.oidc_verify import (
            OidcError,
            fetch_github_jwks,
            verify_github_oidc,
        )

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
            import csv as csv_mod
            import io
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
            _log.warning("trivy SourceSync save failed (ingest succeeded, sync history not updated)", exc_info=True)
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
        import json as _json
        import os as _os

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
            _log.warning("wazuh SourceSync save failed (ingest succeeded, sync history not updated)", exc_info=True)
        return {"ok": True, "records_collected": report.records_collected,
                "entities_saved": report.entities_saved}

    def _promote_scan_to_controls(scan_ev_id: str, repo: str | None, commit: str | None,
                                  findings_count: int, verified: bool,
                                  run_url: str | None, collected_at: str) -> int:
        """스캔 런을 2.8 통제(2.8.1·2.8.5·A.8.25·A.8.28) 증적 레코드로 승격. 승격 건수 반환.

        증적 id 를 (scan_ev_id × control) 로 결정적 생성 → ingest·backfill 어느 경로든
        같은 스캔이면 같은 레코드를 덮어써서 중복이 생기지 않는다(idempotent).
        """
        import hashlib as _hashlib

        from mori_soc.services.code_review_dispatch import CODE_REVIEW_CONTROL_IDS

        short = (commit or "HEAD")[:8]
        vlabel = "검증됨(OIDC)" if verified else "미검증"
        title = f"코드 보안 리뷰 스캔 — {repo or '?'}@{short} · findings {findings_count}건 · {vlabel}"
        body_bits = [f"레포: {repo or '?'}", f"커밋: {commit or 'HEAD'}",
                     f"탐지 findings: {findings_count}건", f"provenance: {vlabel}"]
        if run_url:
            body_bits.append(f"실행 로그: {run_url}")
        body = " · ".join(body_bits)
        now_i = datetime.now(tz=timezone.utc).isoformat()
        n = 0
        from mori_soc.services.evidence import stamp_evidence
        for cid in CODE_REVIEW_CONTROL_IDS:
            rec = {
                "id": "cr-ev-" + _hashlib.sha1(f"{scan_ev_id}|{cid}".encode("utf-8")).hexdigest()[:16],
                "control_id": cid, "title": title, "body": body,
                "collected_by": "MORI 코드 리뷰 파이프라인", "collected_at": collected_at,
                "reference": run_url or "", "source": "code_review", "source_event_id": scan_ev_id,
                "repo": repo or "", "commit": commit or "", "findings_count": findings_count,
                "verified": verified, "created_at": now_i, "created_by": "code_review",
            }
            stamp_evidence(rec)   # content_hash·version·generated_at (#21)
            ctx.control_evidence[rec["id"]] = rec  # 메모리엔 항상 반영
            try:
                if ctx.persist_control_evidence:
                    ctx.persist_control_evidence(rec["id"])
                n += 1
            except Exception:
                # DB 영속 실패 — 재기동 시 증적 유실 위험. 삼키지 말고 계측(승격 카운트엔 미포함).
                _log.exception("control_evidence persist failed: id=%s control=%s", rec["id"], cid)
        return n

    # ── 코드 보안 리뷰 findings 인제스트 (claude-code-security-review → Alert Triage) ──
    @app.post("/ingest/code-review", tags=["Sources"])
    def ingest_code_review(payload: dict[str, Any], request: Request, repo: str | None = None,
                           commit: str | None = None, run_id: str | None = None,
                           run_url: str | None = None, pr: str | None = None,
                           scanner: str | None = None, ruleset: str | None = None,
                           model: str | None = None) -> dict[str, Any]:
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
        # Replay 방지(#11): 같은 OIDC 토큰(jti)을 이미 봤으면 재처리하지 않고 duplicate 로 응답.
        if _is_replayed(oidc_claims):
            if ctx.log_action:
                ctx.log_action("oidc", "INGEST_REPLAY", f"code_review {resolved_repo}@{(commit or '')[:8]} run={run_id}")
            _log.warning("ingest replay ignored: repo=%s commit=%s run=%s", resolved_repo, commit, run_id)
            return {"ok": True, "duplicate": True, "replayed": True, "repo": resolved_repo,
                    "commit": commit or None, "run_id": run_id or None}
        # 스캔 방식 감지 — SARIF(runs[].tool)면 그 도구(무료), 네이티브 findings 면 Claude(유료).
        tool_label = "스캔"
        if isinstance(payload.get("runs"), list):
            drv = ""
            try:
                drv = str(((payload["runs"][0] or {}).get("tool") or {}).get("driver", {}).get("name") or "")
            except Exception:
                drv = ""
            tool_label = f"{drv or 'Semgrep'}(무료)"
        elif isinstance(payload.get("findings"), list):
            tool_label = "Claude(유료)"
        # 재현성 입력(#2): 같은 입력을 다시 돌리면 같은 결과여야 한다. commit·scanner·ruleset·
        # model 을 캡처하고 input_signature 로 '동일 입력'을 식별한다(#3 스캔 diff 의 기준).
        from mori_soc.services.provenance import scan_input_signature
        scanner_ver = (scanner or "").strip() or str(payload.get("scanner") or payload.get("scanner_version") or "").strip()
        ruleset_ver = (ruleset or "").strip() or str(payload.get("ruleset") or "").strip()
        model_id = (model or "").strip() or str(payload.get("model") or "").strip()
        input_signature = scan_input_signature(resolved_repo, commit, tool_label, scanner_ver, ruleset_ver, model_id)
        provenance = {"repo": resolved_repo, "commit": commit or None, "pr": pr or None,
                      "run_id": run_id or None, "run_url": run_url or None,
                      "scan_time": now_iso, "verified": verified, "tool": tool_label,
                      "scanner": scanner_ver or None, "ruleset": ruleset_ver or None,
                      "model": model_id or None, "input_signature": input_signature}
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
        promoted = 0
        pii_seeded = 0
        if state_repo is not None:
            import hashlib as _hashlib
            seed = "|".join(x for x in [resolved_repo or "", commit, run_id] if x) or now_iso
            ev_id = "cr-scan-" + _hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]
            short = (commit or "HEAD")[:8]
            # ── 코드 리뷰와 함께 개인정보 흐름표 자동 시드(스캔 요약에 건수 노출 위해 먼저) ──
            # PII/비밀정보 finding 을 흐름표 후보 행으로 → "코드 리뷰 = 개인정보 흐름도까지 같이".
            # 건별 try — 한 건 실패로 앞서 저장된 건까지 "0건"으로 은폐하지 않는다(부분 성공 정직 보고).
            try:
                from mori_soc.services.data_flow import seed_rows_from_findings
                seeded_rows = seed_rows_from_findings(findings, repo=resolved_repo or "")
            except Exception:
                _log.exception("privacy-flow seed generation failed: repo=%s", resolved_repo)
                seeded_rows = []
            pii_failed = 0
            for row in seeded_rows:  # 결정적 id 로 upsert → 재스캔 시 단계 재분류 반영
                fid = "pdf-" + _hashlib.sha1(
                    f"{resolved_repo}|{row.get('file','')}|{row.get('line','')}|{row.get('item','')}|{row.get('table','')}".encode("utf-8")).hexdigest()[:12]
                row.update({"id": fid, "created_at": now_iso, "created_by": "code_review", "updated_at": now_iso})
                ctx.personal_data_flow[fid] = row  # 메모리엔 항상 반영
                try:
                    if ctx.persist_personal_data_flow:
                        ctx.persist_personal_data_flow(fid)
                    pii_seeded += 1
                except Exception:
                    pii_failed += 1
                    _log.exception("personal_data_flow persist failed: id=%s repo=%s", fid, resolved_repo)

            # ── 스캔 런 자체를 증적으로 — findings + 개인정보 시드 건수를 요약에 노출(진단성) ──
            pii_note = f" · 개인정보 흐름표 시드 {pii_seeded}건" if pii_seeded else " · 개인정보 0건"
            if pii_failed:
                pii_note += f"(저장실패 {pii_failed}건)"
            record = {"id": ev_id, "host_id": resolved_repo or "", "artifact_name": resolved_repo or "",
                      "delta_type": "code_review_scan", "cve": "",
                      "summary": f"코드 보안 리뷰 스캔: {resolved_repo or '?'}@{short} — findings {len(findings)}건{pii_note}",
                      "source": "code_review", "envelope": provenance, "received_at": now_iso,
                      "findings_count": len(findings), "pii_seeded": pii_seeded}
            from mori_soc.services.provenance import attach_provenance
            attach_provenance(record)   # 출처 태그(Semgrep=RULE·CODE / Claude=AI) — 모리다움
            try:
                state_repo.save_evidence_event(ev_id, record)
                scan_recorded = True
            except Exception:
                # 스캔 증적 저장 실패 — 개발보안 증적 유실. 삼키지 말고 계측(응답 scan_recorded=false).
                _log.exception("scan evidence save failed: id=%s repo=%s", ev_id, resolved_repo)
                scan_recorded = False

            # ── 스캔 런 → 2.8 통제 증적 레코드 자동 승격(개발보안 SDLC, idempotent) ──────
            promoted = _promote_scan_to_controls(ev_id, resolved_repo, commit, len(findings),
                                                 verified, run_url, now_iso[:10])

        try:
            repo_db.save(SourceSync(source="code_review", status="success", last_sync_at=now, last_success_at=now,
                                    message=f"http ingest: {report.records_collected} findings ({resolved_repo or '?'}@{(commit or 'HEAD')[:8]})",
                                    records_collected=report.records_collected,
                                    envelopes_normalized=report.envelopes_normalized,
                                    entities_saved=report.entities_saved))
        except Exception:
            _log.warning("code_review SourceSync save failed (ingest succeeded, sync history not updated)", exc_info=True)
        return {"ok": True, "records_collected": report.records_collected,
                "entities_saved": report.entities_saved, "repo": resolved_repo,
                "commit": commit or None, "pr": pr or None, "run_url": run_url or None,
                "scan_recorded": scan_recorded, "provenance_verified": verified,
                "evidence_promoted": promoted, "privacy_flow_seeded": pii_seeded}

    # ── 고객 배포용 code-review-fullscan.yml 템플릿 (UI 도움말의 "파일 예시") ───────
    @app.get("/controls/code-review/workflow-template", tags=["Sources"])
    def code_review_workflow_template() -> dict[str, Any]:
        """고객이 자기 레포에 복붙할 fullscan 2파일(워크플로 + 스캐너 스크립트) 예시."""
        import os as _os
        from pathlib import Path as _Path

        from mori_soc.services.code_review_dispatch import (
            fullscan_template,
            workflow_template,
        )

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
        return {"filename": ".github/workflows/code-review-semgrep.yml",
                "content": workflow_template(aud),
                "fullscan_filename": ".github/workflows/code-review-fullscan.yml",
                "fullscan_content": fullscan_template(aud),
                "script_filename": "scripts/code_review_fullscan.py",
                "script_content": script_content,
                "audience": aud, "public_url": _os.getenv("MORI_PUBLIC_URL", "").strip()}

    @app.get("/code-review/fullscan.py", tags=["Sources"])
    def code_review_fullscan_py():
        """(유료) fullscan 스캐너를 MORI가 직접 서빙 — 워크플로가 fetch 하므로 재복사 불필요."""
        from pathlib import Path as _Path

        from fastapi.responses import Response as _Response

        content = ""
        for cand in (
            _Path(__file__).resolve().parents[4] / "scripts" / "code_review_fullscan.py",
            _Path.cwd() / "scripts" / "code_review_fullscan.py",
        ):
            try:
                content = cand.read_text(encoding="utf-8")
                break
            except OSError:
                continue
        return _Response(content=content, media_type="text/x-python; charset=utf-8")

    @app.get("/code-review/scanners/manifest.json", tags=["Sources"])
    def code_review_scanner_manifest() -> dict[str, Any]:
        """스캐너 자산의 버전 + SHA256 매니페스트(#16).

        고객 CI 가 받은 스크립트의 sha256 을 이 값과 대조하거나, 특정 버전을 핀해
        MORI 가 조용히 다른 스크립트로 바꾸는 것을 감지할 수 있다. (같은 출처가 스크립트와
        해시를 함께 주므로 MORI 자체 침해에는 서명 릴리스가 필요 — 문서 참고.)
        """
        import hashlib as _hl
        from pathlib import Path as _Path

        root = _Path(__file__).resolve().parents[4]
        files: dict[str, str] = {}
        for name, rel in (("fullscan.py", "scripts/code_review_fullscan.py"),
                          ("flow-scanner.py", "scripts/privacy_flow_scan.py")):
            for cand in (root / rel, _Path.cwd() / rel):
                try:
                    files[name] = _hl.sha256(cand.read_bytes()).hexdigest()
                    break
                except OSError:
                    continue
        return {"version": os.getenv("MORI_SCANNER_VERSION", "").strip() or "dev",
                "files": files}

    # ── 코드 리뷰 findings CSV 다운로드 (개발보안 2.8 증적 원본) ──────────────────
    @app.get("/controls/code-review/findings.csv", tags=["Compliance"])
    def code_review_findings_csv(request: Request, repo: str | None = None, commit: str | None = None) -> StreamingResponse:
        """code_review findings(=alert)를 CSV로 내려준다. UI 공통 openCsvPreview 용.

        코드 경로·스니펫·메시지가 담기므로 증적 조회와 동일하게 admin·security 전용.
        repo/commit 쿼리로 특정 스캔만 필터 가능(스캔 이력의 '결과 다운로드'). 없으면 전체.
        """
        from mori_soc.services.csv_export import csv_streaming_response

        if ctx.auth_enabled:
            role = _session_role(request)
            if role not in ("admin", "security"):
                raise HTTPException(status_code=403, detail="findings export requires admin or security role")
        want_repo = (repo or "").strip()
        want_commit = (commit or "").strip()
        rows: list[dict[str, Any]] = []
        for a in get_query_service().store.alerts:
            if a.source != "code_review":
                continue
            rp = a.raw_payload or {}
            prov = rp.get("_provenance") or {}
            r_repo = str(prov.get("repo") or "")
            r_commit = str(prov.get("commit") or "")
            if want_repo and r_repo != want_repo:
                continue
            if want_commit and not (r_commit == want_commit or r_commit.startswith(want_commit) or want_commit.startswith(r_commit)):
                continue
            rows.append({
                "repo": r_repo,
                "commit": r_commit[:12],
                "file": str(rp.get("file") or rp.get("path") or ""),
                "line": rp.get("line") if rp.get("line") is not None else "",
                "severity": a.severity,
                "rule": str(a.rule_id or rp.get("rule_id") or rp.get("category") or ""),
                "title": a.rule_name or "",
                "message": a.message or "",
                "verified": "검증됨" if prov.get("verified") else "미검증",
                "detected_at": a.observed_at.isoformat() if a.observed_at else "",
            })
        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(key=lambda r: (_sev_rank.get(str(r["severity"]), 9), str(r["file"]), str(r["line"])))
        header_map = {"repo": "레포", "commit": "커밋", "file": "파일", "line": "라인",
                      "severity": "심각도", "rule": "룰", "title": "제목", "message": "메시지",
                      "verified": "검증", "detected_at": "탐지시각"}
        return csv_streaming_response(rows, header_map, "mori-code-review-findings")

    # ── 과거 스캔 소급 승격 — 자동승격 도입 전 스캔을 통제 증적으로 backfill ──────────
    @app.post("/controls/code-review/backfill-evidence", tags=["Compliance"])
    def code_review_backfill_evidence(request: Request) -> dict[str, Any]:
        """이미 기록된 code_review_scan 이벤트들을 2.8 통제 증적 레코드로 소급 승격.

        자동 승격은 ingest 시점에만 동작하므로, 그 이전에 들어온 스캔은 이 엔드포인트로
        한 번 올린다. id 가 결정적이라 재실행/이후 재수신과 충돌 없이 idempotent.
        """
        if ctx.auth_enabled and _session_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="backfill requires admin or security role")
        if state_repo is None:
            raise HTTPException(status_code=503, detail="state store unavailable")
        import re as _re

        events = state_repo.load_evidence_events(limit=1000)
        scans = [e for e in events if e.get("delta_type") == "code_review_scan"]
        promoted = 0
        for e in scans:
            env = e.get("envelope") or {}
            fc = e.get("findings_count")
            if fc is None:
                m = _re.search(r"findings\s+(\d+)", str(e.get("summary") or ""))
                fc = int(m.group(1)) if m else 0
            collected_at = (str(e.get("received_at") or "")[:10]
                            or str(env.get("scan_time") or "")[:10]
                            or datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"))
            promoted += _promote_scan_to_controls(
                str(e.get("id") or ""), env.get("repo") or e.get("host_id") or "",
                env.get("commit") or "", int(fc), bool(env.get("verified")),
                env.get("run_url") or "", collected_at)
        return {"ok": True, "scans": len(scans), "evidence_promoted": promoted}

    # ── 스캔 이력 항목 삭제(X 버튼) ─────────────────────────────────────────────
    @app.delete("/controls/code-review/scan/{event_id}", tags=["Compliance"])
    def code_review_scan_delete(event_id: str, request: Request) -> dict[str, Any]:
        if ctx.auth_enabled and _session_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="requires admin or security role")
        if state_repo is None:
            raise HTTPException(status_code=503, detail="state store unavailable")
        try:
            state_repo.delete_evidence_event(event_id)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"delete failed: {exc}") from exc
        return {"ok": True, "id": event_id}

    # ── 적용된 스키마 마이그레이션 이력(운영 점검용, admin·security) ──────────────
    @app.get("/admin/schema-migrations", tags=["Sources"])
    def schema_migrations(request: Request) -> dict[str, Any]:
        """schema_migrations 기록(버전·checksum·적용시각·성공)을 조회(#6). CLI: 이 엔드포인트."""
        if ctx.auth_enabled and _session_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="requires admin or security role")
        fn = getattr(state_repo, "applied_migrations", None)
        rows = fn() if callable(fn) else []
        failed = [r for r in rows if not r.get("success")]
        return {"count": len(rows), "failed": len(failed), "migrations": rows}

    # ── AI 심층 개인정보 흐름도 인제스트(유료 fullscan → 구조화 JSON) ────────────
    @app.post("/ingest/privacy-flow", tags=["Sources"])
    def ingest_privacy_flow(payload: dict[str, Any], request: Request, repo: str | None = None,
                            commit: str | None = None, run_id: str | None = None) -> dict[str, Any]:
        """Claude fullscan(고객 CI)이 코드를 읽고 만든 **구조화된 개인정보 라이프사이클**을 받는다.

        본문: {items:[{item,category,collect[],store[],encryption,use[],dispose[],third_party,overseas,table}],
               gaps:[...], summary:{...}}. MORI 는 코드를 안 읽고 AI 결과를 렌더만 한다.
        """
        oidc_claims = _verify_oidc_header(request)
        if oidc_claims is None:
            _require_ingest_auth(request)
        import hashlib as _hashlib
        import json as _json

        resolved_repo = (repo or "").strip() or str(payload.get("repo") or "").strip()
        if oidc_claims:
            resolved_repo = str(oidc_claims.get("repository") or resolved_repo or "")
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        now_iso = datetime.now(tz=timezone.utc).isoformat()

        def _join(v: Any) -> str:
            if isinstance(v, list):
                return "\n".join(str(x).strip() for x in v if str(x).strip())
            return str(v or "").strip()

        # 이 repo 의 **자동 생성** 흐름(regex 후보·이전 AI 결과)만 AI 결과로 교체한다.
        # 담당자가 수기 입력(source="manual")한 행은 절대 삭제하지 않는다(데이터 손실 방지).
        for fid in [k for k, r in list(ctx.personal_data_flow.items())
                    if str((r or {}).get("repo") or "") == resolved_repo
                    and str((r or {}).get("source") or "") in ("pii_scan", "ai_flow")]:
            ctx.personal_data_flow.pop(fid, None)
            if ctx.delete_personal_data_flow:
                ctx.delete_personal_data_flow(fid)

        saved = 0
        for it in items:
            if not isinstance(it, dict):
                continue
            name = str(it.get("item") or "").strip()
            if not name:
                continue
            table = str(it.get("table") or "").strip()
            enc = str(it.get("encryption") or "").strip()
            store_list = it.get("store") if isinstance(it.get("store"), list) else []
            store = _join(it.get("store"))
            # store 항목은 'Table.column' 형태 → 컬럼만 뽑아 storage_column 에 채운다(무료·유료 공통).
            cols: list[str] = []
            for s in store_list:
                txt = str(s or "").split()[0].strip()   # 'User.emailEnc (블라인드…)' → 'User.emailEnc'
                if "." in txt:
                    col = txt.split(".", 1)[1]
                    if col and col not in cols:
                        cols.append(col)
            col_str = ", ".join(cols)
            # 표시값: 테이블.컬럼 우선(둘 다 있으면), 아니면 테이블.
            storage_loc = f"{table}.{col_str}" if (table and col_str) else table
            if enc:
                store = (store + "\n보호: " + enc).strip()
            fid = "pdf-ai-" + _hashlib.sha1(f"{resolved_repo}|{name}".encode("utf-8")).hexdigest()[:12]
            ctx.personal_data_flow[fid] = {
                "id": fid, "item": name, "category": str(it.get("category") or "").strip(),
                "subject": "", "collection_source": _join(it.get("collect")),
                "storage_location": storage_loc, "storage_table": store,
                "storage_column": col_str, "encryption": enc,
                "purpose": _join(it.get("use")), "retention": "",
                "destruction": _join(it.get("dispose")),
                "third_party": _join(it.get("third_party")), "overseas": _join(it.get("overseas")),
                "note": "", "source": "ai_flow", "table": table, "repo": resolved_repo,
                "created_at": now_iso, "created_by": "ai_fullscan", "updated_at": now_iso,
            }
            if ctx.persist_personal_data_flow:
                ctx.persist_personal_data_flow(fid)
            saved += 1

        # 갭·요약 메타는 settings 에 저장(렌더용).
        meta = {"repo": resolved_repo, "commit": (commit or "").strip() or None,
                "gaps": payload.get("gaps") if isinstance(payload.get("gaps"), list) else [],
                "summary": payload.get("summary") if isinstance(payload.get("summary"), dict) else {},
                "generated_at": now_iso, "source": "ai_fullscan"}
        meta_saved = True
        try:
            ctx.settings["privacy_flow_meta"] = _json.dumps(meta, ensure_ascii=False)
            if ctx.persist_setting:
                ctx.persist_setting("privacy_flow_meta", "ai_fullscan")
        except Exception:
            # 항목(items)은 저장됐으나 갭·요약 메타 저장 실패 — 화면서 갭 분석이 사라질 수 있음.
            meta_saved = False
            _log.warning("privacy_flow_meta save failed: repo=%s (items saved, gaps/summary lost)", resolved_repo, exc_info=True)
        return {"ok": True, "items_saved": saved, "repo": resolved_repo, "meta_saved": meta_saved}

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
