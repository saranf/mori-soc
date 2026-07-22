"""온보딩 라우트 — 실사용 진입을 데모처럼 쉽게(스프린트 1).

세 엔드포인트:
  GET  /onboarding/status              첫 실행 체크리스트(5스텝 진행)
  GET  /onboarding/connectors          커넥터 성숙도·연결 상태 카드
  POST /onboarding/connectors/{id}/test  현재 env 로 라이브 연결 테스트(zabbix·fleet)

정직함(모리다움): 연결 테스트는 **서버 env 에 이미 설정된 값**으로만 시도한다 —
UI 로 새 시크릿을 받지 않는다(시크릿 UI 주입은 암호화 설계가 필요한 별도 에픽).
따라서 URL 은 사용자 입력이 아니라 서버 env 라 SSRF 위험이 없다.

가시성: 커넥터·증적 성숙도는 위험성 평가와 동일하게 admin·security 전용
(인프라·헬프데스크는 조치 현황만) — ctx.require_admin_or_security 재사용.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.payloads import _source_coverage
from mori_soc.api.routes.context import RouteContext
from mori_soc.services.onboarding import (
    build_checklist,
    build_connectors,
    build_scan_setup,
    is_testable,
)

_log = logging.getLogger("mori_soc.onboarding")


def register_onboarding(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service

    def _coverage_by_source() -> dict[str, dict[str, Any]]:
        """현재 store 의 소스별 신선도 행을 source 로 키잉(없으면 빈 매핑)."""
        try:
            rows = _source_coverage(get_query_service().store)
        except Exception as exc:  # store 미준비 등 — 온보딩은 절대 500 으로 막지 않는다
            _log.warning("source coverage unavailable for onboarding: %s", exc)
            return {}
        return {str(r.get("source")): r for r in rows}

    @app.get("/onboarding/connectors", tags=["Onboarding"])
    def onboarding_connectors(request: Request) -> dict[str, Any]:
        """커넥터 성숙도·연결 상태 카드. admin·security 전용."""
        ctx.require_admin_or_security(request, detail="onboarding requires admin or security role")
        connectors = build_connectors(_coverage_by_source(), os.environ)
        return {"connectors": connectors, "count": len(connectors)}

    @app.get("/onboarding/status", tags=["Onboarding"])
    def onboarding_status(request: Request) -> dict[str, Any]:
        """첫 실행 체크리스트(5스텝) + 커넥터 요약 + 보안 태세. admin·security 전용."""
        ctx.require_admin_or_security(request, detail="onboarding requires admin or security role")
        connectors = build_connectors(_coverage_by_source(), os.environ)
        source_connected = any(c.get("state") == "connected" for c in connectors)
        signals = {
            "source_connected": source_connected,
            "alerts_triaged": bool(ctx.triage_store),
            "control_evidence": bool(ctx.control_evidence),
            "privacy_scanned": bool(ctx.personal_data_flow),
            # 감사 패키지 내보내기는 compliance 번들 엔드포인트가 세팅하는 플래그로 판정.
            "bundle_exported": str(ctx.settings.get("onboarding_bundle_exported", "")).strip().lower()
            in ("1", "true", "yes"),
        }
        checklist = build_checklist(signals)
        # HTTPS/운영모드 신호(M5) — server 헬퍼는 순환참조 피해 지연 임포트.
        from mori_soc.api.server import _https_ok, _production_mode
        return {
            "checklist": checklist,
            "security_posture": ctx.security_posture,
            "insecure_defaults": list(ctx.insecure_defaults or []),
            "production_mode": _production_mode(),
            "https_ok": _https_ok(),
            "connectors_connected": sum(1 for c in connectors if c.get("state") == "connected"),
            "connectors_total": len(connectors),
        }

    @app.get("/onboarding/scan-setup", tags=["Onboarding"])
    def onboarding_scan_setup(request: Request) -> dict[str, Any]:
        """코드 스캔(무료 기본) 붙이기 핸드오프 + 복붙용 워크플로. admin·security 전용.

        기존 code_review_dispatch.workflow_template 를 재활용해 워크플로 본문을 함께 준다
        (단일 소스 — UI 가 별도 문자열을 갖지 않는다).
        """
        ctx.require_admin_or_security(request, detail="scan setup requires admin or security role")
        audience = os.getenv("MORI_OIDC_AUDIENCE", "mori-ingest").strip() or "mori-ingest"
        public_url = os.getenv("MORI_PUBLIC_URL", "").strip()
        token_set = bool(os.getenv("MORI_INGEST_TOKEN", "").strip())
        setup = build_scan_setup(public_url, audience=audience, ingest_token_configured=token_set)
        from mori_soc.services.code_review_dispatch import workflow_template
        setup["workflow_content"] = workflow_template(audience)
        return setup

    @app.post("/onboarding/connectors/{source}/test", tags=["Onboarding"])
    def onboarding_connector_test(source: str, request: Request) -> dict[str, Any]:
        """현재 env 설정으로 pull 커넥터(zabbix·fleet) 라이브 연결을 테스트.

        새 시크릿을 받지 않고 서버 env 만 사용 → 성공/실패 + 표본 수집 건수를 돌려준다.
        네트워크 예외는 절대 500 으로 새지 않게 잡아 {ok:false, error:...} 로 보고한다.
        """
        actor = ctx.require_admin_or_security(request, detail="connection test requires admin or security role")
        if not is_testable(source):
            raise HTTPException(status_code=400, detail=f"'{source}' 는 라이브 연결 테스트를 지원하지 않습니다(pull 커넥터만 가능).")

        started = time.monotonic()
        try:
            collector = _build_test_collector(source)
        except _NotConfigured as exc:
            return {"ok": False, "source": source, "reason": "not_configured", "error": str(exc)}

        try:
            sample = 0
            for _ in collector.collect():
                sample += 1
                if sample >= 5:   # 표본만 — 전체 수집이 아니라 '연결되는지'만 확인
                    break
            ok = True
            error = None
        except Exception as exc:  # 네트워크·인증·타임아웃 — 사용자에게 원인을 그대로 보여준다
            ok, sample, error = False, 0, str(exc)[:300]
            _log.info("connector test failed: source=%s err=%s", source, error)

        elapsed_ms = int((time.monotonic() - started) * 1000)
        if ctx.log_action:
            ctx.log_action(actor or "admin", "CONNECTOR_TEST",
                           f"{source} ok={ok} sample={sample} {elapsed_ms}ms")
        return {"ok": ok, "source": source, "sample_count": sample,
                "elapsed_ms": elapsed_ms, "error": error}


class _NotConfigured(Exception):
    """env 에 필수 연결 정보가 없어 테스트 컬렉터를 만들 수 없음."""


def _build_test_collector(source: str) -> Any:
    """서버 env 로 소형(표본) 컬렉터를 만든다. 미설정이면 _NotConfigured."""
    env = os.environ
    if source == "zabbix":
        api_url = str(env.get("MORI_ZABBIX_API_URL") or "").strip()
        token = str(env.get("MORI_ZABBIX_API_TOKEN") or "").strip()
        user = str(env.get("MORI_ZABBIX_USER") or "").strip()
        pw = str(env.get("MORI_ZABBIX_PASSWORD") or "").strip()
        if not api_url or not (token or (user and pw)):
            raise _NotConfigured("MORI_ZABBIX_API_URL 과 토큰(또는 사용자/비밀번호)이 필요합니다.")
        from mori_soc.collectors.zabbix_events import ZabbixEventCollector
        return ZabbixEventCollector(
            api_url=api_url, token=token or None, username=user or None, password=pw or None,
            request_timeout=int(env.get("MORI_ZABBIX_TIMEOUT_SECONDS", "10")),
            host_limit=5, problem_limit=5,
        )
    if source == "fleet":
        api_url = str(env.get("MORI_FLEET_API_URL") or "").strip()
        token = str(env.get("MORI_FLEET_API_TOKEN") or "").strip()
        if not api_url or not token:
            raise _NotConfigured("MORI_FLEET_API_URL 과 MORI_FLEET_API_TOKEN 이 필요합니다.")
        from mori_soc.collectors.fleet_api import FleetApiCollector
        return FleetApiCollector(
            api_url=api_url, token=token,
            request_timeout=int(env.get("MORI_FLEET_TIMEOUT_SECONDS", "10")),
            host_limit=5, page_size=5, include_software=False, include_accounts=False,
            verify_tls=str(env.get("MORI_FLEET_INSECURE_TLS", "")).strip().lower()
            not in ("1", "true", "yes", "on"),
        )
    raise _NotConfigured(f"unknown source: {source}")


__all__ = ["register_onboarding"]
