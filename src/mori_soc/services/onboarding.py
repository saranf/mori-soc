"""온보딩(실사용 진입) 서비스 — 커넥터 성숙도·연결 상태·첫 실행 체크리스트.

MORI 의 데모→실사용 간극을 좁히는 세 화면의 **순수 로직**을 한곳에 모은다
(라우터는 이 함수들을 실데이터로 호출만 한다 — 공통화·테스트 용이).

정직함(모리다움): 커넥터 성숙도는 **부풀리지 않는다**. 실제 라이브 API 로 검증된
Zabbix·Fleet 만 ``verified``(연결 테스트 가능), 나머지는 고객이 밀어넣는(push)
수신형이라 ``partial``/``scaffold`` 로 표시하고 [테스트 연결] 버튼을 주지 않는다.

이 모듈은 I/O 를 하지 않는다 — 환경변수 매핑·소스 신선도 행을 인자로 받아
표시용 dict 를 만들 뿐이다. 실제 수집/네트워크 테스트는 라우터가 담당한다.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

# ── 커넥터 카탈로그 (성숙도·연결방식·필수 env) ─────────────────────────────────
# maturity: verified(실검증·라이브) / partial(수신형·부분) / scaffold(준비중·미검증)
# kind    : pull(MORI 가 주기 수집) / push(고객 CI·에이전트가 전송)
# testable: 현재 env 로 라이브 [테스트 연결] 가능한가(= pull + verified)
_CONNECTORS: tuple[dict[str, Any], ...] = (
    {
        "id": "zabbix", "label_ko": "Zabbix(서버 경보)", "label_en": "Zabbix (server alerts)",
        "kind": "pull", "maturity": "verified", "testable": True,
        "enable_flag": "MORI_ENABLE_ZABBIX", "api_url_env": "MORI_ZABBIX_API_URL",
        # 인증: 토큰 하나 또는 (사용자+비번) 쌍 중 하나면 충분.
        "credential_envs": (("MORI_ZABBIX_API_TOKEN",), ("MORI_ZABBIX_USER", "MORI_ZABBIX_PASSWORD")),
    },
    {
        "id": "fleet", "label_ko": "Fleet(PC/노트북 자산)", "label_en": "Fleet (endpoints)",
        "kind": "pull", "maturity": "verified", "testable": True,
        "enable_flag": "MORI_ENABLE_FLEET", "api_url_env": "MORI_FLEET_API_URL",
        "credential_envs": (("MORI_FLEET_API_TOKEN",),),
    },
    {
        "id": "trivy", "label_ko": "Trivy(취약점 스캔)", "label_en": "Trivy (vuln scan)",
        "kind": "push", "maturity": "partial", "testable": False,
        "enable_flag": "MORI_ENABLE_TRIVY", "ingest_path": "/ingest/trivy",
    },
    {
        "id": "code_review", "label_ko": "코드 보안 리뷰", "label_en": "Code security review",
        "kind": "push", "maturity": "partial", "testable": False,
        "ingest_path": "/ingest/code-review",
    },
    {
        "id": "wazuh", "label_ko": "Wazuh(보안 경보)", "label_en": "Wazuh (security alerts)",
        "kind": "push", "maturity": "scaffold", "testable": False,
        "enable_flag": "MORI_ENABLE_WAZUH", "ingest_path": "/ingest/wazuh",
    },
)

# 카탈로그에 없는 소스(host_log 등)는 온보딩 카드에 노출하지 않는다.
_TESTABLE = {c["id"] for c in _CONNECTORS if c.get("testable")}


def connector_catalog() -> list[dict[str, Any]]:
    """표시용 커넥터 카탈로그 사본(정적)."""
    return [dict(c) for c in _CONNECTORS]


def is_testable(source: str) -> bool:
    """현재 env 로 라이브 연결 테스트가 가능한 소스인가(zabbix·fleet)."""
    return source in _TESTABLE


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _configured(conn: Mapping[str, Any], env: Mapping[str, str]) -> tuple[bool, list[str]]:
    """이 커넥터가 env 로 설정 완료됐는지 + 빠진 필수 항목 목록.

    push 커넥터는 서버측 필수 env 가 없으므로 항상 '수신 대기'(configured=True 취급하되
    별도 상태로 구분) — 여기선 pull 만 엄격 판정하고 push 는 (True, []) 로 둔다.
    """
    if conn.get("kind") != "pull":
        return True, []
    missing: list[str] = []
    flag = conn.get("enable_flag")
    if flag and not _truthy(env.get(flag)):
        missing.append(flag)
    api_env = conn.get("api_url_env")
    if api_env and not str(env.get(api_env) or "").strip():
        missing.append(api_env)
    # 자격증명: 여러 조합 중 하나라도 완비되면 통과.
    cred_sets: Sequence[Sequence[str]] = conn.get("credential_envs") or ()
    if cred_sets:
        satisfied = any(all(str(env.get(name) or "").strip() for name in group) for group in cred_sets)
        if not satisfied:
            # 첫 조합을 대표 누락으로 안내(가장 단순한 경로).
            missing.extend(n for n in cred_sets[0] if not str(env.get(n) or "").strip())
    return (not missing), missing


def build_connectors(
    coverage_by_source: Mapping[str, Mapping[str, Any]],
    env: Mapping[str, str],
) -> list[dict[str, Any]]:
    """카탈로그 × (env 설정여부) × (소스 신선도) 를 합쳐 커넥터 카드 목록을 만든다.

    coverage_by_source: ``_source_coverage`` 행을 source 로 키잉한 매핑
      (status·last_success_at·last_error_at·records_collected·is_stale·message).
    env: 환경변수 매핑(os.environ 등).
    """
    cards: list[dict[str, Any]] = []
    for conn in _CONNECTORS:
        configured, missing = _configured(conn, env)
        cov = coverage_by_source.get(conn["id"]) or {}
        received = int(cov.get("records_collected") or 0) or int(cov.get("entities_saved") or 0)
        has_data = received > 0 or (cov.get("last_success_at") is not None)
        # 표시 상태: 데이터 있으면 connected, pull·설정완료·무데이터면 configured,
        # push·무데이터면 waiting(수신 대기), 그 외 not_configured.
        if has_data:
            state = "connected"
        elif conn["kind"] == "push":
            state = "waiting"
        elif configured:
            state = "configured"
        else:
            state = "not_configured"
        cards.append({
            "id": conn["id"],
            "label_ko": conn["label_ko"], "label_en": conn["label_en"],
            "kind": conn["kind"], "maturity": conn["maturity"],
            "testable": bool(conn.get("testable")),
            "configured": configured, "missing_env": missing,
            "state": state,
            "ingest_path": conn.get("ingest_path"),
            "last_success_at": cov.get("last_success_at"),
            "last_error_at": cov.get("last_error_at"),
            "last_sync_at": cov.get("last_sync_at"),
            "is_stale": bool(cov.get("is_stale", True)) if cov else None,
            "records_collected": received,
            "message": cov.get("message"),
        })
    return cards


# ── 첫 실행 체크리스트 (M2) ────────────────────────────────────────────────────
# 각 스텝: id·라벨(한/영)·done(bool)·action(프론트 이동 힌트). 순수 — signals 로만 판정.
def build_checklist(signals: Mapping[str, Any]) -> dict[str, Any]:
    """5스텝 온보딩 진행 상태. signals 의 불리언/카운트로만 done 을 판정한다.

    signals keys: source_connected(bool), alerts_triaged(bool),
      control_evidence(bool), privacy_scanned(bool), bundle_exported(bool).
    """
    steps = [
        {"id": "connect_source", "label_ko": "소스 연결", "label_en": "Connect a source",
         "action": "connectors", "done": bool(signals.get("source_connected"))},
        {"id": "triage_alert", "label_ko": "경보 하나 처리", "label_en": "Triage one alert",
         "action": "triage", "done": bool(signals.get("alerts_triaged"))},
        {"id": "link_evidence", "label_ko": "통제에 증적 연결", "label_en": "Link evidence to a control",
         "action": "controls", "done": bool(signals.get("control_evidence"))},
        {"id": "privacy_scan", "label_ko": "개인정보 흐름 스캔", "label_en": "Run a privacy-flow scan",
         "action": "privacy", "done": bool(signals.get("privacy_scanned"))},
        {"id": "export_bundle", "label_ko": "감사 패키지 내보내기", "label_en": "Export the audit package",
         "action": "evidence", "done": bool(signals.get("bundle_exported"))},
    ]
    done = sum(1 for s in steps if s["done"])
    # 다음 할 일 = 아직 안 끝난 첫 스텝(빈 화면 금지 원칙).
    next_step = next((s["id"] for s in steps if not s["done"]), None)
    return {
        "steps": steps,
        "done_count": done,
        "total": len(steps),
        "complete": done == len(steps),
        "next_step": next_step,
    }


__all__ = [
    "connector_catalog", "is_testable", "build_connectors", "build_checklist",
]
