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


# ── 스캔 온보딩 핸드오프 (M4) ─────────────────────────────────────────────────
# 대표 기능(코드 보안 리뷰 + 개인정보 흐름)을 고객 레포에 붙이는 최소 절차를 구조화한다.
# 정직함: 기본은 **무료(Semgrep)** — ANTHROPIC 키·유료 의존 없이 시작할 수 있음을 명확히 한다.
def build_scan_setup(
    public_url: str,
    audience: str = "mori-ingest",
    ingest_token_configured: bool = False,
) -> dict[str, Any]:
    """코드 스캔(무료 기본) 붙이기 핸드오프 — 필요한 GitHub 시크릿·3스텝·MORI측 설정.

    public_url: 고객 워크플로가 결과를 보낼 MORI 공개 URL(MORI_PUBLIC_URL).
    audience: OIDC audience(워크플로에 박힘). ingest_token_configured: 정적 토큰 사용 여부.
    """
    ingest_url = (public_url or "").strip()
    github_secrets = [
        {"name": "MORI_INGEST_URL", "required": True,
         "value": ingest_url or None,
         "note_ko": "MORI 공개 주소(결과를 보낼 곳). 미설정이면 워크플로가 전송을 건너뜀."},
        {"name": "MORI_INGEST_TOKEN", "required": False,
         "note_ko": "정적 토큰 인증을 쓸 때만. OIDC(권장)만 쓰면 생략 가능."},
    ]
    steps = [
        {"id": "add_workflow", "ko": "워크플로 파일을 레포의 .github/workflows/ 에 추가",
         "en": "Add the workflow file under .github/workflows/ in your repo"},
        {"id": "set_secret", "ko": "레포 Settings→Secrets 에 MORI_INGEST_URL 등록",
         "en": "Add MORI_INGEST_URL in repo Settings→Secrets"},
        {"id": "run", "ko": "PR 을 열거나 Actions 탭에서 수동 실행(Run workflow)",
         "en": "Open a PR or run it manually from the Actions tab"},
    ]
    # MORI측(서버 운영자) 설정 — 위조 불가 provenance(OIDC)를 켜려면.
    mori_settings = [
        {"name": "MORI_PUBLIC_URL", "set": bool(ingest_url),
         "note_ko": "고객이 결과를 보낼 수 있게 MORI 를 외부에서 접근 가능한 주소로."},
        {"name": "MORI_OIDC_ALLOWED_REPOS", "set": None,
         "note_ko": "허용 레포를 제한(선택). 설정 시 그 레포의 서명된 스캔만 검증됨."},
    ]
    return {
        "free": True, "default_scanner": "semgrep",
        "workflow_filename": ".github/workflows/code-review-semgrep.yml",
        "ingest_url": ingest_url,
        "audience": audience or "mori-ingest",
        "github_secrets": github_secrets,
        "steps": steps,
        "mori_settings": mori_settings,
        "ingest_token_configured": bool(ingest_token_configured),
        # 유료 심층(Claude fullscan)은 '선택 업그레이드'임을 정직하게 표시(기본 아님).
        "paid_upgrade": {"id": "fullscan", "ko": "AI 심층 개인정보 흐름(선택·유료) — ANTHROPIC_API_KEY 필요",
                          "en": "AI deep privacy-flow (optional, paid) — needs ANTHROPIC_API_KEY"},
        "ready": bool(ingest_url),
    }


# ── 데모→실전 전환 준비(M6) ───────────────────────────────────────────────────
# 정직/안전(모리다움): 데모 시드는 인메모리·마커가 없어 런타임 삭제 시 실데이터를
# 잘못 지울 위험이 있다. 따라서 파괴적 버튼 대신 **전환 준비 체크리스트 + 안내**를 준다
# (실제 데모 데이터 제거 = MORI_DEMO_SEED=0 + 재기동).
def build_go_live(
    demo_seed_active: bool,
    production_mode: bool,
    https_ok: bool,
    strong_admin: bool,
    has_real_source: bool,
) -> dict[str, Any]:
    """실전 전환 준비 상태 — 5개 항목의 done 판정 + 전환 안내(비파괴)."""
    steps = [
        {"id": "seed_off", "ko": "데모 시드 끄기 (MORI_DEMO_SEED=0)",
         "en": "Turn off demo seed (MORI_DEMO_SEED=0)", "done": not demo_seed_active},
        {"id": "prod_mode", "ko": "운영 모드 전환 (MORI_DEMO_MODE=false 또는 MORI_PROFILE=production)",
         "en": "Switch to production (MORI_DEMO_MODE=false or MORI_PROFILE=production)", "done": bool(production_mode)},
        {"id": "strong_admin", "ko": "강한 admin 비밀번호 설정",
         "en": "Set a strong admin password", "done": bool(strong_admin)},
        {"id": "https", "ko": "HTTPS 구성 (또는 TLS 프록시 뒤)",
         "en": "Configure HTTPS (or behind a TLS proxy)", "done": bool(https_ok)},
        {"id": "real_source", "ko": "실 소스 연결(경보/자산이 실제로 수집됨)",
         "en": "Connect a real source (alerts/assets actually collected)", "done": bool(has_real_source)},
    ]
    done = sum(1 for s in steps if s["done"])
    return {
        "steps": steps,
        "done_count": done,
        "total": len(steps),
        "ready": done == len(steps),
        # 데모 데이터를 실제로 비우는 절차(파괴적 런타임 삭제 대신).
        "clear_demo_hint_ko": "데모 데이터는 .env 에서 MORI_DEMO_SEED=0 로 바꾸고 재기동하면 주입되지 않습니다.",
        "clear_demo_hint_en": "Demo data stops being injected once you set MORI_DEMO_SEED=0 and restart.",
    }


# ── 통제 채우기 가이드(M7) ────────────────────────────────────────────────────
# "194개 중 어디부터?"에 답한다 — 완료에 가장 가까운(증적 소스가 있는) 통제를 먼저 추천.
def rank_control_todos(
    items: Sequence[Mapping[str, Any]],
    order: Sequence[str],
    limit: int = 3,
) -> dict[str, Any]:
    """오늘 채울 통제 top-N + 진행률. 완료 레벨(order 마지막)이 아닌 것 중 성숙도 높은 순.

    items: [{id, title_ko, framework, maturity, mapped}]. order: 성숙도 낮은→높은.
    성숙도가 높을수록 완료에 가까워 '빠른 승리'라 먼저 추천한다(증적 소스 있는 것 우선).
    """
    order = list(order)
    done_level = order[-1] if order else ""
    rank = {lvl: i for i, lvl in enumerate(order)}

    def _key(it: Mapping[str, Any]):
        # 성숙도 높은(완료 임박) 먼저 → 그 안에서 mapped 먼저 → id 안정 정렬.
        return (-rank.get(str(it.get("maturity")), -1),
                0 if it.get("mapped") else 1,
                str(it.get("id") or ""))

    candidates = [dict(i) for i in items if str(i.get("maturity")) != done_level]
    candidates.sort(key=_key)
    total = len(items)
    done = total - len(candidates)
    return {
        "todos": candidates[: max(0, int(limit))],
        "remaining": len(candidates),
        "done": done,
        "total": total,
        "percent": round(100.0 * done / total, 1) if total else 0.0,
    }


# ── 배포 URL 점검(서버 개편/도메인 이관 시) ───────────────────────────────────
# 브라우저로 나가는 딥링크·공개주소가 운영 모드에서 localhost 를 가리키면 원격 사용자에게
# 깨진 링크가 된다. 값을 억지로 유추하지 않고(모리다움: 그럴듯하지만 틀린 값 금지) 감지만 한다.
_BROWSER_URL_ENVS = (
    ("MORI_PUBLIC_URL", "공개 접속 주소(딥링크·쿠키 Secure·스캔 수신 URL)"),
    ("MORI_GRAFANA_URL", "Grafana 딥링크"),
    ("MORI_ZABBIX_UI_URL", "Zabbix UI 딥링크"),
    ("MORI_FLEET_UI_URL", "Fleet UI 딥링크"),
    ("MORI_WAZUH_UI_URL", "Wazuh UI 딥링크"),
    ("MORI_DOCS_PORTAL_URL", "운영 문서 포털 링크"),
)


def browser_url_warnings(env: "Mapping[str, str]", production: bool) -> list[dict[str, Any]]:
    """운영 모드에서 브라우저용 URL 이 localhost 를 가리키거나 공개주소가 비면 경고 목록.

    개발(비운영)에선 빈 목록(localhost 정상). production 에서만:
      - MORI_PUBLIC_URL 미설정 → 'unset'(공개주소 없이는 쿠키/딥링크/수신 URL 부정확)
      - 그 외 딥링크가 localhost/127.0.0.1 값 → 'localhost'(원격서 깨짐)
    빈 딥링크는 경고하지 않는다(화면이 '미설정'으로 정직하게 표기하므로).
    """
    if not production:
        return []
    out: list[dict[str, Any]] = []
    for var, desc in _BROWSER_URL_ENVS:
        v = str(env.get(var, "") or "").strip()
        if var == "MORI_PUBLIC_URL":
            if not v:
                out.append({"var": var, "issue": "unset", "desc": desc})
            continue
        if v and ("localhost" in v or "127.0.0.1" in v):
            out.append({"var": var, "issue": "localhost", "desc": desc, "value": v})
    return out


__all__ = [
    "connector_catalog", "is_testable", "build_connectors", "build_checklist",
    "build_scan_setup", "build_go_live", "rank_control_todos", "browser_url_warnings",
]
