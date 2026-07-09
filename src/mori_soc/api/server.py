from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from mori_soc.services.query_service import InMemoryQueryStore, QueryService
from mori_soc.api.templates import (
    render_login_html,
    render_signup_request_html,
    render_user_dashboard_html,
    render_query_console_html,
    DEFAULT_UI_PAYLOAD,
)
from mori_soc.api.auth import (
    DEFAULT_ROLE_PERMISSIONS,
    build_session_auth_middleware,
    default_local_users,
    read_auth_config,
    verify_credentials,
)
from mori_soc.api.routes import RouteContext
from mori_soc.repositories import InMemoryStateRepository, StateRepository
from mori_soc.api.payloads import (
    build_dashboard_payload,
    build_pdca_payload,
    build_query_request,
    interpret_query_text,
    _default_dashboard_preferences,
    _isoformat,
)

try:
    from fastapi import FastAPI, HTTPException, Request
except ImportError:  # pragma: no cover - exercised by runtime guard tests
    FastAPI = None
    HTTPException = None


logger = logging.getLogger("mori_soc.api")


# Placeholder password patterns that indicate operators have not customised .env.
# Used by `_warn_insecure_defaults` at app startup to emit audit-visible warnings.
_INSECURE_PLACEHOLDER_PREFIXES = ("change_this_", "generate_with_")
_INSECURE_CHECKED_ENV_VARS = (
    "MORI_DB_PASSWORD",
    "MORI_LDAP_BIND_PASSWORD",
    "LDAP_ADMIN_PASSWORD",
    "ZABBIX_DB_PASSWORD",
    "FLEET_DB_PASSWORD",
    "FLEET_DB_ROOT_PASSWORD",
    "FLEET_SERVER_PRIVATE_KEY",
)


def _warn_insecure_defaults() -> list[str]:
    """Scan critical env vars for placeholder values and emit warning logs.

    Returns the list of variable names still using placeholders so callers
    (e.g. /health) can surface the result without re-reading the environment.
    """
    flagged: list[str] = []
    for name in _INSECURE_CHECKED_ENV_VARS:
        value = os.environ.get(name, "")
        if not value:
            continue
        if any(value.startswith(prefix) for prefix in _INSECURE_PLACEHOLDER_PREFIXES):
            flagged.append(name)
    admin_pw = os.environ.get("MORI_ADMIN_PASSWORD", "1234")
    if admin_pw in ("1234", "admin", "password"):
        flagged.append("MORI_ADMIN_PASSWORD")
    if flagged:
        logger.warning(
            "[security] insecure default credentials detected for: %s — update .env before production use",
            ", ".join(flagged),
        )
    return flagged


def create_query_service(store: InMemoryQueryStore | None = None) -> QueryService:
    return QueryService(store or InMemoryQueryStore())


def create_query_service_from_env() -> QueryService:
    database_url = os.getenv("MORI_DATABASE_URL", "").strip()
    backend = os.getenv("MORI_QUERY_BACKEND", "postgres" if database_url else "memory").strip().lower()
    if backend == "memory":
        return create_query_service()
    if backend == "postgres":
        if not database_url:
            raise RuntimeError("MORI_DATABASE_URL must be set when MORI_QUERY_BACKEND=postgres")
        from mori_soc.repositories import PostgresRepository, snapshot_to_query_store

        repository = PostgresRepository(database_url)
        return QueryService(snapshot_to_query_store(repository.snapshot()))
    raise RuntimeError(f"Unsupported MORI_QUERY_BACKEND: {backend}")


def create_state_repository_from_env() -> StateRepository:
    """Select the operational-state backend from env (mirrors query-service selection).

    Defaults to in-memory unless ``MORI_DATABASE_URL`` is set; ``MORI_QUERY_BACKEND``
    forces the choice. Postgres requires ``MORI_DATABASE_URL``.
    """
    database_url = os.getenv("MORI_DATABASE_URL", "").strip()
    backend = os.getenv("MORI_QUERY_BACKEND", "postgres" if database_url else "memory").strip().lower()
    if backend == "memory":
        return InMemoryStateRepository()
    if backend == "postgres":
        if not database_url:
            raise RuntimeError("MORI_DATABASE_URL must be set when MORI_QUERY_BACKEND=postgres")
        from mori_soc.repositories import PostgresStateRepository

        return PostgresStateRepository(database_url)
    raise RuntimeError(f"Unsupported MORI_QUERY_BACKEND: {backend}")


# ── i18n shared runtime ──────────────────────────────────────────────────────
# The runtime script + translation dictionaries live in ``i18n.py`` and are
# imported at the top of this module (Task J-1 modularization). The login/signup
# page templates live in ``templates.py`` (Task J-2) and are imported above; the
# larger dashboard/console templates below embed the i18n runtime via
# :func:`_i18n_script`.


def create_app(
    service: QueryService | None = None,
    service_factory=None,
    state_repo: StateRepository | None = None,
) -> Any:
    if FastAPI is None or HTTPException is None:
        raise RuntimeError(
            "FastAPI is not installed. Install fastapi and uvicorn to run MVC 1 HTTP server."
        )

    # Operational-state persistence backend (M2-1.0d). Defaults to in-memory,
    # which loads empty and write-throughs to nothing observable — identical to
    # the pre-persistence behaviour relied on by the unit tests / lossless gate.
    if state_repo is None:
        state_repo = InMemoryStateRepository()

    app = FastAPI(title="MORI SOC — Audit-Ready Security Operations API", version="0.2.0")
    insecure_defaults = _warn_insecure_defaults()

    # ── 통제 카탈로그(Phase 2) → DB 싱크 (기동 시 최선노력; 실패해도 앱 기동 계속) ──
    _catalog_dsn = os.getenv("MORI_DATABASE_URL", "").strip()
    if _catalog_dsn:
        try:
            from mori_soc.services.control_catalog import sync_catalog_to_db
            _synced = sync_catalog_to_db(_catalog_dsn)
            logger.info("[controls] catalog synced to DB: %s", _synced)
        except Exception as exc:  # pragma: no cover - best effort
            logger.warning("[controls] catalog DB sync skipped: %s", exc)
    admin_dashboard_preferences = _default_dashboard_preferences()
    # Per-user dashboard preferences: username -> preferences dict
    user_dashboard_prefs: dict[str, dict[str, Any]] = {}

    # ── Auth configuration (env-driven; see auth.py) ──────────────────────────
    _auth_config = read_auth_config()
    _auth_enabled = _auth_config.auth_enabled

    # Predefined local accounts: username -> {password, role}
    local_users: dict[str, dict[str, str]] = default_local_users(
        _auth_config.admin_user, _auth_config.admin_password
    )

    # Sessions: token -> {username, role, created_at}
    sessions: dict[str, dict[str, Any]] = {}
    # Signup requests: [{id, name, email, department, reason, status, created_at}]
    signup_requests: list[dict[str, Any]] = []
    # User action audit log: [{ts, username, action, detail}]
    action_audit_log: list[dict[str, Any]] = []

    def _log_action(username: str, action: str, detail: str = "") -> None:
        """사용자 행동을 action_audit_log에 기록 (최근 2000건 유지)."""
        entry = {
            "ts": _isoformat(datetime.now(tz=timezone.utc)),
            "username": username,
            "action": action,
            "detail": detail,
        }
        action_audit_log.append(entry)
        if len(action_audit_log) > 2000:
            del action_audit_log[:-2000]

    # Role permissions: role -> list of allowed tab ids (defaults from auth.py)
    _DEFAULT_ROLE_PERMISSIONS = DEFAULT_ROLE_PERMISSIONS
    role_permissions: dict[str, list[str]] = {k: list(v) for k, v in _DEFAULT_ROLE_PERMISSIONS.items()}

    # Per-user tab overrides: username -> list of allowed tab ids (overrides role default)
    user_tab_permissions: dict[str, list[str]] = {}

    def _verify_credentials(username: str, password: str) -> bool:
        """LDAP(설정 시) → 로컬 계정 순으로 인증."""
        return verify_credentials(username, password, _auth_config, local_users)

    if _auth_enabled:
        app.add_middleware(build_session_auth_middleware(sessions))

    # Triage: alert_id -> {status, analyst, note, updated_at}
    triage_store: dict[str, dict[str, Any]] = {}
    # Slack webhooks: [{id, name, url, created_at}]
    webhooks: list[dict[str, Any]] = []
    # Incidents: incident_id -> {incident_id, title, status, alert_ids, notes, created_at, updated_at}
    incidents: dict[str, dict[str, Any]] = {}
    # Asset owners: hostname -> {owner, email, team, updated_at}
    asset_owners: dict[str, dict[str, Any]] = {}
    # Asset audit log: [{log_id, hostname, field, old_value, new_value, changed_by, changed_at}]
    asset_audit_log: list[dict[str, Any]] = []
    # Action plans: host_id -> {text, target_date, updated_by, updated_at}
    action_plans: dict[str, dict[str, Any]] = {}
    # Per-vulnerability actions: vuln_id -> {plan_text, plan_target_date, plan_updated_by,
    #                                        exception_until, exception_reason, exception_updated_by, updated_at}
    vuln_actions: dict[str, dict[str, Any]] = {}
    # Risk register (R-2): vuln_id -> {impact, likelihood, score, level, treatment,
    #   accept_reason, accept_approver, residual_level, review_due, assessed_by,
    #   assessed_at, updated_at}
    risk_register: dict[str, dict[str, Any]] = {}
    # User profiles: username -> {display_name, department, assigned_servers: [hostname...], updated_at}
    user_profiles: dict[str, dict[str, Any]] = {}
    # Org settings: key -> value string (e.g. risk_doa = "4")
    settings: dict[str, str] = {}
    # Control status (M2-7): control_id -> {status, owner, exception_reason, improvement_plan, due_date, ...}
    control_status: dict[str, dict[str, Any]] = {}
    # Host account inventory (osquery push): host_key -> [account, ...]
    host_accounts: dict[str, list[dict[str, Any]]] = {}
    # Account approvals (allow-list): id -> {scope, host_key, username, kind, reason, approver, expires}
    account_approvals: dict[str, dict[str, Any]] = {}

    # ── Ensure schema before any load_* (self-healing on pre-existing volumes) ─
    # docker-entrypoint-initdb.d only runs on a *fresh* Postgres volume, so a DB
    # created before a table was added never gets it and the load_* below crash.
    # apply_schema() re-runs the idempotent DDL each boot (no-op for in-memory).
    state_repo.apply_schema()

    # ── Warm caches from the persistence backend (M2-1.0d) ────────────────────
    # Cache-aside: load persisted operational state once at boot so the dicts
    # above act as a read cache. The default in-memory backend returns empty,
    # leaving behaviour identical to the pre-persistence path; a Postgres backend
    # repopulates prior state before the demo seed (which only fills gaps).
    triage_store.update(state_repo.load_triage())
    incidents.update(state_repo.load_incidents())
    asset_owners.update(state_repo.load_asset_owners())
    asset_audit_log.extend(state_repo.load_asset_audit_log())
    vuln_actions.update(state_repo.load_vuln_actions())
    risk_register.update(state_repo.load_risk_register())
    user_profiles.update(state_repo.load_user_profiles())
    settings.update(state_repo.load_settings())
    control_status.update(state_repo.load_control_status())
    host_accounts.update(state_repo.load_host_accounts())
    account_approvals.update(state_repo.load_account_approvals())
    # LDAP 가입 승인으로 만든 계정의 역할을 복원(비밀번호는 LDAP이 검증하므로 role만).
    for _skey, _sval in settings.items():
        if _skey.startswith("ldaprole:") and _sval:  # 빈 값(삭제됨)은 건너뜀
            _luser = _skey[len("ldaprole:"):]
            local_users[_luser] = {"password": "", "role": _sval}

    # ── Demo seed (in-memory) ────────────────────────────────────────────────
    # triage_store / asset_owners / user_profiles 는 런타임 인메모리 저장소라 SQL 시드로
    # 채울 수 없다. MORI_DEMO_SEED 활성화 시에만 초기값을 주입해 데모 임팩트를 확보한다.
    # (hostname/alert_id 는 scripts/mori-seed-sample-data.sh 의 값과 일치)
    if os.environ.get("MORI_DEMO_SEED", "").strip().lower() in ("1", "true", "yes", "on"):
        _seed_now = _isoformat(datetime.now(tz=timezone.utc))
        _demo_triage = {
            "al-01": {"status": "reviewing", "analyst": "보안담당자", "note": "SSH 브루트포스 출처 IP 차단 진행 중"},
            "al-02": {"status": "resolved", "analyst": "보안담당자", "note": "루트킷 격리·재이미지 완료"},
            "al-03": {"status": "pending", "analyst": "", "note": ""},
            "al-07": {"status": "reviewing", "analyst": "운영자1", "note": "비정상 아웃바운드 트래픽 조사 중"},
        }
        for _aid, _t in _demo_triage.items():
            triage_store.setdefault(_aid, {
                "status": _t["status"],
                "analyst": _t["analyst"],
                "note": _t["note"],
                "changed_by": _t["analyst"] or "system",
                "updated_at": _seed_now,
                "history": [{"to_status": _t["status"], "analyst": _t["analyst"] or "system", "changed_at": _seed_now}],
            })
        _demo_owners = [
            {"hostname": "web-server-01", "owner": "보안담당자", "team": "보안팀", "category": "웹 서버", "importance": "상"},
            {"hostname": "web-server-02", "owner": "보안담당자", "team": "보안팀", "category": "웹 서버", "importance": "중"},
            {"hostname": "db-primary", "owner": "DBA", "team": "DBA팀", "category": "DB 서버", "importance": "상"},
            {"hostname": "app-server-01", "owner": "운영자1", "team": "인프라팀", "category": "앱 서버", "importance": "중"},
        ]
        for _o in _demo_owners:
            asset_owners.setdefault(_o["hostname"], {
                "hostname": _o["hostname"], "owner": _o["owner"], "category": _o["category"],
                "importance": _o["importance"], "exception_until": "", "exception_reason": "",
                "email": "", "team": _o["team"], "updated_at": _seed_now,
            })
        _demo_profiles = {
            "admin": {"display_name": "시스템관리자", "department": "IT팀",
                      "assigned_servers": ["web-server-01", "db-primary", "app-server-01"]},
            "security": {"display_name": "보안담당자", "department": "보안팀",
                         "assigned_servers": ["web-server-01", "web-server-02"]},
        }
        for _u, _p in _demo_profiles.items():
            user_profiles.setdefault(_u, {
                "display_name": _p["display_name"], "department": _p["department"],
                "assigned_servers": list(_p["assigned_servers"]), "updated_at": _seed_now,
            })

    # Guides: guide_id -> {id, title, content, updated_at}
    guides: dict[str, dict[str, Any]] = {
        "zabbix_setup": {
            "id": "zabbix_setup",
            "title": "Zabbix 에이전트 설정 방법",
            "content": """## Zabbix 에이전트 설치 가이드

### 1. 에이전트 다운로드
- Zabbix 공식 사이트(https://www.zabbix.com/download)에서 OS에 맞는 에이전트를 다운로드합니다.

### 2. 설치 (Linux - Ubuntu/Debian)
```bash
wget https://repo.zabbix.com/zabbix/6.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.4-1+ubuntu22.04_all.deb
dpkg -i zabbix-release_6.4-1+ubuntu22.04_all.deb
apt update && apt install -y zabbix-agent2
```

### 3. 설정 파일 편집
```bash
vi /etc/zabbix/zabbix_agent2.conf
```
주요 설정:
- `Server=<ZABBIX_SERVER_IP>` — Zabbix 서버 IP 입력
- `ServerActive=<ZABBIX_SERVER_IP>` — Active 모드 서버 IP
- `Hostname=<서버_호스트명>` — 서버 고유 이름 (대소문자 주의)

### 4. 서비스 시작
```bash
systemctl enable zabbix-agent2
systemctl start zabbix-agent2
```

### 5. Zabbix 웹 콘솔에서 호스트 등록
1. Configuration → Hosts → Create host
2. Host name: 에이전트의 Hostname 값과 동일하게 입력
3. Groups: 적절한 그룹 선택
4. Agent interface에 서버 IP 입력

### 6. 확인
```bash
systemctl status zabbix-agent2
zabbix_agent2 -t system.uptime
```

> **ISMS 관련**: 서버 자산 등록 및 모니터링은 ISMS-P 2.10 시스템 및 서비스 보안, ISO 27001 A.8.16 모니터링활동에 해당합니다.""",
            "updated_at": None,
        },
        "fleet_install": {
            "id": "fleet_install",
            "title": "Fleet(osquery) 에이전트 설치 방법",
            "content": """## Fleet osquery 에이전트 설치 가이드

### 개요
Fleet는 osquery 기반 PC/서버 자산 관리 도구입니다. 설치 후 자동으로 Fleet 서버에 등록되어 자산 현황 대시보드에 표시됩니다.

### 1. Fleet 서버 주소 확인
IT 담당자에게 Fleet 서버 Enrollment 패키지 또는 URL을 요청합니다.

### 2. Windows 설치
1. Fleet 서버 콘솔 → Hosts → Add Hosts → Windows 선택
2. 제공되는 PowerShell 명령어를 관리자 권한으로 실행:
```powershell
# 예시 (실제 명령어는 Fleet 서버에서 생성)
Invoke-WebRequest -Uri "https://<FLEET_SERVER>/enroll" -OutFile "fleet-osquery.msi"
msiexec /i fleet-osquery.msi /quiet
```

### 3. macOS 설치
```bash
# Fleet 서버 콘솔에서 생성된 명령어 실행
sudo installer -pkg fleet-osquery.pkg -target /
```

### 4. Linux 설치 (Ubuntu/Debian)
```bash
sudo dpkg -i fleet-osquery_*.deb
sudo systemctl enable orbit
sudo systemctl start orbit
```

### 5. 설치 확인
- Fleet 콘솔 → Hosts 에서 해당 PC가 등록되었는지 확인
- 대시보드 → PC 자산(Fleet) 탭에서 온라인 상태 확인

### 6. 오프라인 PC 조치
오프라인 표시 시:
- PC가 켜져 있는지 확인
- orbit 서비스 재시작: `sudo systemctl restart orbit`
- 방화벽에서 Fleet 서버로의 아웃바운드 허용 확인

> **ISMS 관련**: PC 자산 관리는 ISMS-P 2.1 정보자산 식별, ISO 27001 A.8.1 사용자단말기 정책에 해당합니다.""",
            "updated_at": None,
        },
        "isms_criteria": {
            "id": "isms_criteria",
            "title": "ISMS-P 인증 심사 대비 기준",
            "content": """## ISMS-P 인증 심사 대비 체크리스트

### 2.1 정보자산 식별 및 관리
- [ ] 전체 IT 자산 목록 (서버, PC, 네트워크 장비) 보유 여부
- [ ] 자산별 중요도(상/중/하) 분류 여부
- [ ] 자산별 담당자/소유자 지정 여부
- [ ] 자산 목록 최신화 주기 (분기/반기)

**증적 방법**: 대시보드 → 자산 현황 → CSV 내보내기 (분류·중요도·담당자 포함)

---

### 2.5 인증 및 접근통제
- [ ] 서버 접근 계정 목록 관리
- [ ] 퇴사자 계정 즉시 비활성화 절차
- [ ] 특수권한(관리자) 계정 별도 관리

**증적 방법**: Zabbix → 도메인컨트롤러/인증서버 모니터링 데이터

---

### 2.6 네트워크 보안
- [ ] 방화벽 정책 현황 문서화
- [ ] 내/외부 네트워크 분리 여부
- [ ] VPN 사용 현황

**증적 방법**: Zabbix → 네트워크 보안 장비 자산 목록

---

### 2.9 데이터베이스 보안
- [ ] DB 접근 계정 관리
- [ ] DB 접근 로그 보존
- [ ] 중요 데이터 암호화 여부

**증적 방법**: Trivy → DB 서버 취약점 스캔 결과 + 조치계획

---

### 2.10 시스템 및 서비스 보안
- [ ] 서버별 취약점 점검 주기 (분기 1회 이상)
- [ ] 패치 관리 현황
- [ ] 불필요 서비스 비활성화

**증적 방법**: Trivy 스캔 결과 CSV + 조치계획 등록

---

### 2.11 이벤트 처리
- [ ] 보안 이벤트 모니터링 현황
- [ ] 경보 발생 시 대응 절차 문서화
- [ ] 이벤트 로그 보존 기간 (최소 1년)

**증적 방법**: Alert Triage 현황 + 인시던트 목록

---

### 2.12 업무연속성 보안
- [ ] 백업 서버 운영 현황
- [ ] 백업 주기 및 복구 테스트 이력

**증적 방법**: Zabbix → 백업 서버 자산 모니터링 데이터""",
            "updated_at": None,
        },
        "iso27001_criteria": {
            "id": "iso27001_criteria",
            "title": "ISO/IEC 27001:2022 대비 기준",
            "content": """## ISO/IEC 27001:2022 심사 대비 체크리스트

### A.5 조직 통제 (Organizational Controls)
#### A.5.12 정보 분류 / A.5.13 정보 레이블링
- [ ] 정보자산 중요도 분류 체계 수립 (상/중/하 또는 기밀/내부/공개)
- [ ] 서버/PC 자산에 중요도 레이블 부여

**증적**: 자산 현황 CSV (importance 컬럼)

#### A.5.15 접근통제 / A.5.16 신원 관리
- [ ] 접근통제 정책 문서화
- [ ] 사용자 계정 생애주기 관리 절차

---

### A.8 기술 통제 (Technological Controls)
#### A.8.1 사용자 단말기 정책
- [ ] PC 자산 전수 등록 및 모니터링
- [ ] 오프라인 PC 발생 시 조치 절차

**증적**: Fleet PC 자산 목록 + 오프라인 현황 CSV

#### A.8.2 특수 접근권한
- [ ] 관리자 계정 목록 및 주기적 검토

#### A.8.8 기술적 취약점 관리
- [ ] 분기별 취약점 스캔 실시
- [ ] CVE 기반 위험 평가 (Critical/High 우선)
- [ ] 취약점별 조치계획 수립 및 이행 추적

**증적**: Trivy 스캔 결과 CSV + 조치계획 (target_date, 담당자 포함)

#### A.8.13 정보 백업
- [ ] 백업 주기 및 보존 기간 정의
- [ ] 복구 테스트 주기적 실시

**증적**: 백업 서버 Zabbix 모니터링 데이터

#### A.8.15 로깅 / A.8.16 모니터링 활동
- [ ] 보안 이벤트 로그 수집 및 보존
- [ ] 이상 징후 모니터링 현황

**증적**: Alert Triage 이력 + Zabbix 이벤트 데이터

#### A.8.20 네트워크 보안 / A.8.22 네트워크 분리
- [ ] 네트워크 보안 장비 운영 현황
- [ ] 내/외부 네트워크 분리 구성

**증적**: Zabbix 네트워크 보안장비 자산 목록

#### A.8.31 개발·운영 환경 분리
- [ ] 개발/테스트 서버와 운영 서버 분리 여부

**증적**: 자산 현황 → 개발/테스트 서버 분류 확인""",
            "updated_at": None,
        },
        "ldap_setup": {
            "id": "ldap_setup",
            "title": "LDAP 통합 인증 설정 가이드",
            "content": """## LDAP 통합 인증 설정 가이드

Grafana, Zabbix, Fleet, MORI SOC를 하나의 LDAP 서버로 통합 관리하면 계정 하나로 모든 도구에 로그인할 수 있습니다.

---

### Step 1. OpenLDAP 서버 설치 (Docker Compose)

```yaml
# docker-compose.ldap.yml
services:
  openldap:
    image: osixia/openldap:1.5.0
    environment:
      LDAP_ORGANISATION: "My Company"
      LDAP_DOMAIN: "company.local"
      LDAP_ADMIN_PASSWORD: "AdminSecret123"
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d

  phpldapadmin:
    image: osixia/phpldapadmin:0.9.0
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: openldap
    ports:
      - "8080:80"

volumes:
  ldap_data:
  ldap_config:
```

```bash
docker compose -f docker-compose.ldap.yml up -d
# 관리 UI: http://localhost:8080  (Login DN: cn=admin,dc=company,dc=local)
```

---

### Step 2. Zabbix LDAP 설정

1. **Zabbix 웹 → Administration → Authentication → LDAP**
2. 아래 값 입력:

| 항목 | 값 |
|---|---|
| LDAP host | `ldap://openldap` (또는 서버 IP) |
| Port | 389 |
| Base DN | `dc=company,dc=local` |
| Search attribute | `uid` |
| Bind DN | `cn=admin,dc=company,dc=local` |
| Bind password | AdminSecret123 |

3. **Enable LDAP authentication** 체크 후 저장
4. 사용자 계정: Zabbix → Users → 해당 사용자 → **LDAP** 타입 선택

> **ISMS/ISO 27001**: 중앙집중식 접근통제 → A.5.15 / ISMS-P 2.5

---

### Step 3. Grafana LDAP 설정

`/etc/grafana/grafana.ini` 또는 환경변수 추가:

```ini
[auth.ldap]
enabled = true
config_file = /etc/grafana/ldap.toml
allow_sign_up = true
```

`/etc/grafana/ldap.toml`:

```toml
[[servers]]
host = "openldap"
port = 389
use_ssl = false
bind_dn = "cn=admin,dc=company,dc=local"
bind_password = "AdminSecret123"
search_filter = "(uid=%s)"
search_base_dns = ["dc=company,dc=local"]

[servers.attributes]
name = "cn"
username = "uid"
member_of = "memberOf"
email = "mail"

[[servers.group_mappings]]
group_dn = "cn=grafana-admins,ou=groups,dc=company,dc=local"
org_role = "Admin"

[[servers.group_mappings]]
group_dn = "*"
org_role = "Viewer"
```

```bash
# Docker 환경이면 환경변수로도 가능
GF_AUTH_LDAP_ENABLED=true
GF_AUTH_LDAP_CONFIG_FILE=/etc/grafana/ldap.toml
```

---

### Step 4. Fleet SSO (SAML/LDAP 대안)

Fleet는 직접 LDAP을 지원하지 않고 **SAML SSO**를 통해 IdP와 연동합니다. OpenLDAP + Keycloak 조합 권장:

1. **Keycloak** 설치 후 OpenLDAP을 User Federation으로 연결
2. Fleet → Settings → Single Sign-On → SAML 설정:
   - Identity Provider URL: Keycloak SAML endpoint
   - Issuer URI: Fleet 서버 URL

> 간단한 구성을 원하면 Keycloak 없이 Google Workspace / Azure AD를 SAML IdP로 사용하는 방법도 있습니다.

---

### Step 5. MORI SOC LDAP 인증 설정

MORI SOC는 환경변수로 LDAP 인증을 활성화합니다. `ldap3` 라이브러리가 필요합니다.

```bash
# MORI SOC 환경변수 (.env 또는 docker-compose)
LDAP_URL=ldap://openldap:389
LDAP_BASE_DN=dc=company,dc=local
LDAP_BIND_DN=cn=admin,dc=company,dc=local
LDAP_BIND_PASSWORD=AdminSecret123
LDAP_USER_ATTR=uid
```

**Docker Compose 예시 (`docker-compose.yml`):**

```yaml
services:
  mori-soc:
    image: mori-soc:latest
    environment:
      LDAP_URL: "ldap://openldap:389"
      LDAP_BASE_DN: "dc=company,dc=local"
      LDAP_BIND_DN: "cn=admin,dc=company,dc=local"
      LDAP_BIND_PASSWORD: "AdminSecret123"
      LDAP_USER_ATTR: "uid"
    depends_on:
      - openldap
```

LDAP이 설정되면 모든 API/UI 접근에 HTTP Basic Auth가 요구됩니다.
`/docs`, `/health`, `/openapi.json`은 인증 없이 접근 가능합니다.

---

### LDAP 사용자 추가 (phpLDAPadmin 또는 CLI)

```bash
# ldif 파일로 사용자 추가
cat > user.ldif << 'EOF'
dn: uid=alice,ou=people,dc=company,dc=local
objectClass: inetOrgPerson
uid: alice
cn: Alice Kim
sn: Kim
mail: alice@company.local
userPassword: {SSHA}hashedpassword
EOF

ldapadd -x -D "cn=admin,dc=company,dc=local" -w AdminSecret123 -f user.ldif
```

---

> **보안 권고**: 프로덕션 환경에서는 반드시 LDAPS(636포트, TLS) 또는 StartTLS를 사용하세요.""",
            "updated_at": None,
        },
        "incident_response": {
            "id": "incident_response",
            "title": "인시던트 대응 절차 가이드",
            "content": """## 인시던트 대응 절차 (Incident Response)

보안 이벤트 발생 시 아래 절차에 따라 신속하게 대응합니다.

---

### 1단계. 탐지 및 초기 분류 (Detection & Triage)

- [ ] Alert Triage 탭에서 미확인(🔴) 경보 확인
- [ ] 경보 유형, 영향 호스트, 심각도 파악
- [ ] 상태를 **검토중(🟡)** 으로 변경하고 담당자 지정
- [ ] 오탐 여부 1차 판단 (오탐 시 → `resolved` 처리 + 메모 기록)

---

### 2단계. 인시던트 생성 (Incident Creation)

실제 보안 사고로 판단되면 인시던트를 생성합니다:

1. **인시던트** 탭 → **+ 새 인시던트** 클릭
2. 제목, 심각도, 관련 Alert 연결
3. 담당자 지정 후 상태 → **조사중(investigating)**

---

### 3단계. 분석 및 봉쇄 (Analysis & Containment)

- [ ] 영향 호스트 목록 파악 (자산 현황 탭 참조)
- [ ] 네트워크 격리 또는 서비스 중단 여부 판단
- [ ] 공격 벡터 분석 (로그, Zabbix 이벤트, Fleet 쿼리 결과)
- [ ] 인시던트 **메모**에 분석 내용 지속 기록

---

### 4단계. 제거 및 복구 (Eradication & Recovery)

- [ ] 악성 파일/계정 제거
- [ ] 취약점 패치 적용 (Trivy 스캔 결과 → 조치계획 등록)
- [ ] 서비스 정상화 확인
- [ ] 상태 → **해결됨(resolved)**

---

### 5단계. 사후 분석 (Post-Incident Review)

- [ ] 인시던트 상태 → **종료(closed)**
- [ ] 근본 원인 분석(RCA) 작성 및 인시던트 메모에 첨부
- [ ] 재발 방지 대책 수립
- [ ] ISMS-P 2.11 이벤트 처리 / ISO 27001 A.5.26 증적으로 활용

---

> **ISMS-P 관련 통제**: 2.11 이벤트 처리, 2.12 업무연속성 보안
> **ISO 27001 관련 통제**: A.5.24 정보보안사고 관리 계획, A.5.26 정보보안사고 대응""",
            "updated_at": None,
        },
        "security_policy": {
            "id": "security_policy",
            "title": "보안 정책 및 운영 가이드",
            "content": """## 보안 정책 및 운영 가이드

MORI SOC 플랫폼을 활용한 보안 운영 정책을 안내합니다.

---

### 1. 자산 관리 정책

| 항목 | 주기 | 담당 |
|---|---|---|
| 전체 자산 목록 갱신 | 분기 1회 | IT팀 |
| 자산 중요도 분류 검토 | 반기 1회 | 보안팀 |
| 담당자(Owner) 정보 업데이트 | 변경 발생 시 즉시 | 부서장 |
| 자산 현황 CSV 다운로드 (증적) | 심사 전 | 보안팀 |

---

### 2. 취약점 관리 정책

- **Critical/High 취약점**: 발견 후 **14일** 이내 조치 완료
- **Medium 취약점**: 발견 후 **30일** 이내 조치 완료
- **Low 취약점**: 분기별 일괄 검토 및 조치
- Trivy 스캔은 **주 1회** 실행 권장
- 조치계획은 반드시 MORI SOC 조치계획 탭에 등록

---

### 3. Alert 대응 정책

| 심각도 | 초기 대응 시간 | 에스컬레이션 |
|---|---|---|
| Critical | 15분 이내 | 즉시 팀장 보고 |
| High | 1시간 이내 | 2시간 내 미해결 시 팀장 보고 |
| Medium | 4시간 이내 | 당일 처리 원칙 |
| Low | 익일까지 | 주간 보고에 포함 |

---

### 4. 인시던트 관리 정책

- 보안 사고는 반드시 인시던트로 등록
- 인시던트 종료 후 **5일** 이내 사후 분석 보고서 작성
- 심각 인시던트(Critical)는 경영진 보고 필수
- 모든 인시던트 이력은 최소 **3년** 보존

---

### 5. 접근통제 정책

- 관리자 계정(admin)은 반드시 복잡한 비밀번호 사용
- LDAP 연동 시 그룹 기반 접근통제 적용
- 퇴사/부서 이동 시 즉시 계정 비활성화
- 비밀번호 변경 주기: **90일**

---

### 6. 로그 보존 정책

| 로그 종류 | 보존 기간 |
|---|---|
| 보안 이벤트 (Alert) | 1년 이상 |
| 인시던트 이력 | 3년 이상 |
| 접근 로그 | 6개월 이상 |
| 취약점 스캔 결과 | 2년 이상 |

---

> **ISMS-P 관련 통제**: 2.9 시스템 및 서비스 운영관리, 2.11 이벤트 처리
> **ISO 27001 관련 통제**: A.5.1 정보보안 정책, A.8.15 로깅""",
            "updated_at": None,
        },
        "risk_methodology": {
            "id": "risk_methodology",
            "title": "위험성 평가 기준 (ISMS-P / ISO 27001)",
            "content": """## 취약점 위험성 평가 기준

MORI SOC의 CVE별 위험성 평가는 아래 방법론을 따릅니다.

### 위험도 산정식

> **위험도 = 영향도(Impact) × 발생가능성(Likelihood)**

- **영향도** = 자산 중요도(**상 / 중 / 하** → 3 / 2 / 1). `asset_classifier` 자동 분류 + 담당자 수동 재정의(override) 값을 사용합니다.
- **발생가능성** = 취약점 **심각도**(critical / high / medium / low → 3~1) + 보정계수(공개 패치 존재 시 ↑, 예외 만료 방치 시 ↑).
- **위험등급** = 점수(1~9)를 **낮음 / 중간 / 높음 / 매우높음** 4단계로 매핑(3×3 매트릭스).

### 심각도(severity) 기준은 KISA 척도인가?

**아니요.** 심각도 값은 **Trivy** 스캐너가 산출하며, 내부적으로 **CVSS(NVD/벤더 점수) + 배포판 보안권고**에 기반합니다. **KISA가 정한 고정 척도가 아닙니다.**

3×3 방법론(영향도×발생가능성)은 **ISMS-P 위험관리 / ISO 27001 6.1.2(위험평가)·8.8(기술적 취약점 관리)** 의 일반적 위험평가 방식입니다. **KISA ISMS-P는 위험도 산정표나 척도를 고정하지 않으며**, 조직이 **자체 산정기준 + DoA(수용가능 위험수준, Degree of Assurance)** 를 정의하도록 요구합니다.

### 조직 맞춤(DoA) 조정

- 평가 모달에서 영향도·발생가능성을 **수동 조정**해 조직 기준에 맞출 수 있습니다.
- **위험처리 결정**: 조치(Mitigate) / 수용(Accept) / 이관(Transfer) / 회피(Avoid) + 승인자·잔여위험·재평가일 기록.
- 필요 시 **K-ISMS식 3요소(자산가치 × 위협 × 취약성)** 산정표로 확장 가능합니다.

### 접근 권한

- 위험성 평가(등급 산정·수정)는 **admin · security 역할 전용**입니다.
- 인프라 · 헬프데스크는 자기 담당 서버의 **취약점 존재 여부와 조치율**만 열람합니다.

> **ISMS-P 관련 통제**: 2.10 시스템 및 서비스 보안(위험관리)
> **ISO 27001 관련 통제**: 6.1.2 정보보안 위험평가, 8.8 기술적 취약점 관리""",
            "updated_at": None,
        },
    }

    # ── Route context (Task J-4b) ─────────────────────────────────────────────
    # Shared in-memory state passed to the domain route modules in routes/.
    # Helper closures (get_query_service 등) are wired onto ctx as they are
    # defined below, immediately before the domain that first needs them.
    ctx = RouteContext(
        app=app,
        service=service,
        service_factory=service_factory,
        auth_config=_auth_config,
        auth_enabled=_auth_enabled,
        insecure_defaults=insecure_defaults,
        local_users=local_users,
        sessions=sessions,
        signup_requests=signup_requests,
        action_audit_log=action_audit_log,
        user_tab_permissions=user_tab_permissions,
        triage_store=triage_store,
        webhooks=webhooks,
        incidents=incidents,
        asset_owners=asset_owners,
        asset_audit_log=asset_audit_log,
        action_plans=action_plans,
        vuln_actions=vuln_actions,
        risk_register=risk_register,
        user_profiles=user_profiles,
        settings=settings,
        control_status=control_status,
        host_accounts=host_accounts,
        account_approvals=account_approvals,
        guides=guides,
        user_dashboard_prefs=user_dashboard_prefs,
        admin_dashboard_preferences=admin_dashboard_preferences,
        role_permissions=role_permissions,
        state_repo=state_repo,
    )
    ctx.log_action = _log_action

    # ── Write-through hooks (M2-1.0d) ─────────────────────────────────────────
    # Handlers mutate the in-memory cache then call ctx.persist_*(key) to flush
    # that single record through to state_repo (no-op for the in-memory backend).
    def _persist_user_profile(username: str) -> None:
        state_repo.save_user_profile(username, user_profiles[username])

    def _persist_asset_owner(hostname: str) -> None:
        state_repo.save_asset_owner(hostname, asset_owners[hostname])

    def _delete_asset_owner(hostname: str) -> None:
        state_repo.delete_asset_owner(hostname)

    def _persist_asset_audit(record: dict[str, Any]) -> None:
        state_repo.append_asset_audit(record)

    def _persist_vuln_action(vuln_id: str) -> None:
        state_repo.save_vuln_action(vuln_id, vuln_actions[vuln_id])

    def _persist_risk_assessment(vuln_id: str) -> None:
        state_repo.save_risk_assessment(vuln_id, risk_register[vuln_id])

    def _persist_triage(alert_id: str) -> None:
        state_repo.save_triage(alert_id, triage_store[alert_id])

    def _persist_incident(incident_id: str) -> None:
        state_repo.save_incident(incident_id, incidents[incident_id])

    def _persist_setting(key: str, updated_by: str = "") -> None:
        state_repo.save_setting(key, settings.get(key, ""), updated_by)

    def _persist_control_status(control_id: str) -> None:
        state_repo.save_control_status(control_id, control_status[control_id])

    def _persist_host_accounts(host_key: str) -> None:
        state_repo.save_host_accounts(host_key, host_accounts.get(host_key, []))

    def _persist_account_approval(approval_id: str) -> None:
        state_repo.save_account_approval(approval_id, account_approvals[approval_id])

    def _delete_account_approval(approval_id: str) -> None:
        state_repo.delete_account_approval(approval_id)

    ctx.persist_user_profile = _persist_user_profile
    ctx.persist_asset_owner = _persist_asset_owner
    ctx.delete_asset_owner = _delete_asset_owner
    ctx.persist_asset_audit = _persist_asset_audit
    ctx.persist_vuln_action = _persist_vuln_action
    ctx.persist_risk_assessment = _persist_risk_assessment
    ctx.persist_triage = _persist_triage
    ctx.persist_incident = _persist_incident
    ctx.persist_setting = _persist_setting
    ctx.persist_control_status = _persist_control_status
    ctx.persist_host_accounts = _persist_host_accounts
    ctx.persist_account_approval = _persist_account_approval
    ctx.delete_account_approval = _delete_account_approval

    def get_query_service() -> QueryService:
        if service is not None:
            return service
        if service_factory is not None:
            return service_factory()
        return create_query_service()

    ctx.get_query_service = get_query_service

    ctx.verify_credentials = _verify_credentials

    # ── Auth routes (login / signup / me / profile) ───────────────────────────
    from mori_soc.api.routes.auth import register_auth
    register_auth(ctx)

    # ── RBAC: role / user-tab permissions ─────────────────────────────────────
    from mori_soc.api.routes.rbac import register_rbac
    register_rbac(ctx)

    # ── Audit logs (user action / asset change) ───────────────────────────────
    from mori_soc.api.routes.audit import register_audit
    register_audit(ctx)

    # ── Pages (/, /ui, /admin) + health + catalog ─────────────────────────────
    from mori_soc.api.routes.pages import register_pages
    register_pages(ctx)

    # ── Query / Interpret / Dashboard summary ────────────────────────────────
    from mori_soc.api.routes.query import register_query
    register_query(ctx)

    # ── Compliance (PDCA / crosscheck / 증적 리포트) ─────────────────────────
    from mori_soc.api.routes.compliance import register_compliance
    register_compliance(ctx)

    def _get_session_username(request: Request) -> str | None:
        """현재 세션의 사용자명을 반환 (미인증 시 None)."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        return sess.get("username") if sess else None

    ctx.get_session_username = _get_session_username

    # ── Dashboard preferences (user / admin) ─────────────────────────────────
    from mori_soc.api.routes.dashboard_prefs import register_dashboard_prefs
    register_dashboard_prefs(ctx)

    # ── Alert Triage ────────────────────────────────────────────────────────────
    from mori_soc.api.routes.alerts import register_alerts
    register_alerts(ctx)

    # ── Slack Webhooks ───────────────────────────────────────────────────────────
    from mori_soc.api.routes.webhooks import register_webhooks
    register_webhooks(ctx)

    # ── Org settings (위험 DoA 기준 등) ──────────────────────────────────────────
    from mori_soc.api.routes.settings import register_settings
    register_settings(ctx)

    # ── LDAP 사용자 관리 (admin 전용, LDAP 활성 시) ──────────────────────────────
    from mori_soc.api.routes.ldap_admin import register_ldap_admin
    register_ldap_admin(ctx)

    # ── 계정 거버넌스 (서버/PC 로컬 계정 × LDAP × 승인대장) ──────────────────────
    from mori_soc.api.routes.accounts_gov import register_accounts_gov
    register_accounts_gov(ctx)

    # ── Incidents ────────────────────────────────────────────────────────────────
    from mori_soc.api.routes.incidents import register_incidents
    register_incidents(ctx)

    # ── Assets (collection board / owners / refresh) ──────────────────────────
    from mori_soc.api.routes.assets import register_assets
    register_assets(ctx)

    # ── Action Plans ──────────────────────────────────────────────────────────
    from mori_soc.api.routes.plans import register_plans
    register_plans(ctx)

    # ── Per-Vulnerability Actions (조치 계획 / 조치 예외) ─────────────────────
    from mori_soc.api.routes.vulnerabilities import register_vulnerabilities
    register_vulnerabilities(ctx)

    # ── Guides ───────────────────────────────────────────────────────────────
    from mori_soc.api.routes.guides import register_guides
    register_guides(ctx)

    # ── Per-source asset API (Fleet / Zabbix / Trivy) ─────────────────────────
    from mori_soc.api.routes.sources import register_sources
    register_sources(ctx)

    return app


def create_app_from_env() -> Any:
    return create_app(
        service_factory=create_query_service_from_env,
        state_repo=create_state_repository_from_env(),
    )


__all__ = [
    "DEFAULT_UI_PAYLOAD",
    "build_dashboard_payload",
    "build_query_request",
    "create_app",
    "create_app_from_env",
    "create_query_service",
    "create_query_service_from_env",
    "create_state_repository_from_env",
    "interpret_query_text",
    "render_query_console_html",
    "render_user_dashboard_html",
]
