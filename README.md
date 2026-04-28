# MORI SOC — Audit-Ready Security Operations

오픈소스 보안 도구를 통합하여 **ISMS-P / ISO 27001 인증 심사에 필요한 증적과 통제 점검 결과를 자동으로 수집·관리**하는 경량 SOC 플랫폼입니다.

> **목표:** "중소형 회사에서 IT 헬프데스크 + 담당자 1명이 ISMS / ISO 27001 준비와 기본 보안 운영을 같이 할 수 있는 SOC-lite 제품"

중소 규모 조직(SME)이 `docker compose` 한 줄로 배포하여, 아래 영역의 데이터를 하나의 대시보드에서 **통제 항목(Control) 기준**으로 조회·증적화할 수 있도록 설계했습니다.

| 영역 | 도구 | MORI 역할 |
|---|---|---|
| 인프라 모니터링 | Zabbix | 자산 현황·가용성 증적 |
| 로그 중앙화 | Loki + Fluent Bit | 로그 수집·보관 증적 |
| 엔드포인트 보안 | FleetDM | 자산 식별·구성 점검 |
| 보안 이벤트 | Wazuh | 경보 탐지·대응 증적 |
| 취약점 스캔 | Trivy | 취약점 점검·조치 증적 |
| 시각화 | Grafana | 운영 현황 대시보드 |

## 핵심 가치

> **"점검 결과를 보여주고, 증적을 내보내고, 미비 사항을 알려주는"** Compliance-Evidence Platform

- 통제 항목별 **Pass / Fail / Warning** 자동 점검 결과 관리
- PDCA(Plan-Do-Check-Act) 주기에 맞춘 운영 대시보드
- Zabbix × Fleet × Wazuh **교차 검증**으로 커버리지 Gap 탐지
- 자산·계정·권한·취약점 데이터를 **증적 리포트(CSV/PDF)** 로 즉시 내보내기
- 자연어 질의로 통제 점검 현황을 빠르게 조회

상세 설계와 단계별 구현 계획은 `docs/SECURITY_DATA_QUERY_PLATFORM.md`를 참고하세요.

---

## 🗺️ 현재 상태 한눈에 보기

### ✅ 데모 모드에서 동작하는 것

`./scripts/mori-start-demo.sh` 로 실행했을 때 샘플 데이터 기반으로 동작합니다.

| 기능 | 설명 |
|---|---|
| 대시보드 요약 카드 | 총 호스트 / 오프라인 / Alert 수 / Critical 취약점 표시 |
| 위험 호스트 목록 | 경보·오프라인 기준 상위 위험 호스트 |
| 소스 현황 | Fleet / Zabbix / Trivy 수집 상태 표시 |
| 자연어 질의 (NLQ) | "오프라인 호스트 보여줘", "최근 24시간 high alert 요약" 등 12개 인텐트 |
| 자산·경보·취약점 조회 API | `/query`, `/interpret`, `/dashboard/summary` |
| Compliance PDCA | 통제 항목 현황 시각화 (샘플 데이터) |
| 증적 리포트 CSV | 자산/계정/로그/취약점/월간 5종 |

> ⚠️ **주의:** 데모 모드는 인메모리 저장소로 동작합니다. **서버 재시작 시 모든 데이터가 초기화**됩니다.

---

### 🏭 운영 모드에서 실제 동작하는 것

현재 배포(`http://mori.rmstudio.co.kr:37854`)에서 실제로 사용 가능한 기능입니다.

| 기능 | 상태 | 계정 |
|---|---|---|
| 로그인 / 로그아웃 | ✅ 동작 | admin·security·moniter / 1234 |
| 역할 기반 탭 제어 (RBAC) | ✅ 동작 | 어드민이 역할별 탭 on/off 설정 가능 |
| 🚨 Alert Triage | ✅ 동작 | 3단계 상태(🔴🟡🟢) 변경 시 자동 저장, 이력 기록 |
| 📋 인시던트 관리 | ✅ 동작 | 생성·상태변경·노트·날짜 필터·텍스트 검색·CSV 다운로드 |
| 자산 담당자/카테고리 수정 | ✅ 동작 | 수정 이력 어드민 감사 로그에 기록 |
| 가입 요청 / 승인 | ✅ 동작 | 비가입자 요청 → 어드민 승인/거절 |
| 가이드 7종 노출 제어 | ✅ 동작 | 어드민이 가이드별 on/off 설정 |
| 자연어 질의 (FAB 버튼) | ✅ 동작 | 인메모리 데이터 기준 (실시간 수집 연동 전) |
| API 문서 (Swagger) | ✅ 동작 | `/admin` → 📋 API 문서(Swagger) 링크 |
| CSV 내보내기 | ✅ 동작 | 인시던트·자산 (필터 반영) |

> ⚠️ **주의:** 운영 모드에서도 **데이터 저장소는 인메모리**입니다. 재시작하면 인시던트·Triage 기록 등이 초기화됩니다. 영속성은 PostgreSQL 연동 완료 후 지원 예정입니다.

---

### 🔲 미완 항목 (개발 예정)

| 항목 | 현황 | 우선순위 |
|---|---|---|
| **데이터 영속성 (PostgreSQL)** | 인메모리만 동작, Postgres 코드는 준비됨 | 🔴 높음 |
| **실시간 수집 연동** | Zabbix·Fleet·Wazuh 수집기 코드 존재, API 폴링 미연결 | 🔴 높음 |
| **LDAP 인증 (운영)** | 코드 준비됨, `LDAP_URL` 환경변수 설정 필요 | 🟡 중간 |
| **PDF 증적 리포트** | CSV만 지원 | 🟡 중간 |
| **모바일 UI 완성도** | 기본 대응 완료, 세부 최적화 필요 | 🟢 낮음 |
| **Phase 3: 조사형 에이전트** | 미착수 | 🟢 낮음 |

---

### 🔌 실시간 연동 범위

| 소스 | 수집기 코드 | 운영 연동 | 비고 |
|---|---|---|---|
| **Zabbix** | ✅ 준비됨 | ❌ 미연결 | `ZABBIX_URL` / `ZABBIX_API_KEY` 설정 시 활성화 예정 |
| **FleetDM** | ✅ 준비됨 | ❌ 미연결 | `FLEET_URL` / `FLEET_API_TOKEN` 설정 시 활성화 예정 |
| **Wazuh** | ✅ 준비됨 | ❌ 미연결 | `WAZUH_URL` / `WAZUH_API_*` 설정 시 활성화 예정 |
| **Trivy** | ✅ 준비됨 | 🟡 온디맨드 | `./scripts/trivy-fs-scan.sh` 로 수동 실행 후 결과 적재 |
| **LDAP** | ✅ 준비됨 | 🟡 선택적 | `LDAP_URL` 환경변수 설정 시 HTTP Basic Auth 활성화 |

> **현재 운영 환경의 대시보드 데이터는 샘플 시딩 또는 수동 입력(Triage·인시던트) 기반입니다.**
> 실시간 수집이 연결되면 Zabbix/Fleet에서 자동으로 자산·경보 데이터가 유입됩니다.

---

## Security Data Query Platform — 단계별 진행 현황

### ✅ Phase 1: 데이터 수집/정규화 코어 — **완료**

`src/mori_soc/` 아래에 Python 라이브러리로 구현되었습니다.
현재는 **인메모리 레이어**로 동작하며, 실제 DB/API 연결 없이 로직 검증이 가능합니다.

| 구성 요소 | 모듈 | 내용 |
|---|---|---|
| **데이터 모델** | `models/entities.py` | Host, HostAlias, Alert, Vulnerability, HostObservation, QueryResult |
| **Fleet 수집기** | `collectors/fleet_logs.py` | osquery status/result 로그 파싱, NormalizedEnvelope 생성 |
| **Wazuh 수집기** | `collectors/wazuh_alerts.py` | Wazuh 4.x alert JSON 파싱, level → severity 변환 |
| **Zabbix 수집기** | `collectors/zabbix_events.py` | trigger 이벤트 → alert, item 값 → host_observation |
| **정규화/엔터티 매핑** | `services/normalization.py` | EnvelopeEntityMapper — host 자동 생성, HostAlias 등록 |
| **수집 인제스천** | `services/ingestion.py` | CollectorIngestionService — 수집기 → 저장소 흐름 |
| **Risk Score 계산기** | `services/risk_score.py` | alert/vuln 심각도 가중치 기반 점수 산출 |
| **질의 카탈로그** | `services/query_catalog.py` | 12개 질의 인텐트 정의 |
| **질의 서비스** | `services/query_service.py` | 12개 인텐트 핸들러, 근거(evidence) 기반 응답 |
| **논리 뷰 집계** | `services/views.py` | latest_host_status_view, host_risk_summary_view, host_timeline_view |
| **인메모리 저장소** | `repositories/memory.py` | InMemoryRepository, InMemoryQueryStore |
| **API 계약** | `api/contracts.py` | QueryRequest, QueryResponse, EvidenceRef, QueryScope |
| **단위 테스트** | `tests/test_query_service.py` | 20+ 테스트 케이스 (질의 1~12 + 뷰 3개) |

**12개 질의 인텐트:**

| # | intent | 설명 |
|---|---|---|
| 1 | `alert_summary` | 지난 N시간 high/critical 경보 요약 |
| 2 | `offline_hosts` | 현재 오프라인/unknown 호스트 |
| 3 | `fleet_checkin_gap` | Fleet 체크인 누락 호스트 |
| 4 | `top_vulnerable_hosts` | 취약점 상위 호스트 Top N |
| 5 | `host_timeline` | 특정 호스트 타임라인 (alert+query+obs 병합) |
| 6 | `host_wazuh_alerts` | 특정 호스트 Wazuh 경보만 조회 |
| 7 | `host_fleet_queries` | 특정 호스트 Fleet 쿼리 결과 조회 |
| 8 | `new_high_vulns` | 최근 신규 high+ 취약점 |
| 9 | `risky_hosts` | 경보 多 + offline/unknown 호스트 |
| 10 | `unmapped_assets` | Fleet/Wazuh/Zabbix 미매핑 자산 |
| 11 | `login_failure_spike` | 로그인 실패 급증 호스트 |
| 12 | `collection_errors` | 수집 오류 반복 호스트 |

#### 새 Intent 추가 방법 (Intent Registry)

`QueryService`는 `_INTENT_HANDLERS` 딕셔너리로 intent → handler 메서드를 디스패치합니다.
새 intent를 추가할 때는 아래 **3단계**만 수행하면 됩니다.

1. **`services/query_catalog.py`** — `PHASE1_QUERY_CATALOG`에 `TemplateQuery` 추가
   ```python
   TemplateQuery(
       query_id="my_new_intent",
       name="새 인텐트 이름",
       description="설명",
       intent="my_new_intent",
       default_window="24h",
       required_filters=("time_range",),
       evidence_sources=("alerts",),
   ),
   ```

2. **`services/query_service.py`** — `_INTENT_HANDLERS`에 한 줄 추가 + 핸들러 메서드 구현
   ```python
   _INTENT_HANDLERS: dict[str, str] = {
       ...
       "my_new_intent": "_my_new_intent",   # ← 추가
   }

   def _my_new_intent(self, request: QueryRequest, query_id: str) -> QueryResponse:
       # 구현
       ...
   ```

3. **`tests/test_query_service.py`** — 핸들러 동작 테스트 추가

> 기존 12개 분기 `if-else` 체인이 레지스트리 패턴으로 교체되었으므로,
> `execute()` 메서드를 수정할 필요 없이 위 두 곳만 변경하면 자동으로 라우팅됩니다.

### 🚧 Phase 2: 관제 질의 엔진 — **Alpha (운영 배포 중, 일부 기능 데모 전용)**

| 항목 | 상태 | 모드 | 내용 |
|---|---|---|---|
| **FastAPI HTTP 서버** | ✅ 완료 | 운영 | `GET /health`, `GET /catalog`, `POST /query`, `POST /interpret` |
| **로그인 / 세션 인증** | ✅ 완료 | 운영 | 쿠키 기반 세션, admin·security·moniter 3개 기본 계정 |
| **RBAC (역할별 탭 제어)** | ✅ 완료 | 운영 | 어드민이 역할별 탭 on/off 설정 |
| **Alert Triage** | ✅ 완료 | 운영¹ | 3단계 상태 자동저장, 담당자·노트·이력 기록 |
| **인시던트 관리** | ✅ 완료 | 운영¹ | 생성·상태변경·검색·날짜필터·CSV 다운로드 |
| **자산 담당자/카테고리 편집** | ✅ 완료 | 운영¹ | 수정 이력 감사 로그 기록 |
| **가입 요청 / 승인** | ✅ 완료 | 운영 | 어드민 승인·거절 |
| **가이드 시스템 (7종)** | ✅ 완료 | 운영 | 어드민 on/off 제어, 내용 직접 편집 |
| **자연어 질의 (FAB)** | ✅ 완료 | 데모 | 12개 인텐트, 인메모리 데이터 기준 |
| **Docker Compose 배포선** | ✅ 완료 | 운영 | `mori-api`, `soc-postgres`, Dockerfile, GitHub Actions |
| **원커맨드 데모** | ✅ 완료 | 데모 | `mori-start-demo.sh`, 샘플 데이터 시딩 |
| **PostgresRepository 코드** | ✅ 준비됨 | 미연결 | 코드는 완성, 실제 Postgres 읽기/쓰기는 미연결 |
| **Worker / Poller 코드** | ✅ 준비됨 | 미연결 | Zabbix·Fleet·Wazuh·Trivy 수집기 코드 완성, API 폴링 미연결 |
| **데이터 영속성** | 🔲 남음 | — | 현재 인메모리 → 재시작 시 초기화 |
| **실시간 수집 연동** | 🔲 남음 | — | Zabbix·Fleet·Wazuh API 실시간 폴링 미완 |
| **LDAP 인증 (운영)** | 🔲 남음 | — | 코드 준비됨, `LDAP_URL` 환경변수 설정 필요 |

> ¹ **운영¹** = 실제로 동작하지만 **인메모리 저장소** 기반이라 재시작 시 데이터 초기화됨

**핵심 제약:**
- 현재 `/dashboard/summary` 와 `/ui` 의 자산·경보·취약점 데이터는 **원본 Zabbix/Fleet API에서 직접 읽는 것이 아니라** MORI 인메모리 저장소에 적재된 데이터를 보여줍니다.
- 데모 모드에서는 `mori-seed-sample-data.sh`로 샘플 데이터를 자동 삽입하여 전체 기능을 체험할 수 있습니다.
- **실시간 연동이 완성되기 전까지** Triage/인시던트는 운영 사용 가능하지만, 대시보드 자산 현황은 샘플 데이터 기반입니다.

### 권장 운영 모델

- **PC / 노트북 / 사용자 단말**: `FleetDM`
  - osquery 기반 인벤토리, 쿼리, 취약점, 정책 점검에 강함
- **서버 / VM / 상시 가동 자산**: `Zabbix Agent`
  - 가용성, 리소스 메트릭, trigger/event 기반 운영 관측에 강함
- **보안 이벤트 탐지**: `Wazuh`
  - 인증/프로세스/무결성/탐지 이벤트를 경보 형태로 제공
- **취약점 스캔**: `Trivy`
  - 현재는 온디맨드/배치 스캔이 적합하며, 이후 MORI 수집 파이프라인으로 연결 예정

`Zabbix Agent + Trivy`를 묶은 자체 agent는 장기적으로는 가능하지만,
지금 단계에서는 배포/업데이트/권한/플랫폼별 패키징 복잡도가 커서 **후순위**가 더 자연스럽습니다.
우선은 `PC=Fleet`, `Server=Zabbix Agent`, `Vuln=Trivy`, `Detection=Wazuh`로 역할을 분리하는 편이 운영 리스크가 낮습니다.

### 🔲 Phase 3: 제한형 조사 에이전트 — **미착수**

- host/user/ip 기준 다단계 pivot
- 여러 소스 cross-check
- 조사형 질문 지원 + 다음 확인 포인트 추천

---

## 🚀 Quick Start

### 데모 모드 (샘플 데이터)

Docker와 Docker Compose가 설치된 환경에서 한 줄로 전체 데모를 실행할 수 있습니다.

#### ▶️ 데모 시작

```bash
# 원커맨드 데모: .env 생성 → API 기동 → 스키마/샘플 시딩 → 데모 인시던트 생성 → 워커 시작
./scripts/mori-start-demo.sh
```

실행 완료 후 `http://localhost:18000/ui` 접속 → `admin / 1234` 로그인.

#### ⏹️ 데모 종료

```bash
# 1) 데모 데이터만 삭제 + 컨테이너 정지 (실제 폴러 수집 데이터 보존) — 기본
./scripts/mori-stop-demo.sh

# 2) 데모 데이터만 삭제, 컨테이너는 계속 실행
./scripts/mori-stop-demo.sh --keep

# 3) 컨테이너 + 볼륨까지 모두 제거 (DB 통째로 초기화)
./scripts/mori-stop-demo.sh --purge
```

`mori-stop-demo.sh`는 시드 스크립트가 삽입한 **정확한 ID**(`h-web-01`, `al-01`, `cc-01` 등)만 매칭해서 삭제하므로,
이미 폴러가 실제 환경에서 수집한 데이터는 그대로 보존됩니다.

#### 데모로 체험 가능한 기능

| 기능 | 데모 여부 |
|---|---|
| 📊 대시보드 (자산·경보·취약점 요약) | ✅ 샘플 데이터 |
| 🚨 Alert Triage (3단계 상태 관리) | ✅ 실동작 |
| 📋 인시던트 관리 (검색·날짜필터·CSV) | ✅ 데모 인시던트 3건 자동 생성 |
| 💬 자연어 질의 (12개 인텐트) | ✅ 샘플 데이터 기준 |
| ✅ Compliance PDCA + 교차검증 | ✅ 샘플 데이터 |
| 🔍 Fleet osquery 결과 | ✅ 샘플 데이터 |
| 🛡️ Trivy 취약점 스캔 결과 | ✅ 샘플 데이터 |
| 📥 증적 리포트 CSV 5종 | ✅ 샘플 데이터 |

### 운영 배포 (현재 공개 서버)

- URL: `http://mori.rmstudio.co.kr:37854/`
- 계정: `admin / 1234` (어드민), `security / 1234` (보안담당자), `moniter / 1234` (모니터)
- 운영 배포 방법: `docker compose down && docker compose up -d`
- 데이터: 재시작 시 초기화 (영속성은 PostgreSQL 연동 완료 후 지원)

### 개별 스크립트

```bash
# 샘플 데이터만 (재)삽입
./scripts/mori-seed-sample-data.sh

# 워커(Poller) 관리
./scripts/mori-run-workers.sh start     # 워커 시작
./scripts/mori-run-workers.sh status    # 상태 확인
./scripts/mori-run-workers.sh cycle     # 수동 1회 수집 사이클
./scripts/mori-run-workers.sh logs      # 로그 확인
./scripts/mori-run-workers.sh stop      # 워커 중지
```

### 시딩되는 샘플 데이터

DB(PostgreSQL)에 영속 저장되는 데이터:

| 항목 | 수량 | 설명 |
|---|---|---|
| Hosts | 10 | 서버, PC, 방화벽, VPN 등 다양한 자산 |
| Host Aliases | 13 | Zabbix/Fleet/Trivy 소스별 매핑 |
| Alerts | 8 | Wazuh/Zabbix — SSH brute force, rootkit, disk/CPU 경보 등 |
| Vulnerabilities | 8 | Trivy 6 + Fleet 2 — CVE 기반 critical~medium |
| Observations | 9 | Zabbix/Fleet — CPU, Disk, Memory, 암호화 상태 |
| Fleet Query Results | 8 | osquery — 설치앱, 디스크 암호화, 시작 프로그램 등 |
| Control Checks | 12 | ISO 27001 / ISMS-P 통제 항목 점검 결과 |
| Directory Accounts | 7 | LDAP 사용자 (관리자, 개발자, DBA 등) |
| Privilege Bindings | 6 | sudo, domain_admin, db_admin 권한 |
| Group Memberships | 8 | Domain Admins, Developers, DBA 등 |
| Source Syncs | 4 | Zabbix/Fleet/Trivy/Wazuh 수집 상태 |

API 인메모리 저장(API 재시작 시 초기화)으로 별도 생성되는 데이터:

| 항목 | 수량 | 생성 시점 |
|---|---|---|
| Incidents | 3 | `mori-start-demo.sh`가 시드 후 `POST /incidents` 호출 |
| Triage 상태 | 0 | UI에서 직접 변경 시 누적 |

---

## 🧪 테스트

### 단위 테스트 (Docker 환경)

컨테이너 안에서 pytest를 실행합니다. (로컬에 Python 3.12이 없어도 됩니다)

```bash
# pytest 설치 + 전체 테스트 실행
docker compose run --rm \
  -v "$(pwd)/tests:/app/tests:ro" \
  mori-api \
  sh -c "pip install pytest && python -m pytest /app/tests/ -v"
```

```bash
# 특정 테스트 파일만
docker compose run --rm \
  -v "$(pwd)/tests:/app/tests:ro" \
  mori-api \
  sh -c "pip install pytest && python -m pytest /app/tests/test_api_server.py -v"
```

```bash
# PDCA/Compliance 테스트만
docker compose run --rm \
  -v "$(pwd)/tests:/app/tests:ro" \
  mori-api \
  sh -c "pip install pytest && python -m pytest /app/tests/test_api_server.py -v -k 'Pdca or Compliance'"
```

### 테스트 파일 목록

| 파일 | 대상 |
|---|---|
| `tests/test_api_server.py` | FastAPI 엔드포인트, PDCA payload, Compliance 통합 |
| `tests/test_query_service.py` | 12개 질의 인텐트 + 뷰 집계 |
| `tests/test_fleet_logs.py` | Fleet osquery 로그 수집기 |
| `tests/test_wazuh_alerts.py` | Wazuh alert 수집기 |
| `tests/test_zabbix_events.py` | Zabbix trigger/item 수집기 |
| `tests/test_trivy_collector.py` | Trivy 취약점 수집기 |
| `tests/test_ingestion.py` | 인제스천 파이프라인 |
| `tests/test_intent_parser.py` | 자연어 → intent 파서 |
| `tests/test_postgres_repository.py` | Postgres 저장소 (DB 필요) |

### API 수동 테스트

```bash
# Health check
curl http://localhost:18000/health

# 대시보드 요약 JSON
curl http://localhost:18000/dashboard/summary

# PDCA 현황
curl http://localhost:18000/compliance/pdca

# Cross-verification
curl http://localhost:18000/compliance/crosscheck

# 리포트 목록
curl http://localhost:18000/compliance/reports

# 자산 점검 리포트 (CSV)
curl http://localhost:18000/compliance/reports/asset?format=csv

# 자연어 질의 해석
curl -X POST http://localhost:18000/interpret \
  -H 'Content-Type: application/json' \
  -d '{"text":"오프라인 호스트 보여줘"}'

# 구조화 질의 실행
curl -X POST http://localhost:18000/query \
  -H 'Content-Type: application/json' \
  -d '{"intent":"offline_hosts","scope":{"time_range":"24h"}}'
```

---

## 참고 문서

- `docs/FUNCTIONAL_SPEC.md`: 기능 정의서 원문
- `docs/SECURITY_CONTROL_MAPPING.md`: 보안 통제(Security Controls) 매핑 문서
- `docs/IMPLEMENTATION_ROADMAP.md`: 기능 정의서 기준 구현 로드맵
- `docs/SECURITY_DATA_QUERY_PLATFORM.md`: 데이터 중심 보안 질의 플랫폼 설계 및 단계별 구현 계획
- `docs/MORI_IMPLEMENTATION_SUMMARY.md`: 현재까지 구현된 기능, 운영 전략, 다음 단계 요약
- `docs/PHASE1_INPUT_SOURCES_AND_SCHEMA.md`: Phase 1 입력 소스 명세, 공통 스키마 초안, 1차 질의 카탈로그
- `docs/PHASE1_LOGICAL_SCHEMA.md`: Phase 1 논리 스키마, 테이블 관계, 인덱스 초안
- `schema/001_phase1_initial.sql`: Phase 1 Postgres 초기 DDL 초안
- `docs/ZABBIX_AGENT_ACTIVE_SETUP.md`: PC/단말 Zabbix Agent Active 등록 가이드
- `docs/TRIVY_USAGE.md`: Trivy 파일시스템/이미지 스캔 가이드
- `docs/DEPLOYMENT.md`: 서버 배포/운영/트러블슈팅 가이드
- `docs/FLEET_MACBOOK_ENROLLMENT_AND_TEST.md`: Fleet macOS 등록/검증/대시보드 확인 문서
- `docs/FLEET_RESET_AND_REINSTALL_GUIDE.md`: Fleet 로그인 문제 시 초기화 및 macOS host 재설치 가이드

## 1. 배포 목표

- 공개 주소: `http://mori.rmstudio.co.kr:37854`
- Grafana 주소: `http://mori.rmstudio.co.kr:13000`
- Zabbix 주소: `http://mori.rmstudio.co.kr:18081`
- 배포 경로: `/backup/rmstudio/mori`
- 배포 방식: GitHub Actions + SSH
- 실행 방식: `docker compose`

현재 외부 공개 진입점은 **메인 포털**이며,
포털에서 Grafana와 Zabbix 운영 UI로 이동하는 구조입니다.

## 2. 현재 구성된 서비스

### Public Entry
- `Main Portal` (`37854`)
- `Grafana` (`13000`)
- `Zabbix Web` (`18081`, 기본값)

### Internal Services
- `Loki`: 중앙 로그 저장소
- `Fluent Bit`: 호스트 로그 수집 및 Loki 전송
- `Zabbix Server/Web`: 인프라 모니터링
- `FleetDM`: 엔드포인트/취약점 관리
- `Wazuh Manager/Indexer/Dashboard`: 보안 이벤트 탐지 및 분석
- `Trivy`: 파일시스템 취약점 스캔(Profile 기반)

## 3. 포트 구성

- Public
  - `37854` → Main Portal
  - `13000` → Grafana
  - `18081` → Zabbix Web
  - `1337` → FleetDM

- Internal / localhost only
  - `127.0.0.1:8443` → Wazuh Dashboard

- Service ports
  - `10051` → Zabbix Server
  - `1514` → Wazuh agent traffic
  - `1515` → Wazuh registration
  - `514/udp` → Syslog
  - `55000` → Wazuh API

## 4. 저장소에 추가된 파일

- `docker-compose.yml`: 전체 SOC-lite 스택 구성
- `.env.example`: 배포용 환경변수 예시
- `generate-indexer-certs.yml`: Wazuh 인증서 생성용 compose 파일
- `docs/SECURITY_CONTROL_MAPPING.md`: 보안 통제 매핑 문서
- `docs/SECURITY_DATA_QUERY_PLATFORM.md`: 데이터 중심 보안 질의 플랫폼 설계 문서
- `docs/PHASE1_INPUT_SOURCES_AND_SCHEMA.md`: Phase 1 입력 소스/스키마/질의 명세 문서
- `docs/PHASE1_LOGICAL_SCHEMA.md`: Phase 1 논리 테이블/관계 설계 문서
- `schema/001_phase1_initial.sql`: Phase 1 초기 SQL 스키마 파일
- `src/mori_soc/models/entities.py`: Host, HostAlias, Alert, Vulnerability, HostObservation, QueryResult 엔터티
- `src/mori_soc/collectors/fleet_logs.py`: Fleet osquery log 수집기
- `src/mori_soc/collectors/wazuh_alerts.py`: Wazuh 4.x alert 수집기
- `src/mori_soc/collectors/zabbix_events.py`: Zabbix trigger/item 수집기
- `src/mori_soc/services/normalization.py`: 수집 엔벨로프 → 엔터티 매핑 (EnvelopeEntityMapper)
- `src/mori_soc/services/ingestion.py`: 수집기 인제스천 서비스
- `src/mori_soc/services/risk_score.py`: Risk Score 계산기 (alert/vuln 가중치 기반)
- `src/mori_soc/services/query_catalog.py`: Phase 1 질의 카탈로그 (12개 인텐트)
- `src/mori_soc/services/query_service.py`: 인텐트 핸들러 + 근거(evidence) 기반 응답
- `src/mori_soc/services/views.py`: 논리 뷰 집계 (latest_host_status, host_risk_summary, host_timeline)
- `src/mori_soc/repositories/memory.py`: InMemoryRepository / InMemoryQueryStore
- `src/mori_soc/api/contracts.py`: QueryRequest, QueryResponse, EvidenceRef, QueryScope
- `tests/test_query_service.py`: 20+ 단위 테스트 (질의 1~12 + 뷰 3개)
- `docs/ZABBIX_AGENT_ACTIVE_SETUP.md`: Zabbix Agent 온보딩 문서
- `docs/TRIVY_USAGE.md`: Trivy 활용 가이드
- `docs/FLEET_MACBOOK_ENROLLMENT_AND_TEST.md`: Fleet macOS 등록/검증/대시보드 확인 문서
- `.github/workflows/deploy.yml`: GitHub Actions 배포 워크플로우
- `docs/DEPLOYMENT.md`: 서버 준비 및 운영 가이드
- `config/zabbix_agent/zabbix_agent2.active.example.conf`: Active Agent 예시 설정
- `config/portal/index.html`: 메인 포털 페이지
- `scripts/trivy-fs-scan.sh`: 파일시스템 취약점 스캔 스크립트
- `scripts/trivy-image-scan.sh`: 이미지 취약점 스캔 스크립트
- `scripts/mori-start-demo.sh`: 원커맨드 데모 실행 (env 생성 → 기동 → 스키마/시드 → 인시던트 생성 → 워커)
- `scripts/mori-stop-demo.sh`: 데모 정지 (기본/`--keep`/`--purge` — 시드 ID만 정확히 매칭해 삭제, 실수집 데이터 보존)
- `scripts/mori-seed-sample-data.sh`: 샘플 데이터 SQL 시딩 (10 hosts, 8 alerts, 8 vulns, 9 obs, 8 fleet queries, 12 checks, 7 accounts)
- `scripts/mori-run-workers.sh`: Worker/Poller 관리 유틸리티 (start/stop/status/cycle/logs)
- `src/mori_soc/services/reports.py`: 5종 감사 증적 리포트 생성 (자산/계정/로그/취약점/월간)
- `schema/002_phase2_compliance_identity.sql`: Phase 2 Compliance/Identity DDL
- `config/*`: 각 서비스별 설정 파일

## 5. 배포 방식

GitHub Actions가 아래 순서로 동작하도록 구성했습니다.

1. 저장소 체크아웃
2. 서버 경로 `/backup/rmstudio/mori` 생성 확인
3. `rsync`로 코드 동기화
4. GitHub Secret의 `.env` 내용을 서버에 업로드
5. Wazuh 인증서 디렉터리 준비 후 최초 1회 인증서 생성
6. `docker compose pull`
7. `docker compose up -d --remove-orphans`

## 6. 필수 환경변수

`.env.example` 기준으로 실제 `.env`를 작성해야 합니다.

현재 기본 Grafana 관리자 비밀번호는 요청값에 맞춰 `1234`로 설정되어 있습니다.
단, Grafana 볼륨이 이미 생성된 뒤에는 `.env` 값을 바꿔도 기존 비밀번호가 유지될 수 있으므로,
로그인이 안 되면 `docs/DEPLOYMENT.md`의 Grafana 트러블슈팅 절차를 먼저 확인하세요.

메인 포털은 `PUBLIC_PORT`, Grafana는 `GRAFANA_PORT`, Grafana URL 표시는 `GRAFANA_URL`을 사용합니다.

반드시 변경해야 하는 값:

- `GRAFANA_ADMIN_PASSWORD`
- `ZABBIX_DB_PASSWORD`
- `FLEET_DB_ROOT_PASSWORD`
- `FLEET_DB_PASSWORD`
- `FLEET_SERVER_PRIVATE_KEY`

예시:

- `cp .env.example .env`
- `openssl rand -base64 32`

## 7. 서버 사전 준비

- Docker Engine 설치
- Docker Compose Plugin 설치
- 배포 디렉터리 생성: `/backup/rmstudio/mori`
- Wazuh Indexer용 커널 파라미터 적용

필수 설정:

- `vm.max_map_count=262144`

## 8. GitHub Secrets

워크플로우 실행을 위해 아래 Secret이 필요합니다.

- `DEPLOY_HOST`
- `DEPLOY_PORT`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`
- `DEPLOY_ENV_FILE`
- `DEPLOY_KNOWN_HOSTS` (선택)

## 9. 현재 검증 상태

완료된 검증:

- `docker compose config` 통과
- `docker compose -f generate-indexer-certs.yml config` 통과

또한 Wazuh Dashboard의 설정 마운트 충돌 가능성을 제거하도록 compose를 보정했습니다.
Wazuh 인증서 마운트도 디렉터리 방식으로 보정해 파일/디렉터리 마운트 꼬임 가능성을 낮췄습니다.
Grafana에는 Loki 데이터소스와 starter overview dashboard 프로비저닝을 추가했습니다.
메인 포털 페이지도 추가해 37854 포트에서 운영 UI 동선을 제공하도록 구성했습니다.

## 10. 운영 메모

- 현재 공개 서비스는 Main Portal, Grafana, Zabbix Web, FleetDM입니다.
- Wazuh Dashboard는 localhost 바인딩으로 제한했습니다.
- 메인 포털(`37854`)에서 Grafana(`13000`), Zabbix(`18081`), FleetDM(`1337`)으로 이동할 수 있습니다.
- Zabbix 알람/트리거 조정은 Web UI를 통해 운영할 수 있습니다.
- Zabbix Web 초기 기본 계정은 공식 문서 기준 `Admin / zabbix`이며 현재 compose에서 별도 변경하지 않았습니다.
- Grafana admin 기본값은 `admin / 1234`입니다.
- FleetDM은 현재 HTTP(`1337`)로 공개되어 있으므로 운영 환경에서는 리버스 프록시/TLS 적용을 권장합니다.
- Grafana 로그인 실패는 대부분 기존 `grafana-data` 볼륨에 남아 있는 초기 비밀번호 때문입니다.
- Wazuh 기본 예제 계정은 공식 예시 기본값(`SecretPassword`)을 사용 중입니다.
- Wazuh 비밀번호를 변경하려면 `config/wazuh_indexer/internal_users.yml`의 해시와 관련 설정을 함께 수정해야 합니다.
- Trivy 스캔은 필요 시 profile로 실행합니다.

## 11. 어떻게 테스트하면 되는지

배포 후 아래 순서로 최소 기능 테스트를 진행하면 됩니다.

### 1) 컨테이너 상태 확인

- `docker compose ps`
- `docker compose logs grafana --tail=50`
- `docker compose logs zabbix-web --tail=50`

정상 기준:

- 주요 컨테이너가 `Up` 상태
- Grafana / Zabbix Web 로그에 치명 오류가 없음

### 2) Grafana 로그인 테스트

- 메인 포털 접속: `http://mori.rmstudio.co.kr:37854`
- Grafana 접속: `http://mori.rmstudio.co.kr:13000`
- 계정: `admin / 1234`
- 확인 항목:
  - 메인 포털에서 Grafana 링크 이동 가능
  - 로그인 성공
  - `MORI Security Overview` 대시보드 표시
  - Explore에서 Loki 데이터소스 선택 가능

로그인이 안 되면 `docs/DEPLOYMENT.md`의 Grafana 비밀번호 리셋 절차를 수행합니다.

### 3) Zabbix Web UI 테스트

- 메인 포털 접속: `http://mori.rmstudio.co.kr:37854`
- 접속: `http://mori.rmstudio.co.kr:18081`
- 기본 계정: `Admin / zabbix`
- 확인 항목:
  - 메인 포털에서 Zabbix 링크 이동 가능
  - 로그인 화면 노출
  - 초기 계정으로 로그인 가능한지 확인
  - Zabbix 서버 연결 오류가 없는지 확인
  - 향후 트리거/알람 조정용 UI로 접근 가능한지 확인

### 4) Loki 로그 수집 테스트

Grafana Explore에서 Loki로 아래 쿼리를 실행합니다.

- `{job="fluent-bit"}`

정상 기준:

- 호스트 로그가 조회됨
- 새 로그가 시간 흐름에 따라 계속 유입됨

### 5) Wazuh / Fleet 접속 테스트

- FleetDM: 외부/브라우저에서 `http://mori.rmstudio.co.kr:1337`
- Wazuh Dashboard: 서버에서 `https://127.0.0.1:8443`

FleetDM은 외부 공개 상태이며, Wazuh Dashboard만 내부 운영용으로 유지합니다.

FleetDM 테스트 결과를 Grafana에서 보려면, Fleet에 단말을 등록하고 live query 또는 policy/query pack이 실제로 실행되어
`/logs/osqueryd.status.log`, `/logs/osqueryd.results.log`에 로그가 쌓여야 합니다.

Grafana Explore에서 Loki로 아래 쿼리를 확인합니다.

- Fleet status 로그: `{job="fleetdm", log_type="status"}`
- Fleet result 로그: `{job="fleetdm", log_type="result"}`

## 12. MORI API (Phase 2 MVC 1~4) 배포

이제 `mori-api` + `soc-postgres`가 `docker compose`로 함께 올라가도록 구성을 추가했습니다.

### 추가된 항목

- `Dockerfile` : MORI API 컨테이너 이미지
- `docker-compose.yml` : `mori-api`, `soc-postgres` 서비스 추가
- `src/mori_soc/repositories/postgres.py` : Postgres 저장소
- `src/mori_soc/api/server.py` : env 기반 `memory/postgres` 백엔드 선택 지원

### 환경변수

`.env.example`에 아래 값이 추가되었습니다.

- `MORI_API_PORT=18000`
- `MORI_DB_NAME=mori_soc`
- `MORI_DB_USER=mori`
- `MORI_DB_PASSWORD=...`

### 최초 설정

1. `.env` 준비
   - `cp .env.example .env`
   - `MORI_DB_PASSWORD`를 반드시 변경
2. 기존 스택과 함께 기동
   - `docker compose up -d soc-postgres mori-api`
3. 상태 확인
   - `docker compose ps soc-postgres mori-api`
   - `docker compose logs mori-api --tail=100`

### API 확인

- 브라우저 UI: `http://mori.rmstudio.co.kr:${MORI_API_PORT:-18000}/ui`
- Swagger Docs: `http://mori.rmstudio.co.kr:${MORI_API_PORT:-18000}/docs`
- Health: `curl http://mori.rmstudio.co.kr:${MORI_API_PORT:-18000}/health`
- Catalog: `curl http://mori.rmstudio.co.kr:${MORI_API_PORT:-18000}/catalog`
- Dashboard JSON: `curl http://mori.rmstudio.co.kr:${MORI_API_PORT:-18000}/dashboard/summary`
- Natural language 해석: `POST /interpret`
- Query 예시:

<augment_code_snippet mode="EXCERPT">
````bash
curl -X POST http://mori.rmstudio.co.kr:18000/query \
  -H 'Content-Type: application/json' \
  -d '{"intent":"offline_hosts","scope":{"time_range":"24h"}}'
````
</augment_code_snippet>

웹에서 테스트할 때는 우선 `/ui` 또는 `/docs`로 접속하면 됩니다.
메인 포털(`http://mori.rmstudio.co.kr:${PUBLIC_PORT:-37854}`)에도 MORI Query UI 링크를 추가했습니다.

`/ui`에서는 이제 아래를 한 화면에서 볼 수 있습니다.

- 요약 카드: 총 호스트 / 오프라인 / high alert / critical vuln / source coverage
- Latest Host Status
- Risk Summary
- Recent Activity
- Quick Actions + 자연어 질의 + 구조화 payload 실행

예:

- `오프라인 호스트 보여줘`
- `최근 24시간 wazuh high alert 요약`
- `host-1 타임라인 보여줘`

### 캐시만 지우고 재빌드

데이터 볼륨은 유지하고 **빌드 캐시만** 정리하려면:

- `docker builder prune -f`
- `docker compose build --no-cache mori-api`
- `docker compose up -d mori-api`

### 주의

- `soc-postgres`는 **초기 1회만** `schema/001_phase1_initial.sql`을 자동 적용합니다.
- 이미 `mori-postgres-data` 볼륨이 만들어진 뒤에는 schema 파일 변경이 자동 반영되지 않습니다.
- 현재 단계에서는 **스키마와 조회 API 배포선**까지 포함되며, 실제 데이터 적재는 이후 실시간 수집 연동이 필요합니다.

## 13. 이어서 작업할 때 사용할 프롬프트

다른 장소에서 이 저장소 작업을 다시 이어갈 때는,
현재 목표와 읽어야 할 파일, 그리고 바로 다음 작업 범위를 한 번에 적어주면 가장 빠르게 이어집니다.

### 현재 상태 (Phase 1 완료 / Phase 2 진행 중)

- Phase 1 (데이터 수집/정규화 코어) — **완료**
  - `src/mori_soc/` : 수집기, 정규화, 질의 서비스, 뷰 집계, 인메모리 저장소
  - `tests/test_query_service.py` : 20+ 단위 테스트
- Phase 2 (관제 질의 엔진) — **진행 중**
  - FastAPI HTTP 서버 추가 완료
  - PostgresRepository 추가 완료
  - Dockerfile / `mori-api` / `soc-postgres` compose 항목 추가 완료
  - 규칙형 자연어 질의 변환기 완료
  - `/ui` 운영 대시보드형 웹 UI 완료
  - 남은 큰 작업: 실시간 수집 연동, SQL 기반 읽기 최적화

### Phase 2 이어가기 프롬프트 (추천)

```
이 저장소는 MORI SOC-lite이며, Security Data Query Platform을 단계별로 구현 중이다.
README의 "Security Data Query Platform — 단계별 진행 현황" 섹션과
docs/SECURITY_DATA_QUERY_PLATFORM.md, docs/PHASE1_LOGICAL_SCHEMA.md,
schema/001_phase1_initial.sql, src/mori_soc/를 읽고 현재 상태를 확인해줘.
Phase 1(데이터 수집/정규화 코어)은 완료되어 있다.
Phase 2(관제 질의 엔진)는 MVC 1~4 초안까지 구현되어 있다.
남은 실시간 수집 연동(worker/poller), SQL 기반 조회 최적화, 운영 대시보드 보강을 이어서 진행해줘.
```

### 짧은 버전

```
이 저장소 MORI SOC-lite에서 Phase 2 남은 작업 이어서 해줘.
README 상단 현황 섹션, src/mori_soc, schema/001_phase1_initial.sql 읽고 바로 이어서.
```

### 같이 적으면 좋은 추가 정보

- 이번에 하고 싶은 범위 (예: `FastAPI 서버만`, `Postgres 연결까지`, `Docker까지`)
- 실행 허용 범위 (예: `unit test는 바로 실행해도 됨`)

Starter dashboard에도 아래 패널이 표시됩니다.

- `Fleet Status Logs`
- `Fleet osquery Results`

### 6) Zabbix Agent PC 온보딩 테스트

- 가이드 문서: `docs/ZABBIX_AGENT_ACTIVE_SETUP.md`
- 예시 설정: `config/zabbix_agent/zabbix_agent2.active.example.conf`
- 확인 항목:
  - 내 PC에서 `mori.rmstudio.co.kr:10051` outbound 연결 가능
  - Zabbix Web에 Host 등록 가능
  - `Latest data`에서 CPU/Memory/Disk 항목 수집 확인

### 7) 취약점 스캔 테스트

- `docker compose --profile scanner run --rm trivy`
- `./scripts/trivy-fs-scan.sh .`
- `./scripts/trivy-image-scan.sh grafana/grafana-oss:11.5.2`

정상 기준:

- Trivy가 실행되고 결과 테이블이 출력됨
- `reports/trivy/` 아래에 리포트가 저장됨

### 8) 운영 테스트 체크리스트

- 메인 포털 접속 가능
- Grafana 로그인 가능
- Zabbix Web UI 접속 가능
- 내 PC 또는 테스트 단말 Zabbix Agent 데이터 수집 가능
- Loki 로그 조회 가능
- FleetDM osquery 결과가 Grafana에서 조회 가능
- Trivy 실행 가능
- Wazuh/Fleet 내부 포트 접속 가능

## 14. 다음 작업 후보

### 🔴 높음 — 데이터 신뢰성 완성

1. **데이터 영속성 (PostgreSQL 연결)** — 현재 인메모리 저장소를 Postgres로 전환, 재시작 시 데이터 유지
2. **실시간 수집 연동** — Zabbix / Fleet / Wazuh API 폴링 환경변수 설정 및 실제 연결

### 🟡 중간 — 운영 안정성

3. **LDAP 인증 운영 적용** — `LDAP_URL` 환경변수 설정 및 조직 AD/LDAP 연결 검증
4. **HTTPS 리버스 프록시** — Nginx/Caddy 추가로 TLS 적용
5. **PDF 증적 리포트** — CSV 외 PDF 형태 리포트 생성

### 🟢 낮음 — 기능 확장

6. **Trivy 연동 파이프라인** — 온디맨드 스캔 결과를 MORI ingestion 경로로 자동 적재
7. **대시보드 보강** — source health 표시, collector lag 모니터링
8. **Phase 3: 조사형 에이전트** — host/user/ip 기준 다단계 pivot, 교차 검증

---

이 저장소는 **Phase 1 완료 + Phase 2 Alpha (운영 배포 중)** 상태입니다.

| 구분 | 상태 |
|---|---|
| 로그인·RBAC·Triage·인시던트·가이드 | ✅ 운영 가능 (인메모리, 재시작 시 초기화) |
| 대시보드 자산·경보 데이터 | ⚠️ 샘플 데이터 기반 (실시간 연동 전) |
| PostgreSQL 영속성 | 🔲 미완 (코드 준비됨) |
| 실시간 Zabbix·Fleet·Wazuh 연동 | 🔲 미완 (수집기 코드 준비됨) |

`./scripts/mori-start-demo.sh` 한 줄로 전체 기능을 체험할 수 있습니다.
운영 환경에서는 `docker compose down && docker compose up -d` 로 적용하세요.