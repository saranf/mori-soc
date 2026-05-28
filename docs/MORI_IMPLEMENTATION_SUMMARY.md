# MORI 구현 요약 및 운영 방향

## 1. 현재 위치

MORI는 SOC-lite 배포 스캐폴드에서 출발해, **데이터 수집/정규화/질의 코어 (Phase 1)** + **운영 + 감사 증적 UI + 운영성 폴리시 (Phase 2)** 단계까지 진행됐습니다. 지향점은 **ISMS-P / ISO 27001 인증 심사를 일상 운영과 같이 끌고 갈 수 있는 Audit-Ready Compliance-Evidence Platform** 입니다.

| 단계 | 상태 | 핵심 산출물 |
| --- | --- | --- |
| Phase 1 — 데이터 수집/정규화 코어 | ✅ 완료 | collectors / normalization / ingestion / 12 intent query catalog |
| MVC 1 — FastAPI HTTP API | ✅ 완료 | `/health` (DB ping + freshness 요약) `/catalog` `/query` `/interpret` `/dashboard/summary` |
| MVC 2 — PostgresRepository | ✅ 코드 완료 / 🔲 운영 미연결 | `repositories/postgres.py` (인메모리에서 운영 중) |
| MVC 3 — Docker/Compose 배포선 | ✅ 완료 | `docker-compose.yml`, GitHub Actions, `scripts/mori-backup.sh` · `mori-restore.sh` |
| MVC 4 — 자연어 질의 + 운영 UI | ✅ 완료 | `intent_parser` + `/ui` |
| **Phase 2 — 운영 UI + 감사 증적 + 운영성 폴리시** | ✅ 패키징 준비 완료 | RBAC, 자산/취약점/Triage/인시던트/PDCA, 감사 로그, 5종 증적(CSV+PDF) 리포트, Source Freshness, 8탭 어드민 콘솔 |
| Phase 2.5 — 영속화 + 실시간 폴링 | 🔲 다음 작업 | 인메모리 store → Postgres, 폴러 연결 |
| Phase 3 — 조사형 멀티 피벗 에이전트 | 🔲 미착수 | host/user/ip 다단계 pivot |

---

## 2. Phase 2 에서 추가된 핵심 기능

### 인증 / 권한

- 로그인 / 세션 / 가입 요청·승인 흐름
- RBAC (admin / security / monitor / auditor / helpdesk) — 역할별 탭/기능 on·off
- LDAP 인증 (코드 준비, `LDAP_URL` 설정 시 활성화)
- **기본 비밀번호 감지** — startup 시 `change_this_*` / `generate_with_*` placeholder 잔존 환경변수 + 기본 admin 비밀번호(`1234`) 사용 시 경고 로그(`[security] insecure default credentials detected for: ...`) 출력 및 `/health` 응답에 `insecure_defaults` 노출

### 자산 관리

- 호스트별 담당자·팀·카테고리 편집 (서버 / PC / Trivy 탭)
- **서버 자산 중요도 수동 재정의** (자동 분류 결과보다 우선 적용)
- 변경분은 `asset_audit_log[hostname]`에 `field`, `old_value`, `new_value`, `changed_by`, `changed_at`로 누적

### 취약점 관리 (Trivy)

- 호스트 단위 조치 계획 / 조치 예외
- **CVE별 상세 조치 계획 / 조치 예외** (작성자·목표일·만료일·사유 기록)
- 호스트 단위 ↔ CVE별 충돌 시 안내 모달 자동 노출 (합계 탭으로 유도)
- 모든 변경은 동일 호스트의 📋 이력 모달에 시간순으로 통합 표시

### 알람 트리아지 (Wazuh / Zabbix)

- 3단계 상태(🔴🟡🟢) 변경 + 분석관 / **변경자(actor)** 분리 기록
- actor 미입력 시 세션 사용자 → "unknown" fallback
- 변경 history는 모달 + 테이블 양쪽에 표시

### 인시던트 관리

- 생성·상태·노트·날짜필터·텍스트검색
- 변경 history 누적 (`/incidents/{id}/history`)
- **CSV 다운로드 시 안내 모달** — "변경 내역(history)은 CSV에 포함되지 않으며 변경 일자 + 최신 내역만 1행으로 표시됩니다"

### Compliance PDCA 대시보드

- Plan / Do / Check / Act 4단계 카드 + 카테고리별 통제 점검 결과
- **Do 카드 클릭 → 미조치 항목 통합 모달** (통제 + Trivy + Alert 한 화면)
- 미조치/기한 초과 항목 표 — 기한 초과 🔴 표시
- **CSV 다운로드** (`/compliance/pdca/pending.csv`) — 출처/통제ID/대상/상태/담당자/조치기한/기한초과/비고

### 감사 증적 리포트

- 자산·계정·로그·취약점·월간 5종 **CSV + PDF** 리포트 (`format=csv|pdf`)
- **🔍 미리보기 모달** — 상위 50행 테이블 미리보기 + 모달에서 바로 다운로드
- PDF는 reportlab + NanumGothic 폰트로 한글 임베드, A4 landscape
- JSON 다운로드는 카드에서 제거 (백엔드 엔드포인트는 호환 유지)

### Source Freshness / Collector Lag

- 대시보드 Overview 카드 `📡 Collector Health · Source Freshness` — 소스별 마지막 sync 시각, stale 임계치(`_SOURCE_STALE_THRESHOLDS`), status (running / success / stale / error / unknown), records collected
- 소스별 SLA — zabbix 5분, wazuh 10분, fleet 10일, trivy 7일, ldap 8시간 (`docs/collection-standards.md` 기준)
- `/health` 응답에도 source coverage 요약 포함 (healthy/stale/error/unknown count)

### 어드민 콘솔 (8탭 개편)

- Overview · Reports · **Access Control**(가입 요청 + 사용자 + 권한) · **Audit Log** · Data Sources · **Compliance** · Settings · Dangerous Actions
- 가입 요청 탭은 Access Control 안으로 통합 (기존 별도 `atab_users` → `atab_access`)

### 교차 검증

- Zabbix × Fleet × Trivy 호스트 매핑 차이 검출
- 미매핑 자산(orphan) 식별

### 자연어 질의 (FAB)

- 12개 인텐트 디스패치 — alert_summary, offline_hosts, fleet_checkin_gap, top_vulnerable_hosts, host_timeline 등
- `_INTENT_HANDLERS` 레지스트리로 새 intent 추가가 3단계 (catalog 정의 → 핸들러 → 테스트)

### 운영 스크립트

- `scripts/mori-backup.sh` — `pg_dump -Fc` 기반 PostgreSQL 백업 → `backups/mori-soc-<timestamp>.dump`
- `scripts/mori-restore.sh` — 확인 프롬프트 + `--force` 지원, `pg_restore --clean --if-exists`
- `scripts/mori-seed-sample-data.sh` — 시드 데이터 다양화 (source_syncs를 success-healthy / success-stale / error / running 4가지 상태로 동시 노출하여 Collector Lag UI 시연 가능)
- `scripts/mori-start-demo.sh` — 데모 시작 시 triage 분포 자동 시드 (reviewing 2건 / resolved 2건 / pending 5건)

---

## 3. 인메모리 상태 (재시작 시 초기화)

| store | 내용 | 영속화 우선순위 |
| --- | --- | --- |
| `asset_owners` | hostname → {owner, team, importance, category, …} | 🔴 |
| `asset_audit_log` | hostname → list of 변경 이력 (호스트 + CVE 변경 통합) | 🔴 |
| `vuln_actions` | vuln_id → {plan, plan_target_date, plan_updated_by, exception_until, exception_reason, exception_updated_by} | 🔴 |
| `triage_store` | alert_id → {status, analyst, note, changed_by, changed_at, history[]} | 🔴 |
| `incident_store` | incident_id → {…, history[]} | 🔴 |

→ 다음 마일스톤은 위 5개 store를 **PostgreSQL 테이블로 매핑**하여 영속화하는 작업입니다. `repositories/postgres.py`에 모듈 골격은 준비됨.

---

## 4. 데이터 정확성 메모

### 왜 Zabbix UI 에는 호스트가 보이는데 MORI 대시보드는 0건일 수 있나

`/dashboard/summary` 와 `/ui` 는 **원본 도구 화면을 직접 조회하지 않고**, MORI 저장소(현재 인메모리)에 적재된 host / host_alias / observation / alert 를 집계합니다. 따라서 다음 흐름이 먼저 돌아야 숫자가 맞습니다.

1. Zabbix/Fleet/Wazuh 에 원본 데이터 존재
2. MORI 수집기가 API/log 를 읽음 (`pollers/`에서 주기 폴링)
3. 정규화 후 MORI 저장소에 적재 (`services/ingestion.py`)
4. 대시보드/API 가 적재 결과를 집계

지금은 2~3 단계의 **실시간 ingestion worker**가 폴러 코드는 있으나 실제 외부 시스템 폴링이 비활성화 상태입니다. 데모 모드에서는 `mori-seed-sample-data.sh` 가 시드한 데이터로 동작합니다.

이는 **대시보드 집계 버그가 아니라 수집 파이프라인 부재에 따른 데이터 정확성 갭**으로 봐야 합니다.

---


## 5. 권장 운영 전략

### 자산별 도구 매핑

| 자산 유형 | 도구 | 이유 |
| --- | --- | --- |
| **PC / 사용자 단말** | FleetDM | osquery 기반 인벤토리/정책/라이브 쿼리에 강함, 단말 단위 조회 경험이 좋음 |
| **서버 / VM / 상시 운영** | Zabbix Agent | CPU/메모리/디스크/네트워크 등 인프라 관측에 강함, trigger/event 운영이 안정적임 |
| **보안 탐지** | Wazuh | 침해/이상 이벤트 탐지·경보 축 |
| **취약점 점검** | Trivy | 온디맨드 / 배치 스캔 |
| **통합 운영 + 감사 증적** | **MORI API** (`/ui`) | 통제·자산·취약점·알람·인시던트 통합 + 감사 로그 |

### Zabbix Agent + Trivy 결합형 자체 agent

장기적으로는 가능하지만 **지금 당장은 후순위가 맞습니다.** 이유:

1. 플랫폼별 패키징/배포/업데이트 부담이 큼
2. 스캔 권한과 에이전트 권한을 같이 다뤄야 해서 운영 리스크가 커짐
3. 장애 시 원인 분리가 어려워짐
4. 중앙 수집 경로(영속화 + 폴링) 안정화가 먼저

---

## 6. 다음 큰 작업 (우선순위 순)

### 🔴 데이터 신뢰성

1. **PostgreSQL 영속화** — 인메모리 5개 store(asset_owners / asset_audit_log / vuln_actions / triage_store / incident_store)를 `repositories/postgres.py` 에 매핑
2. **실시간 ingestion worker** — Fleet/Wazuh/Zabbix API 폴링을 `pollers/` 에서 활성화 (코드는 준비됨)

### 🟡 운영 안정성

3. **LDAP 인증 운영 적용** — `LDAP_URL` 환경변수 + AD/LDAP 검증
4. **HTTPS / 리버스 프록시** — Nginx/Caddy + TLS

### 🟢 기능 확장

5. **Trivy 결과 자동 적재** — 온디맨드 스캔 결과를 ingestion 파이프라인에 연결
6. **SQL 기반 읽기 최적화** — snapshot 조회를 Postgres view 기반으로 점진 전환
7. **Phase 3 — 조사형 multi-hop pivot 에이전트**

### ✅ Phase 2 에서 마무리된 항목

- collector lag / sync 상태 표시 (Source Freshness)
- PDF 증적 리포트 (5종, A4 landscape, NanumGothic)
- 어드민 콘솔 8탭 개편 (Access Control 통합)
- 백업/복원 스크립트 (`mori-backup.sh` / `mori-restore.sh`)
- `/health` 강화 (DB ping + source coverage 요약 + insecure_defaults)
- 기본 비밀번호 감지 경고 로그

---

## 7. 한 줄 정리

MORI는 **"보안 데이터를 모으고, 한눈에 보고, 자연어로 질의하고, 변경을 감사 증적으로 누적하는" Audit-Ready 운영 플랫폼 — Phase 2 패키징 단계**입니다. 다음 핵심은 **인메모리 store를 Postgres로 영속화하고 실시간 폴링을 연결하는 것**입니다.
