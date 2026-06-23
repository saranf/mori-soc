# MORI SOC-lite 구현 로드맵

## 1. 목적

이 문서는 `docs/FUNCTIONAL_SPEC.md`와 `docs/SECURITY_CONTROL_MAPPING.md`의 요구사항을 현재 저장소 구현과 연결하고,
다음 개발 단계를 정의하기 위한 운영/개발 기준 문서입니다.

지향점은 **ISMS-P / ISO 27001 인증 심사를 일상 운영과 같이 진행할 수 있는 Audit-Ready Compliance-Evidence Platform** 입니다.

> 🔌 **포지셔닝 — 기존 도구를 대체하지 않고 그 위에 얹는 read-only 증적 레이어.** MORI-SOC는 운영 중인 Zabbix / Wazuh / FleetDM / Trivy에 **config만으로(에이전트 설치·기존 도구 설정 변경 없이) read-only로 연결**해 운영 증적·인시던트 이력·취약점 조치·컴플라이언스 뷰를 정리합니다. *(MORI-SOC is designed to sit on top of existing monitoring and security tools, not replace them.)* read-only 통합 5원칙: ① read-only 토큰 권장 ② 기존 시스템 설정 변경 없음 ③ 소스 장애 격리(MORI 전체 장애로 번지지 않음) ④ source freshness 표시 ⑤ 마지막 수집 시각·실패 사유 저장.

## 2. 기능 모듈 매핑

| 기능 모듈 | 현재 구성 요소 | 현재 상태 | 다음 구현 포인트 |
| --- | --- | --- | --- |
| Infrastructure Monitoring | Zabbix Server/Web | 기본 배포 완료, MORI `/ui` 자산 탭에서 호스트별 담당자/중요도 편집 가능 | 호스트/서비스 템플릿, CPU/메모리/디스크 트리거 정교화, 실시간 폴링 활성화 |
| Endpoint Security | FleetDM | 기본 배포 완료, MORI 자산 탭에서 PC 카테고리 분류/담당자 관리 | osquery 정책/쿼리팩 추가, Fleet API 폴링 활성화 |
| Log Management | Fluent Bit + Loki + Grafana | 기본 배포 완료 | 로그 라벨 정교화, 검색용 dashboard/panel 보강 |
| Vulnerability Management | Trivy + MORI | MORI 취약점 탭 + **CVE별 조치 계획/예외 + 감사 로그** | 자동 적재 파이프라인, 만료 임박 알림 |
| Security Event Detection | Wazuh + MORI Triage | 기본 배포 완료, MORI Triage(상태/분석관/변경자 actor 기록) | Wazuh API 폴링 활성화, 탐지 룰 튜닝 |
| Security Dashboard | Grafana + MORI `/ui` | Grafana starter + **MORI 통합 운영 UI(Overview/PDCA/Crosscheck/Reports)** | KPI 카드/추이/source freshness 강화 |
| **Compliance / 감사 증적** | MORI `/ui` | **PDCA 대시보드, 5종 증적 리포트(CSV 미리보기), 감사 로그 누적, 인시던트 변경 이력** | PDF 리포트, 영속화 |

## 3. 현재 반영된 구현

### 인프라 / 배포

- `docker-compose.yml` 기반 통합 스택 구성
- GitHub Actions를 통한 원격 배포 자동화
- Wazuh 인증서 생성/마운트 구조 보정
- Grafana Loki 데이터소스 프로비저닝
- Grafana starter overview dashboard 프로비저닝
- Trivy profile 실행 구조 반영
- Security Control Mapping 문서

### MORI 통합 운영 UI (`/ui`)

- **인증 / RBAC** — 로그인, 세션, 가입 요청·승인, admin/security/monitor 역할별 탭 on·off
- **자산 관리** — 호스트별 담당자·팀·카테고리 + **서버 자산 중요도 수동 재정의** + 변경 감사 로그
- **취약점 관리** — 호스트 단위 + **CVE별 조치 계획/예외** (작성자·목표일·만료일·사유) + 호스트↔CVE 충돌 안내 모달
- **Alert Triage** — 3단계 상태 + 분석관/**변경자 actor 분리 기록** + 변경 history
- **인시던트 관리** — CRUD + 변경 history + CSV 다운로드(history 미포함 안내 모달)
- **Compliance PDCA** — Plan/Do/Check/Act 4단계 + **Do 클릭 → 미조치 항목 통합 모달** + `/compliance/pdca/pending.csv` 다운로드
- **감사 증적 리포트** — 자산·계정·로그·취약점·월간 5종 CSV + **🔍 미리보기 모달** (상위 50행)
- **교차 검증** — Zabbix × Fleet × Trivy 매핑 차이/orphan 검출
- **자연어 질의** — 12개 인텐트 디스패치 + `/interpret` + `/query`

## 4. 기능 정의서 기준 우선 구현 순서

### Phase 1. 운영 안정화 (✅ 완료)

- Grafana 초기 로그인/비밀번호 리셋 절차 문서화
- `docker compose` 기준 배포 표준화
- Wazuh/Zabbix/Fleet 초기 접속 경로 정리

### Phase 2. 모듈별 기능 구현 (🟡 진행 중 — MORI 통합 UI 측면 ✅, 각 솔루션 내부 설정 🔲)

#### 2-1. Infrastructure Monitoring

- Zabbix 호스트 등록 절차 정리
- CPU/메모리/디스크 임계치 트리거 적용
- 주요 서비스 프로세스 감시 템플릿 반영

#### 2-2. Endpoint Security

- FleetDM osquery pack 설계
- Disk Encryption 확인 쿼리
- Admin Accounts 확인 쿼리
- OS Version/Installed Software 수집 쿼리
- 정책 위반 단말 식별용 saved query/label 구성

#### 2-3. Log Management

- Fluent Bit 입력 경로/파서 세분화
- Loki 라벨 전략 정리 (`job`, `source`, `host`, `service`)
- Grafana Explore/로그 대시보드 보강

#### 2-4. Vulnerability Management

- Trivy 정기 실행 방식 정의 (cron/CI/manual)
- 결과 저장 위치 및 보관 정책 정의
- Critical/High 기준 리포팅 포맷 정의

#### 2-5. Security Event Detection

- Wazuh 기본 룰셋 검토
- 아래 이벤트 중심 룰/튜닝 우선 적용
  - Login Failure Spike
  - Admin Account Created
  - Security Log Cleared
  - Suspicious PowerShell

### Phase 3. Dashboard / Alert / Reporting (🟡 MORI UI ✅ / Grafana·알림 🔲)

- Security Overview 대시보드 (✅ MORI `/ui` Overview)
- Endpoint Compliance 대시보드 (✅ MORI Assets + PDCA)
- Vulnerability Dashboard (✅ MORI Trivy 탭 + CVE별 조치 계획/예외)
- Security Event Timeline (✅ MORI Triage + 자연어 질의 host_timeline)
- Email/Slack/Dashboard Alert 연동 (🔲 미연결)
- 주간/월간 보안 리포트 템플릿 (✅ MORI 5종 CSV 증적 리포트, 🔲 PDF)

### Phase 4. Audit-Ready 기능 (✅ Alpha 운영 중)

- 자산/취약점/Triage/인시던트 변경 이력의 **감사 로그 누적** (`asset_audit_log`)
- 호스트 단위 + **CVE별 조치 계획/예외**의 통합 이력 표시
- **PDCA 미조치 항목 통합 모달** + CSV 다운로드 (`/compliance/pdca/pending.csv`)
- **감사 증적 리포트 미리보기 모달** (5종 CSV)
- 인시던트 CSV 다운로드 시 안내 모달 (변경 이력 미포함 명시)

### Phase 5. 데이터 신뢰성 (🟡 진행 중)

- 운영 store 6개 **PostgreSQL 영속화** ✅ 완료(M2-1, M-series) (`asset_owners`, `asset_audit_log`, `vuln_actions`, `triage_store`, `incident_store`, `user_profiles`) — `schema/003_*` + `repositories/state_*.py`(StateRepository) cache-aside + write-through, 재시작 후 상태 유지
- **Config 기반 read-only 소스 온보딩(N-series)** 🔲 — `config/sources.yaml` 스키마+로더(소스별 `enabled`/`url`/`username`/`token_env`/`input_dir`, 시크릿은 `*_env`로만 참조) → 소스 연결 메타데이터 저장(`source_syncs` 확장) → read-only 가드레일(에이전트 미설치·기존 도구 설정 무변경·소스 장애 격리). **실시간 폴러보다 먼저** 잡는 온보딩 틀
- **실시간 ingestion worker** 🔲 — N-series 위에서 Fleet/Wazuh/Zabbix API 폴링 활성화 (`pollers/`)
- collector lag / source freshness 시각화

## 5. 현재 기준 구현 가능한 세부 항목

저장소만으로 바로 추가 구현하기 좋은 우선순위는 아래입니다.

1. **운영 store → Postgres 매핑** (6개 store) ✅ 완료(M2-1) — `schema/003_*` + `repositories/state_*.py`(StateRepository) cache-aside + write-through, `tests/test_state_persistence.py` 라운드트립 검증
2. **Config 기반 read-only 소스 온보딩(N-series)** — `config/sources.yaml`로 기존 Zabbix/Wazuh/Fleet/Trivy를 read-only 연결(에이전트·기존 설정 무변경), 연결 메타데이터+freshness 저장
3. **폴러 활성화** — N-series config 기반으로 Zabbix/Fleet/Wazuh API 키 환경변수 설정 + `pollers/worker.py`
4. FleetDM용 osquery query pack 파일 추가
5. Wazuh 룰/로컬 룰 추가
6. Slack 알림 webhook 활성화 (`SLACK_WEBHOOK_URL` 환경변수)

## 6. 다음 추천 작업

가장 효율적인 다음 단계는 아래 순서입니다.

1. **PostgreSQL 영속화** ✅ 완료(M2-1) — Phase 2의 6종 운영 store 변경 이력이 재시작 후에도 유지됨
2. **Config 기반 read-only 소스 온보딩(N-series)** — `config/sources.yaml`로 기존 도구를 무변경·read-only 연결하는 온보딩 틀 (실시간 폴링의 전제)
3. **실시간 폴링 활성화** — N-series 위에서 시드 데이터 의존을 끊고 실데이터 기반으로 전환
4. PDF 증적 리포트 출력 (현재 CSV 5종에 추가)
5. Slack/Email 알림 연결
6. FleetDM endpoint compliance 쿼리팩 추가
7. Wazuh 이벤트 탐지 룰 튜닝

## 7. 비고

현재 저장소는 **"통합 운영 UI + 감사 증적이 PostgreSQL에 영속화된 단계(M2-1 완료)"** 입니다. ISMS-P / ISO 27001 대응에 필요한 **운영자 워크플로우와 변경 이력 누적을 지원하는 기반은 구현**되었고 6종 운영 store는 재시작 후에도 유지됩니다. 다음 단계는 **config 기반 read-only 소스 온보딩(N-series)** 으로 기존 도구를 무변경 연결한 뒤 그 위에서 **실시간 수집(폴러 활성화)** 으로 확장하는 것입니다. MORI는 기존 도구를 대체하지 않고 위에 얹는 read-only 증적 레이어를 지향합니다. 각 솔루션 내부 설정(Fleet query, Wazuh rule, Zabbix template, Grafana panel)은 별도 트랙으로 점진 보강합니다.