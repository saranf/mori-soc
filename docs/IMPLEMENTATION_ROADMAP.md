# MORI SOC-lite 구현 로드맵

## 1. 목적

이 문서는 `docs/FUNCTIONAL_SPEC.md`와 `docs/SECURITY_CONTROL_MAPPING.md`의 요구사항을 현재 저장소 구현과 연결하고,
다음 개발 단계를 정의하기 위한 운영/개발 기준 문서입니다.

지향점은 **ISMS-P / ISO 27001 인증 심사를 일상 운영과 같이 진행할 수 있는 Audit-Ready Compliance-Evidence Platform** 입니다.

> **포지셔닝 — 기존 도구를 대체하지 않고 그 위에 얹는 read-only 증적 레이어(evidence layer).** MORI-SOC는 운영 중인 Zabbix / Wazuh / FleetDM / Trivy / Loki에 **config만으로(에이전트 설치·기존 도구 설정 변경 없이) read-only로 연결**해 운영 증적·인시던트 이력·취약점 조치·컴플라이언스 뷰를 정리하며, **"보는 층(viewing)"은 Grafana에 위임**합니다. *(MORI-SOC is designed to sit on top of existing monitoring and security tools, not replace them.)* read-only 통합 5원칙: ① read-only 토큰 권장 ② 기존 시스템 설정 변경 없음 ③ 소스 장애 격리(MORI 전체 장애로 번지지 않음) ④ source freshness 표시 ⑤ 마지막 수집 시각·실패 사유 저장.

## 2. 기능 모듈 매핑

| 기능 모듈 | 현재 구성 요소 | 현재 상태 | 다음 구현 포인트 |
| --- | --- | --- | --- |
| Infrastructure Monitoring | Zabbix Server/Web | 기본 배포 완료, MORI `/ui` 자산 탭에서 호스트별 담당자/중요도 편집 가능, **Zabbix 실시간 폴링 end-to-end 검증됨** | 호스트/서비스 템플릿, CPU/메모리/디스크 트리거 정교화 |
| Endpoint Security | FleetDM | 기본 배포 완료, MORI 자산 탭에서 PC 카테고리 분류/담당자 관리 | osquery 정책/쿼리팩 추가, **Fleet 라이브 폴러(Phase 3)** |
| Log Management | Fluent Bit + Loki + Grafana | 기본 배포 완료 | 로그 라벨 정교화, 검색용 dashboard/panel 보강 |
| Vulnerability Management | Trivy + MORI | MORI 취약점 탭 + **CVE별 조치 계획/예외 + 감사 로그 + 위험점수(1~9) 표기** + **CSOP 증적 인제스트(`/ingest/trivy`, host↔image 매핑)** | 만료 임박 알림 |
| Security Event Detection | Wazuh + MORI Triage | 기본 배포 완료, MORI Triage(상태/분석관/변경자 actor 기록) | **Wazuh 라이브 폴러(Phase 3)**, 탐지 룰 튜닝 |
| Security Dashboard | Grafana + MORI `/ui` | Grafana starter + **MORI 통합 운영 UI(역할별 보안 히어로/24h·12h 인프라 현황/PDCA/Crosscheck/Reports, 패널 편집)** | KPI 카드/추이/source freshness 강화 |
| **위험성 평가 (R-series)** | MORI `/ui` | **CVE별 3×3 영향도×발생가능성 → 위험점수(1~9), 위험처리(조치/수용/이관/회피)·잔여위험·재평가일, DoA 임계 이하 자동 '기본 수용', 어드민 전용 산정근거** (admin·security 전용) | — |
| **Compliance / 통제 카탈로그 / 감사 증적** | MORI `/ui` | **PDCA 대시보드, 6종 증적 리포트(CSV+PDF, 위험성 평가 대장 포함), 통제 카탈로그 194 YAML(ISMS-P 101+ISO 93), 통제별 이행상태 편집·영속, 통제별 증적팩 PDF, 감사 로그 누적** | 커버리지 확대 |

## 3. 현재 반영된 구현

### 인프라 / 배포

- `docker-compose.yml` 기반 통합 스택 구성
- GitHub Actions를 통한 원격 배포 자동화
- Wazuh 인증서 생성/마운트 구조 보정
- Grafana Loki 데이터소스 프로비저닝
- Grafana starter overview dashboard 프로비저닝
- Trivy profile 실행 구조 반영
- Security Control Mapping 문서
- **Brownfield 모드** — 번들 Zabbix/Fleet/Wazuh를 compose 프로파일 뒤로 두고, 기존 인프라를 `.env`로 무변경 연결

### MORI 통합 운영 UI (`/ui`)

- **인증 / RBAC** — 로그인, 세션, 가입 요청·승인, admin/security/monitor/auditor/helpdesk/user 역할별 탭 on·off (위험/증적/카탈로그 = admin·security 전용, 인프라·헬프데스크 = 내 담당 서버 조치현황만)
- **대시보드** — 역할별 보안 히어로 + **24h/12h 인프라 현황(Zabbix/Wazuh 딥링크)** + 패널 편집, 위험 매트릭스 기본 접힘
- **자산 관리** — 호스트별 담당자·팀·카테고리 + **서버 자산 중요도 수동 재정의** + 변경 감사 로그 + **팀 필터·'내 자산만' 필터**
- **내 담당 서버** — 간소화 테이블(호스트명·중요도·상태·IP), 행 더블클릭 → 상세 모달(미조치 3버킷: 예외만료/조치기한초과/기타위험 + 자산 종류별 Zabbix/Grafana/Fleet 딥링크)
- **취약점 관리** — 호스트 단위 + **CVE별 조치 계획/예외** (작성자·목표일·만료일·사유) + 호스트↔CVE 충돌 안내 모달 + **Trivy 표 위험점수(1~9) 표기**
- **위험성 평가 (R-series)** — CVE별 3×3 영향도×발생가능성 → **위험점수(1~9)**, 위험처리(조치/수용/이관/회피)·잔여위험·재평가일, DoA 단일 임계 점수(ui_settings) 이하 자동 '기본 수용', 어드민 전용 산정근거 (admin·security 전용)
- **통제 카탈로그 (Phase 2)** — controls/ **194 YAML(ISMS-P 101 + ISO 93, 한/영)**, 매핑 61, 공통결함 5. 컴플라이언스 탭 '상세 분석' 접이식 트리, **통제별 이행상태(이행/부분이행/미이행/해당없음/미정 + 담당자/개선계획/예외/기한) 편집·영속**, 통제별 증적팩 PDF, '오늘의 작업 큐'(증적 공백) 카드, 호스트↔통제 breakdown (admin·security 전용)
- **Alert Triage** — 3단계 상태 + 분석관/**변경자 actor 분리 기록** + 변경 history
- **인시던트 관리** — CRUD + 변경 history + CSV 다운로드(history 미포함 안내 모달)
- **Compliance PDCA** — Plan/Do/Check/Act 4단계 + **Do 클릭 → 미조치 항목 통합 모달** + `/compliance/pdca/pending.csv` 다운로드
- **감사 증적 리포트** — 자산·계정·로그·취약점·월간·**위험성 평가 대장 6종 CSV/PDF** + **미리보기 모달** (상위 50행)
- **CSOP 증적 인제스트 (v0.7)** — `POST /ingest/trivy`(host↔image 매핑) · `/ingest/evidence` · `GET /evidence`(admin·security), 토큰 인증·`/ingest/*` 세션 미들웨어 우회
- **교차 검증** — Zabbix × Fleet × Trivy 매핑 차이/orphan 검출
- **자연어 질의** — 12개 인텐트 디스패치 + `/interpret` + `/query`

## 4. 기능 정의서 기준 우선 구현 순서

### Phase 1. 운영 안정화 (완료)

- Grafana 초기 로그인/비밀번호 리셋 절차 문서화
- `docker compose` 기준 배포 표준화
- Wazuh/Zabbix/Fleet 초기 접속 경로 정리

### Phase 2. 모듈별 기능 구현 (진행 중 — MORI 통합 UI 측면 , 각 솔루션 내부 설정)

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

### Phase 3. Dashboard / Alert / Reporting (MORI UI / Grafana·알림)

- Security Overview 대시보드 (MORI `/ui` Overview)
- Endpoint Compliance 대시보드 (MORI Assets + PDCA)
- Vulnerability Dashboard (MORI Trivy 탭 + CVE별 조치 계획/예외)
- Security Event Timeline (MORI Triage + 자연어 질의 host_timeline)
- Email/Slack/Dashboard Alert 연동 (미연결)
- 주간/월간 보안 리포트 템플릿 (MORI 6종 CSV/PDF 증적 리포트, 위험성 평가 대장 포함)

### Phase 4. Audit-Ready 기능 (Alpha 운영 중)

- 자산/취약점/Triage/인시던트 변경 이력의 **감사 로그 누적** (`asset_audit_log`)
- 호스트 단위 + **CVE별 조치 계획/예외**의 통합 이력 표시
- **PDCA 미조치 항목 통합 모달** + CSV 다운로드 (`/compliance/pdca/pending.csv`)
- **감사 증적 리포트 미리보기 모달** (6종 CSV/PDF, 위험성 평가 대장 포함)
- **통제 카탈로그 + 통제별 이행상태 편집·영속** (control_status, action-audit-log 기록), 통제별 증적팩 PDF
- **위험성 평가(R-series)** — CVE별 위험점수 산정·위험처리·DoA 자동 수용
- 인시던트 CSV 다운로드 시 안내 모달 (변경 이력 미포함 명시)

### Phase 5. 데이터 신뢰성 (진행 중)

- 운영 store **PostgreSQL 영속화** 완료(M2-1, M-series) 이후 확장 — `user_profiles`, `asset_owners`, `asset_audit_log`, `vuln_actions`, `triage`, `incidents`, `risk_register`, `evidence_events`, `settings`, `control_status` (원래 6종 → 위험성 평가·증적 인제스트·통제 이행상태·설정 추가로 확장) — `schema/003~009_*` + `repositories/state_*.py`(StateRepository) cache-aside + write-through, 재시작 후 상태 유지
- **스키마 마이그레이션 009까지** — 001 phase1 / 002 compliance·identity / 003 ui operational state / 004 risk_register / 005 alert_resolved / 006 evidence_events(CSOP ingest) / 007 controls(통제 카탈로그: controls/control_mappings/control_defects) / 008 settings(ui_settings; 위험 DoA 등) / 009 control_status(통제 이행상태 편집)
- **Config 기반 read-only 소스 온보딩(N-series)** — `config/sources.yaml` 스키마+로더(소스별 `enabled`/`url`/`username`/`token_env`/`input_dir`, 시크릿은 `*_env`로만 참조) → 소스 연결 메타데이터 저장(`source_syncs` 확장) → read-only 가드레일(에이전트 미설치·기존 도구 설정 무변경·소스 장애 격리). **실시간 폴러보다 먼저** 잡는 온보딩 틀
- **실시간 ingestion worker** — N-series 위에서 Fleet/Wazuh/Zabbix API 폴링 활성화 (`pollers/`)
- collector lag / source freshness 시각화

## 5. 현재 기준 구현 가능한 세부 항목

저장소만으로 바로 추가 구현하기 좋은 우선순위는 아래입니다.

1. **운영 store → Postgres 매핑** (10종으로 확장) 완료(M2-1 이후 확장) — `schema/003~009_*` + `repositories/state_*.py`(StateRepository) cache-aside + write-through, `tests/test_state_persistence.py` 라운드트립 검증
2. **Config 기반 read-only 소스 온보딩(N-series)** — `config/sources.yaml`로 기존 Zabbix/Wazuh/Fleet/Trivy를 read-only 연결(에이전트·기존 설정 무변경), 연결 메타데이터+freshness 저장
3. **폴러 활성화** — N-series config 기반으로 Zabbix/Fleet/Wazuh API 키 환경변수 설정 + `pollers/worker.py`
4. FleetDM용 osquery query pack 파일 추가
5. Wazuh 룰/로컬 룰 추가
6. Slack 알림 webhook 활성화 (`SLACK_WEBHOOK_URL` 환경변수)

## 6. 다음 추천 작업

가장 효율적인 다음 단계는 아래 순서입니다.

1. **PostgreSQL 영속화** 완료(M2-1 이후 10종으로 확장) — 운영 store 변경 이력이 재시작 후에도 유지됨
2. **PDF 증적 리포트** 완료 — 6종 CSV/PDF(위험성 평가 대장 포함)
3. **실시간 폴링 확장** — Zabbix는 end-to-end 검증 완료, Fleet/Wazuh 라이브 폴러는 Phase 3(다음)
4. **Config 기반 read-only 소스 온보딩(N-series)** — `config/sources.yaml`로 기존 도구를 무변경·read-only 연결하는 온보딩 틀
5. Slack/Email 알림 연결
6. FleetDM endpoint compliance 쿼리팩 추가
7. Wazuh 이벤트 탐지 룰 튜닝

## 7. 비고

현재 저장소는 **"통합 운영 UI + 위험성 평가 + 통제 카탈로그 + 감사 증적이 PostgreSQL(스키마 009까지, 10종 store)에 영속화된 단계"** 입니다. ISMS-P / ISO 27001 대응에 필요한 **운영자 워크플로우·위험성 평가·통제 이행상태·변경 이력 누적을 지원하는 기반은 구현**되었고 운영 store는 재시작 후에도 유지됩니다. Zabbix 실시간 폴링은 end-to-end 검증되었고, **Fleet/Wazuh 라이브 폴러는 Phase 3(다음)** 입니다. MORI는 기존 도구를 대체하지 않고 위에 얹는 read-only 증적 레이어를 지향하며, "보는 층"은 Grafana에 위임합니다. 각 솔루션 내부 설정(Fleet query, Wazuh rule, Zabbix template, Grafana panel)은 별도 트랙으로 점진 보강합니다.