# MORI Security Data Query Platform 설계

## 1. 목적

이 문서는 MORI SOC-lite를 단순 보안 스택 배포 환경에서,
**데이터 수집/정규화/질의/근거 기반 응답**에 특화된 Security Data Query Platform으로 확장하기 위한 기준 문서입니다.

목표는 다음과 같습니다.

- 여러 보안/운영 도구의 데이터를 한 곳에 연결
- 관제 운영자가 호스트/사용자/IP/경보 단위로 빠르게 조회
- 자연어 질문을 구조화된 질의로 바꿔 결과 반환
- 답변 시 요약뿐 아니라 **근거 데이터**를 함께 제시

## 2. 지향하는 제품 형태

이 프로젝트는 일반적인 보안 챗봇보다 아래에 더 집중합니다.

- 관제 운영용 데이터 수집
- 보안 이벤트 상관분석
- 자산/엔드포인트 중심 조회
- 조사 결과의 재현 가능성
- 근거 기반 설명

즉, 중심축은 "에이전트의 자율성"이 아니라 아래입니다.

- 데이터 레이어
- 공통 엔터티 모델
- 관제 질의 엔진
- Evidence-bound answer generation

## 3. 아키텍처 원칙

### 3-1. Non-agent core 우선

먼저 아래를 단단하게 구축합니다.

- 수집기(collector)
- 정규화(normalizer)
- 엔터티 매핑(entity resolver)
- 템플릿 기반 질의 엔진
- 근거 포함 응답 포맷

### 3-2. Limited agent는 나중에 얹기

에이전트는 아래처럼 제한적으로만 사용합니다.

- 읽기 전용
- 허용된 쿼리 도구만 사용
- 여러 소스를 넘나드는 다단계 pivot 수행
- 항상 근거 포함 응답

## 4. 현재 활용할 데이터 소스

### FleetDM

- 호스트 인벤토리
- live query 결과
- osquery status/result 로그
- 취약점 정보

### Wazuh

- alert/rule 이벤트
- agent 상태
- 인증/프로세스/파일 무결성 관련 보안 이벤트

### Zabbix

- 호스트 가용성
- CPU/메모리/디스크/네트워크 메트릭
- trigger/event

### Host logs

- syslog
- auth log
- process/app 로그

## 5. 공통 엔터티 모델

초기 공통 엔터티는 아래 6개를 최소 기준으로 둡니다.

- `host`
- `user`
- `ip`
- `process`
- `alert`
- `vulnerability`

추가 확장 엔터티:

- `query_result`
- `login_event`
- `network_connection`
- `software`

핵심은 서로 다른 시스템의 식별자를 하나의 `host_id` 등으로 묶는 것입니다.

예시:

- Fleet `uuid`
- Wazuh `agent.name` / `agent.id`
- Zabbix `host`
- host log의 `hostname`

## 6. 단계별 구현 계획

### Phase 1. 데이터 수집/정규화 코어

가장 먼저 만들 단계입니다.

목표:

- Fleet / Wazuh / Zabbix / host logs 입력 경로 정의
- 공통 스키마 초안 정의
- `host_id` 중심 엔터티 매핑 설계
- 시간 범위 기반 기본 조회 API 기준 수립

산출물:

- 데이터 소스별 수집 포인트 목록
- 공통 엔터티/필드 정의서
- 정규화 대상 테이블 또는 문서 구조 초안
- 1차 질의 목록(운영자가 실제로 물을 질문)

우선 구현 질문 예시:

- 지난 24시간 high/critical alert 수
- 현재 오프라인 호스트 목록
- 최근 체크인 없는 Fleet 호스트
- 취약점 많은 호스트 Top N
- 특정 호스트의 최근 타임라인

### Phase 2. 관제 질의 엔진

- 템플릿 기반 질의 엔진 구현
- 시간 범위/호스트/심각도 필터 표준화
- 자연어를 intent + filter로 변환
- 결과를 요약 + 근거 형태로 반환

### Phase 3. 제한형 조사 에이전트

- host / user / ip 기준 다단계 pivot
- 여러 소스 cross-check
- 조사형 질문 지원
- 다음 확인 포인트 추천

## 7. Phase 1 상세 범위

이번 단계에서 실제로 집중할 것은 아래입니다.

### 7-1. 입력 소스 명세

- Fleet: API / status/result log / vulnerability data
- Wazuh: alert event / agent inventory
- Zabbix: host / trigger / metric API
- Host logs: Fluent Bit로 들어오는 로그 라벨 구조

### 7-2. 정규화 기준 수립

최소 공통 필드 예시:

- `source`
- `event_type`
- `host_id`
- `hostname`
- `severity`
- `message`
- `timestamp`
- `raw_ref`

### 7-3. 1차 질의 카탈로그 작성

처음부터 자유 질의 SQL/LogQL 생성으로 가지 않고,
운영자가 자주 묻는 질문을 템플릿으로 먼저 정의합니다.

예:

1. 최근 경보 요약
2. 오프라인 자산 조회
3. 취약점 상위 호스트 조회
4. 특정 호스트 조사 타임라인
5. 최근 체크인 실패/미수집 자산 확인

### 7-4. 저장소 방향

초기 권장 구성:

- 메타데이터/정규화 테이블: `Postgres`
- 로그 조회: 현재 `Loki` 유지
- 향후 대량 이벤트 분석: `ClickHouse` 또는 `OpenSearch` 검토

## 8. 구현 원칙

- 답변은 항상 근거를 포함한다.
- 조회 결과가 없으면 추측하지 않는다.
- 자연어 질의는 먼저 템플릿 질의로 제한한다.
- 에이전트 도입 전 데이터 모델을 먼저 고정한다.
- 관제 운영자가 검증 가능한 형태를 유지한다.

## 9. 진행 현황 및 다음 작업

### 완료 / 진행 중

| 단계 | 상태 | 비고 |
| --- | --- | --- |
| Phase 1 입력 소스/엔터티/질의 카탈로그 문서화 | 완료 | `docs/PHASE1_INPUT_SOURCES_AND_SCHEMA.md` |
| 공통 스키마 초안 작성 | 완료 | `docs/PHASE1_LOGICAL_SCHEMA.md`, `schema/001_phase1_initial.sql` |
| 수집기/저장소/조회 API 디렉터리 구조 설계 | 완료 | `src/mori_soc/{collectors,repositories,services,api}` |
| 첫 번째 조회 기능 구현 | 완료 | 12개 인텐트 + 3개 논리 뷰 |
| **Phase 2 — 운영 UI + 감사 증적** | Alpha 운영 중 | RBAC(admin/security/monitor/auditor/helpdesk/user), 자산/취약점/Triage/인시던트/PDCA, 6종 증적 리포트(CSV/PDF), 증적팩 PDF |
| Phase 2 — Compliance/Identity 스키마 확장 | 완료 | `schema/002_phase2_compliance_identity.sql` |
| **Phase 2 — 영속화(StateRepository)** | 완료(M2-1) | 10종 상태 → Postgres cache-aside + write-through (`schema/003..009`) |
| **위험성 평가 + 통제 카탈로그** | 완료 | R-series 점수(1~9) + DoA 수용기준(`004`,`008`); 통제 카탈로그 194건(ISMS-P 101 + ISO 93) 트리(컴플라이언스 탭) + 통제 이행상태 편집·영속(`007`,`009`) |
| **read-only 소스 실시간 통합** | 진행 중 | Zabbix 실시간 연동 검증 완료 · Trivy HTTP 인제스트(CSOP push) 완료 · Fleet/Wazuh 라이브 폴러 = Phase 3 next |
| Phase 3 — 조사형 multi-hop pivot 에이전트 | 미착수 | 8절 원칙 유지하며 점진 도입 |

### 다음 실제 구현 대상

운영 신뢰도 갭은 이제 **기존 도구를 read-only로 연결한 실시간 수집**입니다(데이터 영속성은 M2-1로 해소). MORI는 기존 도구를 대체하지 않고 그 위에 얹는 read-only 증적 레이어를 지향하며, 구체적 순서는:

1. **운영 store → PostgreSQL 영속화** 완료(M2-1)
   - `user_profiles`, `asset_owners`, `asset_audit_log`, `vuln_actions`, `triage`, `incidents`, `risk_register`, `evidence_events`, `settings`, `control_status` (총 10종)
   - `schema/003..009` + `repositories/state_*.py`(StateRepository: `state_base` ABC / `state_memory` / `state_postgres`)로 cache-aside + write-through 영속화. 재시작 후 상태 유지, `tests/test_state_persistence.py` 라운드트립 검증. `MORI_QUERY_BACKEND=memory` 또는 `MORI_DATABASE_URL` 미설정 시 인메모리 fallback
2. **Config 기반 read-only 소스 온보딩(N-series)** — 실시간 폴러의 전제
   - `config/sources.yaml` 스키마+로더(소스별 `enabled`/`url`/`username`/`token_env`/`input_dir`). 시크릿은 `*_env` 환경변수 이름으로만 참조(리포지토리·DB에 비저장)
   - 소스 연결 메타데이터(`source_syncs` 확장: enabled·마지막 sync·마지막 실패 사유) + read-only 가드레일(에이전트 미설치·기존 도구 설정 무변경·소스 장애 격리·freshness 노출)
   - read-only 통합 5원칙: ① read-only 토큰 권장 ② 기존 설정 무변경 ③ 소스 장애 격리 ④ freshness 표시 ⑤ 마지막 수집 시각·실패 사유 저장
3. **실시간 ingestion worker 활성화** — N-series config 위에서 `pollers/worker.py`
   - Fleet `/api/v1/fleet/hosts`, Zabbix JSON-RPC, Wazuh `/security/user/authenticate` + alerts
   - 정규화 후 Postgres 적재
4. **수집 freshness 가시화** — `/dashboard/summary` 에 `source_health` 카드 (마지막 sync, lag, 에러율)
5. **감사 증적 PDF 출력** 완료 — 6종 증적 리포트(CSV/PDF) + 증적팩 PDF 출력

세부 입력 소스 명세는 `docs/PHASE1_INPUT_SOURCES_AND_SCHEMA.md`, 논리 테이블은 `docs/PHASE1_LOGICAL_SCHEMA.md` + `docs/PHASE2_*` 시리즈를 참조합니다. 운영 + 감사 증적 UI 의 현재 상태는 `docs/MORI_IMPLEMENTATION_SUMMARY.md` 의 §2 를 참고하세요.