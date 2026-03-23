# MORI Phase 1 논리 스키마 초안

## 1. 목적

이 문서는 `docs/PHASE1_INPUT_SOURCES_AND_SCHEMA.md`의 공통 엔터티 초안을
실제 구현 가능한 **논리 테이블 구조**로 구체화한 문서입니다.

목표는 아래 3가지입니다.

- `host_id` 중심 관계 구조 확정
- Phase 1 조회 API가 바로 사용할 테이블 초안 정의
- 이후 collector/API 디렉터리 설계의 기준 제공

## 2. 저장소 역할 분리

초기 기준 저장소 역할은 아래처럼 나눕니다.

- `Postgres`: 정규화된 메타데이터, 관계, 최신 상태
- `Loki`: 원본 로그 검색 및 증거 조회
- 향후 확장: 대량 이벤트 분석용 `ClickHouse` 또는 `OpenSearch`

즉, Phase 1에서는 모든 원본 이벤트를 Postgres에 다 넣기보다,
**정규화 인덱스 + 요약 메타데이터 + 원본 참조**를 우선 관리합니다.

## 3. 핵심 관계

- `hosts`는 표준 자산 레코드
- `host_aliases`는 Fleet/Wazuh/Zabbix/hostname 매핑 테이블
- `alerts`, `vulnerabilities`, `query_results`, `host_observations`는 모두 `host_id` 참조
- 원본 payload는 가능하면 그대로 두고 `raw_ref`, `raw_payload`를 함께 보존

## 4. 테이블 초안

### 4-1. hosts

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| `host_id` | uuid / text PK | 표준 호스트 ID |
| `hostname` | text | 대표 호스트명 |
| `platform` | text | macos/linux/windows |
| `primary_ip` | inet/text | 대표 IP |
| `status` | text | online/offline/unknown |
| `risk_score` | integer | 단순 집계 기반 위험 점수 |
| `first_seen_at` | timestamptz | 최초 관측 |
| `last_seen_at` | timestamptz | 마지막 관측 |
| `created_at` | timestamptz | 생성 시각 |
| `updated_at` | timestamptz | 수정 시각 |

인덱스 후보:

- `hosts(hostname)`
- `hosts(status)`
- `hosts(last_seen_at desc)`

### 4-2. host_aliases

여러 시스템 식별자를 `host_id`에 연결하는 핵심 테이블입니다.

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| `alias_id` | uuid / text PK | 매핑 ID |
| `host_id` | FK -> hosts.host_id | 연결 대상 |
| `source` | text | fleet/wazuh/zabbix/host_log |
| `alias_type` | text | uuid/agent_id/hostname/ip 등 |
| `alias_value` | text | 원본 식별자 |
| `confidence` | numeric | 매핑 신뢰도 |
| `is_primary` | boolean | 대표 식별자인지 여부 |
| `first_seen_at` | timestamptz | 최초 관측 |
| `last_seen_at` | timestamptz | 마지막 관측 |

유니크 후보:

- `(source, alias_type, alias_value)`

인덱스 후보:

- `host_aliases(host_id)`
- `host_aliases(source, alias_value)`

### 4-3. alerts

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| `alert_id` | uuid / text PK | 정규화 경보 ID |
| `source` | text | wazuh/zabbix/host_log |
| `source_event_id` | text | 원본 이벤트 ID |
| `host_id` | FK | 연결 호스트 |
| `severity` | text | critical/high/medium/low/info |
| `original_severity` | text | 원본 심각도 |
| `rule_name` | text | 룰 또는 트리거 이름 |
| `rule_id` | text | 원본 룰 ID |
| `message` | text | 요약 메시지 |
| `observed_at` | timestamptz | 이벤트 시각 |
| `raw_ref` | text | Loki/API 원본 참조 |
| `raw_payload` | jsonb | 원본 데이터 |

인덱스 후보:

- `alerts(host_id, observed_at desc)`
- `alerts(source, observed_at desc)`
- `alerts(severity, observed_at desc)`

### 4-4. vulnerabilities

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| `vuln_id` | uuid / text PK | 정규화 취약점 ID |
| `host_id` | FK | 연결 호스트 |
| `source` | text | 기본값 fleet |
| `cve` | text | CVE |
| `severity` | text | 표준 심각도 |
| `package_name` | text | 영향 패키지 |
| `installed_version` | text | 현재 버전 |
| `fixed_version` | text | 수정 버전 |
| `detected_at` | timestamptz | 탐지 시각 |
| `resolved_at` | timestamptz nullable | 해소 시각 |
| `raw_ref` | text | 원본 참조 |
| `raw_payload` | jsonb | 원본 데이터 |

인덱스 후보:

- `vulnerabilities(host_id, detected_at desc)`
- `vulnerabilities(cve)`
- `vulnerabilities(severity, detected_at desc)`

### 4-5. query_results

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| `query_result_id` | uuid / text PK | 정규화 결과 ID |
| `source` | text | fleet |
| `host_id` | FK | 연결 호스트 |
| `query_name` | text | 쿼리명 |
| `query_text` | text | SQL 또는 식별자 |
| `result_json` | jsonb | 결과 원문 |
| `observed_at` | timestamptz | 수집 시각 |
| `raw_ref` | text | Loki 로그 참조 |

인덱스 후보:

- `query_results(host_id, observed_at desc)`
- `query_results(query_name, observed_at desc)`

### 4-6. host_observations

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| `observation_id` | uuid / text PK | 정규화 관측 ID |
| `source` | text | fleet/zabbix/host_log |
| `host_id` | FK | 연결 호스트 |
| `observation_type` | text | status/metric/availability |
| `metric_name` | text | cpu/memory/checkin 등 |
| `metric_value` | text | 값 |
| `unit` | text | %, bytes, state |
| `severity` | text nullable | 필요 시 심각도 |
| `observed_at` | timestamptz | 관측 시각 |
| `raw_ref` | text | 원본 참조 |
| `raw_payload` | jsonb | 원본 데이터 |

인덱스 후보:

- `host_observations(host_id, observed_at desc)`
- `host_observations(metric_name, observed_at desc)`

## 5. 조회용 뷰/집계 후보

초기 API 편의를 위해 아래 뷰를 고려합니다.

- `latest_host_status_view`: 호스트별 최신 상태/마지막 관측
- `host_risk_summary_view`: alert 수, vuln 수 기반 간단 위험 요약
- `host_timeline_view`: alerts + query_results + observations 시간축 병합

## 6. 매핑 규칙

`host_id` 매핑은 아래 순서로 수행합니다.

1. Fleet UUID 또는 하드웨어 UUID 직접 일치
2. Wazuh agent ID 직접 일치
3. Zabbix host ID 직접 일치
4. 정규화 hostname + IP 조합 일치
5. 애매하면 새 `host_id` 발급 후 수동 검토 대상 표시

주의사항:

- hostname 단독 매핑은 오탐 가능성이 있어 신뢰도 점수 필요
- 동일 alias가 여러 host에 걸리면 자동 병합 금지
- 원본 식별자는 삭제하지 않고 alias로 누적

## 7. API 기준 최소 응답 형태

Phase 1 API는 우선 아래 응답 패턴을 따릅니다.

- `summary`: 사람이 읽는 요약
- `filters`: time range, severity, host 등 적용 조건
- `evidence`: 원본 row 목록 또는 raw_ref 목록
- `meta`: source, count, generated_at

## 8. 다음 구현 연결점

이 문서 다음 실제 구현은 아래 순서가 적절합니다.

1. `schema/` 또는 `docs/schema/` 수준의 DDL 초안 작성
2. `collector/` 디렉터리 구조 정의
3. `api/`의 Phase 1 조회 엔드포인트 초안 설계
4. 첫 질의 템플릿 3~5개 구현

초기 DDL 초안은 `schema/001_phase1_initial.sql`에서 관리합니다.