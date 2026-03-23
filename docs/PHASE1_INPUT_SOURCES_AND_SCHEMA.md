# MORI Phase 1 입력 소스 및 공통 스키마 초안

## 1. 목적

이 문서는 Phase 1인 **데이터 수집/정규화 코어**를 실제 구현하기 위한 세부 명세 초안입니다.

정리 범위는 아래 3가지입니다.

- 현재 저장소 기준으로 수집 가능한 입력 소스
- 공통 엔터티 및 필수 필드 초안
- 운영자 질문 기준 1차 질의 카탈로그

## 2. Phase 1 범위 원칙

- 먼저 **이미 저장소에 있는 수집 경로**를 기준으로 설계한다.
- 초기 답변은 자유 생성보다 **템플릿 질의 + 근거 반환**에 집중한다.
- 원본 데이터의 식별자와 링크를 반드시 유지한다.
- 공통 식별자는 `host_id`를 중심으로 설계한다.

## 3. 입력 소스 명세

| 소스 | 수집 대상 | 현재 저장소 기준 접근 경로 | 현재 상태 | 정규화 대상 |
| --- | --- | --- | --- | --- |
| FleetDM | 호스트 인벤토리 | Fleet 서비스 (`:1337`) 기반 API/내부 DB 연계 예정 | 추가 구현 필요 | `host` |
| FleetDM | osquery status 로그 | `/logs/osqueryd.status.log` → Fluent Bit → Loki (`job=fleetdm`, `log_type=status`) | 이미 수집 중 | `query_result`, `host_observation` |
| FleetDM | osquery results 로그 | `/logs/osqueryd.results.log` → Fluent Bit → Loki (`job=fleetdm`, `log_type=result`) | 이미 수집 중 | `query_result` |
| FleetDM | 취약점 정보 | Fleet 서비스/API 기반 수집 예정, 취약점 DB 볼륨 사용 중 | 추가 구현 필요 | `vulnerability` |
| Wazuh | alert/rule 이벤트 | Wazuh Manager/API (`:55000`) 및 내부 indexer 연계 예정 | 추가 구현 필요 | `alert` |
| Wazuh | agent inventory/status | Wazuh API 기반 수집 예정 | 추가 구현 필요 | `host`, `alert` |
| Zabbix | host inventory | Zabbix Web/API (`:18081`) 연계 예정 | 추가 구현 필요 | `host` |
| Zabbix | trigger/event | Zabbix API 기반 수집 예정 | 추가 구현 필요 | `alert`, `host_observation` |
| Zabbix | metric snapshot | Zabbix API 기반 수집 예정 | 추가 구현 필요 | `host_observation` |
| Host logs | 시스템/애플리케이션 로그 | `/var/log/*.log`, `/var/log/*/*.log` → Fluent Bit → Loki (`job=fluent-bit`, `source=host`) | 이미 수집 중 | `login_event`, `process`, `alert` |

## 4. Source별 우선 구현 순서

### 4-1. 즉시 활용 가능

- Fleet status/result 로그
- Host logs

이 둘은 이미 Fluent Bit에서 Loki로 들어오고 있으므로,
초기 Phase 1에서는 **정규화 규칙 정의 + 조회 템플릿화**부터 시작할 수 있습니다.

### 4-2. 다음 연결 대상

- Fleet 인벤토리/취약점
- Wazuh alert/agent inventory
- Zabbix host/trigger/metric

이 구간은 별도 collector 또는 API pull 작업이 필요합니다.

## 5. 공통 식별자 전략

### 5-1. Canonical host_id

`host_id`는 소스별 ID를 그대로 재사용하지 않고,
하나의 정규화 레코드에 연결되는 **표준 자산 키**로 둡니다.

추천 우선순위는 아래와 같습니다.

1. 하드웨어/플랫폼 고유 식별자
2. Fleet host 식별자
3. Wazuh agent 식별자
4. Zabbix host 식별자
5. 정규화된 hostname 기반 fallback

### 5-2. Source reference 보존

각 엔터티는 원본 시스템의 식별자를 별도 필드로 남깁니다.

- `fleet_host_id`
- `fleet_query_id`
- `wazuh_agent_id`
- `wazuh_alert_id`
- `zabbix_host_id`
- `zabbix_event_id`

## 6. 공통 엔터티 초안

### 6-1. host

| 필드 | 설명 |
| --- | --- |
| `host_id` | 정규화된 표준 호스트 ID |
| `hostname` | 대표 호스트명 |
| `platform` | macOS / Linux / Windows 등 |
| `primary_ip` | 대표 IP |
| `status` | online / offline / unknown |
| `first_seen_at` | 최초 관측 시각 |
| `last_seen_at` | 마지막 관측 시각 |
| `fleet_host_id` | Fleet 원본 식별자 |
| `wazuh_agent_id` | Wazuh 원본 식별자 |
| `zabbix_host_id` | Zabbix 원본 식별자 |

### 6-2. alert

| 필드 | 설명 |
| --- | --- |
| `alert_id` | 정규화된 경보 ID |
| `source` | `wazuh` / `zabbix` / `host_log` 등 |
| `source_event_id` | 원본 이벤트 ID |
| `host_id` | 연결된 호스트 |
| `severity` | 표준 심각도 |
| `rule_name` | 룰/트리거명 |
| `message` | 요약 메시지 |
| `observed_at` | 발생 시각 |
| `raw_ref` | 원본 로그/이벤트 위치 |

### 6-3. vulnerability

| 필드 | 설명 |
| --- | --- |
| `vuln_id` | 정규화된 취약점 ID |
| `host_id` | 연결된 호스트 |
| `cve` | CVE 식별자 |
| `severity` | 표준 심각도 |
| `package_name` | 영향 패키지 |
| `installed_version` | 현재 버전 |
| `fixed_version` | 수정 버전 |
| `detected_at` | 탐지 시각 |
| `raw_ref` | 원본 취약점 레코드 참조 |

### 6-4. query_result

| 필드 | 설명 |
| --- | --- |
| `query_result_id` | 정규화된 결과 ID |
| `source` | 기본값 `fleet` |
| `host_id` | 연결된 호스트 |
| `query_name` | 쿼리명 또는 pack 이름 |
| `query_text` | 원본 쿼리 또는 식별자 |
| `result_json` | 결과 원문 |
| `observed_at` | 수집 시각 |
| `raw_ref` | Loki 로그 또는 원본 경로 |

### 6-5. host_observation

| 필드 | 설명 |
| --- | --- |
| `observation_id` | 정규화된 관측 ID |
| `source` | `fleet`, `zabbix`, `host_log` 등 |
| `host_id` | 연결된 호스트 |
| `observation_type` | status / metric / availability 등 |
| `metric_name` | cpu, memory, disk, checkin 등 |
| `metric_value` | 값 |
| `unit` | %, bytes, state 등 |
| `observed_at` | 관측 시각 |
| `raw_ref` | 원본 이벤트 참조 |

## 7. 공통 필드 규칙

모든 이벤트성 엔터티는 가능하면 아래 필드를 공통으로 갖습니다.

- `source`
- `event_type`
- `host_id`
- `severity`
- `message`
- `observed_at`
- `raw_ref`
- `raw_payload`

정규화 규칙:

- 시간은 UTC 기준 ISO 8601로 저장
- 심각도는 원본 값과 표준 값을 함께 보존
- 원본 payload 삭제 금지
- 사람이 읽는 요약과 원본 증거를 함께 저장

## 8. 1차 질의 카탈로그

Phase 1에서 먼저 템플릿화할 질문 후보는 아래와 같습니다.

1. 지난 24시간 `high/critical` alert 수는 얼마인가?
2. 현재 오프라인 또는 unavailable 상태인 호스트는 무엇인가?
3. Fleet에 등록됐지만 최근 체크인이 없는 호스트는 무엇인가?
4. 취약점이 가장 많은 호스트 Top 10은 무엇인가?
5. 특정 호스트의 최근 24시간 타임라인을 보여줘.
6. 특정 호스트에서 최근 발생한 Wazuh alert만 보여줘.
7. 특정 호스트의 최근 Fleet query 결과를 보여줘.
8. 최근 새로 탐지된 high 이상 취약점은 무엇인가?
9. 경보가 많으면서 동시에 상태가 불안정한 호스트는 무엇인가?
10. Fleet/Wazuh/Zabbix 중 하나라도 매핑되지 않은 자산은 무엇인가?
11. 최근 로그인 실패가 많은 사용자 또는 호스트는 무엇인가?
12. 최근 수집 오류 또는 상태 오류가 반복된 호스트는 무엇인가?

## 9. 구현 순서 제안

1. `host` 매핑 규칙과 source reference 필드를 먼저 확정
2. Fleet/host log용 정규화 규칙부터 적용
3. Wazuh/Zabbix collector 입력 스펙 추가
4. 1차 질의 카탈로그를 API 템플릿으로 변환
5. 이후 자연어 → intent/filter 매핑 추가

## 10. 다음 바로 할 일

이 문서 다음 단계는 아래 둘 중 하나입니다.

1. **공통 스키마를 테이블 설계 수준으로 내리기**
2. **collector / API / schema 디렉터리 구조를 저장소에 실제로 만들기**

권장 순서는 **스키마 상세화 → 구현 골격 추가**입니다.
세부 테이블 설계는 `docs/PHASE1_LOGICAL_SCHEMA.md`에서 이어집니다.