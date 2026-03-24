# MORI 구현 요약 및 운영 방향

## 1. 현재까지 구현된 범위

MORI는 기존 SOC-lite 배포 스캐폴드에서 출발해, 지금은 **Security Data Query Platform**의 초안까지 연결된 상태입니다.

현재 완료된 축은 아래와 같습니다.

- **Phase 1 완료**: 수집/정규화/질의 코어
- **MVC 1 완료**: FastAPI HTTP API
- **MVC 2 완료**: PostgresRepository
- **MVC 3 완료**: Dockerfile + docker compose 배포선
- **MVC 4 초안 완료**: 규칙형 자연어 질의 변환 + `/interpret` + `/ui` 연동

## 2. 구현된 핵심 모듈

### 데이터 수집/정규화

- `src/mori_soc/collectors/fleet_logs.py`
- `src/mori_soc/collectors/wazuh_alerts.py`
- `src/mori_soc/collectors/zabbix_events.py`
- `src/mori_soc/services/normalization.py`
- `src/mori_soc/services/ingestion.py`

이 레이어는 Fleet / Wazuh / Zabbix 데이터를 공통 엔터티로 맞추고 `host_id` 중심으로 연결합니다.

### 저장소/조회

- `src/mori_soc/repositories/memory.py`
- `src/mori_soc/repositories/postgres.py`
- `src/mori_soc/services/query_service.py`
- `src/mori_soc/services/views.py`

현재 12개 intent 질의와 3개 논리 뷰를 지원합니다.

### API/UI

- `src/mori_soc/api/server.py`
- `src/mori_soc/services/intent_parser.py`

지원 endpoint:

- `GET /health`
- `GET /catalog`
- `GET /dashboard/summary`
- `POST /interpret`
- `POST /query`
- `GET /ui`

## 3. 현재 웹 UI 성격

`/ui`는 더 이상 최소 테스트 콘솔만이 아니라, 아래를 한 화면에 보여주는 **운영 대시보드형 UI**입니다.

- 요약 카드
- Source Coverage
- Latest Host Status
- Risk Summary
- Recent Activity
- Quick Actions
- 자연어 질의 → 구조화 payload 변환 → 실행

즉, 운영자가 브라우저에서 바로 “현재 상황 파악 + 질의 실행”을 이어갈 수 있는 형태입니다.

## 4. 권장 운영 전략

### PC / 사용자 단말

**FleetDM 중심**이 맞습니다.

이유:

- osquery 기반 인벤토리/정책/라이브 쿼리에 강함
- 사용자 단말 상태와 취약점/설정 확인에 유리
- 단말 단위 탐색과 질의 경험이 좋음

### 서버 / VM / 상시 운영 자산

**Zabbix Agent 중심**이 맞습니다.

이유:

- CPU/메모리/디스크/네트워크 등 인프라 관측에 강함
- trigger/event 운영이 익숙하고 안정적임
- 서버 모니터링/운영 알람 체계와 자연스럽게 맞음

### 보안 탐지

**Wazuh**는 탐지/경보 축으로 유지하는 것이 적절합니다.

### 취약점 점검

**Trivy**는 현재는 온디맨드 또는 배치 스캔 도구로 두는 편이 자연스럽습니다.

## 5. Zabbix Agent + Trivy 결합형 자체 agent는 어떤가

장기적으로는 가능하지만, **지금 당장은 후순위가 맞습니다.**

이유:

1. 플랫폼별 패키징/배포/업데이트 부담이 큼
2. 스캔 권한과 에이전트 권한을 같이 다뤄야 해서 운영 리스크가 커짐
3. 장애 시 원인 분리가 어려워짐
4. MORI가 아직 실시간 수집 worker 단계 전이라, agent를 먼저 무겁게 만드는 것보다 중앙 수집 경로를 먼저 안정화하는 편이 이득임

따라서 당분간은 아래 역할 분리가 가장 현실적입니다.

- **PC**: Fleet
- **Server**: Zabbix Agent
- **Detection**: Wazuh
- **Vulnerability**: Trivy
- **Unified query / dashboard**: MORI

## 6. 현재 남은 큰 작업

### 우선순위 높음

1. **실시간 ingestion worker**
   - Fleet/Wazuh/Zabbix API 폴링
   - Postgres 적재
   - collector lag / sync 상태 표시

2. **SQL 기반 읽기 최적화**
   - 현재 snapshot 기반 조회를 Postgres view/query 기반으로 점진 전환

3. **대시보드 고도화**
   - collector health
   - source freshness
   - drill-down

### 후순위

4. **Trivy 결과 표준 ingestion**
5. **자체 lightweight agent 검토**
6. **조사형 multi-hop pivot 기능**

## 7. 지금 시점 한 줄 정리

MORI는 이제 **“보안 데이터를 모으고, 웹에서 한눈에 보고, 자연어로 질의하는” 초기 운영 플랫폼** 단계까지 왔고,
다음 핵심은 **실데이터를 자동 적재하는 ingestion worker** 입니다.