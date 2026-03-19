# MORI SOC-lite 구현 로드맵

## 1. 목적

이 문서는 `docs/FUNCTIONAL_SPEC.md`의 요구사항을 현재 저장소 구현과 연결하고,
다음 개발 단계를 정의하기 위한 운영/개발 기준 문서입니다.

## 2. 기능 모듈 매핑

| 기능 모듈 | 현재 구성 요소 | 현재 상태 | 다음 구현 포인트 |
| --- | --- | --- | --- |
| Infrastructure Monitoring | Zabbix Server/Web | 기본 배포 완료 | 호스트/서비스 템플릿, CPU/메모리/디스크 트리거 정교화 |
| Endpoint Security | FleetDM | 기본 배포 완료 | osquery 정책/쿼리팩 추가, 준수 지표 시각화 |
| Log Management | Fluent Bit + Loki + Grafana | 기본 배포 완료 | 로그 라벨 정교화, 검색용 dashboard/panel 보강 |
| Vulnerability Management | Trivy + FleetDM | 초기 스캐너 수준 | 정기 실행, 결과 적재/리포팅 방식 정의 |
| Security Event Detection | Wazuh | 기본 배포 완료 | 탐지 룰 튜닝, 알림 연동, 이벤트 분류 |
| Security Dashboard | Grafana | 데이터소스 + starter dashboard 적용 | KPI 카드/추이 대시보드 고도화 |

## 3. 현재 반영된 구현

- `docker-compose.yml` 기반 통합 스택 구성
- GitHub Actions를 통한 원격 배포 자동화
- Wazuh 인증서 생성/마운트 구조 보정
- Grafana Loki 데이터소스 프로비저닝
- Grafana starter overview dashboard 프로비저닝
- Trivy profile 실행 구조 반영

## 4. 기능 정의서 기준 우선 구현 순서

### Phase 1. 운영 안정화

- Grafana 초기 로그인/비밀번호 리셋 절차 문서화
- `docker compose` 기준 배포 표준화
- Wazuh/Zabbix/Fleet 초기 접속 경로 정리

### Phase 2. 모듈별 기능 구현

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

### Phase 3. Dashboard / Alert / Reporting

- Security Overview 대시보드
- Endpoint Compliance 대시보드
- Vulnerability Dashboard
- Security Event Timeline
- Email/Slack/Dashboard Alert 연동
- 주간/월간 보안 리포트 템플릿

## 5. 현재 기준 구현 가능한 세부 항목

저장소만으로 바로 추가 구현하기 좋은 우선순위는 아래입니다.

1. Grafana dashboard 고도화
2. FleetDM용 osquery query pack 파일 추가
3. Wazuh 룰/로컬 룰 추가
4. Trivy 실행 결과 수집 스크립트 추가
5. 운영용 체크리스트/런북 정리

## 6. 다음 추천 작업

가장 효율적인 다음 단계는 아래 순서입니다.

1. FleetDM endpoint compliance 쿼리팩 추가
2. Wazuh 이벤트 탐지 룰 튜닝
3. Grafana 대시보드 KPI 패널 확장
4. Slack/Email 알림 연결

## 7. 비고

현재 저장소는 “배포 스캐폴드 + 초기 통합” 단계이며,
기능 정의서의 모든 요구사항을 충족하려면 각 솔루션 내부 설정(Fleet query, Wazuh rule, Zabbix template, Grafana panel)을
추가로 단계별 구현해야 합니다.