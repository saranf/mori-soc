# MORI SOC-lite

오픈소스 기반 **Security Visibility Platform (SOC-lite)** 배포 스캐폴드입니다.

이 저장소는 중소 규모 조직(SME)을 위한 보안 가시성 플랫폼을 `docker compose` 기반으로 구성하며,
다음 영역을 한 번에 묶어 운영할 수 있도록 설계했습니다.

- Infrastructure Monitoring: Zabbix
- Log Centralization: Loki + Fluent Bit
- Endpoint Security / Compliance: FleetDM
- Security Event Detection: Wazuh
- Visualization: Grafana
- Vulnerability Scan: Trivy

## 1. 배포 목표

- 공개 주소: `http://mori.rmstudio.co.kr:37854`
- 배포 경로: `/backup/rmstudio/mori`
- 배포 방식: GitHub Actions + SSH
- 실행 방식: `docker compose`

현재 외부 공개 진입점은 **Grafana**입니다.

## 2. 현재 구성된 서비스

### Public Entry
- `Grafana` (`37854`)

### Internal Services
- `Loki`: 중앙 로그 저장소
- `Fluent Bit`: 호스트 로그 수집 및 Loki 전송
- `Zabbix Server/Web`: 인프라 모니터링
- `FleetDM`: 엔드포인트/취약점 관리
- `Wazuh Manager/Indexer/Dashboard`: 보안 이벤트 탐지 및 분석
- `Trivy`: 파일시스템 취약점 스캔(Profile 기반)

## 3. 포트 구성

- Public
  - `37854` → Grafana

- Internal / localhost only
- `127.0.0.1:18081` → Zabbix Web
  - `127.0.0.1:1337` → FleetDM
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
- `.github/workflows/deploy.yml`: GitHub Actions 배포 워크플로우
- `docs/DEPLOYMENT.md`: 서버 준비 및 운영 가이드
- `config/*`: 각 서비스별 설정 파일

## 5. 배포 방식

GitHub Actions가 아래 순서로 동작하도록 구성했습니다.

1. 저장소 체크아웃
2. 서버 경로 `/backup/rmstudio/mori` 생성 확인
3. `rsync`로 코드 동기화
4. GitHub Secret의 `.env` 내용을 서버에 업로드
5. Wazuh 인증서가 없으면 최초 1회 생성
6. `docker compose pull`
7. `docker compose up -d --remove-orphans`

## 6. 필수 환경변수

`.env.example` 기준으로 실제 `.env`를 작성해야 합니다.

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

## 10. 운영 메모

- 현재 공개 서비스는 Grafana만 노출합니다.
- Zabbix / FleetDM / Wazuh Dashboard는 localhost 바인딩으로 제한했습니다.
- Wazuh 기본 예제 계정은 공식 예시 기본값(`SecretPassword`)을 사용 중입니다.
- Wazuh 비밀번호를 변경하려면 `config/wazuh_indexer/internal_users.yml`의 해시와 관련 설정을 함께 수정해야 합니다.
- Trivy 스캔은 필요 시 profile로 실행합니다.

## 11. 다음 작업 후보

- Grafana 대시보드/프로비저닝 고도화
- HTTPS 리버스 프록시(Nginx/Caddy) 추가
- Wazuh/Fleet 초기 운영 설정 보강
- 실제 서버 기동 후 헬스체크 및 초기 로그인 검증

---

이 저장소는 **초기 배포 스캐폴드와 자동화 기반**까지 정리된 상태이며,
실서비스 운영 전에는 서버 리소스, 인증서, 초기 계정/비밀번호 정책에 맞춘 추가 보완이 필요합니다.