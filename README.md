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

## 참고 문서

- `docs/FUNCTIONAL_SPEC.md`: 기능 정의서 원문
- `docs/SECURITY_CONTROL_MAPPING.md`: 보안 통제(Security Controls) 매핑 문서
- `docs/IMPLEMENTATION_ROADMAP.md`: 기능 정의서 기준 구현 로드맵
- `docs/ZABBIX_AGENT_ACTIVE_SETUP.md`: PC/단말 Zabbix Agent Active 등록 가이드
- `docs/TRIVY_USAGE.md`: Trivy 파일시스템/이미지 스캔 가이드
- `docs/DEPLOYMENT.md`: 서버 배포/운영/트러블슈팅 가이드

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
- `docs/ZABBIX_AGENT_ACTIVE_SETUP.md`: Zabbix Agent 온보딩 문서
- `docs/TRIVY_USAGE.md`: Trivy 활용 가이드
- `.github/workflows/deploy.yml`: GitHub Actions 배포 워크플로우
- `docs/DEPLOYMENT.md`: 서버 준비 및 운영 가이드
- `config/zabbix_agent/zabbix_agent2.active.example.conf`: Active Agent 예시 설정
- `config/portal/index.html`: 메인 포털 페이지
- `scripts/trivy-fs-scan.sh`: 파일시스템 취약점 스캔 스크립트
- `scripts/trivy-image-scan.sh`: 이미지 취약점 스캔 스크립트
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

## 12. 다음 작업 후보

- Grafana 대시보드/프로비저닝 고도화
- Zabbix 템플릿/API 자동화 또는 통합 운영 UI 설계
- HTTPS 리버스 프록시(Nginx/Caddy) 추가
- Wazuh/Fleet 초기 운영 설정 보강
- 실제 서버 기동 후 헬스체크 및 초기 로그인 검증

---

이 저장소는 **초기 배포 스캐폴드와 자동화 기반**까지 정리된 상태이며,
실서비스 운영 전에는 서버 리소스, 인증서, 초기 계정/비밀번호 정책에 맞춘 추가 보완이 필요합니다.