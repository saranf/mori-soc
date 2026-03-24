## MORI SOC-lite 배포 가이드

### 1. 공개 진입점

- 메인 URL: `http://mori.rmstudio.co.kr:37854`
- 메인 포털: `http://mori.rmstudio.co.kr:37854`
- Grafana: `http://mori.rmstudio.co.kr:13000`
- FleetDM: `http://mori.rmstudio.co.kr:1337`
- 공개 관리 UI: `http://mori.rmstudio.co.kr:18081` (`Zabbix Web`)
- 내부/로컬 관리 포트
  - `127.0.0.1:8443` → Wazuh Dashboard

### 2. 서버 사전 준비

- Docker Engine + Docker Compose Plugin 설치
- 대상 경로 생성: `/backup/rmstudio/mori`
- Wazuh indexer 요구사항 적용

```bash
sudo sysctl -w vm.max_map_count=262144
```

영구 반영 시 `/etc/sysctl.conf` 또는 `/etc/sysctl.d/*.conf`에 동일 값 추가.

### 3. 환경변수 준비

`.env.example`을 기준으로 `.env`를 작성합니다.

현재 Grafana 기본 로그인 값은 `admin / 1234`입니다.
다만 첫 기동 시 생성된 `grafana-data` 볼륨에 이전 비밀번호가 남아 있으면,
`.env` 값을 변경해도 바로 로그인 비밀번호가 바뀌지 않습니다.

현재 Zabbix Web 초기 로그인 값은 공식 문서 기준 `Admin / zabbix`이며,
현재 compose에서는 Zabbix 프런트엔드 관리자 계정을 별도로 오버라이드하지 않습니다.

포트 구성은 아래 기준입니다.

- `PUBLIC_PORT=37854` → 메인 포털
- `GRAFANA_PORT=13000` → Grafana
- `ZABBIX_WEB_PORT=18081` → Zabbix Web

필수 변경값:

- `GRAFANA_ADMIN_PASSWORD`
- `ZABBIX_DB_PASSWORD`
- `FLEET_DB_ROOT_PASSWORD`
- `FLEET_DB_PASSWORD`
- `FLEET_SERVER_PRIVATE_KEY`
- `MORI_DB_PASSWORD`

예시:

```bash
cp .env.example .env
openssl rand -base64 32
```

### 4. 최초 실행

```bash
rm -rf config/wazuh_indexer_ssl_certs
mkdir -p config/wazuh_indexer_ssl_certs
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
docker compose ps
```

기존에 인증서 생성 전에 `docker compose up`을 먼저 실행했다면,
`config/wazuh_indexer_ssl_certs` 내부 경로가 디렉터리로 잘못 생성될 수 있으므로 위처럼 초기화 후 다시 생성하는 것을 권장합니다.

### 4-1. MORI API + Postgres 기동

Phase 2의 HTTP API는 아래 두 서비스로 추가되었습니다.

- `soc-postgres`: MORI 질의용 전용 Postgres
- `mori-api`: FastAPI 기반 조회 API (`/health`, `/catalog`, `/query`)

기본 포트:

- `MORI_API_PORT=18000`

기동:

```bash
docker compose up -d soc-postgres mori-api
docker compose ps soc-postgres mori-api
docker compose logs mori-api --tail=100
```

정상 기준:

- `soc-postgres`가 healthy
- `mori-api`가 healthy
- `GET /health`가 `{"status":"ok", ...}` 반환

확인 예시:

```bash
curl http://mori.rmstudio.co.kr:18000/health
curl http://mori.rmstudio.co.kr:18000/catalog
curl -X POST http://mori.rmstudio.co.kr:18000/query \
  -H 'Content-Type: application/json' \
  -d '{"intent":"offline_hosts","scope":{"time_range":"24h"}}'
```

주의:

- `schema/001_phase1_initial.sql`은 `mori-postgres-data` 볼륨이 비어 있는 **최초 기동 시점에만** 자동 적용됩니다.
- 이미 데이터 볼륨이 생성된 상태라면, 이후 schema 파일 변경은 자동 반영되지 않습니다.
- 현재 단계는 **조회 API + DB 배포선**까지이며, 실제 보안 데이터 적재 자동화는 후속 수집 연동 작업이 필요합니다.

### 4-2. 캐시만 삭제하고 MORI API 재빌드

데이터 볼륨을 지우지 않고 **이미지 빌드 캐시만** 정리한 뒤 재빌드하려면 아래 순서를 권장합니다.

```bash
docker builder prune -f
docker compose build --no-cache mori-api
docker compose up -d mori-api
```

DB까지 함께 올리고 싶다면:

```bash
docker compose up -d soc-postgres mori-api
```

중요:

- 위 명령은 **빌드 캐시만** 정리합니다.
- `docker compose down -v`는 볼륨까지 삭제하므로 DB 데이터가 날아갑니다.
- schema를 처음부터 다시 적용해야 할 때만 `mori-postgres-data` 볼륨 삭제를 고려하세요.

### 5. Grafana 로그인 안 될 때

가장 흔한 원인은 아래 3가지입니다.

- 서버 `.env`의 `GRAFANA_ADMIN_PASSWORD`가 기대값과 다름
- GitHub Secret `DEPLOY_ENV_FILE`에 이전 값이 남아 있음
- 기존 `grafana-data` 볼륨에 예전 admin 비밀번호가 저장되어 있음

먼저 실제 적용값을 확인합니다.

```bash
cd /backup/rmstudio/mori
grep '^GRAFANA_ADMIN_' .env
docker compose ps grafana
```

비밀번호를 안전하게 현재 컨테이너 기준으로 재설정하려면:

```bash
cd /backup/rmstudio/mori
docker compose exec grafana grafana cli admin reset-admin-password 1234
docker compose restart grafana
```

이후 아래 계정으로 다시 로그인합니다.

- ID: `admin`
- PW: `1234`

그래도 안 되면 GitHub Actions에 등록한 `DEPLOY_ENV_FILE` 내용도 같이 확인해야 합니다.

### 6. Zabbix 초기 로그인

Zabbix Web 초기 로그인은 아래 계정을 사용합니다.

- ID: `Admin`
- PW: `zabbix`

현재 `docker-compose.yml`은 Zabbix DB 연결 정보만 설정하며,
Zabbix 프런트엔드 관리자 기본 계정은 변경하지 않습니다.

초기 로그인 후에는 비밀번호를 즉시 변경하는 것을 권장합니다.

### 7. Zabbix Agent Active 등록

개인 PC나 테스트 단말을 연결할 때는 **Active Agent 방식**을 권장합니다.

- Zabbix Server: `mori.rmstudio.co.kr:10051`
- 설정 예시: `config/zabbix_agent/zabbix_agent2.active.example.conf`
- 상세 가이드: `docs/ZABBIX_AGENT_ACTIVE_SETUP.md`

핵심 설정값:

- `Server=mori.rmstudio.co.kr`
- `ServerActive=mori.rmstudio.co.kr:10051`
- `Hostname=<Zabbix Host name과 동일>`
- `HostMetadata=windows|linux|macos`

### 8. Trivy 활용

빠른 점검은 아래 두 방식 중 하나로 진행하면 됩니다.

```bash
docker compose --profile scanner run --rm trivy
./scripts/trivy-fs-scan.sh .
./scripts/trivy-image-scan.sh grafana/grafana-oss:11.5.2
```

리포트는 `reports/trivy/` 아래에 저장됩니다.
상세 사용법은 `docs/TRIVY_USAGE.md`를 참고하세요.

### 9. FleetDM 결과를 Grafana에서 보기

현재 구성은 Fleet가 아래 파일에 osquery 로그를 기록하고,
Fluent Bit가 이를 Loki로 전송한 뒤 Grafana starter dashboard에서 조회하는 방식입니다.

Fleet UI는 외부에서 `http://mori.rmstudio.co.kr:1337` 로 접속할 수 있으며,
단말 등록은 `Hosts -> Add hosts -> macOS` 순서로 진행합니다.

- Fleet status: `/logs/osqueryd.status.log`
- Fleet results: `/logs/osqueryd.results.log`

Grafana Explore의 Loki 쿼리 예시:

```logql
{job="fleetdm", log_type="status"}
{job="fleetdm", log_type="result"}
```

기본 대시보드 패널:

- `Fleet Status Logs`
- `Fleet osquery Results`

주의:

- Fleet 로그는 단말 등록만으로 항상 바로 쌓이지 않을 수 있습니다.
- Live query 실행, policy 점검, query pack 실행 등 실제 osquery 활동이 있어야 결과 로그가 보입니다.

### 10. GitHub Actions 시크릿

다음 시크릿을 저장소에 추가하세요.

- `DEPLOY_HOST`
- `DEPLOY_PORT`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`
- `DEPLOY_ENV_FILE`
- `DEPLOY_KNOWN_HOSTS` (선택)

`DEPLOY_ENV_FILE`에는 서버에서 사용할 `.env` 전체 내용을 멀티라인 그대로 넣으면 됩니다.

### 11. GitHub Actions 배포 동작

워크플로우는 다음 순서로 동작합니다.

1. 저장소를 체크아웃
2. `/backup/rmstudio/mori`로 파일 동기화
3. GitHub Secret의 `.env` 내용을 서버에 업로드
4. Wazuh 인증서가 없으면 자동 생성
5. `docker compose pull`
6. `docker compose up -d --remove-orphans`

### 12. 운영 메모

- 현재 공개 포트는 Main Portal, Grafana, Zabbix Web입니다.
- 메인 포털에서 운영자가 Grafana/Zabbix로 이동하는 구조입니다.
- Zabbix 알람/트리거 운영은 Web UI를 통해 직접 조정할 수 있습니다.
- Zabbix 단말 연결은 Active Agent 방식을 기본 권장합니다.
- FleetDM osquery 결과는 Loki를 통해 Grafana에서 로그 형태로 확인할 수 있습니다.
- 수동 실행 시에는 `docker-compose` 대신 `docker compose` 사용을 권장합니다.
- Wazuh 기본 계정 해시는 공식 예제 기본값(`SecretPassword`) 기준입니다.
- Wazuh 기본 비밀번호를 변경하려면 `config/wazuh_indexer/internal_users.yml` 해시와 관련 설정을 함께 수정해야 합니다.
- Trivy 점검은 필요 시 아래처럼 실행합니다.

```bash
docker compose --profile scanner run --rm trivy
```