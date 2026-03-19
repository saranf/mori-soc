## MORI SOC-lite 배포 가이드

### 1. 공개 진입점

- 메인 URL: `http://mori.rmstudio.co.kr:37854`
- 메인 포털: `http://mori.rmstudio.co.kr:37854`
- Grafana: `http://mori.rmstudio.co.kr:13000`
- 공개 관리 UI: `http://mori.rmstudio.co.kr:18081` (`Zabbix Web`)
- 내부/로컬 관리 포트
- `127.0.0.1:1337` → FleetDM
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

### 6. GitHub Actions 시크릿

다음 시크릿을 저장소에 추가하세요.

- `DEPLOY_HOST`
- `DEPLOY_PORT`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`
- `DEPLOY_ENV_FILE`
- `DEPLOY_KNOWN_HOSTS` (선택)

`DEPLOY_ENV_FILE`에는 서버에서 사용할 `.env` 전체 내용을 멀티라인 그대로 넣으면 됩니다.

### 7. GitHub Actions 배포 동작

워크플로우는 다음 순서로 동작합니다.

1. 저장소를 체크아웃
2. `/backup/rmstudio/mori`로 파일 동기화
3. GitHub Secret의 `.env` 내용을 서버에 업로드
4. Wazuh 인증서가 없으면 자동 생성
5. `docker compose pull`
6. `docker compose up -d --remove-orphans`

### 8. 운영 메모

- 현재 공개 포트는 Main Portal, Grafana, Zabbix Web입니다.
- 메인 포털에서 운영자가 Grafana/Zabbix로 이동하는 구조입니다.
- Zabbix 알람/트리거 운영은 Web UI를 통해 직접 조정할 수 있습니다.
- 수동 실행 시에는 `docker-compose` 대신 `docker compose` 사용을 권장합니다.
- Wazuh 기본 계정 해시는 공식 예제 기본값(`SecretPassword`) 기준입니다.
- Wazuh 기본 비밀번호를 변경하려면 `config/wazuh_indexer/internal_users.yml` 해시와 관련 설정을 함께 수정해야 합니다.
- Trivy 점검은 필요 시 아래처럼 실행합니다.

```bash
docker compose --profile scanner run --rm trivy
```