## MORI SOC-lite 배포 가이드

### 1. 공개 진입점

- 메인 URL: `http://mori.rmstudio.co.kr:37854`
- 공개 서비스: `Grafana`
- 내부/로컬 관리 포트
- `127.0.0.1:18081` → Zabbix Web
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
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
docker compose ps
```

### 5. GitHub Actions 시크릿

다음 시크릿을 저장소에 추가하세요.

- `DEPLOY_HOST`
- `DEPLOY_PORT`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`
- `DEPLOY_ENV_FILE`
- `DEPLOY_KNOWN_HOSTS` (선택)

`DEPLOY_ENV_FILE`에는 서버에서 사용할 `.env` 전체 내용을 멀티라인 그대로 넣으면 됩니다.

### 6. GitHub Actions 배포 동작

워크플로우는 다음 순서로 동작합니다.

1. 저장소를 체크아웃
2. `/backup/rmstudio/mori`로 파일 동기화
3. GitHub Secret의 `.env` 내용을 서버에 업로드
4. Wazuh 인증서가 없으면 자동 생성
5. `docker compose pull`
6. `docker compose up -d --remove-orphans`

### 7. 운영 메모

- 현재 공개 포트는 Grafana만 사용합니다.
- Wazuh 기본 계정 해시는 공식 예제 기본값(`SecretPassword`) 기준입니다.
- Wazuh 기본 비밀번호를 변경하려면 `config/wazuh_indexer/internal_users.yml` 해시와 관련 설정을 함께 수정해야 합니다.
- Trivy 점검은 필요 시 아래처럼 실행합니다.

```bash
docker compose --profile scanner run --rm trivy
```