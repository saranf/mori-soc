# 브라운필드 연결 — 기존 Zabbix/Wazuh/Fleet 위에 MORI 얹기

이미 운영 중인 모니터링·보안 도구가 있는 환경에서, **MORI 코어만 띄우고 `.env` 설정만으로** 기존 인프라에 read-only로 연결하는 방법입니다. MORI가 자체 번들 Zabbix/Fleet/Wazuh를 띄울 필요가 없습니다.

## TL;DR

```bash
cp .env.example .env          # 최초 1회
# .env 에서 소스 URL/자격증명을 기존 인프라로 교체 (아래 표 참고)
docker compose up -d          # MORI 코어(api + worker + postgres)만 기동
```

`docker compose up` 은 이제 **MORI 코어 + 대시보드(grafana/loki/fluent-bit) + LDAP** 만 띄웁니다. 번들 소스 스택(Zabbix/Fleet/Wazuh + 각 DB)은 `bundled` 프로파일 뒤로 빠져 있어 명시적으로 요청할 때만 올라옵니다.

## compose 프로파일

| 명령 | 기동 대상 |
|---|---|
| `docker compose up -d` | MORI 코어만 (브라운필드 기본) |
| `docker compose --profile bundled up -d` | 코어 + 번들 Zabbix·Fleet·Wazuh 데모 스택 전체 |
| `docker compose --profile zabbix up -d` | 코어 + 번들 Zabbix 만 |
| `docker compose --profile fleet up -d` | 코어 + 번들 Fleet 만 |
| `docker compose --profile wazuh up -d` | 코어 + 번들 Wazuh 만 |
| `docker compose --profile pollers up -d` | 개별 폴러 컨테이너(zabbix/trivy/ldap) 분리 실행 |
| `docker compose --profile scanner run trivy …` | 일회성 Trivy 스캔 |

프로파일은 조합 가능합니다: `docker compose --profile zabbix --profile fleet up -d`.

## 소스별 연결 현황

| 소스 | 연결 방식 | 상태 | 필요한 .env |
|---|---|---|---|
| **Zabbix** | 라이브 REST(JSON-RPC) 폴링 | ✅ 설정만으로 동작 | `MORI_ENABLE_ZABBIX`, `MORI_ZABBIX_API_URL`, `MORI_ZABBIX_API_TOKEN` **또는** `MORI_ZABBIX_USER`/`MORI_ZABBIX_PASSWORD` |
| **Trivy / CSOP** | 원격 토큰 push (`POST /ingest/trivy`, `/ingest/evidence`) | ✅ 토큰만 설정 | `MORI_INGEST_TOKEN` |
| **Fleet** | 라이브 REST 폴러 | ⚠️ Phase 3 예정(미구현) | `MORI_FLEET_API_URL`, `MORI_FLEET_API_TOKEN` (자리만 마련) |
| **Wazuh** | Manager REST(55000) 폴러 | ⚠️ Phase 3 예정(미구현) | `MORI_WAZUH_API_URL`, `MORI_WAZUH_API_USER`, `MORI_WAZUH_API_PASSWORD` (자리만 마련) |

### 1) Zabbix (기존 인스턴스)

```dotenv
MORI_ENABLE_ZABBIX=true
MORI_ZABBIX_API_URL=https://zabbix.your-corp.com/api_jsonrpc.php
# 인증 — 토큰 권장(설정 시 user/password 무시)
MORI_ZABBIX_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx
# 또는
MORI_ZABBIX_USER=mori-readonly
MORI_ZABBIX_PASSWORD=********
```

적용: `docker compose up -d mori-worker` (재기동). 워커는 `MORI_ZABBIX_INTERVAL_SECONDS`(기본 30초) 주기로 `problem.get`/`host.get` 을 폴링해 PostgreSQL에 적재합니다. 읽기 전용 계정이면 충분합니다.

### 2) Trivy / CSOP (원격 스캐너 → MORI push)

MORI가 스캐너를 폴링하지 않고, 스캐너/에이전트가 리포트를 **push** 합니다. `.env`:

```dotenv
MORI_INGEST_TOKEN=$(openssl rand -hex 32)   # 실제 랜덤 값
```

에이전트/CSOP에서:

```bash
# 원본 Trivy 리포트 (호스트 매핑 원하면 ?hostname= 또는 X-MORI-Hostname)
curl -X POST "https://mori.example.com/ingest/trivy?hostname=server-db01" \
  -H "Authorization: Bearer $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' --data @trivy-report.json

# 조치 전/후 증적(delta_type new/fixed/reopened) — 조회는 /evidence(admin·security)
curl -X POST "https://mori.example.com/ingest/evidence" \
  -H "X-MORI-Token: $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' --data @evidence-envelope.json
```

`MORI_INGEST_TOKEN` 미설정 시 인제스트는 로그인 세션을 요구합니다(자동화 불가).

### 3) Fleet / Wazuh (예정)

현재 라이브 API 폴러가 **미구현**입니다(`src/mori_soc/pollers/{fleet,wazuh}.py` 의 `build_collector()` 가 `None` 반환). `.env`에 연결 변수 자리는 마련돼 있으나 코드가 아직 읽지 않습니다. 구현되면 위 Zabbix와 동일하게 URL+자격증명만으로 기존 FleetDM / Wazuh Manager에 read-only 연결할 예정입니다.

그 전까지 번들 Fleet/Wazuh 데모를 체험하려면 `--profile fleet` / `--profile wazuh` 를 사용하세요.

## 딥링크 URL (선택)

호스트/경보 클릭 시 원본 도구로 이동하는 링크는 다음으로 설정합니다(비우면 링크 숨김):

```dotenv
MORI_ZABBIX_UI_URL=https://zabbix.your-corp.com
MORI_FLEET_UI_URL=https://fleet.your-corp.com
MORI_WAZUH_UI_URL=https://wazuh.your-corp.com
```

## 운영 주의

- 브라운필드 배포에서는 `MORI_ADMIN_PASSWORD` 교체 + `MORI_DEMO_MODE=false` + `MORI_DEMO_SEED=0` 로 설정하세요.
- 워커는 소스가 일시적으로 닿지 않아도 매 주기 재시도합니다(번들 소스에 의존하지 않음).
