# 기존 스택 연결 — 운영 중인 Zabbix/Wazuh/Fleet를 MORI에 붙이기

**🇰🇷 한국어** · [🇬🇧 English](./BROWNFIELD_CONNECT.en.md)

> **이 문서는 이런 분을 위한 것입니다** — *"이미 Zabbix(그리고 Wazuh/Fleet)를 운영 중인데,
> 그 데이터를 MORI로 받아서 ISMS-P/ISO 증적으로 쌓고 싶다."*
> MORI는 기존 도구를 **대체하지 않고**, **MORI 코어만 띄우고 `.env` 설정만으로** read-only로
> 얹습니다. 번들 Zabbix/Fleet/Wazuh를 따로 띄울 필요가 없습니다.
>
> MORI를 처음 설치한다면 → [시작하기 가이드](GETTING_STARTED.md) 먼저 보세요.

---

## TL;DR (3단계)

```bash
# 1) 설정 파일 생성 (최초 1회)
cp .env.example .env

# 2) .env 에서 소스 URL/자격증명을 '기존 인프라'로 교체 (아래 §3)

# 3) MORI 코어만 기동 (번들 소스 없이)
docker compose up -d
```

`docker compose up -d` = **MORI 코어(api + worker + postgres) + 대시보드(grafana/loki) + LDAP**.
번들 소스 스택은 `bundled` 프로파일 뒤로 빠져 있어, 명시적으로 요청할 때만 올라옵니다.

---

## 1. 사전 준비

| 항목 | 내용 |
| --- | --- |
| MORI 호스트 | Docker 24+ / Compose v2, 기존 인프라에 **네트워크로 닿는** 위치 |
| Zabbix | 버전 5.0+ (JSON-RPC API). **read-only 계정 또는 API 토큰** 발급 권한 |
| 방화벽 | MORI → Zabbix API 포트(보통 443/80/8080) 아웃바운드 허용 |
| (선택) Trivy/CSOP | 스캐너가 MORI로 **push** 할 수 있는 아웃바운드 경로 |

> MORI는 소스에 **읽기 전용**으로 접근합니다. 기존 도구의 설정을 바꾸지 않으며, 에이전트를
> 새로 심지 않습니다. 소스가 잠깐 안 닿아도 MORI 전체가 죽지 않고 다음 주기에 재시도합니다.

---

## 2. compose 프로파일 (무엇이 뜨는가)

| 명령 | 기동 대상 |
|---|---|
| `docker compose up -d` | **MORI 코어만** (브라운필드 기본) |
| `docker compose --profile bundled up -d` | 코어 + 번들 Zabbix·Fleet·Wazuh 데모 전체 |
| `docker compose --profile zabbix up -d` | 코어 + 번들 Zabbix 만 |
| `docker compose --profile fleet up -d` | 코어 + 번들 Fleet 만 |
| `docker compose --profile wazuh up -d` | 코어 + 번들 Wazuh 만 |
| `docker compose --profile scanner run trivy …` | 일회성 Trivy 스캔 |

프로파일은 조합 가능: `docker compose --profile zabbix --profile fleet up -d`.
**기존 인프라에 붙이는 경우 프로파일 없이** `docker compose up -d` 만 쓰면 됩니다.

---

## 3. 소스별 연결

| 소스 | 연결 방식 | 상태 | 핵심 .env |
|---|---|---|---|
| **Zabbix** | 라이브 REST(JSON-RPC) 폴링 | ✅ **설정만으로 동작(검증됨)** | `MORI_ZABBIX_API_URL` + 토큰 **또는** user/password |
| **Trivy / CSOP** | 원격 토큰 push | ✅ 토큰만 설정 | `MORI_INGEST_TOKEN` |
| **Fleet** | 라이브 REST 폴러 | ⚠️ **Phase 3 예정(미구현)** | `MORI_FLEET_API_URL`, `…_TOKEN` (자리만) |
| **Wazuh** | Manager REST(55000) 폴러 | ⚠️ **Phase 3 예정(미구현)** | `MORI_WAZUH_API_URL`, `…_USER/PASSWORD` (자리만) |

### 3-1) Zabbix (기존 인스턴스) — 단계별

**① Zabbix에서 read-only 접근 준비**
- 권장: **API 토큰** 발급 (Zabbix 5.4+): *Users → API tokens → Create*, 읽기 권한 유저에 연결.
- 또는 **읽기 전용 유저**(예: `mori-readonly`)를 만들어 user/password 사용.

**② `.env` 설정**
```dotenv
MORI_ENABLE_ZABBIX=true
MORI_ZABBIX_API_URL=https://zabbix.your-corp.com/api_jsonrpc.php
# 인증 — 토큰 권장(설정 시 user/password 무시)
MORI_ZABBIX_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx
#   (토큰이 없으면 아래 사용)
# MORI_ZABBIX_USER=mori-readonly
# MORI_ZABBIX_PASSWORD=********
MORI_ZABBIX_TIMEOUT_SECONDS=10
MORI_ZABBIX_HOST_LIMIT=500
MORI_ZABBIX_PROBLEM_LIMIT=500
```

**③ 적용(워커 재기동)**
```bash
docker compose up -d mori-worker
docker compose logs -f mori-worker   # "zabbix … problems/hosts" 수집 로그 확인
```
워커는 주기적으로 `problem.get`/`host.get` 을 폴링해 PostgreSQL `alerts`/`hosts` 에 적재합니다.

**④ MORI에서 확인**
- `/ui` → **자산 현황 → 서버 자산(Zabbix)** 에 호스트가 뜨는지
- **Alert Triage** 에 `source=zabbix` 경보가 뜨는지 → 상태 처리 → **인시던트** 승격 → 증적 export

> 데모 문제를 한 번 쏘아 파이프라인을 확인하려면(번들 Zabbix 사용 시):
> `./scripts/mori-zabbix-demo-problem.sh`

### 3-2) Trivy / CSOP (원격 스캐너 → MORI push)

MORI가 스캐너를 폴링하는 게 아니라, **스캐너/에이전트가 리포트를 MORI로 보냅니다(push).**

**① `.env`에 인제스트 토큰**
```dotenv
MORI_INGEST_TOKEN=<openssl rand -hex 32 로 생성한 값>
```
> 토큰을 설정하면 `/ingest/*` 는 로그인 세션 없이 토큰만으로 받습니다. 미설정 시 세션을 요구해
> 자동화가 안 됩니다.

**② 스캐너/CSOP에서 전송**
```bash
# 취약점 원본 리포트 (호스트 매핑: ?hostname= 또는 X-MORI-Hostname 헤더)
curl -X POST "https://mori.your-corp.com/ingest/trivy?hostname=server-db01" \
  -H "Authorization: Bearer $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' --data @trivy-report.json

# 조치 전/후 증적 (delta_type: new/fixed/reopened) — 조회는 GET /evidence (admin·security)
curl -X POST "https://mori.your-corp.com/ingest/evidence" \
  -H "X-MORI-Token: $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' --data @evidence-envelope.json
```

**③ MORI에서 확인** — `/ui` → **자산 현황 → 취약점(Trivy)** 에 호스트별 집계가 뜨고,
위험점수·조치 계획/예외를 관리할 수 있습니다.

### 3-3) Fleet / Wazuh (Phase 3 — 아직 라이브 폴러 없음)

현재 Fleet/Wazuh **라이브 API 폴러는 미구현**입니다(`src/mori_soc/pollers/{fleet,wazuh}.py`
의 `build_collector()` 가 `None`). `.env`에 연결 변수 **자리는** 있으나 코드가 아직 읽지 않습니다.
구현되면 위 Zabbix와 똑같이 **URL + 자격증명만으로** 기존 FleetDM / Wazuh Manager에 read-only
연결할 예정입니다.

그 전까지 번들 Fleet/Wazuh 데모로 화면을 체험하려면 `--profile fleet` / `--profile wazuh` 를 쓰세요.

---

## 4. 소스 콘솔 딥링크를 **내 URL**로 (선택)

MORI 화면의 `Zabbix ↗ / Fleet ↗ / Wazuh ↗ / Grafana ↗` 버튼을 **내 콘솔**로 연결합니다.
기본값은 MORI 데모 서버이니, 내 URL로 바꾸세요(비우면 해당 링크만 숨김).

```dotenv
MORI_ZABBIX_UI_URL=https://zabbix.your-corp.com    # 서버 자산 → Zabbix 호스트 페이지
MORI_FLEET_UI_URL=https://fleet.your-corp.com      # PC 자산 → Fleet 호스트 페이지
MORI_WAZUH_UI_URL=https://wazuh.your-corp.com      # 경보 타일 → Wazuh
MORI_GRAFANA_URL=https://grafana.your-corp.com     # 담당 서버 상세 → Grafana(Loki 로그)
```

> 딥링크는 자산 종류에 맞게만 노출됩니다 — 서버엔 Zabbix, PC엔 Fleet, 공통으로 Grafana.

---

## 5. 운영 주의 (브라운필드 배포)

`.env`에서 반드시:
```dotenv
MORI_ADMIN_PASSWORD=<강력한 값>   # 데모 기본값 교체
MORI_AUTH_ENABLED=true            # 비로그인 접근 차단
MORI_DEMO_MODE=false              # 데모 동작 끄기
MORI_DEMO_SEED=0                  # 샘플 데이터 주입 중단 (실데이터만)
```
- 워커는 소스가 일시적으로 안 닿아도 매 주기 **재시도**합니다(번들 소스에 의존하지 않음).
- MORI 접근은 **read-only 토큰** 권장 — 기존 시스템 설정은 건드리지 않습니다.

---

## 6. 트러블슈팅

| 증상 | 확인 |
| --- | --- |
| Zabbix 호스트/경보가 안 뜸 | `docker compose logs mori-worker` → API URL/토큰, 방화벽(아웃바운드), `MORI_ENABLE_ZABBIX=true` |
| 인증 오류 | 토큰 권한(읽기), user/password 오타. 토큰 설정 시 user/password는 무시됨 |
| Trivy push가 401 / "login" | `MORI_INGEST_TOKEN` 설정 + 요청 헤더 토큰 일치 |
| 호스트↔이미지가 따로 잡힘 | Trivy push에 `?hostname=` 또는 `X-MORI-Hostname` 로 실호스트 지정 |
| 딥링크가 MORI 데모로 감 | `.env`의 `MORI_*_UI_URL`을 내 URL로 교체(§4) |
| 번들 소스가 같이 떠버림 | 프로파일 없이 `docker compose up -d` 만 실행 |

---

## 다음 단계

- 엔드포인트에 Zabbix Agent + Trivy 온보딩 → [ZABBIX_AGENT_ACTIVE_SETUP.md](ZABBIX_AGENT_ACTIVE_SETUP.md)
- Wazuh 이해·운영 → [WAZUH_SETUP_AND_OPERATIONS.md](WAZUH_SETUP_AND_OPERATIONS.md)
- Fleet 설치·운영 → [FLEET_SETUP_AND_OPERATIONS.md](FLEET_SETUP_AND_OPERATIONS.md)
- 서버 배포·HTTPS·운영 → [DEPLOYMENT.md](DEPLOYMENT.md)
