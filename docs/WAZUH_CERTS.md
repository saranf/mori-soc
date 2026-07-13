# Wazuh TLS 인증서 — 왜 깨졌고, 지금은 어떻게 자동으로 도는가

> 이 문서는 Wazuh나 이 레포를 처음 보는 사람도 읽고 바로 조치할 수 있게 쓰였습니다.
> 영문: [WAZUH_CERTS.en.md](WAZUH_CERTS.en.md)

## 30초 요약

Wazuh 3종(indexer / manager / dashboard)은 **서로 TLS로만 통신**합니다. 그래서 뜨기 전에
인증서 파일이 **반드시** 있어야 합니다. 예전에는 그 인증서를 **사람이 수동으로 만들어야** 했고,
아무도 안 만들면 스택이 조용히 죽었습니다(실제로 2026년 3월부터 5개월간 죽어 있었습니다).

지금은 `docker compose --profile wazuh up -d` 한 번이면 **인증서 생성 → 이름 보정 → 서비스 기동**이
자동으로 순서대로 일어납니다. 사람이 할 일은 없습니다.

```bash
docker compose --profile wazuh up -d          # 이게 전부
```

---

## 무엇이 문제였나 (재발 방지를 위해 기록)

### 1. 인증서를 만들어 주는 서비스가 compose에 없었다

`docker-compose.yml`은 `config/wazuh_indexer_ssl_certs/` 를 컨테이너 안으로 마운트합니다.
그런데 그 디렉터리를 **채워 주는 주체가 아무 데도 없었습니다**. 그래서 비어 있었습니다.

여기서 Docker의 함정이 터집니다.

> **Docker는 "없는 파일"을 마운트하라고 하면, 에러를 내지 않고 같은 이름의 _빈 디렉터리_ 를 만들어 버립니다.**

그 결과 `root-ca.pem` 같은 8개의 **.pem이 전부 "디렉터리"가 됐고**, OpenSearch(indexer)는
부팅하면서 이렇게 죽었습니다:

```
root-ca.pem - is a directory
```

컨테이너는 `Restarting` 을 무한 반복했고, 아무도 몰랐습니다.

### 2. 인증서를 만들어도 파일명이 안 맞는다

인증서 생성기(`wazuh/wazuh-certs-generator`)는 **한 가지 규칙으로만** 파일을 만드는데,
정작 세 서비스는 **각기 다른 이름**을 기대합니다. 이름이 하나만 어긋나도 위와 똑같이 죽습니다.

| 서비스 | 기대하는 이름 | 생성기가 만드는 이름 | 보정 |
|---|---|---|---|
| indexer | `wazuh.indexer.pem` | `wazuh.indexer.pem` | 불필요 |
| indexer | **`wazuh.indexer.key`** | `wazuh.indexer-key.pem` | **복사 필요** |
| dashboard | **`wazuh-dashboard.pem`** | `wazuh.dashboard.pem` | **복사 필요** |
| dashboard | **`wazuh-dashboard-key.pem`** | `wazuh.dashboard-key.pem` | **복사 필요** |
| manager | `root-ca-manager.pem` / `wazuh.manager.pem` / `wazuh.manager-key.pem` | 동일 | 불필요 |

(점 `.` 과 하이픈 `-` 차이뿐이라 눈으로는 잘 안 보입니다. 이게 이 사고가 오래 안 잡힌 이유입니다.)

---

## 지금은 어떻게 도는가

`docker-compose.yml` 에 **`generate-indexer-certs`** 서비스가 있습니다. 한 번 실행되고 종료되는
1회성 작업이며, wazuh 3종은 **이 작업이 성공적으로 끝난 뒤에야** 뜹니다
(`depends_on: condition: service_completed_successfully`).

```
generate-indexer-certs  (1회 실행)
   1. 인증서가 이미 있으면?  -> 아무것도 안 하고 넘어감 (멱등)
   2. 없으면?               -> config/certs.yml 을 읽어 12개 파일 생성
   3. 이름이 다른 3개를 복사로 별칭 생성
   4. 정상 종료
        |
        v
wazuh.indexer / wazuh.manager / wazuh.dashboard  기동
```

- **입력**: [`config/certs.yml`](../config/certs.yml) — 어떤 노드에 어떤 인증서를 발급할지 정의.
- **출력**: `config/wazuh_indexer_ssl_certs/` — 실제 인증서(**git에 커밋되지 않습니다**. `.gitignore` 처리).
- **멱등**: 몇 번을 다시 실행해도 기존 인증서를 덮어쓰지 않습니다. 없을 때만 만듭니다.

### 왜 심볼릭 링크가 아니라 "복사"인가

링크는 **컨테이너 안에서 깨질 수 있습니다**(링크가 가리키는 경로가 컨테이너의 마운트 경로 기준으로
달라짐). 인증서는 몇 KB짜리 텍스트 파일이라 복사 비용이 사실상 0입니다. **안전한 쪽을 택했습니다.**

---

## 절대 규칙 하나만 기억하세요

> ### 인증서는 "디렉터리 단위"로만 마운트한다. **파일 단위 마운트 금지.**
>
> ```yaml
> # 올바름 — 디렉터리를 통째로
> - ./config/wazuh_indexer_ssl_certs:/usr/share/wazuh-indexer/config/certs:ro
>
> # 금지 — 파일 하나하나
> - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/.../certs/root-ca.pem:ro
> ```
>
> 파일 단위로 걸면, **그 파일이 아직 없을 때 Docker가 같은 이름의 빈 디렉터리를 만들어** 버리고,
> 서비스는 `is a directory` 로 죽습니다. 3월 사고가 정확히 이것이었습니다.

`config/certs.yml` 에도 규칙이 하나 있습니다: **`ip:` 필드에는 점(`.`)이 있는 DNS 이름이나 IP만**
넣습니다. `indexer` 같은 짧은 이름을 넣으면 생성기가 `Invalid IP or DNS` 로 거부합니다.
(그래서 `wazuh.indexer` 처럼 씁니다 — 이 이름은 compose 서비스명 = 컨테이너 hostname 과 같아야 TLS 검증이 통과합니다.)

---

## 잘 도는지 확인하는 법

```bash
# 1) 세 컨테이너가 Restarting 이 아니라 Up 이어야 한다
docker compose --profile wazuh ps

# 2) 클러스터가 green 이어야 한다
docker exec mori-soc-wazuh.indexer-1 \
  curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health
# -> {"cluster_name":"wazuh-cluster","status":"green", ...}
```

컨테이너 이름의 `mori-soc-` 접두사는 compose 프로젝트명(=디렉터리명)에 따라 달라집니다.
`docker ps` 로 실제 이름을 확인하세요.

## 고장났을 때 (복구 절차)

증상: 컨테이너가 계속 `Restarting`. 로그에 `is a directory` 또는 `no such file`.

```bash
# 1) 인증서 디렉터리 상태 확인 — .pem 이 "디렉터리"로 보이면 그게 원인이다
ls -la config/wazuh_indexer_ssl_certs/

# 2) wazuh 3종만 내린다 (주의: 그냥 `docker compose down` 을 쓰면
#    같은 프로젝트의 다른 컨테이너 — mori-api, grafana 등 — 까지 전부 내려간다)
docker compose --profile wazuh rm -sf wazuh.indexer wazuh.manager wazuh.dashboard

# 3) 망가진 인증서를 통째로 버린다 (실제 인증서가 아니라 빈 디렉터리들이다)
rm -rf config/wazuh_indexer_ssl_certs

# 4) 다시 올리면 generate-indexer-certs 가 알아서 새로 만든다
docker compose --profile wazuh up -d wazuh.indexer wazuh.manager wazuh.dashboard
```

인증서를 새로 만들면 **기존 indexer 데이터는 그대로**입니다(인증서는 통신 신원일 뿐, 데이터가 아닙니다).

---

## 관련 문서

- [Wazuh 설치·운영](WAZUH_SETUP_AND_OPERATIONS.md)
- [배포](DEPLOYMENT.md)
