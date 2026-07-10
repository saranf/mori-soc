# 실제 Zabbix Agent 설치 & MORI 연동 가이드 (Zabbix 7.4)

실제 서버/PC에 **Zabbix Agent 2**를 설치해 MORI 스택의 Zabbix Server에 연결하고,
문제(problem)가 발생하면 **MORI Alert Triage로 흘러 들어오는 것까지** 확인하는 전체 절차입니다.

```
[대상 서버] Zabbix Agent 2  ──(Active)──▶  [MORI] Zabbix Server(10051)
                                                    │
                                        트리거 발생 → problem
                                                    │  (mori-worker 30초 폴링)
                                                    ▼
                                          MORI Alert Triage → Incident → 증적
```

권장은 **Active Agent** 방식입니다 — 단말이 서버로 outbound 접속하므로 NAT/사내망에서 구성이 단순하고, 서버가 단말의 10050 포트로 들어올 필요가 없습니다.

> **빠른 길 (원커맨드 번들)** — 대상 서버에서 한 번에 **Zabbix Agent 2 + Trivy**를 설치·설정합니다.
>
> 저장소를 클론했다면:
> ```bash
> MORI_ZABBIX_SERVER=<MORI 서버> MORI_HOSTNAME=my-web-01 sudo -E ./scripts/mori-endpoint-onboard.sh
> ```
>
> 클론 없이 **바로 설치**(GitHub raw 호스팅). 파이프 대신 **다운로드→확인→실행**을 권장:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/saranf/mori-soc/main/scripts/mori-endpoint-onboard.sh -o mori-onboard.sh
> less mori-onboard.sh                      # 내용 확인 (curl | sudo bash 는 지양)
> sudo -E MORI_ZABBIX_SERVER=<MORI 서버> MORI_HOSTNAME=my-web-01 \
>      bash mori-onboard.sh --check          # 먼저 사전 점검(설치 안 함)
> sudo -E MORI_ZABBIX_SERVER=<MORI 서버> MORI_HOSTNAME=my-web-01 \
>      MORI_INGEST_URL=http://<MORI>:18000 MORI_INGEST_TOKEN=<토큰> \
>      bash mori-onboard.sh                   # 설치 + Trivy 스캔 결과 MORI 자동 전송
> ```
> `MORI_INGEST_URL`(+`MORI_INGEST_TOKEN`)을 주면 **Trivy 스캔 결과가 `POST /ingest/trivy` 로 MORI에 바로 적재**됩니다(원격→MORI 자동 배송). 안 주면 로컬 `reports/trivy` 에만 저장.
>
> **MORI 표준 Zabbix 템플릿**(디스크/CPU/메모리/에이전트 + 매크로 임계):
> ```bash
> # A) MORI 스택에서 API 로 바로 생성
> ./scripts/mori-zabbix-template.sh
>
> # B) 또는 커밋된 공식 export 를 Zabbix Web 으로 import
> #    Data collection → Templates → Import → config/zabbix/templates/mori_linux_security_baseline.yaml
> ```
> 이후 Zabbix Web에서 호스트에 템플릿만 연결하면 됩니다. (아래는 각 단계 수동 절차)

---

## 0. 사전 확인 (MORI 측)

MORI 스택이 떠 있으면 Zabbix Server/Web은 이미 실행 중입니다.

```bash
docker compose ps zabbix-server zabbix-web
```

- **Zabbix Web**: `http://<서버>:18081` (`.env`의 `MORI_ZABBIX_UI_URL`, 기본 `Admin` / `zabbix`)
- **Zabbix Server(agent 접속 대상)**: `<서버>:10051` (compose에서 `10051:10051` 노출)

대상 서버에서 `<서버>:10051` 로 outbound 연결이 가능해야 합니다.

```bash
nc -vz <서버> 10051    # succeeded 나오면 OK
```

---

## 1. 대상 서버에 Zabbix Agent 2 설치

### Ubuntu / Debian

```bash
# Zabbix 7.4 리포지토리 (배포판 버전에 맞게: ubuntu24.04, debian12 등)
wget https://repo.zabbix.com/zabbix/7.4/release/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.4+ubuntu24.04_all.deb
sudo dpkg -i zabbix-release_latest_7.4+ubuntu24.04_all.deb
sudo apt update
sudo apt install -y zabbix-agent2
```

### RHEL / Rocky / AlmaLinux

```bash
sudo rpm -Uvh https://repo.zabbix.com/zabbix/7.4/release/rhel/9/noarch/zabbix-release-latest-7.4.el9.noarch.rpm
sudo dnf clean all
sudo dnf install -y zabbix-agent2
```

### macOS (Homebrew — 테스트용)

```bash
brew install zabbix
# 설정 파일: $(brew --prefix)/etc/zabbix/zabbix_agent2.conf
```

---

## 2. 에이전트 설정

설정 파일: `/etc/zabbix/zabbix_agent2.conf` (macOS는 brew 경로). 아래 3개만 맞추면 됩니다.

```ini
# 수동 체크(Passive)용 — 서버 IP 허용
Server=<MORI 서버 IP>

# Active 체크용 — 에이전트가 접속할 서버:포트
ServerActive=<MORI 서버 IP>:10051

# 이 호스트의 고유 이름 — Zabbix Web에서 등록할 Host name 과 반드시 동일하게
Hostname=my-web-01
```

적용:

```bash
sudo systemctl enable --now zabbix-agent2
sudo systemctl restart zabbix-agent2
sudo systemctl status zabbix-agent2      # active(running) 확인
# 로그: /var/log/zabbix/zabbix_agent2.log
```

---

## 3. Zabbix Web에서 Host 등록

Zabbix Web(`:18081`, Admin/zabbix) 접속 후:

1. **Data collection → Hosts → Create host**
2. 값 입력:
   - **Host name**: 에이전트의 `Hostname`과 **동일값** (예: `my-web-01`)
   - **Templates**: `Linux by Zabbix agent` (또는 `Linux by Zabbix agent active`) 추가
   - **Host groups**: `Linux servers` 등 아무 그룹
   - **Interfaces → Add → Agent**: 대상 서버 IP / 포트 `10050`
     - (Active만 쓸 경우 인터페이스 IP는 형식상 넣어두면 됩니다)
3. **Add** 저장

수 분 뒤 **Monitoring → Latest data**에서 CPU/메모리/디스크 값이 들어오면 성공입니다.

> **CLI로 등록**하고 싶으면 `host.create` + `templateid` API를 쓸 수 있습니다. 데모용 문제 발생은 `./scripts/mori-zabbix-demo-problem.sh` 참고.

---

## 4. 문제(problem) 발생 → MORI로 흐르는지 확인

실제 트리거가 걸리는 상황(디스크 사용률 초과, 서비스 다운 등)을 만들거나,
`Linux by Zabbix agent` 템플릿의 기본 트리거가 발화하면 **Monitoring → Problems**에 문제가 뜹니다.

- **mori-worker**가 30초 주기로 `problem.get`을 폴링해 정규화 → PostgreSQL `alerts` 적재.
- MORI `/ui` → **Alert Triage** 탭에 `source=zabbix`로 표시됩니다(각 알림에 `Zabbix ↗` 딥링크).
- 확인용:

```bash
# MORI가 방금 폴링했는지 (source freshness)
docker exec -it mori-soc-soc-postgres-1 psql -U mori -d mori_soc \
  -c "SELECT source,status,last_success_at FROM source_syncs WHERE source='zabbix';"

# 적재된 zabbix alert
docker exec -it mori-soc-soc-postgres-1 psql -U mori -d mori_soc \
  -c "SELECT alert_id,severity,rule_name,resolved_at FROM alerts WHERE source='zabbix' ORDER BY observed_at DESC LIMIT 5;"
```

Zabbix에서 문제가 **해소(resolve)** 되면(복구 이벤트 발생) MORI alert의 `resolved_at`이 채워지고
Triage에 "소스 해소"뱃지가 표시됩니다.

---

## 5. 자주 겪는 문제

| 증상 | 원인 / 해결 |
|---|---|
| Latest data에 값이 안 옴 | `Hostname`(에이전트) ≠ Host name(Web) 불일치 / 방화벽에서 10051 outbound 막힘 |
| Web에서 host가 빨간 ZBX | Passive 인터페이스 IP 오류 — Active만 쓰면 무시 가능, 또는 IP 교정 |
| MORI Triage에 안 뜸 | Problems에 실제 problem이 있는지 확인 → `source_syncs` last_success 갱신 확인 → `mori-worker` 로그 확인 |
| `mori-worker` 로그에 Zabbix 인증 오류 | `.env`의 `MORI_ZABBIX_USER/PASSWORD` 확인 (기본 Admin/zabbix). 7.x는 반복 로그인 일시 차단 있음 |

---

## 6. 참고

- MORI는 Zabbix를 **read-only**로 폴링만 합니다(에이전트 설치·Zabbix 설정 변경은 이 문서대로 사용자가 수행). MORI가 Zabbix 구성을 바꾸지 않습니다.
- 데모 시나리오(실제 서버 없이 problem 발생)는 `./scripts/mori-zabbix-demo-problem.sh` 로 재현할 수 있습니다.
- 배포 자동화(GitHub Actions)용 SSH 설정은 [DEPLOY_SSH_SETUP.md](./DEPLOY_SSH_SETUP.md) 참고.
