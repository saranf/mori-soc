# Wazuh 이해 & 운영 가이드

> TLS 인증서가 안 만들어져 스택이 안 뜨거나 `is a directory` 로 죽는다면 → **[Wazuh 인증서](WAZUH_CERTS.md)** 를 먼저 보세요.
> (인증서는 `generate-indexer-certs` 서비스가 자동 생성합니다. 인증서를 **파일 단위로 bind-mount 하면 안 됩니다.**)

## 1. 한 줄 요약

**Wazuh = 오픈소스 SIEM/XDR.** 단말·서버에 에이전트를 깔면, 그 에이전트가 로그·파일변경·
프로세스를 감시해서 **"보안 이벤트(alert)"** 를 만들고, 중앙 서버가 이를 룰로 판정·저장·시각화합니다.
쉽게 말해 **"보안 관점의 CCTV + 경보 시스템"** 입니다.

- **Zabbix** = 인프라 상태(디스크/CPU/가용성) 감시 → *운영* 문제
- **Wazuh** = 보안 이벤트(무단로그인/파일변조/루트킷) 탐지 → *보안* 사고
- **MORI** = 둘의 이벤트를 감사 증적으로 정리 (Triage → Incident → 증적)

---

## 2. 구조 — 3개 컴포넌트 (이게 핵심)

Wazuh 는 하나가 아니라 **3개가 한 세트**로 돕니다. MORI 스택에도 3개가 다 떠 있어요.

```
[단말] wazuh-agent ──이벤트(1514)──▶ ┌───────────────────┐
                                      │  wazuh.manager    │  ① 룰 판정 + 경보 생성
                     ◀──enroll(1515)──│  (두뇌)            │     API :55000
                                      └─────────┬─────────┘
                                                │ 저장
                                      ┌─────────▼─────────┐
                                      │  wazuh.indexer    │  ② 검색 엔진(OpenSearch)
                                      │  (저장/검색) :9200 │     경보 데이터 저장
                                      └─────────┬─────────┘
                                                │ 조회
                                      ┌─────────▼─────────┐
                                      │  wazuh.dashboard  │  ③ 웹 화면
                                      │  (눈)              │     경보 시각화/검색
                                      └───────────────────┘
```

| 컴포넌트 | 비유 | 하는 일 | 포트 |
|---|---|---|---|
| **wazuh.manager** | 두뇌 | 에이전트 이벤트를 **룰셋으로 판정** → 경보 생성, 에이전트 등록 관리 | 1514(이벤트), 1515(등록), **55000(API)** |
| **wazuh.indexer** | 기억 | 경보를 저장·검색 (OpenSearch 기반) | 9200 |
| **wazuh.dashboard** | 눈 | 경보를 웹에서 보고 검색 | (웹 UI) |

MORI 스택 버전: **4.14.4**.

**번들 Wazuh 는 `wazuh` profile 뒤에 있어 기본 `up` 으로는 뜨지 않습니다.** 인덱서 인증서를
먼저 만든 뒤 profile 로 켜세요:

```bash
rm -rf config/wazuh_indexer_ssl_certs && mkdir -p config/wazuh_indexer_ssl_certs
docker compose -f generate-indexer-certs.yml run --rm generator   # 인덱서 TLS 인증서 생성
docker compose --profile wazuh up -d                              # (또는 전체 번들: --profile bundled)
docker compose ps wazuh.manager wazuh.indexer wazuh.dashboard      # 3개 Up 확인
# Dashboard: 기본 https://127.0.0.1:${WAZUH_DASHBOARD_PORT:-8443} (localhost 바인딩 —
#   원격 접속은 SSH 터널/역프록시 필요). .env 의 MORI_WAZUH_UI_URL 채우면 MORI 위젯에 Wazuh↗ 링크.
```

---

## 3. Wazuh 가 실제로 잡는 것 (왜 보안에 쓰나)

에이전트가 단말에서 아래를 감시하고, manager 룰이 판정해 경보로 만듭니다.

- **로그 분석(LIDS)** — SSH 무차별 대입(brute force), sudo 오용, 웹서버 공격 패턴
- **파일 무결성 감시(FIM)** — `/etc`, 시스템 바이너리 등 **중요 파일 변조** 탐지
- **루트킷/이상행위(rootcheck)** — 숨은 프로세스·포트, 루트킷 흔적
- **보안 설정 점검(SCA)** — CIS 벤치마크 등 하드닝 기준 미준수
- **취약점 탐지** — 설치 패키지 vs 알려진 CVE 대조
- **Active Response** — 특정 경보 시 자동 대응(IP 차단 등)

→ 이게 **ISMS-P 2.11(사고 예방·대응)·2.9(로그관리)** 증적으로 직결됩니다.

---

## 4. 운영 흐름 — 단말 등록부터 경보까지

### 4-1. Dashboard 로그인

- `https://<서버>:<대시보드포트>` 접속 (기본 계정은 배포 시 생성된 `admin` / 초기 비밀번호)
- 초기 비밀번호는 Wazuh 설치 시 생성됨 — `docker compose logs wazuh.dashboard` 또는 설치 문서 참고

### 4-2. 단말에 wazuh-agent 설치

Dashboard → **Agents → Deploy new agent** 가 OS별 설치 명령을 만들어 줍니다. 예(Linux):

```bash
# manager 주소를 지정해 설치 (Dashboard 가 생성해주는 명령을 그대로 사용 권장)
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.4-1_amd64.deb
sudo WAZUH_MANAGER="<서버 IP>" dpkg -i ./wazuh-agent_4.14.4-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

- 에이전트가 manager **1514** 로 이벤트를 보냅니다(등록은 1515).
- Dashboard → **Agents** 에 **Active** 로 뜨면 성공.

### 4-3. 경보 확인

Dashboard → **Security events / Threat Hunting** 에서 경보를 봅니다.
- 테스트: 대상 단말에서 `sudo cat /etc/shadow` 같은 민감 동작이나 SSH 로그인 실패 반복 → 관련 경보 생성.

### 4-4. 룰/튜닝 (manager)

- 룰셋: `/var/ossec/etc/rules/`, 로컬 룰: `local_rules.xml`
- FIM 감시 경로: `/var/ossec/etc/ossec.conf` 의 `<syscheck>` 블록
- 너무 시끄러운 경보는 룰 레벨 조정으로 억제.

---

## 5. MORI 연동

**HTTP push (`POST /ingest/wazuh`) — 이미 구현·동작**합니다. Wazuh 측(또는 중계 스크립트)에서
경보를 MORI 로 밀어 넣으면 alert 로 정규화 적재 → Alert Triage → Incident → 증적으로 흐릅니다.

```bash
# 본문: {"alerts": [{ "rule": {...}, "agent": {...}, ... }]}  — Wazuh alerts.json 포맷
curl -fsS -X POST "$MORI_INGEST_URL/ingest/wazuh" \
  -H "Authorization: Bearer $MORI_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  --data @wazuh-alerts.json
# 응답: {"ok": true, "records_collected": N, "entities_saved": M}
```

- 인증: `MORI_INGEST_TOKEN` Bearer(또는 `X-MORI-Token`) 헤더. **`MORI_DATABASE_URL` 이 설정된
  상태여야** 적재됩니다(state 백엔드 필요).
- 확인: 응답의 `records_collected` + MORI 소스 신선도(**설정 → 소스**)와 **Alert Triage** 화면.
- **예정(Next)**: `pollers/wazuh.py` 로 Wazuh API(`:55000`)/indexer(`:9200`)를 **주기 폴링**(현재 스텁
  — `MORI_ENABLE_WAZUH`/`MORI_WAZUH_API_*` 는 자리만 잡아둔 상태로 아직 무동작).
- `MORI_WAZUH_UI_URL` 설정 시 인프라 위젯에서 **Wazuh↗** 딥링크.

> ⚠️ 어떤 룰/레벨이 **어떤 통제 증적으로 매핑**되는지는 아직 자동화되지 않았습니다(Trivy 의 스캔→2.8
> 자동승격 같은 매핑 미구현). 현재는 Triage→Incident 경로로 다뤄집니다.

즉 MORI 에서 최종 그림은:

```
Wazuh(보안 이벤트)  ┐
Zabbix(운영 문제)   ├─▶ MORI Alert Triage → Incident → 감사 증적(CSV/PDF)
Trivy(취약점)       ┘
```

---

## 6. 자주 겪는 것 / 주의

| 증상 | 확인 |
|---|---|
| Agent 가 Active 안 됨 | 단말→manager `1514/1515` outbound? `WAZUH_MANAGER` 주소 정확? `systemctl status wazuh-agent` |
| Dashboard 안 열림 | indexer(9200) 정상? 인증서(`config/wazuh_indexer_ssl_certs`) 생성됨? `docker compose logs wazuh.indexer` |
| 경보가 안 보임 | manager→indexer 연결, 시간대(clock) 확인. 이벤트를 실제로 유발했는지 |
| 메모리 많이 먹음 | indexer(OpenSearch)는 무겁습니다. 데모/소형에선 JVM 힙·리소스 제한 권장 |

> Wazuh 3대(manager/indexer/dashboard)는 **인증서 기반 상호 TLS** 로 묶여 있어, MORI 스택에서는
> `generate-indexer-certs.yml` 로 인증서를 먼저 생성합니다(배포 문서 참조). 운영에선 기본 비밀번호를
> 반드시 교체하세요.
