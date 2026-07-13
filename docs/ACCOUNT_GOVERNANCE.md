# 계정 거버넌스 — 수집 · 운영 가이드

서버·PC의 **로컬 계정 인벤토리**를 모아 **LDAP 디렉터리 × 승인 대장**과 대조해
**퇴사자 잔존 · 미등록 특권 · 미승인 sudo · 휴면 계정**을 검출합니다.
접근권한 검토 증적: **ISMS-P 2.5.1·2.5.5·2.5.6 / ISO A.5.16·A.5.18·A.8.2**

---

## 1. 먼저 — 어드민에서 켜기

로컬 계정 목록은 민감정보라 **수집 자체를 admin이 켜고 끕니다.**

> 어드민 콘솔 → **Access Control** 탭 → **계정 수집** 카드

| 설정 | 값 | 의미 |
|---|---|---|
| **계정 수집 사용** | on(기본) / off | **off면 MORI가 계정 데이터를 아예 받지 않습니다** — `POST /ingest/accounts` 가 `403` (fail-closed) |
| **수집 경로** | **`Fleet (osquery)`** (기본) / `스크립트 push` | 어떤 경로로 계정을 넣을지 |

설정은 `ui_settings`(`schema/008`)에 영속되어 재시작 후에도 유지됩니다.
(`account_collect_enabled` · `account_collect_source`, 변경은 감사 로그에 기록)

---

## 2. 경로 A — Fleet (osquery) · **기본**

Fleet 에이전트(fleetd)가 깔린 호스트는 osquery 가 이미 로컬 계정을 알고 있으므로,
MORI가 Fleet에서 가져옵니다. 엔드포인트에서 따로 할 일이 없습니다.

- 에이전트 설치: [`scripts/mori-endpoint-onboard.sh`](../scripts/mori-endpoint-onboard.sh) 가 **Zabbix Agent + fleetd + Trivy** 를 한 번에 설치(설치 시 대화형 선택)
- Fleet 설치·운영: [FLEET_SETUP_AND_OPERATIONS.md](./FLEET_SETUP_AND_OPERATIONS.md)
- `.env`: `MORI_FLEET_API_URL` · `MORI_FLEET_API_TOKEN`

---

## 3. 경로 B — 스크립트 push (Fleet 없는 호스트)

Fleet을 깔 수 없는 서버는 **`/etc/passwd`·`group`·`sudoers`·`lastlog`** 만으로도 수집됩니다.
osquery가 있으면 자동으로 osquery를 씁니다.

```bash
# 대상 서버에서 (토큰은 환경변수로 — 화면/스크린샷에 남기지 마세요)
export MORI_INGEST_URL=https://mori.example.com
export MORI_INGEST_TOKEN=<MORI 서버 .env 의 MORI_INGEST_TOKEN>

sudo -E bash scripts/mori-collect-accounts.sh              # 1회 수집
sudo -E bash scripts/mori-collect-accounts.sh --cron       # 수집 + 매일 03:20 cron 등록
sudo -E bash scripts/mori-collect-accounts.sh --dry-run    # 전송 없이 payload만 확인
```

| env | 기본 | 설명 |
|---|---|---|
| `MORI_INGEST_URL` | (필수) | MORI 베이스 URL |
| `MORI_INGEST_TOKEN` | (필수) | 인제스트 토큰 |
| `MORI_HOSTNAME` | `hostname` | **자산 매칭 키** — Zabbix/Fleet에 등록된 호스트명과 맞추세요 |
| `MORI_HOST_TYPE` | `server` | `server` \| `pc` |

> 수집이 꺼져 있으면 스크립트가 `403 — 어드민 콘솔에서 '계정 수집'이 꺼져 있습니다` 로 종료합니다.

---

## 4. API — `POST /ingest/accounts`

토큰 인증(`Authorization: Bearer` 또는 `X-MORI-Token`). **호스트별 계정 집합을 통째로 교체**하므로
주기 실행하면 항상 최신 상태가 됩니다(삭제된 계정도 자동 반영).

```bash
curl -X POST "https://mori.example.com/ingest/accounts?hostname=srv-01" \
  -H "Authorization: Bearer $MORI_INGEST_TOKEN" -H 'Content-Type: application/json' -d '{
  "hostname": "srv-01",
  "host_type": "server",
  "accounts": [
    {"username":"root","uid":"0","gid":"0","shell":"/bin/bash","home":"/root",
     "groups":["root"],"sudo":true,"disabled":false,
     "last_login":"2026-07-13T09:00:00Z","pwd_last_change":"2026-01-02"}
  ]
}'
# → {"ok":true,"host_key":"srv-01","host_type":"server","count":1}
```

호스트명 우선순위: `?hostname=` 쿼리 → `X-MORI-Hostname` 헤더 → 본문의 `hostname`/`host_id`

**특권 판정(자동)** — `uid=0` 이거나, `sudo:true` 이거나, 그룹이
`root·wheel·sudo·admin·adm·domain admins·administrators` 중 하나면 `is_privileged`.

---

## 5. 결과 읽는 법

> **계정 탭** (기본 admin·security — 어드민 콘솔 → Access Control → *계정 거버넌스 열람 역할*에서 조정)

검출되는 4가지(`services/account_recon.py`):

| 검출 | 뜻 | 조치 |
|---|---|---|
| **퇴사자 잔존** | 서버엔 계정이 있는데 **LDAP 디렉터리에 없음**(또는 비활성) | 즉시 계정 삭제/잠금 |
| **미등록 특권** | 특권 계정인데 **승인 대장에 없음** | 승인 등록하거나 특권 회수 |
| **미승인 sudo** | sudo 권한인데 승인 대장에 없음 | 위와 동일 |
| **휴면 계정** | 장기 미로그인 | 잠금/삭제 검토 |

**승인 대장**(allow-list)에 정당한 계정을 등록해두면 검출에서 빠집니다 —
계정 탭 → 승인 대장 (`scope: global|host`, `kind: account|sudo`, 만료일 지정 가능).

**증적**: `GET /accounts/overview.csv` — 접근권한 검토 결과를 CSV로 내려 심사 증적으로 사용.
호스트 상세(자산 → 호스트 더블클릭)에도 그 서버의 계정 섹션이 붙습니다.

---

## 6. 주기 권장

| 환경 | 주기 |
|---|---|
| Fleet(osquery) | Fleet의 호스트 상세 갱신 주기를 따름 |
| 스크립트 push | **1일 1회**(`--cron` 기본 03:20). 접근권한 검토는 보통 분기 1회지만, 증적은 매일 쌓아두는 편이 안전 |

관련: [DB ERD](./DB_ERD.md) (`host_accounts` · `account_approvals`) · [API 설계](./API_DESIGN.md) · [Fleet 운영](./FLEET_SETUP_AND_OPERATIONS.md)
