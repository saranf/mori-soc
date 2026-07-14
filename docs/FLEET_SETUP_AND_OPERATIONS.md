# FleetDM 설치 & 운영 가이드

## 1. Fleet 이 뭐고 MORI 에서 왜 쓰나

**FleetDM = osquery 를 대규모로 관리하는 서버.** osquery 는 "OS를 SQL로 조회하는" 도구로,
단말의 설치 프로그램·계정·프로세스·디스크 암호화·패치 상태 등을 SQL 한 줄로 뽑습니다.
Fleet 은 그 osquery 에이전트(수백~수천 대)를 한 곳에서 관리·질의합니다.

MORI 관점(엔드포인트 자산·구성 점검 증적):

```
[단말] fleetd(osquery)  ──▶  [Fleet 서버 :1337]  ──▶  osquery 결과(자산/구성)
                                                            │
                                                MORI 가 Fleet API 로 수집(예정)
                                                            ▼
                                        MORI 자산 탭(PC 자산) · 구성 점검 증적
```

> 현재 MORI 는 Fleet **UI 딥링크**(자산 탭 → Fleet)까지 되어 있고, **라이브 API 폴링은
> 다음 단계(Next)** 입니다. 이 문서는 Fleet 자체 설치·운영과 단말 등록까지를 다룹니다.

---

## 2. MORI 스택에서 Fleet 구성

**번들 Fleet 은 `fleet` profile 뒤에 있어 기본 `docker compose up` 으로는 뜨지 않습니다.** 켜세요:

```bash
docker compose --profile fleet up -d       # (또는 전체 번들: --profile bundled)
docker compose ps fleet mysql redis         # 3개 Up 확인
# Fleet UI: http://<서버>:1337   (.env 의 MORI_FLEET_UI_URL)
```

| 구성요소 | 역할 | 포트 |
|---|---|---|
| `fleet` (fleetdm/fleet) | Fleet 서버 + 웹 UI + API | **1337** |
| `mysql` | Fleet 메타 저장소 | (내부) |
| `redis` | 라이브 쿼리 pub/sub | (내부) |
| `fleet-init` | vuln DB / 로그 볼륨 준비 | - |

> **로그인 루프 주의**: Fleet UI 최초 로그인이 무한 루프면 이미지 태그를 고정하세요
> (`docker-compose.yml` 의 `fleetdm/fleet` → 검증된 태그, 예: `fleetdm/fleet:v4.x`).
> 자세한 건 `docs/FLEET_RESET_AND_REINSTALL_GUIDE.md`.

---

## 3. 최초 설정 (Fleet 서버)

### 3-1. 관리자 계정 생성

1. 브라우저에서 `http://<서버>:1337` 접속 → **Set up Fleet** 마법사
2. 관리자 이메일/비밀번호, 조직명 입력 → 완료
   - (CLI 자동화가 필요하면 `fleetctl setup` 사용)

### 3-2. Enroll Secret 확인

단말이 Fleet 에 등록할 때 쓰는 비밀키입니다.

- Fleet UI → **Settings → Enroll secret** 에서 확인/복사
- 또는 `fleetctl get enroll_secret`

---

## 4. 단말에 fleetd(에이전트) 설치·등록

Fleet 은 osquery + 관리 데몬을 묶은 **fleetd** 설치 패키지를 만들어 줍니다.

### 4-1. 설치 패키지 생성 (관리 PC에서, fleetctl 필요)

```bash
# fleetctl 설치 — 공식 npm 패키지 사용(brew 포뮬러는 없음)
npm i -g fleetctl            # 또는 fleetctl preview 문서 참고

# 서버가 HTTP(TLS 미설정, compose 기본 FLEET_SERVER_TLS=false)이므로 --insecure 필수.
fleetctl package --type=msi --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET> --insecure   # Windows
fleetctl package --type=pkg --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET> --insecure   # macOS
fleetctl package --type=deb --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET> --insecure   # Ubuntu/Debian
fleetctl package --type=rpm --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET> --insecure   # RHEL 계열
```

> `fleetctl get enroll_secret` 은 먼저 `fleetctl config set --address http://<서버>:1337 --tls-skip-verify`
> + `fleetctl login` 을 해야 동작합니다. (또는 UI **Settings → Enroll secret** 에서 복사)

생성된 패키지를 대상 단말에 설치하면 자동 등록됩니다.
- macOS 상세 절차: [FLEET_MACBOOK_ENROLLMENT_AND_TEST.md](./FLEET_MACBOOK_ENROLLMENT_AND_TEST.md)
- 초기화/재설치: [FLEET_RESET_AND_REINSTALL_GUIDE.md](./FLEET_RESET_AND_REINSTALL_GUIDE.md)

### 4-2. 등록 확인

Fleet UI → **Hosts** 에 단말이 **online** 으로 뜨면 성공. 수 분 내 OS·하드웨어·소프트웨어 정보가 수집됩니다.

### 4-3. 클라이언트에 "쉽게" 설치하는 방법들 (상황별 추천)

> **MORI 번들(추천)** — Zabbix Agent + **Fleet 에이전트(fleetd)** + Trivy 를 **한 번에** 설치:
> ```bash
> sudo -E MORI_ZABBIX_SERVER=<서버> MORI_HOSTNAME=my-web-01 \
>      MORI_FLEET_URL=https://<fleet>:1337 MORI_FLEET_SECRET=<enroll-secret> \
>      bash scripts/mori-endpoint-onboard.sh
> ```
> Fleet 부분은 `fleetctl package` 로 설치 패키지를 만들어 자동 설치합니다(내부적으로 fleetctl
> 자동 설치). Fleet 만 원하면 `--skip-zabbix --skip-trivy`. (`scripts/mori-endpoint-onboard.sh --help`)

| 방법 | 언제 | 방법 |
|---|---|---|
| **① Fleet UI 복붙 (가장 쉬움)** | 단말 1~수십 대, 손으로 설치 | Fleet UI → **Hosts → Add hosts** → OS 선택 → **생성된 설치 명령/패키지를 그대로 복사** 해 단말에서 실행. fleet-url·enroll secret 이 이미 박혀 나옴 |
| **② `fleetctl package` (대량/오프라인)** | 이미지·배포도구로 뿌릴 때 | 위 4-1 처럼 msi/pkg/deb/rpm 생성 → **MDM / Intune / Ansible / GPO / SCCM** 으로 푸시 |
| **③ macOS 대량** | 회사 맥 다수 | 생성한 `.pkg` 를 **MDM(Jamf 등)** 에 업로드해 무인 배포. 상세: [FLEET_MACBOOK_ENROLLMENT_AND_TEST.md](./FLEET_MACBOOK_ENROLLMENT_AND_TEST.md) |
| **④ 스크립트 자동화** | 프로비저닝 자동화 | `fleetctl package ...` 산출물을 프로비저닝 스크립트/cloud-init 에 넣어 부팅 시 설치 |

**가장 빠른 길(단건):** Fleet UI → **Add hosts** 에서 나오는 명령을 그대로 붙여넣기.
예시(Linux, Fleet 가 생성해주는 형태):

```bash
# Fleet UI 가 만들어주는 실제 명령을 사용하세요(아래는 형태 예시)
sudo fleetctl package --type=deb --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET>
sudo dpkg -i fleet-osquery_*.deb        # 설치 즉시 자동 등록
```

> enroll secret 은 비밀입니다. 스크립트/이미지에 하드코딩하지 말고 배포도구의 시크릿으로 주입하세요.

---

## 5. 운영 — 자주 쓰는 것

### 5-1. Live Query (즉시 질의)

Fleet UI → **Queries → Create new query** → SQL 입력 → 대상 호스트 선택 → **Run**.

```sql
-- 설치된 소프트웨어
SELECT name, version FROM programs;               -- (Windows: programs, macOS: apps)
-- 로컬 관리자 계정
SELECT username, uid FROM users WHERE uid < 1000;
-- 디스크 암호화(FileVault/BitLocker) 상태
SELECT * FROM disk_encryption;
-- 최근 로그인
SELECT username, time FROM last;
```

### 5-2. Saved Query & Scheduling

- 자주 쓰는 쿼리는 **Save** 해두고, **Schedule** 로 주기 실행 → 결과가 로그로 축적됩니다.
- 스케줄 결과 로그는 Fleet 이 `fleet-logs` 볼륨/Loki 로 흘려보내 증적화할 수 있습니다.

### 5-3. Policies (정책 점검)

Fleet UI → **Policies** — "예/아니오"로 판정되는 컴플라이언스 점검.

- 예: *디스크 암호화 켜져 있는가?* / *방화벽 켜져 있는가?* / *특정 패치 설치됐는가?*
- 정책 위반 단말이 목록으로 나와 **ISMS-P 2.1(자산)·2.10(패치)** 증적으로 활용.

### 5-4. Teams / RBAC

- **Teams** 로 단말을 부서/역할별로 나누고, 팀별 enroll secret·쿼리 권한을 분리합니다.

---

## 6. MORI 연동 (라이브 REST — 설정만으로 동작)

MORI 는 Fleet REST API 를 주기 폴링해 **PC 자산**과 **소프트웨어 취약점**을 적재한다.
osquery **로그**(status/result)는 이미 fluent-bit → Loki 로 흐르므로 **다시 수집하지 않는다**
— 로그 조회는 Grafana/Loki 에 위임하고, MORI 는 증적 층으로 남는다.

### 6-1. 켜는 법

1. **API 토큰 발급** — Fleet UI > **Settings > Users** 에서 **API-only 유저** 생성 후 토큰 복사
   (또는 `POST /api/v1/fleet/login` 응답의 `token`).
2. **`.env` 설정** (자세한 항목은 `.env.example` 의 Fleet 절)

   ```bash
   MORI_ENABLE_FLEET=true
   MORI_FLEET_API_URL=http://fleet:1337        # 브라운필드: https://fleet.your-corp.com
   MORI_FLEET_API_TOKEN=<발급받은 토큰>
   MORI_FLEET_INCLUDE_SOFTWARE=true            # 취약점까지 수집(호스트 수만큼 요청 증가)
   # MORI_FLEET_INSECURE_TLS=true              # 사내 자체서명 인증서일 때만
   ```

   셋 중 하나라도 비어 있으면 **수집하지 않는다**(기본 비활성 — 기존 배포에 영향 없음).
3. **워커 재빌드·재시작** — MORI 코드는 이미지에 들어 있다. 코드를 갱신했다면
   `docker compose build mori-worker && docker compose up -d mori-worker`.
   (재빌드를 빠뜨리면 폴러가 예전 코드로 돌아 `skipped` 가 뜬다.)

### 6-2. 무엇이 들어오나

| Fleet | → MORI |
|---|---|
| `GET /api/v1/fleet/hosts` | 자산(호스트) — ID 는 **`pc-<hostname>`** 으로 스코프됨 |
| `GET /api/v1/fleet/hosts/{id}` 의 `software[].vulnerabilities` | 취약점(`source=fleet`) → Triage → Incident → 증적 |

- 자산 탭의 각 PC 에는 **Fleet ↗ 딥링크**(`MORI_FLEET_UI_URL`)가 붙는다 — `pc-` 접두사 기준.
- 수집 주기 기본값: **하루 1회**(자산), stale 10일 — `docs/collection-standards.md` 기준. `MORI_FLEET_INTERVAL_SECONDS` 로 조정.
- 정상 동작 시 대시보드 **Source freshness** 에 `fleet / success / N records` 로 보인다.

### 6-3. 확인된 것 / 남은 것

- **확인됨(실 API E2E)**: 실제 Fleet 에 osquery 호스트를 enroll → 폴링 1주기 → PostgreSQL 자산 적재
  → 로그인한 `/assets` 응답에 `asset_type: PC` 로 노출 → Fleet 딥링크 정상.
  스키마는 실응답 캡처(`tests/fixtures/fleet/`) 기준이며 추측이 아니다.
- **남음**: **실 CVE 로는 아직 검증되지 않았다.** 취약점 매핑 코드는 있으나, 검증에 쓴 환경에서
  Fleet 이 CVE 를 산출하지 못했다(취약점 크론이 해당 배포판에 매칭 실패). 실단말에서 CVE 가 뜨면
  그 응답을 fixture 로 추가해 검증한다 — **스키마를 추측해 채우지 말 것.**

---

## 7. 트러블슈팅

> **먼저 볼 것 — 단말을 붙이려면 Fleet 이 HTTPS 여야 한다.**
> osquery/fleetd 는 **HTTPS 로만** Fleet 에 접속한다(평문 HTTP 로 붙일 방법이 없다).
> 그런데 번들 compose 는 `FLEET_SERVER_TLS: "false"` (평문) 이다 → **이 상태로는 실단말 enroll 이 안 된다.**
> 실제 단말을 붙이려면 둘 중 하나가 필요하다:
> - Fleet 에 인증서를 주고 `FLEET_SERVER_TLS=true` + `FLEET_SERVER_CERT`/`FLEET_SERVER_KEY`, 또는
> - Fleet 앞에 **HTTPS 리버스 프록시**(레포의 `--profile https` caddy 등)를 두고 그 주소로 enroll.
>
> MORI → Fleet **API 폴링**은 평문 HTTP 로도 동작하므로, 위 제약은 **단말 enroll 에만** 해당한다.

| 증상 | 확인 |
|---|---|
| Hosts 에 단말 안 뜸 | **Fleet 이 HTTPS 인가**(위 참고)? 단말→`<서버>:1337` outbound 가능? enroll secret 일치? `orbit`/`fleetd` 서비스 실행 중? |
| MORI 에 PC 자산이 안 들어옴 | `.env` 의 `MORI_ENABLE_FLEET`/`API_URL`/`API_TOKEN` 셋 다 채워졌나? **워커 이미지 재빌드**했나(`docker compose build mori-worker`)? Source freshness 에 `fleet` 이 `skipped` 면 설정 미비, `error` 면 메시지 확인 |
| online 인데 데이터 없음 | osquery 스케줄/라이브쿼리 실행해야 결과 로그가 쌓임 |
| 서버 기동 실패 | `docker compose logs fleet` — mysql/redis 의존성 준비 여부 확인 |
| 인증서/HTTPS | 운영은 리버스 프록시(HTTPS) 뒤에 두고 `--fleet-url` 을 https 로 |

> 운영 배포에서는 반드시 HTTPS + 강한 관리자 비밀번호 + enroll secret 로테이션을 적용하세요.
