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

> ⚠️ 현재 MORI 는 Fleet **UI 딥링크**(자산 탭 → Fleet)까지 되어 있고, **라이브 API 폴링은
> 다음 단계(Next)** 입니다. 이 문서는 Fleet 자체 설치·운영과 단말 등록까지를 다룹니다.

---

## 2. MORI 스택에서 Fleet 구성

`docker compose` 로 이미 함께 뜹니다(별도 설치 불필요).

| 구성요소 | 역할 | 포트 |
|---|---|---|
| `fleet` (fleetdm/fleet) | Fleet 서버 + 웹 UI + API | **1337** |
| `mysql` | Fleet 메타 저장소 | (내부) |
| `redis` | 라이브 쿼리 pub/sub | (내부) |
| `fleet-init` | vuln DB / 로그 볼륨 준비 | - |

```bash
docker compose ps fleet mysql redis
# Fleet UI: http://<서버>:1337   (.env 의 MORI_FLEET_UI_URL)
```

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
# fleetctl 설치 (macOS)
brew install fleetctl        # 또는 npm i -g fleetctl

# 대상 OS별 설치 패키지 생성
fleetctl package --type=msi   --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET>   # Windows
fleetctl package --type=pkg   --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET>   # macOS
fleetctl package --type=deb   --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET>   # Ubuntu/Debian
fleetctl package --type=rpm   --fleet-url=http://<서버>:1337 --enroll-secret=<SECRET>   # RHEL 계열
```

생성된 패키지를 대상 단말에 설치하면 자동 등록됩니다.
- macOS 상세 절차: [FLEET_MACBOOK_ENROLLMENT_AND_TEST.md](./FLEET_MACBOOK_ENROLLMENT_AND_TEST.md)
- 초기화/재설치: [FLEET_RESET_AND_REINSTALL_GUIDE.md](./FLEET_RESET_AND_REINSTALL_GUIDE.md)

### 4-2. 등록 확인

Fleet UI → **Hosts** 에 단말이 **online** 으로 뜨면 성공. 수 분 내 OS·하드웨어·소프트웨어 정보가 수집됩니다.

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

## 6. MORI 연동 (현재/예정)

- **현재**: MORI 자산 탭(PC 자산)에서 각 호스트의 **Fleet ↗ 딥링크**(`MORI_FLEET_UI_URL`)로 Fleet 상세로 이동.
- **예정(Next)**: `pollers/fleet.py` 로 Fleet API(`/api/v1/fleet/hosts` 등)를 주기 폴링 → 호스트/osquery 결과를 MORI 자산·관측치로 정규화 적재(Zabbix 와 동일 패턴). Trivy 처럼 `POST /ingest/*` HTTP 인제스트로도 확장 가능.

---

## 7. 트러블슈팅

| 증상 | 확인 |
|---|---|
| Hosts 에 단말 안 뜸 | 단말→`<서버>:1337` outbound 가능? enroll secret 일치? `orbit`/`fleetd` 서비스 실행 중? |
| online 인데 데이터 없음 | osquery 스케줄/라이브쿼리 실행해야 결과 로그가 쌓임 |
| 서버 기동 실패 | `docker compose logs fleet` — mysql/redis 의존성 준비 여부 확인 |
| 인증서/HTTPS | 운영은 리버스 프록시(HTTPS) 뒤에 두고 `--fleet-url` 을 https 로 |

> 운영 배포에서는 반드시 HTTPS + 강한 관리자 비밀번호 + enroll secret 로테이션을 적용하세요.
