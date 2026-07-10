# 시작하기 — MORI 설치 & 운영 (신규 사용자용)

**한국어** · [English](./GETTING_STARTED.en.md)

> 처음 MORI를 설치해서 데모로 익히고, 실제 운영으로 넘어가는 전 과정을 **한 페이지**로 정리했습니다.
> 이미 Zabbix/Wazuh/Fleet를 운영 중이고 **데이터만 MORI로 받고 싶다면** →
> [기존 스택 연결 가이드](BROWNFIELD_CONNECT.md)를 보세요.

---

## 0. MORI가 뭔가요? (30초)

MORI는 **ISMS-P / ISO 27001 증적을 자동으로 쌓아주는 "증적 층(evidence layer)"** 입니다.
- Zabbix·Wazuh·Fleet·Trivy·Loki를 **read-only로 얹어서** 자산·취약점·경보·인시던트·통제 이행을
  한 화면(`/ui`)에서 운영하고, 모든 변경을 **누가·언제·무엇을**과 함께 증적으로 남깁니다.
- "보는 층(대시보드 시각화)"은 Grafana에 위임하고, MORI는 **심사에 낼 증적**에 집중합니다.

---

## 1. 사전 준비물

| 항목 | 필요 버전 | 확인 |
| --- | --- | --- |
| Docker Engine | 24+ | `docker --version` |
| Docker Compose | v2 (`docker compose`) | `docker compose version` |
| 여유 자원 | 4 vCPU / 8GB RAM 권장 | 데모 전체 스택 기준 |
| 포트 | 18000(MORI) 등 | `.env`에서 변경 가능 |

> 그냥 MORI만 체험하려면 Docker만 있으면 됩니다. 번들 데모(Zabbix/Fleet/Wazuh 포함)까지
> 띄우려면 메모리를 넉넉히 확보하세요.

---

## 2. 설치 & 첫 실행 (한 줄)

```bash
git clone https://github.com/saranf/mori-soc.git
cd mori-soc
cp .env.example .env          # 설정 파일 생성 (그대로도 데모 동작)
./scripts/mori-start-demo.sh  # MORI 코어 기동 + 샘플 데이터 시드
```

- 브라우저에서 **http://localhost:18000/ui** 접속
- 로그인: **`admin` / `1234`** (데모 전용 — 운영 전 반드시 변경, §6 참고)

> `mori-start-demo.sh`는 **MORI 코어(api·worker·postgres)** 만 띄우고 샘플 데이터를 넣습니다.
> 번들 데모 소스(Zabbix/Fleet/Wazuh)까지 함께 보려면:
> ```bash
> docker compose --profile bundled up -d   # 전체 데모 스택
> # 또는 개별: --profile zabbix / --profile fleet / --profile wazuh
> ```

정지 / 재기동:
```bash
./scripts/mori-stop-demo.sh     # 정지
docker compose ps               # 상태 확인
docker compose logs -f mori-api # 로그
```

---

## 3. 기본 계정 & 권한(RBAC)

데모에는 역할별 계정이 준비돼 있습니다 (비밀번호 모두 `1234`, **데모 전용**).

| 계정 | 역할 | 볼 수 있는 것 |
| --- | --- | --- |
| `admin` | 관리자 | 전체 + 설정·산정 근거 |
| `security` | 보안담당자 | 위험성 평가·통제 카탈로그·증적 전체 |
| `monitor` | 서버모니터 | 모니터링·자산(읽기 위주) |
| `auditor` | 감사자 | 모니터링·변경 이력(읽기 전용) |
| `helpdesk` | 헬프데스크 | **내 담당 서버 조치현황만** |

> **위험성 평가 / 통제 카탈로그 / 증적**은 admin·security 전용입니다. 인프라·헬프데스크는
> 자기 담당 서버의 조치현황만 봅니다. (프로필 → 담당 서버 등록으로 "내 서버"필터 사용)

---

## 4. 첫 운영 한 바퀴 (심사 시나리오)

1. **대시보드** — 역할별 보안 히어로 + 24h/12h 인프라 현황(경보 타일 → 소스 딥링크)
2. **자산 현황** — Fleet(PC)·Zabbix(서버)·Trivy(취약점) 탭. 팀별·'내 자산만'필터,
   호스트별 담당자·중요도 편집(변경 이력 자동 기록)
3. **취약점 → 위험성 평가** — CVE별 **위험점수(1~9)** = 영향도(중요도)×발생가능성(심각도).
   위험 처리(조치/수용/이관/회피) 기록. admin은 **DoA(수용가능 위험 기준)** 점수를 정하면
   그 이하 위험은 자동 '기본 수용'으로 분류됩니다.
4. **컴플라이언스 → 통제 카탈로그** — '상세 분석'을 펼치면 **ISMS-P 101 × ISO 194개 인증기준**
   트리. 항목을 클릭해 **이행 상태(이행/부분이행/미이행/해당없음)·담당자·개선계획·기한**을
   편집하면 **재시작 후에도 유지**되고 변경 이력이 남습니다. 통제별 **증적 팩 PDF**도 1클릭.
5. **내 담당 서버** — 행을 **더블클릭**하면 상세 모달에서 미조치가 **예외 만료·조치기한 초과·
   기타 위험** 3버킷으로 정리되고, 자산 종류에 맞는 **Zabbix/Grafana/Fleet 딥링크**가 뜹니다.
6. **증적 export** — 자산·계정·로그·취약점·월간·**위험성 평가 대장 6종**을 CSV/PDF로 다운로드.

---

## 5. 백업 & 복구

```bash
./scripts/mori-backup.sh    # PostgreSQL 논리 백업 생성
./scripts/mori-restore.sh   # 백업에서 복구
```

- MORI의 운영 상태(담당자·조치·Triage·인시던트·위험성 평가·통제 이행상태·설정)는 모두
  PostgreSQL에 **write-through 영속화**되어 재시작·복구 후에도 유지됩니다. (스키마 `001`~`009`)

---

## 6. 데모 → 운영 전환 체크리스트

`.env`에서 아래를 반드시 바꾸세요.

```bash
# 1) 관리자 비밀번호 (필수)
MORI_ADMIN_PASSWORD=<강력한 값>

# 2) 세션 인증 켜기 (비로그인 접근 차단)
MORI_AUTH_ENABLED=true

# 3) DB/서비스 비밀번호 (change_this_* 전부 교체)
MORI_DB_PASSWORD=...
ZABBIX_DB_PASSWORD=...   # 번들 소스 쓸 때만
FLEET_DB_PASSWORD=...    # 번들 소스 쓸 때만

# 4) 원격 인제스트 토큰 (Trivy/CSOP push 쓸 때)
MORI_INGEST_TOKEN=<openssl rand -hex 32 로 생성>

# 5) 데모 시드 끄기 (샘플 데이터 주입 중단)
MORI_DEMO_MODE=false
MORI_DEMO_SEED=0
```

- 자세한 서버 배포·HTTPS·운영은 [DEPLOYMENT.md](DEPLOYMENT.md) 참고.

---

## 7. 소스 콘솔 딥링크를 **내 URL**로 바꾸기

MORI 화면 곳곳의 `Zabbix ↗ / Fleet ↗ / Wazuh ↗ / Grafana ↗` 버튼은 각 소스의 웹 콘솔로
연결됩니다. 기본값은 MORI 데모 서버지만, `.env`에서 **내 서버 URL로 자유롭게 교체**할 수 있습니다.

```bash
MORI_ZABBIX_UI_URL=https://zabbix.your-corp.com    # 비우면 Zabbix 링크 숨김
MORI_FLEET_UI_URL=https://fleet.your-corp.com      # 비우면 Fleet 링크 숨김
MORI_WAZUH_UI_URL=https://wazuh.your-corp.com      # 비우면 Wazuh 링크 숨김
MORI_GRAFANA_URL=https://grafana.your-corp.com     # 비우면 Grafana 링크 숨김
```

> 소스 종류에 맞는 링크만 노출됩니다 — 서버(Zabbix)엔 Zabbix, PC(Fleet)엔 Fleet, 공통으로 Grafana.

---

## 8. 자주 겪는 문제

| 증상 | 확인 |
| --- | --- |
| `/ui`가 안 열림 | `docker compose ps`로 `mori-api` healthy 여부, `docker compose logs mori-api` |
| 로그인 후 데이터 없음 | 시드 여부 — `./scripts/mori-seed-sample-data.sh` 재실행 |
| 딥링크가 엉뚱한 서버로 감 | `.env`의 `MORI_*_UI_URL`을 내 URL로 교체(§7) |
| 포트 충돌 | `.env`의 `MORI_API_PORT` 등 변경 후 재기동 |
| 원격 push가 401/"login" | `MORI_INGEST_TOKEN` 설정 + 요청 헤더 토큰 일치 확인 |

---

## 다음 단계

- **이미 Zabbix/Wazuh/Fleet를 운영 중** → [기존 스택 연결 가이드](BROWNFIELD_CONNECT.md)
- 엔드포인트에 Zabbix Agent + Trivy 붙이기 → [ZABBIX_AGENT_ACTIVE_SETUP.md](ZABBIX_AGENT_ACTIVE_SETUP.md)
- 서버 배포·HTTPS·트러블슈팅 → [DEPLOYMENT.md](DEPLOYMENT.md)
