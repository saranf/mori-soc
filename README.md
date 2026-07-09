# MORI SOC — 감사 대응형 보안 운영 플랫폼

**🇰🇷 한국어 (this page)** · [🇬🇧 English](./README.en.md) · [📘 상세 가이드](./README_FULL.md)

[![tests](https://github.com/saranf/mori-soc/actions/workflows/test.yml/badge.svg)](https://github.com/saranf/mori-soc/actions/workflows/test.yml)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Phase](https://img.shields.io/badge/phase-2%20(audit--ready)-yellow)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey)

---

`docker compose up -d` 한 줄로 띄우는 **ISMS-P / ISO 27001 증적 자동 누적 플랫폼**.
기존 **Zabbix · FleetDM · Wazuh · Trivy · Loki** 위에 read-only로 얹혀, 자산·취약점·경보·인시던트·통제 점검을 한 화면(`/ui`)에서 운영하고 **모든 변경을 _누가·언제·무엇을·어떤 근거로_ 자동 기록**합니다.

> **"보는 층"이 아니라 "증적 층"** — 시계열·로그 시각화는 Grafana/Loki에 위임하고, MORI는 그 위에서 **판단·기록·증명**(트리아지 → 조치 → 통제 매핑 → 증적 PDF → 감사 로그)을 담당합니다.

<!-- ═══════════════════════════════════════════════════════════════════════
     📸 스크린샷 가이드 ①  — 대표 이미지(README 맨 위에 크게 들어가는 첫 화면)
     "히어로 이미지"라고도 부릅니다. README를 열면 가장 먼저 보이는 한 장이라,
     이 스크린샷이 MORI를 "한 장으로 설명"하는 얼굴입니다. 가장 잘 나온 화면으로.

     ▸ 어디서   : admin 계정으로 로그인 → /ui 첫 화면(통합 대시보드)
     ▸ 무엇을   : 아래가 한 프레임(스크롤 없이)에 모두 보이게 캡처
                  · 상단 KPI 카드 4개 — Total Hosts / Offline Hosts /
                    High Alerts 24h / Critical Vulns (숫자가 0이 아닌 데모 시드 상태)
                  · Latest Host Status 표 (offline/unknown 호스트가 위로)
                  · 좌측(또는 상단) 탭 메뉴 — 대시보드/Triage/인시던트/자산/Compliance
     ▸ 팁       : 브라우저 폭 ≈1280px, 라이트 테마, 실호스트명·개인정보 없는 데모 데이터.
                  가로로 길게(파노라마)보다 상단 영역이 꽉 차게 찍어야 대표 이미지로 좋음.
     ▸ 저장     : docs/images/01-dashboard.png  (지금 걸린 demo-dashboard.png 교체)
     ▸ 넣는 법  : 위 경로에 저장 → 아래 27번째 줄의 이미지 경로에서
                  demo-dashboard.png → 01-dashboard.png 로만 바꾸면 끝
     ═══════════════════════════════════════════════════════════════════════ -->

![MORI 통합 대시보드](docs/images/demo-dashboard.png)

---

## 🎯 한눈에

- **대상** — 보안 담당자 1~2명 + IT 헬프데스크로 ISMS-P / ISO 27001을 준비하는 중소형 조직
- **한 줄 시작** — `./scripts/mori-start-demo.sh` → `http://localhost:18000/ui` (`admin / 1234`, 데모 전용)
- **핵심 가치** — 기존 도구를 **대체하지 않고**, 그 운영 데이터를 감사 증적으로 전환하는 read-only 레이어

## ✨ 핵심 기능

| | 기능 | 요약 |
|---|---|---|
| 📊 | **통합 운영 UI** | 대시보드 · Alert Triage · 인시던트 · 자산/취약점 · Compliance PDCA를 한 화면(`/ui`)에서 |
| 🎯 | **위험성 평가** | CVE별 3×3 매트릭스 = 영향도(자산 중요도) × 발생가능성 → **점수(1~9)** + 위험처리 결정·잔여위험·DoA 자동분류 (admin·security) |
| 📚 | **통제 카탈로그** | ISMS-P 101 + ISO 27001:2022 93 = **194 인증기준**(한/영) 트리 + 이행상태 편집·영속 + **admin 직접 편집(추가/수정/삭제)** + **법령 텍스트 NLP 임포트**(Claude/휴리스틱) + **수기 증적 문서화 + ⚡실증적 상세 자동 스냅샷(정기·일괄)** + **증적 문서**(자산 인벤토리 표) **CSV/PDF 다운로드** |
| 🧑‍💻 | **계정 거버넌스** | 서버·PC 로컬 계정(osquery) × LDAP × 승인대장 대조 → 퇴사자 잔존·미등록 특권·미승인 sudo·휴면 검출 · IP 팀/용도 선별 CSV (기본 admin·security, admin이 열람 역할 조정) |
| 🧾 | **자동 증적** | 자산 담당자·중요도, CVE 조치·예외, 위험성 평가, Triage·인시던트 변경을 _who/when/what_ 으로 누적 → **6종 CSV/PDF** |
| 🔐 | **역할별 화면** | 위험성 평가·통제는 admin·security 전용, 인프라·헬프데스크는 **내 담당 서버 조치율**만 |
| 🔑 | **LDAP 통합 (선택)** | 계정 하나로 MORI·Grafana·Zabbix·Fleet 로그인, 가입 승인 시 LDAP 계정 생성, 어드민 콘솔에서 직접 관리 |
| 🌐 | **다국어 UI** | 로그인·대시보드·어드민 전 페이지 한국어/영어 즉시 토글 |
| 💾 | **영속화** | UI 운영 상태 10종 store를 PostgreSQL에 write-through — 재시작 후에도 유지 |

## ⚡ 지금 되는 것 / 다음 — 30초 요약

| ✅ 지금 되는 것 | 🧪 부분 통합 | 🚧 다음 |
|---|---|---|
| **Zabbix 실시간 폴링 → alert (실 API 검증)** | Trivy collector 로컬 폴링 | **FleetDM 라이브 폴러** |
| **Trivy/CSOP 원격 push 증적 인제스트** (토큰) | Source freshness / Worker cycle | **Wazuh 라이브 폴러** |
| **브라운필드 연결** — `.env` config만으로 | | LDAP/AD 운영 연동 |
| Alert Triage / 인시던트 / **위험성 평가** | | Slack / Email 알림 |
| 로그인·RBAC · PostgreSQL 영속 · CSV/PDF 증적 | | 라이브 조회 캐싱 |

> ✅ **Zabbix**는 _problem → 수집 → Triage → Incident → 증적 → 해소_ 전 구간이 실 API로 검증됨. **Fleet / Wazuh**는 컬렉터·파서는 준비됐고 라이브 연동은 다음 단계입니다.

---

## 🚀 빠른 시작

**데모 (샘플 데이터)**
```bash
./scripts/mori-start-demo.sh          # .env 생성 → 기동 → 스키마/시드 → 워커
# → http://localhost:18000/ui  (admin / 1234, 데모 전용)
```

**브라운필드 (기존 Zabbix/Wazuh/Fleet 위에 얹기)**
```bash
docker compose up -d                  # MORI 코어만 (api + worker + postgres)
# .env 에서 기존 인프라 연결:
#   MORI_ZABBIX_API_URL=https://zabbix.your-corp.com/api_jsonrpc.php
#   MORI_ZABBIX_API_TOKEN=<토큰>
docker compose up -d mori-worker      # 재적용
```

> 번들 데모 스택까지: `docker compose --profile bundled up -d` (개별: `--profile zabbix`/`fleet`/`wazuh`)
> 자세한 절차는 [브라운필드 연결 가이드](docs/BROWNFIELD_CONNECT.md).

> 🔒 **데모 자격증명** — `admin`/`security`/`monitor` (비번 `1234`)는 격리된 **데모 전용**입니다. 운영 배포 시 `.env`의 `MORI_ADMIN_PASSWORD` 변경 + `MORI_DEMO_MODE=false`로 반드시 교체하세요.

---

## 🖼️ 화면 미리보기

> 아래는 데모 모드 기준 화면입니다. `<!-- 📸 -->` 블록은 **캡처해서 넣을 스크린샷 가이드**입니다(대상·구도·저장 파일명). 캡처 후 바로 아래 이미지 태그의 주석을 해제하세요.

### 1) 자연어 질의 (NLQ)
"오프라인 호스트 보여줘" 같은 한국어 질문 → 12개 인텐트 중 매칭 → 결과 + 요약 + CSV.

![자연어 질의](docs/images/demo-nlq.png)

### 2) 취약점 (Trivy) — CVE별 조치 계획·예외
호스트별 Critical/High 합계 + CVE별 조치 계획/예외/만료일 + 변경 이력.

![취약점 관리](docs/images/demo-trivy.png)

### 3) 위험성 평가 매트릭스
<img width="647" height="367" alt="image" src="https://github.com/user-attachments/assets/a3190b6f-aa5a-4153-b25c-734452f7120f" />


### 4) 통제 카탈로그 (ISMS-P × ISO 27001)
<img width="858" height="682" alt="image" src="https://github.com/user-attachments/assets/7b2c7fa3-98ff-4041-8fb5-07bc1592efd2" />


**admin은 카탈로그를 직접 편집**합니다 — 트리에서 통제 ✏️수정/🗑️삭제, "➕ 통제 추가", 그리고
**"📥 법령 텍스트 임포트(NLP)"** 로 CISA·개인정보보호법·고시 전문을 붙여넣으면 통제 초안(draft)으로
자동 변환·저장됩니다(`MORI_ANTHROPIC_API_KEY`가 있으면 Claude로 정밀 구조화, 없으면 조항 단위
휴리스틱). 통제별로 **수기 증적을 문서화**하거나, **⚡ "실증적 자동 기록"** 으로 현재 라이브 집계를
**날짜 찍힌 상세 증적으로 스냅샷**할 수 있습니다(통제 취지·이행상태 + 라이브 **실제 호스트 목록**(hostname·IP·상태)까지 캡처).
**정기 스냅샷**(off/매일/매주/매월)을 admin이 설정하면 **부팅·열람 시 도래분을 전 통제 일괄 스냅샷**하고,
**"⚡ 지금 일괄 스냅샷"** 수동 실행도 됩니다. **증적 문서**는 **CSV 또는 PDF**로 내려받습니다 — 통제 팩이 아니라 **자산 인벤토리 표**(호스트명·IP·상태·소스,
전체) + **문서화 증적 표**만 깔끔하게(화면에선 3건까지만 보이고 "더보기", 다운로드는 항상 전체). 상단
**"📦 전체 증적 ZIP"** 로 전 통제 증적을 **폴더별(프레임워크/통제)로 묶어 한방에 ZIP**(+`INDEX.csv`).
편집·정기설정은 admin 전용, 증적 문서화·ZIP은 admin·security.

### 5) 계정 거버넌스 (접근권한 검토)
<img width="1287" height="694" alt="image" src="https://github.com/user-attachments/assets/274b5b78-1ee5-439b-9b37-452daa4ba1f4" />


계정 탭의 **🌐 IP 리스트**는 **팀·용도(자산 소유자 메타)로 선별** 후 **CSV로 내보내기**를 지원합니다
(호스트/IP 검색 + 팀·용도 드롭다운 → `hostname,ip,importance,team,category,status`).

**열람 권한은 admin이 조정합니다.** 기본은 **admin·security** 전용이지만, 어드민 콘솔 **권한 탭 →
"🔑 계정 거버넌스 열람 역할"** 에서 인프라(monitor)·감사자 등 다른 역할에게도 열어줄 수 있습니다
(admin은 항상 포함). 저장 후 대상 사용자가 재로그인하면 계정 탭이 보입니다.

### 6) 어드민 콘솔 (/admin)
<img width="1411" height="744" alt="image" src="https://github.com/user-attachments/assets/73bd715d-c610-4271-91e2-653bbbecea3c" />


---

## 📖 문서

| 문서 | 내용 |
|---|---|
| [📘 **상세 가이드 (README_FULL)**](./README_FULL.md) | 아키텍처·API·테스트·배포·로드맵 전체 레퍼런스 |
| [시작하기 (신규 사용자)](docs/GETTING_STARTED.md) | 데모 기동 → 첫 운영 → 운영 전환 (한/영) |
| [기존 스택 연결 (브라운필드)](docs/BROWNFIELD_CONNECT.md) | `.env`만으로 read-only 연결 (한/영) |
| [LDAP 통합 인증](docs/LDAP_INTEGRATION.md) | 계정 하나로 MORI·Grafana·Zabbix·Fleet (한/영) |
| [배포 가이드](docs/DEPLOYMENT.md) | 서버 배포·운영·트러블슈팅 |
| [기능 정의서](docs/FUNCTIONAL_SPEC.md) · [로드맵](docs/IMPLEMENTATION_ROADMAP.md) | 기능 명세 / Phase 0~5 구현 로드맵 |

---

> ⚠️ **Alpha / Work in Progress** — 일상 보안 운영 + 감사 증적 시나리오가 동작하며 UI 운영 상태는 PostgreSQL에 영속화됩니다. Zabbix 실시간 폴링은 실 API로 검증됨(다른 시드 데이터는 데모용). Fleet / Wazuh 라이브 연동은 다음 단계입니다.
>
> 라이선스: Apache 2.0 · 전체 기능 체험은 `./scripts/mori-start-demo.sh` 한 줄로.
