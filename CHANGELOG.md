# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this is an alpha project so
versions are `x.y.z-alpha.n`.

## [v0.13.0-alpha.1] — 2026-07-08 — 관리자 콘솔 정리 (중복 제거 · 진입점 · 톤 통일)

### Changed
- **`/admin` 중복 운영 탭 제거** — 내용이 `/ui#…` 링크뿐이던 **Compliance · Triage & Incidents**
  탭을 콘솔에서 제거(운영 뷰는 `/ui`로 일원화) → 관리자 콘솔은 **6탭**(Overview · Remediation ·
  자산/Owners · Access Control · Audit & Logs · Settings)으로 슬림화.
- **진입점 정리** — 사용자 대시보드(`/ui`) 계정 메뉴에 **⚙️ 관리자 콘솔** 링크(admin 전용) 추가
  (기존엔 `/ui`→`/admin` 링크가 없었음). 문서 타이틀 `MORI — 관리자 콘솔`로 정정.
- **입력 컨트롤 톤 통일** — LDAP 사용자 관리·가입 승인·감사/사용자 로그 필터의 제각각이던
  인라인 입력/셀렉트 스타일(#1e293b·radius 5~6)을 공용 `.inp-sm` 클래스로 교체 → 콘솔 베이스
  팔레트(#0b1220·radius 10·#334155)로 통일.

## [v0.12.0-alpha.1] — 2026-07-08 — LDAP 통합 인증 (선택) + 가입 승인 프로비저닝

계정 하나로 MORI·Grafana·Zabbix·Fleet 로그인. **기본 OFF**, 원하면 켜는 옵션.

### Added
- **어드민 LDAP 사용자 관리 UI** — 어드민 콘솔 → Access Control → **🔑 LDAP 사용자 관리**:
  상태 표시 + 사용자 목록/추가/삭제/비번 재설정/역할 변경(admin 전용). 엔드포인트
  `GET /admin/ldap/status`·`GET/POST /admin/ldap/users`·`.../{uid}/password`·`.../role`·
  `DELETE .../{uid}` + 헬퍼 `auth.ldap_list_users/ldap_delete_user/ldap_set_password`.
- **LDAP 계정 생성** (`auth.ldap_add_user`) — `inetOrgPerson` 를 디렉터리에 추가.
- **가입 승인 프로비저닝(승인제)** — `/signup-request` 에 로그인 아이디 필드 추가, admin 승인
  시 **역할·초기 비밀번호**를 정하면 계정이 실제로 생성된다: LDAP 활성 시 디렉터리 계정(같은
  LDAP을 보는 Grafana/Zabbix/Fleet 에서도 로그인), 비활성 시 로컬 계정. 역할은 `ui_settings`
  (`ldaprole:<uid>`)에 영속되어 **재시작 후 유지**, 초기 비밀번호는 승인 화면에 1회 표시.
- **헬퍼 스크립트** `scripts/mori-ldap-adduser.sh` — 번들/외부 LDAP 에 사용자 CLI 추가(OU 자동 생성).
- **문서** `docs/LDAP_INTEGRATION.md`(+`.en`) — 켜기/가입/CLI 추가/기존 Grafana·Zabbix 연동/끄기.

### Fixed
- **LDAP 로그인이 항상 실패하던 버그** — `ldap_verify` 가 검색 시 유효하지 않은 속성 `dn` 을
  요청해 예외 → 인증 실패로 처리되던 문제 수정(`cn` 으로 변경, DN 은 `entry_dn` 사용).
- **LDAP env 배선 불일치** — `read_auth_config` 가 무프리픽스 `LDAP_*` 를 읽어 compose 의
  `MORI_LDAP_*` 와 어긋나던 문제 수정(`MORI_LDAP_*` 우선 + 레거시 폴백). **`MORI_LDAP_ENABLED`
  을 실제로 존중**(기본 OFF). compose 바인드 비밀번호를 `LDAP_ADMIN_PASSWORD` 와 자동 일치.

## [v0.11.0-alpha.1] — 2026-07-08 — 자산 뷰 정제 · 딥링크 · 필터

### Added
- **호스트 상세 모달 외부 딥링크** — '내 담당 서버' 행 더블클릭 상세에 자산 종류별 딥링크:
  서버→**Zabbix**, PC→**Fleet**, 공통→**Grafana**(Explore, host 로그). `MORI_GRAFANA_URL`
  플레이스홀더 치환 추가. URL 미설정 소스는 자동 생략.
- **자산 테이블 필터** — Fleet·Zabbix 자산 표에 **팀별 드롭다운** + **'⭐ 내 자산만'**
  체크박스(프로필 담당서버/담당자 일치). 팀 옵션은 자산 team 값에서 자동 추출.

### Changed
- **취약점 현황(Trivy) 표** — `High/Medium/Low` 카운트 컬럼을 **위험점수(1~9)** 컬럼으로
  대체(Critical·합계 유지). 위험점수 = 영향도(중요도)×발생가능성(최고 심각도).
- **'내 담당 서버' 표 간소화** — 컬럼을 `호스트명·중요도·상태·IP`로(분류 컬럼 제거, 그룹
  헤더가 이미 카테고리). 헤더/값 좌측정렬 통일.
- 통제 카탈로그 트리를 컴플라이언스 탭 상단 카드 → **'상세 분석' 접이식 섹션**으로 이동.

## [v0.10.0-alpha.1] — 2026-07-08 — Control Catalog 이행상태 편집 (M2-7)

컴플라이언스 화면을 시드 control_checks 12건이 아니라 **ISMS-P 101개 인증기준 카탈로그**로
운영. 통제별 이행 상태를 편집·영속한다.

### Added
- **control_status 편집·영속** (`schema/009_control_status.sql`) — 통제별 이행 상태
  (이행/부분이행/미이행/해당없음/미정)·담당자·예외사유·개선계획·기한. `controls`(원본,
  schema/007)와 분리된 유일 편집 테이블. StateRepository `load/save_control_status` +
  부팅 warm-load + write-through 영속 → **재시작 후에도 유지**.
- **`PUT /controls/status/{id}`** (admin·security) — 상태 편집. 상태 화이트리스트·기한
  형식·통제 존재 검증, 변경을 action-audit-log 에 기록. `GET /controls/tree` 에 `status_map`,
  `GET /controls/detail/{id}` 에 `runtime_status` 병기.
- **컴플라이언스 탭 통제 트리** — 통제 카탈로그 트리(ISMS-P 101 × ISO)를 자산 탭에서
  **컴플라이언스 탭으로 이동**, 항목에 이행 상태 배지 + 클릭 상세에 **상태 편집 폼**.
  기존 control_checks 기반 PDCA 요약은 삭제하지 않고 병행 유지.

### Note
- 의뢰서(M2-7)의 schema/006·`controls(id)` FK·`checkpoints/operation` 상세뷰는 현재
  레포 상태(006=evidence_events, controls PK=(framework,id), YAML 필드 상이)에 맞춰 적응:
  schema/009 신규 + `control_id` 단독 PK + 기존 카탈로그 서비스 재사용. 카탈로그 YAML→DB
  싱크와 CI validate(`catalog` 잡)는 이미 구축돼 있어 재사용.

## [v0.9.0-alpha.1] — 2026-07-08 — Risk UX 점수화 + DoA 수용기준 + 내 서버 조치현황

피드백 반영: 위험을 라벨(Critical/High) 대신 **점수**로, 대시보드는 최소화, 내 담당
서버는 간소화 + 더블클릭 상세로.

### Added
- **위험 수용 기준(DoA)** — 조직 단위 단일 임계 점수(1~9). admin이 위험 매트릭스
  카드에서 입력하면 그 점수 **이하 위험은 "기본 수용가능"으로 자동 분류**된다.
  경량 key-value 설정 저장소(`schema/008_settings.sql`, `ui_settings`) +
  `GET/PUT /settings/risk`(쓰기는 admin 전용) + StateRepository `load_settings`/
  `save_setting` 로 영속화. `/vulnerabilities/risk-summary` 응답에 `doa`·`accepted`·
  항목별 `doa_accept` 추가.
- **내 서버 조치현황 버킷** (`GET /dashboard/host-remediation/{hostname}`) —
  한 호스트의 미조치 항목을 **예외 만료 / 조치기한 초과 / 기타 위험** 3버킷으로 분류
  (활성 예외는 수용된 것으로 제외). '내 담당 서버' 행 더블클릭 상세 모달에 표시.

### Changed
- **위험 표기를 점수 중심으로** — 위험 매트릭스 셀·버킷 목록·배지가 `N점`을 전면에,
  등급 라벨은 보조로. DoA 이하 셀은 🟢 '기본수용'으로 음영 표시.
- **대시보드 최소화** — 위험 매트릭스 카드 **기본 접힘**('펼치기'로 상세 노출).
- **'내 담당 서버' 테이블 간소화** — 컬럼을 `호스트명·중요도·분류·상태·IP`로 축소
  (통제·리스크·이력 컬럼 제거). 상세·조치현황은 **행 더블클릭 → 상세 모달**로 이동.
- KO/EN i18n 키(`dash.risk.doa_*`, `dash.mine.*`, `dash.host.*`) 추가.

## [v0.8.0-alpha.1] — 2026-07-07 — Control Catalog (Phase 2 skeleton) + Evidence-Gap Dashboard

### Added
- **Control catalog** (`controls/`) — the Phase 2 identity pivot. ISMS-P 2023 (101) +
  ISO 27001:2022 Annex A (93) = **194 controls**, all with KO/EN titles, plus N:M
  crossmapping and common-defect cases. JSON Schema (draft-07) for control/mapping/defect,
  a stdlib+PyYAML `validate.py` (schema + cross-reference integrity), a full-skeleton
  generator, and a YAML→JSON build (`src/mori_soc/data/controls_catalog.json`, a committed
  runtime artifact so the image needs no PyYAML).
- **Catalog→DB sync** (`schema/007`, bilingual `controls`/`control_mappings`/`control_defects`)
  run best-effort on app boot (`services/control_catalog.py`).
- **Per-control evidence-pack PDF** (evidence mapper) — `GET /controls/detail/{id}` +
  `.../evidence.pdf`: joins a control to its cross-mappings, related defects, and the
  **current live evidence-gap counts**, rendered as a one-click PDF (📄 per control in the
  tree). **58 controls** enriched to `reviewed`; crossmappings grown 7 → **61** (coverage
  lite ~24% / full ~30% — the honest ceiling for 5 technical sources; policy/HR/physical/
  privacy controls are documentary-evidence territory and are not force-mapped).
- **Catalog CI** (`.github/workflows/test.yml`) — a `catalog` job runs `controls/validate.py`
  and fails if the committed `controls_catalog.json` is stale vs the YAML.
- **Control-tree screen** — dashboard "Control catalog" card (admin·security),
  framework→domain→section tree with **auto-derived lite/full coverage %** (`GET /controls/tree`).
- **Evidence-gap "today's work queue"** dashboard card (admin·security) —
  unremediated Critical/High · exceptions expiring (D-7) · untriaged alerts · overdue ·
  controls pending · **unmapped assets (Zabbix×Fleet×Trivy reconciliation)**
  (`GET /dashboard/evidence-gaps`). Common defects link to these tiles via `mori_signal`.

- **Live evidence mapper** — clicking a control in the tree fetches per-source **live
  data** (Trivy open CVEs, Zabbix/Wazuh recent alerts + monitored hosts, Fleet assets,
  MORI incidents/risk/audit) shown inline and in the evidence-pack PDF, with a deep-link to
  the relevant tab. Turns "mapped" into "here is this much real evidence right now."
  Includes a **host↔control breakdown** (which asset holds the evidence, e.g.
  `onboard-web-01: C1·H1`) inline and in the PDF.

### Changed
- Bilingual (KO/EN) coverage extended across the catalog, `controls/README`,
  `docs/BROWNFIELD_CONNECT`, and the README roadmap (Fleet reframed as "foundation work").
- Removed the CSOP evidence-events UI card (the `/ingest`·`/evidence` APIs remain).

## [v0.7.0-alpha.1] — 2026-07-07 — CSOP Evidence Ingest + Brownfield Mode

### Added
- **CSOP evidence ingest** (`POST /ingest/evidence`): remote scanners/agents push a
  "before/after" diff envelope (`delta_type` new/fixed/reopened) — persisted verbatim as
  JSONB in `ui_evidence_events` (`schema/006`) with extracted `host_id`/`artifact_name`/
  `delta_type`/`cve`/`summary` for filtering. Accepts a single envelope or `{"events":[…]}`.
- **Evidence read API** (`GET /evidence`): newest-first list with `host`/`delta` filters,
  gated to **admin·security** roles (same visibility policy as the risk register).
- **Trivy ingest host↔image mapping**: `POST /ingest/trivy` now accepts a hostname via
  `?hostname=` / `X-MORI-Hostname` header / body `hostname`, so image scans
  (`ArtifactName=alpine:3.19`) bind to the real Zabbix/Fleet host instead of the artifact
  name. Backward-compatible (omit → previous ArtifactName derivation).
- **Brownfield mode**: bundled Zabbix/Fleet/Wazuh stacks moved behind compose profiles
  (`bundled`, and per-source `zabbix`/`fleet`/`wazuh`). `docker compose up` now starts
  **MORI core only** (api + worker + postgres + dashboards) and connects to existing
  infrastructure via `.env`. `docs/BROWNFIELD_CONNECT.md` guide added; `.env.example`
  gains a brownfield source-connection block + Fleet/Wazuh API scaffolding vars.

### Changed
- `MORI_INGEST_TOKEN` and `MORI_ADMIN_PASSWORD` are now passed through to the `mori-api`
  container (were defined but never wired) — token-based ingest works without a login
  session, and the admin password is configurable from `.env`.
- Session-auth middleware bypasses `/ingest/*` so the endpoints' own token-or-session auth
  governs remote pushes (previously the middleware blocked token pushes when auth was on).
- `mori-worker` / `mori-poller-zabbix` no longer hard-depend on the bundled `zabbix-web`
  (they retry the source each cycle) — required for pointing at an external Zabbix.

### Security
- Default `MORI_ADMIN_PASSWORD` replaced in `.env` with a strong value; `/health`
  `insecure_defaults` no longer flags it.

## [v0.6.0-alpha.1] — 2026-07-07 — Zabbix Evidence Flow + Risk Register

### Added
- **Zabbix evidence flow (verified end-to-end against the real Zabbix API)**: problem →
  `mori-worker` `problem.get` polling → PostgreSQL `alerts` → Alert Triage (`source=zabbix`)
  → Incident → CSV/PDF evidence → **resolve** (Zabbix recovery → `alert.resolved_at`).
- **Risk assessment (R-series)**: per-CVE 3×3 impact × likelihood matrix, treatment
  decision (mitigate/accept/transfer/avoid), residual risk, admin-only provenance panel,
  role-gated (admin/security). Persisted in `ui_risk_register` (`schema/004`).
  Risk Register CSV/PDF report (6th audit-evidence report).
- **Role-aware dashboard**: security hero + 24h/12h infra status with Zabbix/Wazuh deep
  links; panel editing (per-user widget on/off + drag-resize, persisted).
- **Compliance PDCA** on real ISMS-P criteria (2.x controls); weakness-rate summary.
- **Trivy HTTP ingest** (`POST /ingest/trivy`) for remote endpoints; token auth.
- **Onboarding**: `mori-endpoint-onboard.sh` (Zabbix Agent 2 + Trivy, one-command/curl),
  `mori-zabbix-template.sh` (MORI Zabbix template with LLD + macros; exported YAML),
  `mori-community-pr.sh` (assemble a zabbix/community-templates PR).
- **CI**: GitHub Actions `tests` workflow (ruff + unittest); deploy workflow hardened to
  skip gracefully when deploy secrets are absent.
- **Docs**: Zabbix agent, deploy SSH, Fleet, Wazuh, community-template PR guides;
  `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- Alert `resolved_at` (`schema/005`), Zabbix ↔ Alert Triage bidirectional URL links.

### Changed
- Dashboard reads PostgreSQL **live per request** (postgres backend) — worker-ingested
  data surfaces with no API restart.
- READMEs (KO/EN) reworked: 30-second Status table; demo security notice; Zabbix marked
  **verified**, Fleet/Wazuh **Next**, Trivy **partial**.

### Removed
- Removed the public demo-server URL/credentials block and internal "resume prompt" from
  the README.

## [v0.5.0-alpha.2] — Core Structure Stabilization
- `server.py` modularized into `routes/` (16 domain modules) + `RouteContext`.
- Prepared Phase 2 PostgreSQL persistence (M2-1) foundation.

## [v0.4.0-alpha.1]
- Initial audit-ready operations UI, seed data, compliance/reporting scaffolding.
