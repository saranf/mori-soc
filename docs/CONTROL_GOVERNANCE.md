# 통제 운영 플랫폼 (Control-to-Evidence Operating System)

MORI 를 "ISMS-P 체크리스트"가 아니라 **기준 버전·조직 통제·적용 범위·증적 요구·기술 수집 규칙·
사람의 판단을 시간축으로 연결하는 통제 운영 플랫폼**으로 확장한 기능(통제 신규 에픽).

## 1. 왜 모리다운가

통제가 바뀜 → 영향받는 조직 통제 식별 → 영향받는 기술 증적 규칙 식별 → 새 증적 수집 → 사람이
검토 → 새 기준으로 승인 → **과거 기준과 증적은 그대로 재현**. 기술 현실과 관리체계의 주장을
시간축 위에서 연결·검증하고, 사람의 판단을 감사 증적으로 남긴다.

## 2. 핵심 원칙

- **버전 불변**: FrameworkVersion·ControlDefinition·OrganizationControl·EvidenceContract 는
  덮어쓰지 않고 새 버전으로 쌓는다. active/retired 버전 편집은 409. `supersedes`로 계보를 잇는다.
- **해석 층 분리**: `official`·`mori_summary`·`org_interpretation`·`operation_guide` 를 한 필드에
  섞지 않는다(ControlDefinition.interpretations).
- **증적 상태 ≠ 통제 평가 상태**: `evidence_status`(missing…approved) 와
  `assessment_status`(not_assessed…effective)는 별도 필드. 증적 approved 여도 평가 effective 아님.
- **자동 승계 금지**: 새 운영주기는 담당자·적용성·매핑만 승계하고 평가·승인·과거증적은 초기화.
- **AI 는 후보만**: diff·매핑·영향은 후보 제안, 사람이 확정(모리다움).

## 3. 객체 (Phase 1~2)

| 객체 | 설명 |
|---|---|
| Framework | 외부 기준 그 자체(ISMS-P·ISO 27001·개인정보보호법…) |
| FrameworkVersion | 특정 시점 버전(불변·content_hash·supersedes·status draft/active/retired) |
| ControlDefinition | 버전 안 통제(control_uid 계보 + display_code 분리 + 해석층) |
| ControlRelationship | 통제 계보 그래프(same_as·replaces·split_into·merged_from… + coverage_percent=담당자판단) |
| OrganizationControl | 회사 내부통제(여러 외부기준 동시 충족, mapped_controls) |
| ScopeSnapshot | 운영주기별 인증범위 고정(불변) |
| AssuranceCycle | 연도·기간별 운영 인스턴스 |
| CycleControl | 주기 안 통제 인스턴스(증적/평가 분리, append-only history, as-of) |
| EvidenceContract | 통제별 필요 증적 정의(버전관리, 증적에 계약버전 각인) |
| EvidenceMapping | 통제 ↔ 기술 소스(valid_from/valid_to) |

저장: `(kind, entity_id)` 네임스페이스 1테이블(`ui_control_governance`, schema 017),
state repo 3메서드(load/save/delete_governance — base no-op·memory·postgres).

## 4. 버전 영향분석 (Phase 3)

- **버전 diff**: `GET /governance/framework-versions/{id}/compare?to=` — control_uid 기준
  신규·삭제·번호변경(renumbered)·실질 변경(text_changed) 후보. AI 확정 아님.
- **운영주기 마이그레이션**: `POST /assurance-cycles/{id}/initialize-from/{prev}` — 담당자·적용성
  승계 / 증적·평가 초기화.

## 5. 감사 실사용 · 다중기준 (Phase 4~5)

- **as-of 재현**: `GET /assurance-cycles/{id}/audit-snapshot?date=` — 감사 기준일의 주기 전체 상태를
  history 재생으로 복원(+범위 스냅샷 고정). 통제 단위는 `/cycle-controls/{id}/as-of`.
- **crosswalk**: `GET /governance/crosswalk` — 내부통제의 mapped_controls 를 외부기준별로 묶어
  같은 증적을 여러 인증에서 재사용.
- **Base + Overlay**: `POST /governance/controls/{id}/overlay-view` — 기준 통제(base 불변)에 조직
  오버레이(담당·주기·범위·증적·승인자)를 얹은 뷰. base 내용 변경 시 conflict 표시.

## 6. API 요약 (`/governance/*`, 모두 admin·security)

```
POST /frameworks · /framework-versions (+/activate +/retire) · /control-definitions
POST /relationships · /organization-controls · /scope-snapshots · /assurance-cycles
POST /evidence-contracts · /evidence-mappings · /cycle-controls (+/{id}/update)
GET  /frameworks/{id}/versions · /framework-versions/{id}/controls · /relationships
GET  /framework-versions/{id}/compare?to= · /crosswalk
GET  /assurance-cycles/{id}/controls · /audit-snapshot · /cycle-controls/{id}/as-of
POST /assurance-cycles/{id}/initialize-from/{prev} · /controls/{id}/overlay-view
```

## 6-1. 감사 무결성 강화 (S1–S4)

리뷰가 지적한 "강한 단어(불변·append-only·시점 재현) vs 실제 구현" 격차를 감사급으로 좁힘.

- **content_hash 안정성(S1a)**: 해시는 lifecycle 메타(status·activated_at·effective_to·lifecycle·
  history) 를 제외한 **실질 내용**만 대상. activate/retire 후에도 지문 불변. 상태 전환은
  `lifecycle[]` 이벤트로 append.
- **as-of 정확성(S1b)**: CycleControl 최초 history 에 초기 assignee/applicability 를 `changed` 로
  기록 → 생성 시점 상태를 정확히 재현.
- **버전 상태기계(S1c)**: `draft→active→retired` 만(`can_version_transition`). framework 당 active
  1개, 재활성 금지, 시행기간 겹침 거부.
- **참조 무결성(S1d)**: cycle→framework_version/scope, contract·mapping→organization_control,
  cycle_control→cycle/control, relationship source·target 실재 검증(dangling 금지).
- **입력 검증(S1e)**: coverage 0~100·비숫자 400(500 아님)·자기참조·중복 관계·중복 매핑 버전 거부.
- **no-op 방지(S1f)**: 값 변화 없는 갱신은 history 를 남기지 않음(`_no_op`).
- **진짜 마이그레이션(S2)**: `plan_cycle_migration` 이 version diff 계보로 번호변경=새 참조 이관·
  내용변경=재설계검토·삭제=removed·신규=생성. 운영설정 승계 / 증적·평가 초기화 +
  `carried_from_control_ref`·`migration_reason`·`requires_design_review` 계보 기록.
- **append-only 이벤트 원장(S3)**: `ui_control_governance` 는 projection, `ui_control_governance_events`
  (schema 018)가 진짜 변경 이력. 모든 저장이 `(revision·event_type·actor·payload·prev_hash·hash)`
  이벤트를 append — 감사로그와 동일 **hash chain** 으로 변조·삭제·재배열 검증
  (`GET /governance/events/verify`).
- **실 Postgres E2E(S4)**: 2019 등록→2025 운영→2023 버전변경→2026 이관→**재시작**→객체·이벤트·
  history 보존·chain 무결·as-of 재현까지 실 DB 로 검증.

## 6-2. 이중 모델 브리지 (C6)

기존 통제 카탈로그(`controls`/`control_status`/`control_evidence`, 194개)와 새 governance 모델
(017/018)이 공존하면 **정본이 둘**이 된다. C6 은 정본을 하나로 모으기 위한 **일방 흡수 경로**:

- `plan_catalog_import(controls)` — 카탈로그를 프레임워크·버전별 FrameworkVersion + ControlDefinition
  으로 변환. 카탈로그의 intent/evidence_hint 는 MORI 해석이므로 `mori_summary`·`operation_guide`
  층에 넣고, **공식 원문(official)은 비워 둔다**(원문은 사용자 import — 라이선스·정직).
- `POST /governance/import-catalog?framework=` — 흡수 실행(idempotent, 이미 있는 건 건너뜀).
- 방향: 기존 카탈로그는 당분간 운영 화면으로 유지하되, governance 가 **버전·계보를 갖는 상위 모델**
  로서 이를 흡수한다. 양쪽 동시 개발이 아니라 한쪽(governance)으로 수렴.

## 6-3. 저장 정규화 (2차 리뷰 #4, 진행 중)

범용 `ui_control_governance` (kind,entity_id) 스토어는 FK·unique·기간겹침을 DB 로 못 막는다.
핵심 계보를 정규 테이블(schema 019)로 빼서 **DB 가 무결성을 강제**한다.

- **1차(완료)**: `gov_frameworks` · `gov_framework_versions` · `gov_control_definitions`.
  - FK: version→framework, control→version (`ON DELETE RESTRICT` — 하위 있는데 상위 삭제 금지).
  - UNIQUE: (framework_id, version), (framework_version_id, display_code).
  - CHECK: status ∈ draft/active/retired. **부분 유니크 인덱스**로 framework 당 active 1개 보장.
  - 관계·무결성은 관계형 컬럼, **전체 레코드 원본은 metadata JSONB** → 앱은 정확히 같은 dict 를
    돌려받는다(round-trip). Postgres repo 의 save/load_governance 가 kind 로 dispatch.
  - 구 범용 스토어 → 정규 테이블 **일회성 backfill**(FK 순서, 성공분만 삭제, 실패는 원본 보존+로그).
- **2차(완료)**: `gov_organization_controls`(UNIQUE code+version) · `gov_evidence_contracts`
  (FK org_control, UNIQUE org+version) · `gov_evidence_mappings`(FK org_control) ·
  `gov_scope_snapshots` · `gov_control_relationships`(coverage 0~100 CHECK·자기참조 CHECK·
  source+target+type UNIQUE). schema 020, 동일 dispatch·backfill(FK 순서) 패턴.
- **3차(완료)**: `gov_assurance_cycles`(FK framework_version·nullable FK scope_snapshot) →
  `gov_cycle_controls`(FK cycle). cycle_control.control_ref 는 통제정의/내부통제 이중 대상이라
  FK 없이 서비스층 검증. nullable FK 빈 문자열은 NULL 저장. schema 021.
- **완결**: 10개 거버넌스 객체 전부 정규 테이블 + DB 제약(FK·UNIQUE·CHECK·부분유니크). 원본은
  metadata JSONB 로 정확 round-trip, 구 범용 스토어→정규 backfill(FK 순서·실패보존). in-memory 는
  dict 유지(단일 테넌트).

## 7. 검증 상태

- 유닛/라우트: `tests/test_control_governance.py` — content_hash 불변성·해석층 분리·버전 diff·
  운영주기 승계·증적/평가 분리·as-of 재현·crosswalk·overlay conflict. 그린.
- 순수 함수(빌더·diff·as-of·crosswalk·overlay) I/O 없음. 영속은 in-memory/postgres 양쪽 지원.
