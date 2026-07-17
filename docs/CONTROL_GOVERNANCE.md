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

## 7. 검증 상태

- 유닛/라우트: `tests/test_control_governance.py` — content_hash 불변성·해석층 분리·버전 diff·
  운영주기 승계·증적/평가 분리·as-of 재현·crosswalk·overlay conflict. 그린.
- 순수 함수(빌더·diff·as-of·crosswalk·overlay) I/O 없음. 영속은 in-memory/postgres 양쪽 지원.
