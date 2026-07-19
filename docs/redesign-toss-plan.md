# MORI UI 토스 스타일 전면 개편 계획

> 대상: 프로토타입 <https://claude.ai/code/artifact/b46e8496-a469-4f4e-ada8-aa5c17d64e5b> 의 디자인 언어를 MORI 전체(13뷰)에 적용.
> 작성 기준일: 2026-07-20. 상태: **초안 — Phase 0 결정 대기**.

---

## 0. 지금 구조 vs 프로토타입 (왜 "그냥 CSS 교체"가 아닌가)

| 축 | 현재 MORI | 프로토타입 | 개편 난이도 |
|---|---|---|---|
| IA/내비 | 페이지별 서버렌더(dashboard·console·login 각 완결 HTML) + **상단 top-tab** | **좌측 레일 단일 셸**에서 13뷰 클라이언트 전환 | 높음 (라우팅·RBAC 영향) |
| 스타일 소스 | `:root` 토큰 + **인라인 311개 하드코드 hex** + JS(dashboard.js 376KB·console.js 124KB) 안의 `style="color:#…"` | 토큰 + 컴포넌트 클래스, 인라인 최소 | 높음 (대부분이 인라인/JS에 박힘) |
| i18n | `data-i18n` 키 **407개**를 JS `tt(key,fallback)`가 치환 | chrome만 data-en 토글(데모 수준) | 중 (새 마크업마다 키 필요) |
| 테마 | **라이트 고정**(`color-scheme:light only`) — 기존 가드레일 | 다크/라이트 토큰 양쪽 | 결정 필요 (가드레일 충돌) |
| 팔레트 | 6색, 파랑 `#2563eb` | 토스 hex(`#3182f6·#f04452·#15c47e…`) | 낮음 (토큰 값 교체) |

**결론:** 시각 대부분이 인라인·JS에 흩어져 있어 토큰 교체만으론 안 닿는다. 개편의 척추는 **① 공용 토큰·컴포넌트 레이어 단일화 → ② 인라인/JS 인라인을 클래스로 흡수 → ③ 화면별 토스 레이아웃**. IA(좌측 레일) 전환은 분리된 선택 트랙.

---

## Phase 0 — 방향 확정 (코드 전 결정 3건)

작은 결정이 뒤 단계를 크게 가른다. **권장값**을 함께 표기.

1. **IA 전환 범위** — (A) 시각 언어만 채택, 현 top-tab/route/RBAC 유지 · (B) 좌측 레일 단일 셸까지.
   → **권장 A 먼저**. 레일은 Phase 4 선택 트랙(라우팅·RBAC 재배선 리스크 격리).
2. **다크모드** — 프로토타입은 다크 포함, 현재는 "라이트 고정"이 **명문 가드레일**.
   → **권장: 이번 개편에선 라이트 유지**, 다크는 별도 에픽. (뒤집을 거면 여기서 명시적으로.)
3. **팔레트 hex 교체** — 6색을 토스 값으로 중앙 교체(`2563eb→3182f6`, 위험 `dc2626→f04452`, 완료 `16a34a→15c47e`, 주의 `ca8a04→f5a623`).
   → **권장 교체**. 6색 규율(색=상태)은 유지, 값만 토스로. 단 배지 알파·대비 재검증.

---

## Phase 1 — 토큰·컴포넌트 단일화 (기반, 시각 회귀 0)

목표: 프로토타입 컴포넌트를 **공용 CSS 레이어**로 이식하되 기존 화면은 안 깨지게(클래스 추가만).

- `static/css/tokens.css` 신설 — 토스 값 토큰 단일 소스. dashboard.css·console.css의 중복 `:root` 제거하고 여기서 import.
- `static/css/components.css` 신설 — 프로토타입 컴포넌트 이식: `.kpi`(빅넘버) · `.card`(소프트섀도 20px) · `.chip`(상태색) · `.ring`(준비율 도넛) · `.bar`(진행) · `.lrow`(분류/인시던트 행) · `.srcrow`(소스 LED) · `.sw`(토글) · `.nav`(레일, Phase 4용 미리) · 토스 그레이 배경 `#f2f4f6`.
- dashboard.css/console.css 중복(예: `.mori-strip` 양쪽 정의, `.amber` 누락) 정리 → 단일화.
- **산출 게이트:** 기존 test_dashboard_render·test_console_render 그린 유지(마크업 미변경).

## Phase 2 — 인라인/JS 인라인 → 클래스 흡수 (실작업의 대부분)

목표: 311개 인라인 + JS 생성 HTML의 `style="color:#…"`를 컴포넌트 클래스/`var()`로 교체. **페이지 단위**로.

- 정적 템플릿(`templates/*.py`, `screens/*.py`): 하드코드 hex 인라인 → 클래스. `.u-ink/.u-blue` 유틸 최소 도입.
- 동적 JS(`static/js/dashboard.js`·`console.js`): `renderTable`류가 뿜는 인라인 색을 클래스로. (여기가 숨은 대부분 — CSS만으론 못 고침.)
- **불변식:** 모든 교체 마크업에 기존 `data-i18n` 키 보존 → 한영 토글 유지.
- **게이트:** 화면 교체마다 해당 render 테스트 + `_scan_i18n_gaps.py` 그린.

## Phase 3 — 화면별 토스 레이아웃 (13뷰, "한눈에")

순서(리스크 낮은 것 먼저): 로그인 → 사용자 대시보드 → 알림분류 → 자산 → 심사준비 → 인시던트 → 가이드 → 콘솔 현황 → 조치 → 자산·담당자 → 권한 → 감사로그 → 설정.

- 각 뷰 = **KPI 빅넘버 행 + 2열(표/카드)**, 세로 스크롤 최소화(프로토타입 각 패널 규격 준용).
- 상단 top-tab은 유지하되 토스 슬림 스타일로. 모바일은 기존 하단탭 재사용(구조 유지).
- RBAC 가시성 유지: 위험성 평가·통제는 admin·security 전용 뷰([[role-visibility-policy]]).

## Phase 4 — (선택) 좌측 레일 셸 + 반응형 폰 + 테마

Phase 0에서 B/다크를 택했을 때만.

- 좌측 레일 단일 셸: RBAC로 뷰 필터(security-only 숨김), 라우트→뷰 매핑 재배선.
- 모바일 폰 리플로우 정리, (택했다면) 다크 토글 + 라이트고정 가드레일 갱신.

## Phase 5 — 회귀·정직성·문서 (매 Phase 말미 반복)

- 테스트: test_dashboard_render · test_console_render · test_secure_boot · test_scale_smoke + 라우트 baseline(`_routes_baseline.json`) 그린.
- 정직성 유지: 준비율은 검토완료+증적연결만 집계(부풀리기 금지), draft 라벨 유지([[mori-identity]]).
- 문서: CHANGELOG, README 스크린샷(`docs/images/`) 갱신, i18n gap 0.
- 커밋: 내가 건드린 hunk만 스테이징, 동시편집 액터 주의([[commit-scope]]·[[concurrent-git-staging-hazard]]), Claude 트레일러 금지([[commit-style]]).

---

## 리스크 · 가정

- ⚠️ **다크모드 = 기존 가드레일 충돌** — Phase 0-2에서 명시 결정 없이는 라이트 유지(기본).
- ⚠️ **시각의 대부분이 JS 376KB 안 인라인** — CSS 토큰 교체만으로 "바뀐 것처럼" 보이지만 실제 화면은 안 바뀜. Phase 2가 진짜 작업.
- ⚠️ **IA 전환(좌측 레일)은 RBAC·라우팅 재배선** — 시각 개편과 분리해 리스크 격리(Phase 4).
- 팔레트 hex 교체 시 배지 배경 알파·대비(WCAG) 재검증 필요.
- 프로토타입 폰트는 시스템 스택 — Pretendard 임베드는 별도(용량 트레이드오프).

## 추천 착수 슬라이스 (첫 PR)

**로그인 + 사용자 대시보드 1화면**을 Phase 1+2+3 수직 관통으로 먼저 완성 → 토스 방향을 실화면·실데이터·한영·테스트그린으로 검증한 뒤 나머지 12뷰 확산. (되돌리기 쉽고 방향 합의에 가장 레버리지 큼.)

---

## 진행 현황 (2026-07-20)

| 슬라이스 | 상태 | 커밋 |
|---|---|---|
| 전 UI 팔레트·컴포넌트 토스 이관(CSS 재작성 + JS/템플릿 hex 스윕) | ✅ | 181de41 |
| 증적 PDF 팔레트 토스화 + Swagger 기능별 분류 + 심사링 상시표시 | ✅ | 0ca6fd8 |
| 뷰별 "한눈에" 레이아웃 재구성(마크업/JS 렌더러) | ⬜ 대기 | — |

---

## 추가 표면 A — 개인정보/증적 PDF 아웃풋

- **엔진**: ReportLab(프로그램 생성, HTML 아님). 팔레트가 `services/pdf.py` 한 곳(공용 프리미티브)에 집중.
- **완료**: `pdf.py·data_flow.py·soa.py` 팔레트를 토스 중성색으로. 개인정보 흐름표 SVG 6색 의미매핑(수집파·저장초·이용노·파기빨) 보존. PDF 색 검증 테스트 없어 안전.
- **남은 깊이작업**: 표 헤더/여백/타이포를 토스 문서 레이아웃으로(요약카드 상단, 흐름 라이프사이클 바, 외부수신자 구분). ReportLab이라 레이아웃 변경은 코드 작업 — `docs` 목업 참고. reportlab 설치 테스트 환경에서 PDF 바이트 생성 스모크 필요.

## 추가 표면 B — Swagger / OpenAPI (기능별 분류)

- **현황**: 엔드포인트엔 이미 `tags=`(Compliance 46·Governance 32·Privacy 28·Admin 18·Accounts 15·Sources 11·Assets 8·Vuln 7·Auth 7·Incidents 4·Alerts 4·Health 3·Settings 2·Zabbix/Trivy/Fleet 각 1).
- **완료**: `server.py`에 `openapi_tags` 16개 그룹 **설명+논리순서**(핵심 통제·증적 → 버티컬 → 증적소스 → 운영) + `swagger_ui_parameters`(docExpansion none·filter). 순수 메타라 부팅 안전.
- **남은 깊이작업(부팅 안전상 보류)**: 토스 테마 `/docs` — `docs_url=None` + `get_swagger_ui_html` 커스텀 라우트 + 토스 CSS 주입. **이 환경엔 fastapi 미설치라 라우트 배선 런타임 검증 불가 → 테스트 환경에서 진행.** 태그 일관화(code-review 엔드포인트가 Sources/Compliance로 갈림 정리).

## 남은 큰 덩어리 — 뷰별 "한눈에" IA 재구성 (Phase 3 본체)

색은 끝났고, "토스답게" = **정보설계**(요약 먼저·상세 접기·큰 숫자·여백)라 **탭마다 마크업/JS 렌더러를 다시 짜야** 함. 각 뷰가 **무엇을 앞세우고 무엇을 접을지**는 제품 판단이 필요 → 뷰 단위로 목업 합의 후 실装. 심사 준비 히어로(링 상시표시)가 첫 스텝.

**제약**: 이 개발 환경엔 **fastapi·reportlab·pytest·브라우저 미설치** → create_app 런타임·PDF 생성·실화면 눈검증 불가. 정적 렌더 스모크 + compileall로만 검증 중. 실검증은 `docker compose up` 또는 테스트 환경 필요.
