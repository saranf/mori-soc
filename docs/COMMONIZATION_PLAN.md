# MORI 공통화(共通化) 계획

전체 코드베이스(~30k Python + ~7.4k JS)를 5개 층으로 정독해 도출한 중복 제거·공통화 계획.
모리다움 가드레일 중 하나(**공통화**)의 실행 문서다. "이미 만든 공용(render_csv·pdf_table·RouteContext.require_role·write_bundle_with_manifest)을 안 쓰고 중복인 곳"을 마저 정리하고, 새 공용 지점을 추가한다.

> 상태 표기: ☐ 미착수 · ◐ 부분 · ☑ 완료. 발견 시점 2026-07-20.

## 요약 — 우선순위(심각도×영향범위)

| # | 클러스터 | 층 | 성격 | 우선순위 |
|---|----------|-----|------|:--:|
| C1 ☑ | content_hash / canonicalization 3중 구현 | services | **정합성(감사)** | CRITICAL·전역 |
| C2 ☑ | CSV가 공용 render_csv 우회 → 수식 인젝션 미방어 | routes+services | **보안** | CRITICAL·전역 |
| C3 ☑ | RBAC 역할추출·403 인라인 중복(공용 ctx 미채택) | routes | **보안** | CRITICAL·전역 |
| C4 | i18n 중복키·ko 블록에 영문 혼입(triplicated) | i18n | **정합성(한영)** | MAJOR·전역 |
| C5 | ReportLab 문서 스캐폴딩·팔레트 재정의 | services | DRY·시각드리프트 | MAJOR·전역 |
| C6 | PDF/ZIP/format 응답 셰이핑 반복 | routes | DRY | MAJOR·전역 |
| C7 | Postgres 커넥션·upsert·컬럼목록 보일러플레이트 | repositories | DRY | MAJOR·전역 |
| C8 | 프론트 공용 모듈 부재(dashboard↔console 바이트동일) | JS/CSS | DRY·유지비 | MAJOR·전역 |
| C9 | 콜렉터 helper(str/id/time/severity)·Zabbix transport 중복 | collectors | DRY | MAJOR·국소 |
| C10 | poller 임계치 프로퍼티 20종 재오버라이드 | pollers | DRY | MINOR·국소 |
| C11 | text 유틸(esc·coerce·parse_iso·group_by) 산재 | services | DRY | MINOR·전역 |
| C12 | 인메모리/템플릿/payloads 미세 중복 | repo/templates | DRY | MINOR·국소 |

---

## 신설/확장할 공용 모듈 (착지점)

**신설**
- `services/hashing.py` — `canonical_json`, `content_hash(obj,*,exclude,prefix)`, `short_id(prefix,*parts)`; `CANONICALIZATION` 상수 단일화 (C1)
- `services/text_utils.py` — `esc`(html.escape), `coerce_str`, `append_unique`, `parse_iso`, `collapse_ws`, `norm_term`, `group_by_ordered` (C11)
- `api/http_helpers.py` — `pdf_response`, `pdf_response_or_503`, `call_or_503`, `export_response(fmt,…)` (C6)
- `repositories/_pg_common.py` — `PSYCOPG_AVAILABLE`·`Jsonb`·`_jsonb`·`_cursor()/_txn()` + 범용 `_upsert(table,pk,cols,rec,jsonb_cols,now_cols)`/`_select_map` (C7)
- `collectors/_helpers.py`·`_identity.py`·`envelopes.py`·`http.py`·`severity.py` (C9)
- `mori_soc/_env.py` — `env_flag`, `split_csv_env` (C9/C10)
- `static/js/common.js` — palette·escapeHtml·formatTime·tt·Paginator·`api.*`·renderTable·chip·sevColor/statusColor·toast·openModal (C8)
- `static/css/tokens.css` — `:root` 팔레트 + `.card/.badge/.table/.metric*` 프리미티브 (C8)

**확장**
- `services/pdf.py` — `new_doc(buf,*,landscape,margins)`·`default_table_style()`·`PALETTE` 노출 (C5)
- `services/csv_export.py` — `csv_text_response(text,prefix)`·다중섹션 writer(셀마다 `_defuse`) (C2)
- `services/evidence_bundle.py` — `zip_bundle_response(files,*,filename,extra)` (C6)
- `api/routes/context.py`(RouteContext) — `require_admin_or_security`·`require_ingest_token`·`resolve_host_key`·`persisted_write`/`save_control_evidence` (C2/C3)
- `pollers/base.py` — 클래스레벨 `DEFAULT_*` → 서브클래스 프로퍼티 20종 삭제 (C10)
- i18n — key-major `TRANSLATIONS: {key:(ko,en)}` + import시 중복키/공백 파리티 가드 (C4)

---

## 실행 단계 (ROI·위험 기준)

### Phase 1 — 정합성·보안 먼저 (CRITICAL/MAJOR, 저위험)
- **C1 ☑ 완료** `services/hashing.py` 신설(`canonical_json`·`sha256_hex`·`content_hash`·`short_id`, `CANONICALIZATION` 단일화). 3개 content_hash(evidence·control_governance·evidence_bundle) + short-id 6곳(provenance·evidence_approval·control_governance rel-·gap_workflow·normalization alias-/scoped) 통합, 중복 삭제. **기존 공식과 바이트 동일 출력**을 `tests/test_hashing.py`로 고정(감사 해시 무드리프트). 496 통과·mypy 게이트 clean.
- **C2 ☑ 완료** csv_export 에 `SafeWriter`/`SafeDictWriter`/`safe_writer`/`safe_dict_writer`/`defuse_cell`/`csv_text_response` 추가(fastapi 임포트는 지연화 → 순수 서비스도 안전 임포트). 손수 CSV 전수 전환: reports.py(6빌더)·control_catalog(2)·soa·query_service → safe writer; routes sources(trivy)·incidents·accounts_gov(계정명!)·compliance(evidence/SoA/report/PDCA/INDEX) → csv_streaming_response/csv_text_response/safe_writer. **모든 감사 CSV 셀이 이제 무력화**(계정명·finding·호스트명 인젝션 갭 폐쇄). 미사용 `import csv/io` 삭제. 506 통과.
- **C3 ☑ 완료** `ctx.require_admin_or_security` 추가 + `ctx.session` 을 request=None 안전화. 로컬 쿠키파싱 헬퍼 정리: sources(`_session_role` 삭제, 인라인 403 6곳→ctx), assets(삭제), audit(`_session_role` 삭제·username→ctx), settings(`_role` 삭제·username 위임), compliance(`_evidence_role`/`_require_ev`→ctx 위임, 25 호출부 유지). authz 로직 단일화(‘not in’/‘!=’ 발산 제거). test_route_context 추가, 500 통과·mypy 게이트 clean.
- **C4** i18n 중복키 가드(중복 시 raise하는 dict 서브클래스) 도입 + `dash.acc.*` triplicated 정리. **선(先) 가드로 회귀 방지**, 후(後) tuple 레이아웃 전환.

### Phase 2 — 구조 백엔드 (MAJOR)
- **C5** `pdf.py` `new_doc`/`PALETTE` → `reports.py:595`·`control_catalog.py:279/455`·`data_flow.py:1122`·`soa.py:84` 스캐폴딩·팔레트 흡수(슬레이트/토스 색 드리프트도 해소).
- **C6** `http_helpers`·`zip_bundle_response`로 PDF 4곳·ZIP 3곳·format 분기 2곳 통일.
- **C7** `_pg_common` + `_NORMALIZED_GOV`가 이미 증명한 spec 방식을 전 store로 일반화(save/load 15쌍), `postgres.py` isinstance 250줄 → 레지스트리, 인메모리 store 테이블화.

### Phase 3 — 콜렉터·폴러 (MAJOR·국소)
- **C9** `collectors/_helpers`·`_identity`·`envelopes`·`http`·`severity`로 `_str`/`_make_id`/시각파싱/severity/shared-IP 5~6중 중복 제거. `zabbix_transport.py` TODO대로 콜렉터가 transport 사용.
- **C10** poller `DEFAULT_*` 클래스레벨화 + `pollers/__main__.py`; `_env_flag` 2곳 → `_env.py`.

### Phase 4 — 프론트 (MAJOR·전역, 무동작변경)
- **C8** `common.js` 추출(escapeHtml·formatTime·tt·Paginator·`api.*`·renderTable·chip·color-map·toast) → dashboard↔console 바이트동일 블록 제거. CSV는 `openCsvPreview`+`_parseSimpleCsv`+`downloadTextFile` 공용화 후 낙오 다운로드 5곳 편입(대기중이던 CSV 통일 완료). `tokens.css` 팔레트/프리미티브 공유.

---

## 발견된 실버그(공통화 착수 시 동시 수정)

- **i18n 중복키(last-wins로 은폐):** ko 대시보드 리터럴 내 63키, ko 어드민 174키 중복 — 어드민 ko dict에 영문 전체 사본이 섞임. `dash.acc.title`이 `i18n.py:687/717/1312` 3곳. → C4 가드가 잡아냄.
- **수식 인젝션 갭:** `render_csv._defuse`를 우회하는 reports/control_catalog/soa/accounts CSV. → C2.
- **canonicalization 불일치:** 두 `CANONICALIZATION` 상수·화이트리스트 vs 블랙리스트 해시. → C1.
- **팔레트 시각 드리프트:** `pdf.py`(토스 `#e5e8eb/#191f28`) vs `reports.py`/`control_catalog.py`(슬레이트 `#1e293b/#cbd5e1`). → C5.
- **프론트 페이저 라벨 하드코딩:** 이전/다음이 `tt()` 미경유. dashboard.js `sevColor` 2회 선언(1641/1751). → C8.

## 비적용(과공통화 경계)
- `state_base.py` ABC는 타이핑 위해 명시 유지(생성 안 함).
- provenance는 이미 `provenance.py` 단일소스 — 손대지 않음.
- payloads.py엔 pydantic 모델 없음(순수 빌더) — 상속 리팩터 대상 아님.
