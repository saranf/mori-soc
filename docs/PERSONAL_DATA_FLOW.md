# 개인정보 처리흐름표/흐름도 (ISMS-P 3.x) — PII 탐지 연계

MORI의 개인정보 증적 도구. **수집→저장→이용→파기** 흐름과 저장위치(DB/테이블)를
기록·시각화하고 ISMS-P 3.x 통제 증적으로 승격한다. MORI는 코드를 읽지 않는다
(증적 층 원칙) — 후보 행은 **스캔(고객 CI)** 이 찾은 PII/비밀정보에서 시드한다.

## 1. 왜 모리다운가

- 코드에서 흐름도를 "자동 생성"하는 건 코드를 읽어야 하니 모리답지 않다. 대신
  **스캔 findings(고객 CI에서 이미 수행)** 로 처리지점 후보만 시드하고, 담당자가
  저장위치·목적·보관·파기를 채워 **감사 대응용 개인정보 흐름표**를 완성한다.
- ISMS-P 3.1(수집)·3.2(현황관리/이용)·3.4(파기)의 **필수 증적인 "개인정보 흐름표"**
  를 코드로 관철 — 흐름도(SVG)까지 자동 렌더.

## 2. 동작 흐름

```
[고객 레포 CI]  code-review-semgrep.yml  (semgrep --config auto --config p/secrets)
   └─ 하드코딩 비밀/자격증명·PII 신호 → findings → /ingest/code-review
                │
[MORI]  findings → code_review alert
   ├─ PII 스캔 시드: is_pii_finding() 로 개인정보/비밀정보 finding 선별
   │    → 흐름표 후보 행(항목 추론·저장위치=repo·코드위치 단서) 생성(중복 방지)
   ├─ 담당자 편집: 저장위치(DB/테이블)·수집경로·목적·보관·파기·제3자·국외이전
   ├─ 흐름도(SVG): 항목별 수집→저장→이용→파기 레인 + 제3자/국외 배지
   ├─ CSV 다운로드(공통 openCsvPreview) + 3.x 통제 증적 승격(3.1.1·3.2.1·3.4.1)
   └─ 저장: personal_data_flow(JSONB) — 재부팅에도 유지
```

UI: Compliance → 통제 카탈로그 관리자 바(admin·security 전용) → **개인정보 흐름도**.

## 3. API (모두 admin·security 전용 — 개인정보 민감)

| 메서드 | 경로 | 용도 |
|---|---|---|
| GET | `/privacy/data-flow` | 흐름표 행·단계·필드 |
| POST | `/privacy/data-flow` | 행 추가(item 필수) |
| PUT | `/privacy/data-flow/{id}` | 행 수정 |
| DELETE | `/privacy/data-flow/{id}` | 행 삭제 |
| POST | `/privacy/data-flow/seed-from-scan?repo=` | PII code_review finding → 후보 행 시드 |
| GET | `/privacy/data-flow.svg` | 처리흐름도(SVG, 무의존성 문자열 렌더) |
| GET | `/privacy/data-flow.csv` | 흐름표 CSV |
| POST | `/privacy/data-flow/promote-evidence` | 3.1.1·3.2.1·3.4.1 통제 증적 승격(idempotent) |

## 4. 데이터 모델

`personal_data_flow(id TEXT PK, record JSONB, updated_at)` — 레코드 필드:
`item·subject·collection_source·storage_location·storage_table·purpose·retention·
destruction·third_party·overseas·note` + `source(manual|pii_scan)·repo·file·rule`.
control_evidence 와 동형 영속(load/save/delete + ctx 콜백 + boot 캐시-어사이드).

## 5. 검증 상태

- 유닛: 서비스(PII 판별·항목추론·시드 중복제거·SVG 렌더) + 라우트(CRUD·svg·csv·
  승격·seed·role gate) 7건 그린.
- 실 postgres E2E: schema 013 self-heal, ingest→seed(PII 1건), 수동추가, SVG/CSV,
  3.x 승격 3건, **재부팅 후 유지** — 통과.

관련 코드: `services/data_flow.py` · `api/routes/privacy.py` · `schema/013_personal_data_flow.sql`
· `repositories/state_*`(personal_data_flow) · controls `3.1.1·3.2.1·3.4.1`(evidence_sources:[privacy_flow]).
