# 개인정보 처리흐름표/흐름도 (ISMS-P 3.x) — PII 탐지 연계

MORI의 개인정보 증적 도구. **수집→저장→이용→파기** 흐름과 저장위치(DB/테이블)를
기록·시각화하고 ISMS-P 3.x 통제 증적으로 승격한다. MORI는 코드를 읽지 않는다
(증적 층 원칙) — 후보 행은 **스캔(고객 CI)** 이 찾은 PII/비밀정보에서 시드한다.

> **한국형 PII 탐지**: Semgrep 워크플로에 커스텀 룰(`korean-pii-rrn`·`-phone`·`-card`)을 런타임 생성해
> 주민등록번호·휴대전화·카드번호 하드코딩을 탐지한다(고객 파일은 여전히 워크플로 1개). 탐지 결과는
> `is_pii_finding()`로 분류돼 흐름표 시드로 이어진다. 실 semgrep 실행으로 3종 탐지 검증됨.

## 1. 왜 모리다운가

- 코드에서 흐름도를 "자동 생성"하는 건 코드를 읽어야 하니 모리답지 않다. 대신
  **스캔 findings(고객 CI에서 이미 수행)** 로 처리지점 후보만 시드하고, 담당자가
  저장위치·목적·보관·파기를 채워 **감사 대응용 개인정보 흐름표**를 완성한다.
- ISMS-P 3.1(수집)·3.2(현황관리/이용)·3.4(파기)의 **필수 증적인 "개인정보 흐름표"**
  를 코드로 관철 — 흐름도(SVG)까지 자동 렌더.

## 2. 동작 흐름

```
[고객 레포 CI]  code-review-semgrep.yml  (semgrep --config auto --config p/secrets --config korean-pii)
   └─ 하드코딩 비밀/자격증명 + 한국형 PII(주민번호·휴대전화·카드번호) → findings → /ingest/code-review
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
| GET | `/privacy/data-flow.pdf` | 흐름표 PDF(감사관 제출용, reportlab·팔레트 6색) |
| POST | `/privacy/data-flow/reset` | 흐름표 전체 리셋(재스캔으로 재생성) |
| GET | `/privacy/pii-rules.yml` | 스캔용 Semgrep 룰(리터럴+필드명 기본셋+어드민 커스텀). 워크플로가 스캔 때 fetch |
| GET·PUT | `/privacy/pii-criteria` | 어드민 PII 기준(기본 노출 + 커스텀 정규식=항목 편집) |
| POST | `/ingest/privacy-flow` | **구조화된 라이프사이클** 수신(무료 파서 또는 Claude fullscan → 동일 스키마) |
| GET | `/privacy/flow-scanner.py` | 무료 스키마·관례 파서 스크립트 서빙(어드민 옵션 주입 후, 워크플로가 fetch·실행) |
| GET·PUT | `/privacy/flow-opts` | 어드민 옵트인 고급 옵션 — **라우트 매칭**(수집·이용·파기 경로 연결)·**추가 ORM**(TypeORM·Sequelize·JPA) |

**심층 흐름도 — 무료(후보 생성) vs Claude(시맨틱 보강)**: 둘 다 `수집→저장→이용→파기` 구조화 JSON을
`/ingest/privacy-flow`로 보내 **동일하게 렌더**(항목별 다중 위치·암호화·마스킹·파기·제3자·갭·요약카드).
- **무료**: `scripts/privacy_flow_scan.py`(순수 stdlib, API 키 0)가 **Prisma 스키마 + 관례(*Enc·*Hash·mask*·erase/withdraw/purge)**를 읽어 후보를 재구성. 워크플로가 MORI 서빙본을 fetch·실행(파일 1개 유지).
- **Claude**: `scripts/code_review_fullscan.py`(유료)가 코드 시맨틱(마스킹 로직·파기 경로·갭)까지 보강. 무료보다 폭넓지만 여전히 **후보 제안**이다.

> ⚠️ **기술적 후보 지도이지 법적 판단이 아니다(Technical candidate map, not a legal determination).**
> 개인정보/민감정보 해당 여부·보유기간 적정성·국외이전·제3자 제공은 코드만으로 확정할 수 없다.
> 무료·Claude 어느 경로든 산출물은 **담당자(개인정보 보호책임자 등)의 검토·확정**을 거쳐야 증적이 된다.
> 흐름표는 읽기 전용 후보이고, 상태는 자동 시드(`pii_scan`/`ai_flow`) vs 사람 확정(`manual`)으로 구분된다.

**탐지 범위**: 리터럴 값(주민번호·전화·카드)만이 아니라 **PII 필드명**(email·phone·gender·birthDate·cardNumber·account·address·name·주민등록번호…)까지 잡아, 실제 앱의 개인정보 항목을 폭넓게 발견한다. 어드민이 `/privacy/pii-criteria`에 **커스텀 기준(정규식=항목)**을 추가하면 다음 스캔부터 **기본셋 + 커스텀**이 함께 적용된다(워크플로가 `pii-rules.yml`을 fetch). 파일 경로로 단계(수집/저장/이용/파기)를 추정해 해당 칸에 배치한다.
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
