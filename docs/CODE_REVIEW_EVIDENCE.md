# 코드 보안 리뷰 증적 (SDLC / 2.8 개발보안) — MORI의 6번째 증적 소스

> **한 줄** — 고객 레포의 CI가 AI로 **기존 코드 전체**를 보안 리뷰하고, MORI는 **코드를 만지지 않고** 그 결과를 받아 **ISMS-P 2.8 / ISO 27001 A.8.25·A.8.28 개발보안 증적**으로 바꾼다. 결과의 출처(repo·commit·run)는 **GitHub OIDC 서명으로 검증**해 위조를 차단한다.

작성일: 2026-07-11 · 상태: alpha (파이프라인·OIDC 실 postgres E2E 검증, 실 GitHub 런 미검증)

---

## 1. 왜 모리다운가

MORI의 명제는 **"관제가 곧 증적"** — 보는 층(Grafana)에 위임하고 MORI는 판단·기록·증명만 한다. 기존 증적 소스(Zabbix·Fleet·Wazuh·Trivy)는 전부 **런타임/인프라**였고, 통제 카탈로그의 **2.8 개발보안(SDLC)** 도메인은 이를 먹여줄 소스가 없었다. 코드 보안 리뷰가 정확히 그 공백을 채운다.

핵심은 **MORI가 스캐너가 되지 않는다**는 것. 코드를 clone/스캔하지 않고 CI가 만든 결과(findings)만 받는다(Trivy 리포트 push와 동형). MORI는 **제3자 증적자** — GitHub이 서명한 사실을 독립 검증해 보관·증명한다. "증적의 강함 = 자동·상시·변조불가·출처명확"을 그대로 구현한다.

## 2. 동작 흐름

**대상 = 기존 코드 전체**(PR diff 아님). 보안 담당자가 PR마다 리뷰할 수 없으므로, "지금 있는 코드"를 온디맨드/정기로 감사하는 것이 핵심.

**스캐너 2모드** — 둘 다 SARIF/findings를 같은 `/ingest/code-review`로 보내며 MORI 파싱은 동일하다:

| | **무료(기본)** | **유료(고급)** |
|---|---|---|
| 스캐너 | Semgrep OSS (SAST 룰) | Claude AI 전체 리뷰 |
| 워크플로 | `code-review-semgrep.yml` | `code-review-fullscan.yml` (스캐너는 MORI가 서빙·fetch) |
| 파일 | 1개 | 1개 (스크립트 재복사 불필요) |
| 시크릿 | `MORI_INGEST_URL` 1개 | `ANTHROPIC_API_KEY` · `MORI_INGEST_URL` 2개 |
| 비용 | 무료 | Anthropic API 크레딧 |
| 강점 | 즉시·무료 패턴 SAST | 로직·맥락까지 심층 |
| 산출 | findings(2.8) | **한 호출로** findings(2.8) + 개인정보 흐름(3.x) 동시 |

```
[고객 레포 CI]  (무료) code-review-semgrep.yml   또는   (유료) code-review-fullscan.yml + scripts/code_review_fullscan.py
   ├─ 레포 소스 전체 스캔  ── Semgrep OSS(SARIF)  /  Claude 보안 리뷰 (온디맨드 / 월간)
   ├─ GitHub OIDC 토큰(repo·sha·run 서명) 획득
   └─ POST /ingest/code-review  (X-MORI-OIDC + SARIF/findings)
                │
[MORI]  OIDC 서명 검증 → repo·commit·run 을 서명 클레임으로 확정(위조 차단)
   ├─ findings → 호스트 없는 alert(source=code_review) → Alert Triage 재사용
   ├─ 스캔 런 자체를 증적 이벤트로 기록 (0건이어도 "통제가 작동했다")
   ├─ **스캔 런 → 2.8 통제 증적 레코드 자동 승격**(2.8.1·2.8.5·A.8.25·A.8.28) — 통제 상세에 날짜 찍힌 증적
   │    (id = scan seed × control 로 결정적 생성 → 재수신 시 갱신, 중복 없음)
   ├─ findings CSV 다운로드(공통 openCsvPreview): `/controls/code-review/findings.csv?repo=&commit=`
   └─ 대시보드 "미조치 코드 보안 리뷰" 작업 큐 타일
```

원격 트리거: MORI UI(Compliance → 통제 카탈로그 관리자 바 → **GitHub 코드 보안 리뷰**)에 repo URL + 토큰 입력 → `workflow_dispatch`로 그 레포에서 스캔 실행(기본 `code-review-semgrep.yml`). MORI는 여전히 코드를 만지지 않는다(스캔은 고객 CI에서).

> **왜 PR-diff 경로(claude-code-security-review 액션)를 안 쓰나**: 그 액션은 PR의 변경분만 리뷰하고 `workflow_dispatch`에선 스킵된다 — "기존 코드 전체 감사"를 못 한다. 그래서 이 프로젝트는 **전체 코드 스캔**(Semgrep/fullscan) 경로만 유지한다.

## 3. 고객이 할 일 (최소)

**무료(기본)** — 파일 1개 + 시크릿 1개, 끝.
1. 레포에 `.github/workflows/code-review-semgrep.yml` 복사 (UI 도움말 "① 워크플로(.yml) 보기·복사")
2. 레포 시크릿 1개: `MORI_INGEST_URL`
3. 실행: GitHub Actions 탭 **code-review-semgrep → Run workflow**, 또는 MORI UI **스캔 요청**(GitHub 토큰 actions:write 입력, 저장 안 함)

**유료(고급, 선택)** — 더 깊은 Claude 리뷰가 필요할 때. UI 도움말 ⚙️ "고급(유료)" 팝업에서 `.yml` 복사.
1. 레포에 `.github/workflows/code-review-fullscan.yml` **하나만** 복사(스캐너는 워크플로가 `${MORI_INGEST_URL}/code-review/fullscan.py`에서 최신본을 받아 실행 — 재복사 불필요)
2. 레포 시크릿 2개: `ANTHROPIC_API_KEY` · `MORI_INGEST_URL`
3. 실행: **code-review-fullscan → Run workflow** → **한 번의 Claude 호출**로 보안 findings(2.8)와 개인정보 흐름(3.x)이 함께 나온다(파일을 두 번 보내지 않아 잘림·비용↓)

OIDC를 쓰므로 **정적 ingest 토큰 시크릿이 불필요**하다(GitHub 서명으로 대체).

## 4. 증적 진위성 (OIDC provenance)

- 정적 공유 토큰만 쓰면 `repo`는 호출자 자기신고 → 위조 가능. **GitHub OIDC**는 GitHub이 서명한 `repository·sha·run_id`를 MORI가 검증해, 자기신고 값을 이긴다(위조 무력화). 저장 provenance에 `verified: true`.
- RS256 서명 검증은 **공개키로 공개데이터 검증**이라 새 라이브러리 없이 표준 라이브러리로 구현(무의존성 원칙).
- **0건 스캔도 증적** — "repo@commit를 언제 스캔했고 findings N건"을 기록해 "통제가 실제 작동했다"를 증명(실패만이 아니라 성공도).

## 5. 가치

**포트폴리오 (국내)** — ISMS-P 2.8 개발보안을 *자동 증적*으로 구현한 사례는 국내 보안/컴플라이언스 채용에서 희소. OIDC 페더레이션(공유 시크릿 → 서명 검증)·무의존성 RS256 검증은 보안 엔지니어링 깊이 신호.

**포트폴리오 (해외)** — ISO A.8.25/28 + "evidence layer, not scanner" 아키텍처 논지 + OIDC는 글로벌하게 읽힘. "제3자 증적자"를 코드로 관철한 서사가 킬러 포인트.

**제품** — MORI가 못 채우던 개발보안 도메인을 채우는 옵션 소스(개발 조직 세그먼트). 서명 검증 provenance로 "증적 위조 불가"는 감사 신뢰성 차별화 — Vanta/Drata 대비 self-host + ISMS-P + 서명 검증.

## 6. 더 딥하게 (로드맵, 레버리지 순)

1. **provenance를 감사 산출물에 노출** — 통제 증적 PDF/ZIP에 commit·run URL을 박아 감사관이 클릭 추적(현재 raw_payload에만).
2. ✅ **스캔 런 → 통제 evidence-record 승격**(완료) — ingest 시 `code_review_scan`을 2.8.1·2.8.5·A.8.25·A.8.28 통제의 날짜 찍힌 증적 레코드(`source=code_review`)로 자동 스냅샷. id 결정적 → 재수신 idempotent. 통제 상세 증적 목록·PDF/CSV에 노출.
3. **finding → 위험평가(3×3) 연동** — 코드 finding에도 영향×가능성 위험등급.
4. **findings 해소 추적** — 같은 finding 재등장/소멸 = reopened/fixed 이력(트리아지 자동 해소).
5. **reusable workflow 배포** — 고객 파일을 3줄 caller로 축소.
6. **OIDC 강제·allowlist를 UI 설정으로** — `MORI_INGEST_REQUIRE_OIDC`·repo allowlist를 admin 화면에서.
7. **다중 레포 대시보드** — repo별 필터·집계(현재 repo는 provenance에만).

> **개인정보(3.x) 연계**: 이 스캔이 발견한 PII/개인정보는 **개인정보 처리흐름도**로 이어진다 —
> 무료(스키마·관례 파서)/유료(Claude)가 수집→저장→이용→파기 라이프사이클을 만들어 3.1.1·3.2.1·3.4.1
> 통제 증적으로 승격한다. 상세: [PERSONAL_DATA_FLOW.md](PERSONAL_DATA_FLOW.md).

## 7. 문서 반영 상태

- README(한/영): 6번째 소스·2.8 커버리지·OIDC + **개인정보 처리흐름도(3.x)** 반영.
- README_FULL / 로드맵(Phase 표): 코드리뷰 소스 심화 반영은 **후속 필요**(현재 이 문서가 정본).
- 참고: 동시 진행 중인 **접속기록/로그 검토(Loki)** 작업은 별도 트랙으로 이 문서 범위 밖.

## 8. 검증 상태

- 유닛: OIDC 검증 8건(서명·변조거부·aud·exp·iss·allowlist·kid·alg), 인제스트·컬렉터·dispatch 등 포함 전체 그린.
- 실 postgres E2E: findings 적재·provenance 저장·0건 스캔 증적·**OIDC 서명 claim이 위조 repo override(verified:true)**·bad token 401·정적 폴백 — 통과.
- 실 GitHub Actions 런(무료 Semgrep): `saranf/trivy_Test` 스캔 → findings 51건 push, OIDC 검증됨(스캔 이력 UI 확인). fullscan(유료) 실 런은 크레딧 조건부.

관련 코드: `services/oidc_verify.py` · `collectors/code_review.py` · `services/code_review_dispatch.py` · `api/routes/sources.py`(`/ingest/code-review`, `/controls/code-review/*`, `/controls/code-review/findings.csv`) · `.github/workflows/code-review-semgrep.yml`(무료 기본) · `.github/workflows/code-review-fullscan.yml` + `scripts/code_review_fullscan.py`(유료) · `schema/012_code_review_source.sql`.
