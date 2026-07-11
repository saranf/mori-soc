# 코드 보안 리뷰 증적 (SDLC / 2.8 개발보안) — MORI의 6번째 증적 소스

> **한 줄** — 고객 레포의 CI가 AI 코드 보안 리뷰(claude-code-security-review)를 돌리고, MORI는 **코드를 만지지 않고** 그 결과를 받아 **ISMS-P 2.8 / ISO 27001 A.8.25·A.8.28 개발보안 증적**으로 바꾼다. 결과의 출처(repo·commit·run)는 **GitHub OIDC 서명으로 검증**해 위조를 차단한다.

작성일: 2026-07-11 · 상태: alpha (파이프라인·OIDC 실 postgres E2E 검증, 실 GitHub 런 미검증)

---

## 1. 왜 모리다운가

MORI의 명제는 **"관제가 곧 증적"** — 보는 층(Grafana)에 위임하고 MORI는 판단·기록·증명만 한다. 기존 증적 소스(Zabbix·Fleet·Wazuh·Trivy)는 전부 **런타임/인프라**였고, 통제 카탈로그의 **2.8 개발보안(SDLC)** 도메인은 이를 먹여줄 소스가 없었다. 코드 보안 리뷰가 정확히 그 공백을 채운다.

핵심은 **MORI가 스캐너가 되지 않는다**는 것. 코드를 clone/스캔하지 않고 CI가 만든 결과(findings)만 받는다(Trivy 리포트 push와 동형). MORI는 **제3자 증적자** — GitHub이 서명한 사실을 독립 검증해 보관·증명한다. "증적의 강함 = 자동·상시·변조불가·출처명확"을 그대로 구현한다.

## 2. 동작 흐름

```
[고객 레포 CI]  security-review.yml
   ├─ claude-code-security-review 실행 (매 PR / MORI 원격 트리거)
   ├─ GitHub OIDC 토큰(repo·sha·run 서명) 획득
   └─ POST /ingest/code-review  (X-MORI-OIDC + findings)
                │
[MORI]  OIDC 서명 검증 → repo·commit·run 을 서명 클레임으로 확정(위조 차단)
   ├─ findings → 호스트 없는 alert(source=code_review) → Alert Triage 재사용
   ├─ 스캔 런 자체를 증적 이벤트로 기록 (0건이어도 "통제가 작동했다")
   ├─ 통제 매핑: 2.8.1 · 2.8.5 · A.8.25 · A.8.28
   └─ 대시보드 "미조치 코드 보안 리뷰" 작업 큐 타일
```

원격 트리거: MORI UI(Compliance → 통제 카탈로그 관리자 바 → **GitHub 코드 보안 리뷰**)에 repo URL + 토큰 입력 → `workflow_dispatch`로 그 레포에서 실행. MORI는 여전히 코드를 만지지 않는다.

## 3. 고객이 할 일 (최소)

**자동 경로 (가장 가벼움)** — 파일 1개 + 시크릿 2개, 끝. 매 PR마다 증적.
1. 레포 `.github/workflows/security-review.yml` 복사 (UI 도움말의 "📄 예시 보기·복사")
2. 레포 시크릿 2개: `ANTHROPIC_API_KEY` · `MORI_INGEST_URL`
3. (선택) UI 온디맨드 스캔 → GitHub 토큰(actions:write)을 MORI UI에 입력(저장 안 함)

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
2. **스캔 런 → 통제 evidence-record 승격** — `code_review_scan` 이벤트를 2.8 통제의 날짜 찍힌 증적 레코드로 자동 스냅샷(현재 evidence_events에만).
3. **finding → 위험평가(3×3) 연동** — 코드 finding에도 영향×가능성 위험등급.
4. **findings 해소 추적** — 같은 finding 재등장/소멸 = reopened/fixed 이력(트리아지 자동 해소).
5. **reusable workflow 배포** — 고객 파일을 3줄 caller로 축소.
6. **OIDC 강제·allowlist를 UI 설정으로** — `MORI_INGEST_REQUIRE_OIDC`·repo allowlist를 admin 화면에서.
7. **다중 레포 대시보드** — repo별 필터·집계(현재 repo는 provenance에만).

## 7. 문서 반영 상태

- README(한/영): 이 커밋에서 6번째 소스·2.8 커버리지·OIDC를 반영.
- README_FULL / 로드맵(Phase 표): 코드리뷰 소스 심화 반영은 **후속 필요**(현재 이 문서가 정본).
- 참고: 동시 진행 중인 **접속기록/로그 검토(Loki)** 작업은 별도 트랙으로 이 문서 범위 밖.

## 8. 검증 상태

- 유닛: OIDC 검증 8건(서명·변조거부·aud·exp·iss·allowlist·kid·alg), 인제스트·컬렉터·dispatch 등 포함 전체 그린.
- 실 postgres E2E: findings 적재·provenance 저장·0건 스캔 증적·**OIDC 서명 claim이 위조 repo override(verified:true)**·bad token 401·정적 폴백 — 통과.
- 미검증: 실 GitHub Actions 런(첫 PR 로그로 `oidc=yes` + push 200 확인 필요).

관련 코드: `services/oidc_verify.py` · `collectors/code_review.py` · `services/code_review_dispatch.py` · `api/routes/sources.py`(`/ingest/code-review`, `/controls/code-review/*`) · `.github/workflows/security-review.yml` · `schema/012_code_review_source.sql`.
