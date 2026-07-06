BEGIN;

-- ── Phase 5 / R-series: 취약점 위험성 평가 대장(Risk Register) ──────────────────
-- ISMS-P(2.10/위험관리)·ISO 27001(6.1.2, 8.8) 위험성 평가 결과를 CVE(vuln_id)
-- 단위로 영속화한다. 산정 로직은 services/risk_assessment.py(R-1). 이 테이블은
-- 기존 ui_* 운영 상태 store와 동일한 cache-aside + write-through 패턴을 따른다.
--
-- 값 원칙(schema/003과 동일):
-- - ISO-8601 timestamp(assessed_at/updated_at)는 verbatim 왕복을 위해 text.
-- - review_due 는 날짜 문자열(빈 문자열 허용)이라 text.
-- - impact/likelihood/score 는 정수(왕복 안전). level/treatment 등은 CHECK 없이
--   저장한다 — write-through cache는 (이미 검증된) 핸들러가 쓴 값을 그대로 보관.
--
-- impact/likelihood: 1~3 (하/중/상), score = impact*likelihood (1~9), 0 = 미평가.
-- treatment: 조치(mitigate)/수용(accept)/이관(transfer)/회피(avoid) 중 하나(자유값).

CREATE TABLE IF NOT EXISTS ui_risk_register (
    vuln_id text PRIMARY KEY,
    impact integer NOT NULL DEFAULT 0,
    likelihood integer NOT NULL DEFAULT 0,
    score integer NOT NULL DEFAULT 0,
    level text NOT NULL DEFAULT '',
    treatment text NOT NULL DEFAULT '',
    accept_reason text NOT NULL DEFAULT '',
    accept_approver text NOT NULL DEFAULT '',
    residual_level text NOT NULL DEFAULT '',
    review_due text NOT NULL DEFAULT '',
    assessed_by text NOT NULL DEFAULT '',
    assessed_at text,
    updated_at text
);

CREATE INDEX IF NOT EXISTS idx_ui_risk_register_level ON ui_risk_register (level);
CREATE INDEX IF NOT EXISTS idx_ui_risk_register_score ON ui_risk_register (score);

COMMIT;
