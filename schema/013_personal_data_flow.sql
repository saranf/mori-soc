-- 013_personal_data_flow.sql — 개인정보 처리흐름표/흐름도 (ISMS-P 3.x 개인정보)
--
-- ISMS-P 3.1(수집)·3.2(이용/제공)·3.4(파기)의 필수 증적인 "개인정보 흐름표"를
-- 담는다. 각 행 = 하나의 개인정보 항목이 수집→저장→이용→파기로 흐르는 경로.
-- MORI 는 코드를 읽지 않는다 — PII 스캔 findings(고객 CI Semgrep)로 후보를 시드하고
-- 담당자가 저장위치/테이블·목적·보관·파기를 채운다. 흐름도(SVG)로 렌더되고
-- 3.x 통제 증적으로 승격된다. 유연성을 위해 레코드 전체를 JSONB 로 보관.
CREATE TABLE IF NOT EXISTS personal_data_flow (
    id          TEXT PRIMARY KEY,
    record      JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE personal_data_flow IS '개인정보 처리흐름표(수집→저장→이용→파기) — ISMS-P 3.x 증적.';
