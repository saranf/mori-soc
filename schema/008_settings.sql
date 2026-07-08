-- 008_settings.sql — 조직 단위 운영 설정 key-value 저장 (M2 / 위험 DoA 등)
--
-- 단일 값(예: 위험 수용 기준 DoA 점수)을 UI에서 입력받아 영속화한다.
-- key: 설정 식별자(예: 'risk_doa'), value: 문자열(정수/JSON 등 상위에서 해석).

CREATE TABLE IF NOT EXISTS ui_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE ui_settings IS '조직 단위 운영 설정(key-value). 예: risk_doa = 위험 수용 기준 점수(1~9).';
