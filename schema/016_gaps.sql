-- 016_gaps.sql — 기술 Gap 워크플로(#5). MORI 가 발견한 결함 후보를 사람이 판단·조치·재검증.
CREATE TABLE IF NOT EXISTS ui_gaps (
    gap_id       TEXT PRIMARY KEY,
    source       TEXT,
    control_id   TEXT,
    key          TEXT,
    title        TEXT,
    detail       TEXT,
    status       TEXT NOT NULL DEFAULT 'candidate',
    assignee     TEXT,
    due_date     TEXT,
    resolution   TEXT,
    evidence_ref TEXT,
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    history      JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_gaps_status ON ui_gaps (status);
CREATE INDEX IF NOT EXISTS ix_gaps_control ON ui_gaps (control_id);

COMMENT ON TABLE ui_gaps IS '기술 Gap 워크플로(#5). candidate→confirmed→remediation→resolved 등. AI 확정 아님, 사람 판단.';
