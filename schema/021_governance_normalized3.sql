-- 021_governance_normalized3.sql — 통제 거버넌스 정규화 3차(2차 리뷰 #4) — 운영주기 체인.
-- gov_assurance_cycles(FK framework_version·nullable FK scope_snapshot) → gov_cycle_controls(FK cycle).
-- cycle_control.control_ref 는 통제정의 또는 내부통제 둘 다 가리킬 수 있어(이중 대상) FK 를 걸지
-- 않고 서비스층에서 검증한다. 나머지는 019/020 과 동일 패턴(원본=metadata JSONB).
CREATE TABLE IF NOT EXISTS gov_assurance_cycles (
    cycle_id             TEXT PRIMARY KEY,
    framework_version_id TEXT NOT NULL
        REFERENCES gov_framework_versions(framework_version_id) ON DELETE RESTRICT,
    scope_snapshot_id    TEXT
        REFERENCES gov_scope_snapshots(scope_snapshot_id) ON DELETE RESTRICT,
    name         TEXT,
    status       TEXT,
    period_start TEXT,
    period_end   TEXT,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gov_cycle_controls (
    cycle_control_id  TEXT PRIMARY KEY,
    cycle_id          TEXT NOT NULL
        REFERENCES gov_assurance_cycles(cycle_id) ON DELETE RESTRICT,
    control_ref       TEXT NOT NULL,
    evidence_status   TEXT,
    assessment_status TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_gov_cc_cycle ON gov_cycle_controls (cycle_id);

COMMENT ON TABLE gov_assurance_cycles IS '통제 거버넌스 정규화 3차(#4) — 운영주기. FK framework_version·scope_snapshot.';
