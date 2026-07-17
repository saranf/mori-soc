-- 020_governance_normalized2.sql — 통제 거버넌스 정규화 2차(2차 리뷰 #4).
-- 내부통제 계열을 정규 테이블로: organization_controls → evidence_contracts/mappings(FK),
-- scope_snapshots, control_relationships(coverage CHECK·중복 금지). 019 와 동일 패턴
-- (관계=관계형 컬럼, 원본=metadata JSONB). 사이클 체인은 후속 슬라이스에서.
CREATE TABLE IF NOT EXISTS gov_organization_controls (
    organization_control_id TEXT PRIMARY KEY,
    code       TEXT NOT NULL,
    title      TEXT,
    version    INTEGER NOT NULL DEFAULT 1,
    status     TEXT,
    metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (code, version)                              -- 같은 내부통제 코드에 같은 버전 금지
);

CREATE TABLE IF NOT EXISTS gov_scope_snapshots (
    scope_snapshot_id TEXT PRIMARY KEY,
    content_hash TEXT,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gov_evidence_contracts (
    evidence_contract_id    TEXT PRIMARY KEY,
    organization_control_id TEXT NOT NULL
        REFERENCES gov_organization_controls(organization_control_id) ON DELETE RESTRICT,
    version    INTEGER NOT NULL DEFAULT 1,
    content_hash TEXT,
    metadata   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_control_id, version)
);

CREATE TABLE IF NOT EXISTS gov_evidence_mappings (
    mapping_id              TEXT PRIMARY KEY,
    organization_control_id TEXT NOT NULL
        REFERENCES gov_organization_controls(organization_control_id) ON DELETE RESTRICT,
    source_type     TEXT NOT NULL,
    mapping_version INTEGER NOT NULL DEFAULT 1,
    valid_from      TEXT,
    valid_to        TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gov_control_relationships (
    relationship_id   TEXT PRIMARY KEY,
    source_control_id TEXT NOT NULL,
    target_control_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    coverage_percent  INTEGER CHECK (coverage_percent IS NULL OR (coverage_percent BETWEEN 0 AND 100)),
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (source_control_id <> target_control_id),     -- 자기참조 금지(DB 레벨)
    UNIQUE (source_control_id, target_control_id, relationship_type)
);

COMMENT ON TABLE gov_organization_controls IS '통제 거버넌스 정규화 2차(#4) — 내부통제. 무결성=관계형, 원본=metadata JSONB.';
