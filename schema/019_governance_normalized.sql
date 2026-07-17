-- 019_governance_normalized.sql — 통제 거버넌스 핵심 객체 정규화(2차 리뷰 #4, 저장 정규화).
-- ui_control_governance (kind,entity_id) 범용 스토어는 FK·unique·기간겹침을 DB 로 못 막는다.
-- 핵심 계보(framework → version → control)를 정규 테이블로 빼서 **DB 가 무결성을 강제**한다.
-- 관계·무결성은 관계형 컬럼, 유동 속성은 metadata JSONB(= 앱이 받는 전체 레코드 원본 → round-trip).
CREATE TABLE IF NOT EXISTS gov_frameworks (
    framework_id TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    type         TEXT,
    publisher    TEXT,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,   -- 전체 레코드 원본
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gov_framework_versions (
    framework_version_id TEXT PRIMARY KEY,
    framework_id   TEXT NOT NULL REFERENCES gov_frameworks(framework_id) ON DELETE RESTRICT,
    version        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','retired')),
    effective_from TEXT,
    effective_to   TEXT,
    content_hash   TEXT,
    supersedes     TEXT,
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (framework_id, version)                       -- 같은 framework 에 같은 버전 번호 금지
);
-- 한 framework 당 active 버전은 최대 1개(부분 유니크 인덱스 — DB 레벨 보장).
CREATE UNIQUE INDEX IF NOT EXISTS ux_gov_fv_one_active
    ON gov_framework_versions (framework_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gov_control_definitions (
    control_id           TEXT PRIMARY KEY,
    framework_version_id TEXT NOT NULL
        REFERENCES gov_framework_versions(framework_version_id) ON DELETE RESTRICT,
    control_uid          TEXT,
    display_code         TEXT NOT NULL,
    title                TEXT,
    content_hash         TEXT,
    parent_control_id    TEXT,
    metadata             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (framework_version_id, display_code)          -- 한 버전에 같은 표시번호 금지
);
CREATE INDEX IF NOT EXISTS ix_gov_cd_uid ON gov_control_definitions (control_uid);

COMMENT ON TABLE gov_frameworks IS '통제 거버넌스 정규화(#4) — Framework. 무결성=관계형 컬럼, 원본=metadata JSONB.';
