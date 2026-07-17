-- 017_control_governance.sql — 통제 운영 플랫폼(통제 신규 에픽).
-- Framework/Version/ControlDefinition/Relationship/OrganizationControl/AssuranceCycle/
-- ScopeSnapshot/EvidenceContract 등을 (kind, entity_id) 네임스페이스 하나로 보관한다.
-- 버전은 덮어쓰지 않고 새 레코드로 쌓는다(승인본 불변) — record.supersedes 로 계보를 잇는다.
CREATE TABLE IF NOT EXISTS ui_control_governance (
    kind        TEXT NOT NULL,               -- framework|framework_version|control_definition|...
    entity_id   TEXT NOT NULL,
    record      JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, entity_id)
);
CREATE INDEX IF NOT EXISTS ix_ctlgov_kind ON ui_control_governance (kind);

COMMENT ON TABLE ui_control_governance IS '통제 운영 플랫폼 객체(framework~evidence_contract). 버전 불변(새 레코드로 append), 사람 승인.';
