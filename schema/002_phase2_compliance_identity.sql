BEGIN;

-- ── Phase 2: Compliance / Audit ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS control_check_results (
    check_id text PRIMARY KEY,
    control_id text NOT NULL,
    entity_type text NOT NULL,
    entity_id text NOT NULL,
    status text NOT NULL DEFAULT 'not_checked',
    checked_at timestamptz NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    owner text,
    note text,
    remediation_due_at timestamptz,
    resolved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ccr_entity_type_check CHECK (entity_type IN ('host', 'account', 'network', 'application', 'policy')),
    CONSTRAINT ccr_status_check CHECK (status IN ('pass', 'fail', 'warning', 'not_applicable', 'not_checked'))
);

CREATE INDEX IF NOT EXISTS idx_ccr_control_id ON control_check_results (control_id);
CREATE INDEX IF NOT EXISTS idx_ccr_entity ON control_check_results (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_ccr_status ON control_check_results (status);
CREATE INDEX IF NOT EXISTS idx_ccr_checked_at ON control_check_results (checked_at DESC);

-- ── Phase 2: Directory / Identity (LDAP/AD) ─────────────────────────────────

CREATE TABLE IF NOT EXISTS directory_accounts (
    account_id text PRIMARY KEY,
    username text NOT NULL UNIQUE,
    display_name text,
    email text,
    department text,
    status text NOT NULL DEFAULT 'active',
    is_privileged boolean NOT NULL DEFAULT false,
    last_login_at timestamptz,
    password_last_set timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT da_status_check CHECK (status IN ('active', 'disabled', 'locked', 'expired'))
);

CREATE TABLE IF NOT EXISTS privilege_bindings (
    binding_id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES directory_accounts(account_id) ON DELETE CASCADE,
    privilege_type text NOT NULL,
    target text,
    granted_at timestamptz,
    expires_at timestamptz,
    granted_by text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS group_memberships (
    membership_id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES directory_accounts(account_id) ON DELETE CASCADE,
    group_name text NOT NULL,
    source text NOT NULL DEFAULT 'ldap',
    synced_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT gm_unique UNIQUE (account_id, group_name, source)
);

CREATE TABLE IF NOT EXISTS account_observations (
    observation_id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES directory_accounts(account_id) ON DELETE CASCADE,
    observation_type text NOT NULL,
    source text NOT NULL DEFAULT 'ldap',
    observed_at timestamptz,
    detail text,
    severity text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ao_severity_check CHECK (severity IS NULL OR severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

CREATE INDEX IF NOT EXISTS idx_pb_account_id ON privilege_bindings (account_id);
CREATE INDEX IF NOT EXISTS idx_gm_account_id ON group_memberships (account_id);
CREATE INDEX IF NOT EXISTS idx_gm_group_name ON group_memberships (group_name);
CREATE INDEX IF NOT EXISTS idx_ao_account_id ON account_observations (account_id);
CREATE INDEX IF NOT EXISTS idx_ao_type ON account_observations (observation_type);
CREATE INDEX IF NOT EXISTS idx_ao_observed_at ON account_observations (observed_at DESC);

COMMIT;

