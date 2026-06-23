BEGIN;

-- ── Phase 2: UI operational state (M2-1) ─────────────────────────────────────
-- Persists the 6 in-memory dicts the API mutates at runtime
-- (asset_owners / asset_audit_log / vuln_actions / triage_store /
--  incidents / user_profiles). Cache-aside: loaded in full at boot into the
-- in-memory dicts; write-through on each mutation.
--
-- ISO-8601 timestamp fields that the API echoes back verbatim are stored as
-- text (not timestamptz) so the persisted value round-trips byte-identically
-- with the in-memory representation. Nested list/object fields use jsonb.
-- status fields carry no CHECK constraint on purpose: a write-through cache
-- must persist whatever the (already-validated) handlers wrote.

-- user_profiles: username -> {display_name, department, assigned_servers[], updated_at}
CREATE TABLE IF NOT EXISTS ui_user_profiles (
    username text PRIMARY KEY,
    display_name text NOT NULL DEFAULT '',
    department text NOT NULL DEFAULT '',
    assigned_servers jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at text
);

-- asset_owners: hostname -> {owner, category, importance, exception_until,
--                            exception_reason, email, team, updated_at}
CREATE TABLE IF NOT EXISTS ui_asset_owners (
    hostname text PRIMARY KEY,
    owner text NOT NULL DEFAULT '',
    category text NOT NULL DEFAULT '',
    importance text NOT NULL DEFAULT '',
    exception_until text NOT NULL DEFAULT '',
    exception_reason text NOT NULL DEFAULT '',
    email text NOT NULL DEFAULT '',
    team text NOT NULL DEFAULT '',
    updated_at text
);

-- asset_audit_log: append-only
--   [{log_id, hostname, field, old_value, new_value, changed_by, changed_at}]
CREATE TABLE IF NOT EXISTS ui_asset_audit_log (
    log_id text PRIMARY KEY,
    hostname text NOT NULL,
    field text NOT NULL,
    old_value text NOT NULL DEFAULT '',
    new_value text NOT NULL DEFAULT '',
    changed_by text NOT NULL DEFAULT '',
    changed_at text
);

CREATE INDEX IF NOT EXISTS idx_ui_asset_audit_hostname ON ui_asset_audit_log (hostname);
CREATE INDEX IF NOT EXISTS idx_ui_asset_audit_changed_at ON ui_asset_audit_log (changed_at);

-- vuln_actions: vuln_id -> {plan_text, plan_target_date, plan_updated_by,
--   exception_until, exception_reason, exception_updated_by, updated_at}
CREATE TABLE IF NOT EXISTS ui_vuln_actions (
    vuln_id text PRIMARY KEY,
    plan_text text NOT NULL DEFAULT '',
    plan_target_date text NOT NULL DEFAULT '',
    plan_updated_by text NOT NULL DEFAULT '',
    exception_until text NOT NULL DEFAULT '',
    exception_reason text NOT NULL DEFAULT '',
    exception_updated_by text NOT NULL DEFAULT '',
    updated_at text
);

-- triage_store: alert_id -> {status, analyst, note, changed_by, updated_at, history[]}
CREATE TABLE IF NOT EXISTS ui_triage_state (
    alert_id text PRIMARY KEY,
    status text NOT NULL DEFAULT 'pending',
    analyst text NOT NULL DEFAULT '',
    note text NOT NULL DEFAULT '',
    changed_by text NOT NULL DEFAULT '',
    updated_at text,
    history jsonb NOT NULL DEFAULT '[]'::jsonb
);

-- incidents: incident_id -> {title, status, status_updated_at, hostname,
--   analyst, handler, alert_ids[], notes[], history[], created_at, updated_at}
CREATE TABLE IF NOT EXISTS ui_incidents (
    incident_id text PRIMARY KEY,
    title text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'open',
    status_updated_at text,
    hostname text NOT NULL DEFAULT '',
    analyst text NOT NULL DEFAULT '',
    handler text NOT NULL DEFAULT '',
    alert_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    notes jsonb NOT NULL DEFAULT '[]'::jsonb,
    history jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at text,
    updated_at text
);

CREATE INDEX IF NOT EXISTS idx_ui_incidents_created_at ON ui_incidents (created_at);
CREATE INDEX IF NOT EXISTS idx_ui_incidents_status ON ui_incidents (status);

COMMIT;
