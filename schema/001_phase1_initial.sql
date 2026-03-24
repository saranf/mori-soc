BEGIN;

CREATE TABLE IF NOT EXISTS hosts (
    host_id text PRIMARY KEY,
    hostname text NOT NULL,
    platform text,
    primary_ip text,
    status text NOT NULL DEFAULT 'unknown',
    risk_score integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz,
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT hosts_status_check CHECK (status IN ('online', 'offline', 'unknown'))
);

CREATE TABLE IF NOT EXISTS host_aliases (
    alias_id text PRIMARY KEY,
    host_id text NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    source text NOT NULL,
    alias_type text NOT NULL,
    alias_value text NOT NULL,
    confidence numeric(5,4) NOT NULL DEFAULT 1.0000,
    is_primary boolean NOT NULL DEFAULT false,
    first_seen_at timestamptz,
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT host_aliases_confidence_check CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT host_aliases_source_check CHECK (source IN ('fleet', 'wazuh', 'zabbix', 'host_log')),
    CONSTRAINT host_aliases_unique UNIQUE (source, alias_type, alias_value)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id text PRIMARY KEY,
    source text NOT NULL,
    source_event_id text,
    host_id text REFERENCES hosts(host_id) ON DELETE SET NULL,
    severity text NOT NULL DEFAULT 'info',
    original_severity text,
    rule_name text,
    rule_id text,
    message text NOT NULL,
    observed_at timestamptz NOT NULL,
    raw_ref text,
    raw_payload jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alerts_source_check CHECK (source IN ('wazuh', 'zabbix', 'host_log')),
    CONSTRAINT alerts_severity_check CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id text PRIMARY KEY,
    host_id text NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    source text NOT NULL DEFAULT 'fleet',
    cve text,
    severity text NOT NULL DEFAULT 'info',
    package_name text,
    installed_version text,
    fixed_version text,
    detected_at timestamptz NOT NULL,
    resolved_at timestamptz,
    raw_ref text,
    raw_payload jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vulnerabilities_source_check CHECK (source IN ('fleet')),
    CONSTRAINT vulnerabilities_severity_check CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

CREATE TABLE IF NOT EXISTS query_results (
    query_result_id text PRIMARY KEY,
    source text NOT NULL DEFAULT 'fleet',
    host_id text NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    query_name text,
    query_text text,
    result_json jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    raw_ref text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT query_results_source_check CHECK (source IN ('fleet'))
);

CREATE TABLE IF NOT EXISTS host_observations (
    observation_id text PRIMARY KEY,
    source text NOT NULL,
    host_id text NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    observation_type text NOT NULL,
    metric_name text NOT NULL,
    metric_value text,
    unit text,
    severity text,
    observed_at timestamptz NOT NULL,
    raw_ref text,
    raw_payload jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT host_observations_source_check CHECK (source IN ('fleet', 'zabbix', 'host_log')),
    CONSTRAINT host_observations_severity_check CHECK (severity IS NULL OR severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

CREATE TABLE IF NOT EXISTS source_syncs (
    source text PRIMARY KEY,
    status text NOT NULL,
    last_sync_at timestamptz NOT NULL,
    last_success_at timestamptz,
    last_error_at timestamptz,
    message text,
    records_collected integer NOT NULL DEFAULT 0,
    envelopes_normalized integer NOT NULL DEFAULT 0,
    entities_saved integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT source_syncs_source_check CHECK (source IN ('fleet', 'wazuh', 'zabbix', 'host_log')),
    CONSTRAINT source_syncs_status_check CHECK (status IN ('success', 'error', 'running'))
);

CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts (hostname);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts (status);
CREATE INDEX IF NOT EXISTS idx_hosts_last_seen_at ON hosts (last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_host_aliases_host_id ON host_aliases (host_id);
CREATE INDEX IF NOT EXISTS idx_host_aliases_source_alias_value ON host_aliases (source, alias_value);

CREATE INDEX IF NOT EXISTS idx_alerts_host_observed_at ON alerts (host_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_observed_at ON alerts (source, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_observed_at ON alerts (severity, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_vulns_host_detected_at ON vulnerabilities (host_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities (cve);
CREATE INDEX IF NOT EXISTS idx_vulns_severity_detected_at ON vulnerabilities (severity, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_query_results_host_observed_at ON query_results (host_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_results_name_observed_at ON query_results (query_name, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_observations_host_observed_at ON host_observations (host_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_observations_metric_observed_at ON host_observations (metric_name, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_source_syncs_last_sync_at ON source_syncs (last_sync_at DESC);

CREATE OR REPLACE VIEW latest_host_status_view AS
SELECT
    h.host_id,
    h.hostname,
    h.platform,
    h.status,
    h.last_seen_at,
    h.risk_score,
    (
        SELECT ho.metric_value
        FROM host_observations ho
        WHERE ho.host_id = h.host_id
          AND ho.observation_type = 'status'
        ORDER BY ho.observed_at DESC
        LIMIT 1
    ) AS latest_status_value,
    (
        SELECT ho.observed_at
        FROM host_observations ho
        WHERE ho.host_id = h.host_id
          AND ho.observation_type = 'status'
        ORDER BY ho.observed_at DESC
        LIMIT 1
    ) AS latest_status_observed_at
FROM hosts h;

CREATE OR REPLACE VIEW host_risk_summary_view AS
SELECT
    h.host_id,
    h.hostname,
    h.platform,
    h.status,
    h.risk_score,
    COALESCE(a.alert_count, 0) AS alert_count,
    COALESCE(v.vuln_count, 0) AS vulnerability_count,
    GREATEST(h.last_seen_at, a.last_alert_at, v.last_vuln_at) AS last_activity_at
FROM hosts h
LEFT JOIN (
    SELECT host_id, COUNT(*) AS alert_count, MAX(observed_at) AS last_alert_at
    FROM alerts
    GROUP BY host_id
) a ON a.host_id = h.host_id
LEFT JOIN (
    SELECT host_id, COUNT(*) AS vuln_count, MAX(detected_at) AS last_vuln_at
    FROM vulnerabilities
    GROUP BY host_id
) v ON v.host_id = h.host_id;

CREATE OR REPLACE VIEW host_timeline_view AS
SELECT
    a.host_id,
    'alert'::text AS event_type,
    a.source,
    a.alert_id AS record_id,
    a.observed_at,
    a.severity,
    a.message,
    a.raw_ref
FROM alerts a
UNION ALL
SELECT
    qr.host_id,
    'query_result'::text AS event_type,
    qr.source,
    qr.query_result_id AS record_id,
    qr.observed_at,
    NULL::text AS severity,
    COALESCE(qr.query_name, 'fleet query result') AS message,
    qr.raw_ref
FROM query_results qr
UNION ALL
SELECT
    ho.host_id,
    'observation'::text AS event_type,
    ho.source,
    ho.observation_id AS record_id,
    ho.observed_at,
    ho.severity,
    CONCAT(ho.observation_type, ':', ho.metric_name) AS message,
    ho.raw_ref
FROM host_observations ho;

COMMIT;