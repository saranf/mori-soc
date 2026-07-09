-- 010_accounts.sql — 서버/PC 로컬 계정 인벤토리 + 승인 대장 (접근권한 거버넌스)
--
-- host_accounts: osquery(Fleet) push 로 수집한 호스트별 로컬 계정 인벤토리.
-- account_approvals: 허용 계정/sudo 승인 대장 — 이상 검출의 기준선(여기 없는 것만 이상).
-- 목적: 서버 로컬 계정 × LDAP 디렉터리 대조 → 퇴사자 잔존·미등록 특권·미승인 sudo·휴면 검출.
-- ISMS-P 2.5.1/2.5.5/2.5.6, ISO 27001:2022 A.5.16/A.5.18/A.8.2 증적.

CREATE TABLE IF NOT EXISTS host_accounts (
    host_key         TEXT NOT NULL,              -- hostname (또는 host_id)
    username         TEXT NOT NULL,
    host_type        TEXT NOT NULL DEFAULT 'server',  -- server | pc
    uid              TEXT,
    gid              TEXT,
    shell            TEXT,
    home             TEXT,
    groups           JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_privileged    BOOLEAN NOT NULL DEFAULT false,   -- uid 0 / wheel·admin·sudo 그룹
    is_sudo          BOOLEAN NOT NULL DEFAULT false,
    disabled         BOOLEAN NOT NULL DEFAULT false,
    last_login       TIMESTAMPTZ,
    pwd_last_change  DATE,
    source           TEXT NOT NULL DEFAULT 'osquery',
    collected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host_key, username)
);

CREATE INDEX IF NOT EXISTS idx_host_accounts_priv ON host_accounts (is_privileged) WHERE is_privileged;

CREATE TABLE IF NOT EXISTS account_approvals (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL DEFAULT 'global',   -- global | host
    host_key    TEXT,                             -- scope=host 일 때만
    username    TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'account',  -- account | sudo
    reason      TEXT,
    approver    TEXT,
    expires     DATE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE host_accounts IS 'osquery push 로컬 계정 인벤토리(호스트별). 접근권한 검토 증적.';
COMMENT ON TABLE account_approvals IS '허용 계정/sudo 승인 대장 — 이상 검출 기준선(예외 승인 근거=증적).';
