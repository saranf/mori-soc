-- 015_audit_log.sql — 행동 감사로그 영속(#20). hash chain(prev_hash·hash)으로 변조 감지.
-- append-only: 애플리케이션은 INSERT 만 하고 UPDATE/DELETE 하지 않는다(감사 무결성).
CREATE TABLE IF NOT EXISTS ui_audit_log (
    seq        BIGINT PRIMARY KEY,        -- 애플리케이션이 매기는 연속 번호(체인 순서)
    ts         TIMESTAMPTZ NOT NULL,
    username   TEXT,
    action     TEXT,
    detail     TEXT,
    prev_hash  TEXT,
    hash       TEXT NOT NULL
);

COMMENT ON TABLE ui_audit_log IS '행동 감사로그(hash chain). 재시작 후에도 유지되며 /admin/audit-log/verify 로 검증.';
