-- 018_control_governance_events.sql — 통제 거버넌스 append-only 이벤트 로그(에픽 S3).
-- ui_control_governance 는 '최신 projection', 이 테이블은 변경 이력의 **진짜 append-only** 원장이다.
-- 각 이벤트는 이전 이벤트 해시에 연결된 hash chain 을 가져(감사로그와 동일 방식) 변조·삭제·재배열을
-- 검증할 수 있다. UPDATE/DELETE 없이 INSERT 만 한다.
CREATE TABLE IF NOT EXISTS ui_control_governance_events (
    seq         BIGSERIAL PRIMARY KEY,
    event_id    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    event_type  TEXT NOT NULL,               -- create|update|lifecycle|migrate
    actor       TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ctlgov_events_entity ON ui_control_governance_events (kind, entity_id);

COMMENT ON TABLE ui_control_governance_events IS '통제 거버넌스 append-only 이벤트 원장(hash chain). projection=ui_control_governance.';
