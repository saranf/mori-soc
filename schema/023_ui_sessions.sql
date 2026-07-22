-- 023_ui_sessions.sql — 로그인 세션 영속(M10 Phase A)
--
-- 세션을 프로세스 인메모리에서 Postgres 로 영속해 (1) 재기동 시 로그아웃 방지
-- (2) 다중 인스턴스 공유의 토대를 만든다. 옵트인(MORI_SESSION_BACKEND=postgres)일 때만 사용.
-- record 는 세션 원형(JSONB), 나머지 컬럼은 조회·만료정리용 파생값.

CREATE TABLE IF NOT EXISTS ui_sessions (
    token       TEXT PRIMARY KEY,
    username    TEXT NOT NULL DEFAULT '',
    role        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    record      JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- 만료 세션 정리(주기 삭제)·사용자별 조회용 인덱스.
CREATE INDEX IF NOT EXISTS idx_ui_sessions_expires ON ui_sessions (expires_at);

COMMENT ON TABLE ui_sessions IS '로그인 세션 영속(M10). MORI_SESSION_BACKEND=postgres 일 때만 사용.';
