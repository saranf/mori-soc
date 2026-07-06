BEGIN;

-- ── Zabbix 실전 시나리오: alert 해소(resolve) 반영 ──────────────────────────
-- Zabbix problem 이 해소되면(problem.get recent=True 의 r_eventid/r_clock),
-- 컬렉터가 resolved_at 을 채워 upsert 한다. 라이프사이클: 발생 → Triage →
-- Incident → 해소. NULL = 미해소(활성).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_alerts_resolved_at ON alerts (resolved_at);

COMMIT;
