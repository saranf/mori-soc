BEGIN;

-- ── CSOP 증적(evidence) 이벤트 대장 ─────────────────────────────────────────────
-- 원격 스캐너/CSOP 에이전트가 push 하는 "조치 전/후" diff envelope 를 영속화한다.
-- /ingest/trivy 는 원본 Trivy 리포트만 받아 자체 정규화하므로, delta_type
-- (new/fixed/reopened) 과 before/after 증적은 담지 못한다. 이 테이블은 그 공백을
-- 메우는 별도 수신함으로, POST /ingest/evidence 가 write-through 한다.
--
-- 값 원칙(schema/003·004 와 동일):
-- - envelope 은 전체 payload 를 원형 그대로 보관(jsonb) — 스키마 변화에 무관하게 수용.
-- - 상단 컬럼(host_id/artifact_name/delta_type/cve/summary)은 조회·필터용 추출값.
-- - received_at 은 ISO-8601 text (verbatim 왕복).
-- 조회는 admin·security 롤 전용(GET /evidence) — 위험성 평가와 동일한 가시성 정책.

CREATE TABLE IF NOT EXISTS ui_evidence_events (
    id text PRIMARY KEY,
    host_id text NOT NULL DEFAULT '',
    artifact_name text NOT NULL DEFAULT '',
    delta_type text NOT NULL DEFAULT '',
    cve text NOT NULL DEFAULT '',
    summary text NOT NULL DEFAULT '',
    source text NOT NULL DEFAULT 'csop',
    envelope jsonb NOT NULL DEFAULT '{}'::jsonb,
    received_at text
);

CREATE INDEX IF NOT EXISTS idx_ui_evidence_events_host ON ui_evidence_events (host_id);
CREATE INDEX IF NOT EXISTS idx_ui_evidence_events_delta ON ui_evidence_events (delta_type);
CREATE INDEX IF NOT EXISTS idx_ui_evidence_events_received ON ui_evidence_events (received_at);

COMMIT;
