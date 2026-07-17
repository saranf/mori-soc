-- 015_evidence_approvals.sql — 증적 승인 라이프사이클·버전 스냅샷(#4).
-- 승인본은 불변: 새 스캔이 control_evidence 를 갱신해도 이 스냅샷은 덮어쓰지 않는다.
-- approval_id 는 애플리케이션이 결정적으로 생성(evidence_id·content_hash·status·시각).
CREATE TABLE IF NOT EXISTS ui_evidence_approvals (
    approval_id      TEXT PRIMARY KEY,
    control_id       TEXT,
    evidence_id      TEXT,
    content_hash     TEXT,
    version          TEXT,
    status           TEXT NOT NULL,       -- draft|reviewed|approved|superseded|revoked
    reviewer         TEXT,
    approver         TEXT,
    reviewed_at      TIMESTAMPTZ,
    approved_at      TIMESTAMPTZ,
    pdf_sha256       TEXT,
    prev_approval_id TEXT,
    supersede_reason TEXT,
    actor            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_evidence_approvals_control ON ui_evidence_approvals (control_id);

COMMENT ON TABLE ui_evidence_approvals IS '증적 승인 스냅샷(불변). 새 스캔이 나와도 과거 승인본을 보존 — 감사 시점 재현.';
