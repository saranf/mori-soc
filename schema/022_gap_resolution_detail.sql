-- 022_gap_resolution_detail.sql — Gap 해결 근거 영속(2차 리뷰 #19).
-- resolved 의 근거(resolution_type·verifier·verified_at·verifying_scan)를 JSONB 로 보관해
-- '사람이 눌렀다'로 끝나지 않게(재검증 근거를 postgres 에도 남긴다).
ALTER TABLE ui_gaps ADD COLUMN IF NOT EXISTS resolution_detail JSONB NOT NULL DEFAULT '{}'::jsonb;
