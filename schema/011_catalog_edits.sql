-- 011_catalog_edits.sql — 카탈로그 편집 오버레이 + 수기 증적 레코드 (M2-8)
--
-- 정본 카탈로그(controls/*.yaml → schema/007 controls)는 읽기전용이다. admin이
-- 통제를 추가/수정/삭제하거나 법령 텍스트를 NLP로 임포트한 결과는 여기 오버레이에
-- 쌓이고, 카탈로그 로드 시 base 위에 병합된다(control_status 와 같은 분리 원칙 —
-- 카탈로그 재싱크에도 유지). op='delete' 는 base 통제를 화면에서 숨긴다.
CREATE TABLE IF NOT EXISTS catalog_controls (
    control_id        TEXT PRIMARY KEY,
    op                TEXT NOT NULL DEFAULT 'upsert',   -- upsert | delete
    framework         TEXT NOT NULL DEFAULT '',         -- isms-p | iso27001 | custom
    version           TEXT NOT NULL DEFAULT '',
    domain            TEXT NOT NULL DEFAULT '',
    section           TEXT NOT NULL DEFAULT '',
    title_ko          TEXT NOT NULL DEFAULT '',
    title_en          TEXT NOT NULL DEFAULT '',
    intent_ko         TEXT NOT NULL DEFAULT '',
    intent_en         TEXT NOT NULL DEFAULT '',
    evidence_hint_ko  TEXT NOT NULL DEFAULT '',
    evidence_hint_en  TEXT NOT NULL DEFAULT '',
    evidence_sources  JSONB NOT NULL DEFAULT '[]'::jsonb,
    tags              JSONB NOT NULL DEFAULT '[]'::jsonb,
    status            TEXT NOT NULL DEFAULT 'draft',     -- draft | reviewed
    origin            TEXT NOT NULL DEFAULT 'manual',    -- manual | nlp
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by        TEXT
);

-- 통제별 수기 증적 레코드 — 라이브 집계로 안 잡히는 증적을 직접 문서화(정책 캡처,
-- 회의록, 결재 링크 등). 다운로드 시 라이브 증적과 합본(CSV/PDF)된다.
CREATE TABLE IF NOT EXISTS control_evidence (
    id            TEXT PRIMARY KEY,
    control_id    TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    body          TEXT NOT NULL DEFAULT '',
    collected_by  TEXT NOT NULL DEFAULT '',
    collected_at  TEXT NOT NULL DEFAULT '',   -- YYYY-MM-DD (수집/작성일)
    reference     TEXT NOT NULL DEFAULT '',    -- 링크/문서 위치
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT
);

CREATE INDEX IF NOT EXISTS idx_control_evidence_control ON control_evidence (control_id);

COMMENT ON TABLE catalog_controls IS 'admin 편집/NLP 임포트 통제 오버레이(base 카탈로그와 분리, 재싱크에도 유지).';
COMMENT ON TABLE control_evidence IS '통제별 수기 증적 레코드(라이브 증적과 합본 다운로드).';
