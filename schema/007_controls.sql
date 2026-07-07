BEGIN;

-- ── Phase 2: 통제 카탈로그 (ISMS-P × ISO 27001) ─────────────────────────────────
-- controls/ 의 YAML(정본)을 기동 시 여기로 싱크한다(YAML→DB, evidence mapper).
-- 값 원칙(schema/003~006 과 동일): 배열/구조는 jsonb, 나머지는 text.
-- 정본은 리포지토리의 controls/*.yaml 이며, 이 테이블은 조회·매핑용 투영(projection)이다.

CREATE TABLE IF NOT EXISTS controls (
    framework text NOT NULL,             -- 'isms-p' | 'iso27001'
    id text NOT NULL,                    -- '2.11.2' | 'A.8.8'
    version text NOT NULL DEFAULT '',
    domain text NOT NULL DEFAULT '',
    section text NOT NULL DEFAULT '',
    title_ko text NOT NULL DEFAULT '',
    title_en text NOT NULL DEFAULT '',
    intent_ko text NOT NULL DEFAULT '',
    evidence_hint_ko text NOT NULL DEFAULT '',
    evidence_sources jsonb NOT NULL DEFAULT '[]'::jsonb,  -- ["trivy","zabbix",...]
    mori_intents jsonb NOT NULL DEFAULT '[]'::jsonb,
    tags jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at text,
    PRIMARY KEY (framework, id)
);

-- ISMS-P ↔ ISO N:M 매핑 (한 행 = isms_p ↔ iso27001 한 쌍)
CREATE TABLE IF NOT EXISTS control_mappings (
    isms_p_id text NOT NULL,
    iso27001_id text NOT NULL,
    relation text NOT NULL DEFAULT 'related',   -- equivalent|subset|superset|related
    note_ko text NOT NULL DEFAULT '',
    PRIMARY KEY (isms_p_id, iso27001_id)
);

-- 심사 단골 결함 사례. mori_signal 은 대시보드 evidence-gaps 타일 키와 연결.
CREATE TABLE IF NOT EXISTS control_defects (
    id text PRIMARY KEY,
    controls jsonb NOT NULL DEFAULT '[]'::jsonb,  -- ["2.11.2","A.8.8"]
    title_ko text NOT NULL DEFAULT '',
    symptom_ko text NOT NULL DEFAULT '',
    evidence_gap_ko text NOT NULL DEFAULT '',
    mori_signal text NOT NULL DEFAULT '',
    fix_ko text NOT NULL DEFAULT '',
    severity text NOT NULL DEFAULT '',
    updated_at text
);

CREATE INDEX IF NOT EXISTS idx_controls_framework ON controls (framework);
CREATE INDEX IF NOT EXISTS idx_control_mappings_iso ON control_mappings (iso27001_id);
CREATE INDEX IF NOT EXISTS idx_control_defects_signal ON control_defects (mori_signal);

COMMIT;
