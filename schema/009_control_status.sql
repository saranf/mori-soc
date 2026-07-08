-- 009_control_status.sql — 통제별 런타임 이행 상태 (M2-7)
--
-- controls / control_mappings (schema/007) 는 YAML 원본의 읽기전용 사본이다.
-- control_status 는 앱이 쓰는 유일한 테이블로, 통제별 이행 상태·담당자·예외사유·
-- 개선계획·기한을 편집·영속한다. 통제 카탈로그(원본)와 분리되어 재싱크에도 유지된다.

-- controls 의 PK 는 (framework, id) 복합키라 id 단독 FK 는 불가.
-- ISMS-P('2.11.2') 와 ISO('A.8.8') id 형식이 서로 겹치지 않아 control_id 단독으로 유일하며,
-- 카탈로그에서 통제가 사라져도 남는 status 행은 표시되지 않을 뿐 해가 없으므로 FK 없이 둔다.
CREATE TABLE IF NOT EXISTS control_status (
    control_id        TEXT PRIMARY KEY,
    status            TEXT NOT NULL DEFAULT '미정',
    owner             TEXT,
    exception_reason  TEXT,
    improvement_plan  TEXT,
    due_date          DATE,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by        TEXT
);

COMMENT ON TABLE control_status IS '통제별 런타임 이행 상태(편집 대상). 카탈로그 원본(controls)과 분리, 재싱크에도 유지.';
