-- 012 — code_review 를 alert/source_sync 소스로 허용 (Track 2: SDLC 증적 소스)
-- claude-code-security-review findings 를 트리아지 가능한 alert 로 적재하기 위해
-- alerts / source_syncs 의 소스 CHECK 제약에 'code_review' 를 추가한다.
-- 재실행 안전(idempotent): 기존 제약을 DROP 후 재생성.

ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_source_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_source_check
    CHECK (source IN ('wazuh', 'zabbix', 'host_log', 'code_review'));

ALTER TABLE source_syncs DROP CONSTRAINT IF EXISTS source_syncs_source_check;
ALTER TABLE source_syncs ADD CONSTRAINT source_syncs_source_check
    CHECK (source IN ('fleet', 'wazuh', 'zabbix', 'host_log', 'trivy', 'code_review'));
