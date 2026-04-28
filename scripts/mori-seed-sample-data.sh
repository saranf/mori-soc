#!/usr/bin/env bash
# ============================================================================
# MORI SOC — 샘플 데이터 시딩
#
# 사용법:
#   ./scripts/mori-seed-sample-data.sh
#
# soc-postgres 컨테이너에 직접 SQL을 실행하여 데모용 샘플 데이터를 삽입합니다.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Load .env for DB credentials
if [ -f .env ]; then
  set -a; source .env; set +a
fi
DB_NAME="${MORI_DB_NAME:-mori_soc}"
DB_USER="${MORI_DB_USER:-mori}"

run_sql() {
  docker compose exec -T soc-postgres psql -U "$DB_USER" -d "$DB_NAME" -q -v ON_ERROR_STOP=1 <<< "$1"
}

run_sql_file() {
  docker compose exec -T soc-postgres psql -U "$DB_USER" -d "$DB_NAME" -q < "$1"
}

run_sql_lenient() {
  docker compose exec -T soc-postgres psql -U "$DB_USER" -d "$DB_NAME" -q <<< "$1"
}

echo "🌱 Seeding sample data into $DB_NAME..."

# ── 0) Apply schema migrations (idempotent) ──────────────────────────────────
echo "   🔧 Applying schema migrations..."
if [ -f "$PROJECT_ROOT/schema/001_phase1_initial.sql" ]; then
  run_sql_file "$PROJECT_ROOT/schema/001_phase1_initial.sql" >/dev/null 2>&1 || true
fi
if [ -f "$PROJECT_ROOT/schema/002_phase2_compliance_identity.sql" ]; then
  run_sql_file "$PROJECT_ROOT/schema/002_phase2_compliance_identity.sql" >/dev/null 2>&1 || true
fi

# Fix legacy CHECK constraints (older DBs missing 'trivy' in source whitelists)
run_sql_lenient "
ALTER TABLE host_aliases DROP CONSTRAINT IF EXISTS host_aliases_source_check;
ALTER TABLE host_aliases ADD CONSTRAINT host_aliases_source_check
  CHECK (source IN ('fleet', 'wazuh', 'zabbix', 'host_log', 'trivy'));
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_source_check;
ALTER TABLE vulnerabilities ADD CONSTRAINT vulnerabilities_source_check
  CHECK (source IN ('fleet', 'trivy'));
" >/dev/null 2>&1 || true

# ── 1) Hosts ─────────────────────────────────────────────────────────────────
echo "   📦 Hosts..."
run_sql "
INSERT INTO hosts (host_id, hostname, platform, primary_ip, status, risk_score, first_seen_at, last_seen_at) VALUES
  ('h-web-01', 'web-server-01', 'linux', '10.10.1.10', 'online', 35, now() - interval '90 days', now() - interval '5 minutes'),
  ('h-web-02', 'web-server-02', 'linux', '10.10.1.11', 'online', 20, now() - interval '60 days', now() - interval '3 minutes'),
  ('h-db-01',  'db-primary',    'linux', '10.10.2.10', 'online', 72, now() - interval '120 days', now() - interval '1 minute'),
  ('h-db-02',  'db-replica',    'linux', '10.10.2.11', 'online', 15, now() - interval '100 days', now() - interval '2 minutes'),
  ('h-app-01', 'app-server-01', 'linux', '10.10.3.10', 'online', 45, now() - interval '80 days', now() - interval '10 minutes'),
  ('h-pc-01',  'dev-macbook-01','darwin', '10.10.10.50','online', 60, now() - interval '30 days', now() - interval '15 minutes'),
  ('h-pc-02',  'dev-macbook-02','darwin', '10.10.10.51','online', 10, now() - interval '25 days', now() - interval '8 minutes'),
  ('h-pc-03',  'ops-win-01',   'windows','10.10.10.60','offline', 85, now() - interval '45 days', now() - interval '3 days'),
  ('h-fw-01',  'firewall-main','linux',  '10.10.0.1',  'online',  5, now() - interval '200 days', now() - interval '1 minute'),
  ('h-vpn-01', 'vpn-gateway',  'linux',  '10.10.0.5',  'online', 25, now() - interval '150 days', now() - interval '4 minutes')
ON CONFLICT (host_id) DO NOTHING;
"

# ── 2) Host Aliases ──────────────────────────────────────────────────────────
echo "   🔗 Host Aliases..."
run_sql "
INSERT INTO host_aliases (alias_id, host_id, source, alias_type, alias_value) VALUES
  ('a-z-01','h-web-01','zabbix','hostid','10201'), ('a-z-02','h-web-02','zabbix','hostid','10202'),
  ('a-z-03','h-db-01', 'zabbix','hostid','10203'), ('a-z-04','h-db-02', 'zabbix','hostid','10204'),
  ('a-z-05','h-app-01','zabbix','hostid','10205'), ('a-z-06','h-fw-01', 'zabbix','hostid','10206'),
  ('a-z-07','h-vpn-01','zabbix','hostid','10207'),
  ('a-f-01','h-pc-01', 'fleet','uuid','fleet-mac-01'), ('a-f-02','h-pc-02','fleet','uuid','fleet-mac-02'),
  ('a-f-03','h-pc-03', 'fleet','uuid','fleet-win-01'),
  ('a-t-01','h-web-01','trivy','hostname','web-server-01'), ('a-t-02','h-app-01','trivy','hostname','app-server-01'),
  ('a-t-03','h-pc-01', 'trivy','hostname','dev-macbook-01')
ON CONFLICT DO NOTHING;
"

# ── 3) Alerts ────────────────────────────────────────────────────────────────
echo "   🚨 Alerts..."
run_sql "
INSERT INTO alerts (alert_id, source, host_id, severity, message, rule_name, observed_at) VALUES
  ('al-01','wazuh','h-web-01','high','SSH brute force detected','sshd_auth_failed',now()-interval '2 hours'),
  ('al-02','wazuh','h-web-01','critical','Rootkit detected','rootkit_trojans',now()-interval '1 hour'),
  ('al-03','zabbix','h-db-01','high','Disk usage > 90%','disk_usage_high',now()-interval '30 minutes'),
  ('al-04','wazuh','h-pc-03','medium','Malware signature match','malware_detected',now()-interval '3 days'),
  ('al-05','zabbix','h-app-01','medium','CPU spike > 95%','cpu_high',now()-interval '45 minutes'),
  ('al-06','wazuh','h-pc-01','low','USB storage connected','usb_storage_connect',now()-interval '6 hours'),
  ('al-07','zabbix','h-fw-01','high','Unusual outbound traffic','net_anomaly',now()-interval '20 minutes'),
  ('al-08','wazuh','h-vpn-01','medium','Failed VPN auth attempts','vpn_auth_fail',now()-interval '4 hours')
ON CONFLICT (alert_id) DO NOTHING;
"

# ── 4) Vulnerabilities ───────────────────────────────────────────────────────
echo "   🛡️ Vulnerabilities..."
run_sql "
INSERT INTO vulnerabilities (vuln_id, host_id, source, cve, severity, package_name, installed_version, fixed_version, detected_at) VALUES
  ('v-01','h-web-01','trivy','CVE-2024-6387','critical','openssh-server','8.9p1','9.3p2',now()-interval '5 days'),
  ('v-02','h-web-01','trivy','CVE-2024-2961','high','glibc','2.35','2.38',now()-interval '3 days'),
  ('v-03','h-app-01','trivy','CVE-2024-21626','critical','runc','1.1.10','1.1.12',now()-interval '7 days'),
  ('v-04','h-pc-01','fleet','CVE-2024-44308','high','WebKit','617.1.17','617.2.4',now()-interval '2 days'),
  ('v-05','h-db-01','trivy','CVE-2024-0985','high','postgresql','16.1','16.2',now()-interval '10 days'),
  ('v-06','h-web-02','trivy','CVE-2023-44487','medium','nginx','1.24.0','1.25.3',now()-interval '14 days'),
  ('v-07','h-pc-03','fleet','CVE-2024-30088','critical','windows-kernel','10.0.19041','10.0.19045',now()-interval '4 days'),
  ('v-08','h-vpn-01','trivy','CVE-2024-3661','medium','openvpn','2.6.6','2.6.9',now()-interval '8 days')
ON CONFLICT (vuln_id) DO NOTHING;
"

# ── 5) Observations ──────────────────────────────────────────────────────────
echo "   📊 Observations..."
run_sql "
INSERT INTO host_observations (observation_id, source, host_id, observation_type, metric_name, metric_value, unit, observed_at) VALUES
  ('obs-01','zabbix','h-web-01','metric','cpu.util','42','%',now()-interval '5 minutes'),
  ('obs-02','zabbix','h-web-02','metric','cpu.util','28','%',now()-interval '5 minutes'),
  ('obs-03','zabbix','h-db-01','metric','disk.used_pct','91','%',now()-interval '5 minutes'),
  ('obs-04','zabbix','h-db-02','metric','mem.available','65','%',now()-interval '5 minutes'),
  ('obs-05','zabbix','h-app-01','metric','cpu.util','96','%',now()-interval '5 minutes'),
  ('obs-06','zabbix','h-fw-01','metric','net.out_bps','850000000','bps',now()-interval '5 minutes'),
  ('obs-07','fleet','h-pc-01','metric','disk.encrypted','1','bool',now()-interval '15 minutes'),
  ('obs-08','fleet','h-pc-02','metric','disk.encrypted','1','bool',now()-interval '8 minutes'),
  ('obs-09','fleet','h-pc-03','metric','disk.encrypted','0','bool',now()-interval '3 days')
ON CONFLICT (observation_id) DO NOTHING;
"

# ── 6) Control Check Results ─────────────────────────────────────────────────
echo "   ✅ Control Check Results..."
run_sql "
INSERT INTO control_check_results (check_id, control_id, entity_type, entity_id, status, checked_at, owner, note, remediation_due_at) VALUES
  ('cc-01','A.8.1','host','h-web-01','pass',now()-interval '1 day','보안팀','자산 등록 확인',NULL),
  ('cc-02','A.8.1','host','h-db-01','pass',now()-interval '1 day','보안팀','자산 등록 확인',NULL),
  ('cc-03','A.8.1','host','h-pc-03','fail',now()-interval '1 day','보안팀','오프라인 자산 미관리',now()+interval '7 days'),
  ('cc-04','A.8.8','host','h-web-01','fail',now()-interval '12 hours','보안팀','critical 취약점 미패치',now()+interval '3 days'),
  ('cc-05','A.8.8','host','h-app-01','warning',now()-interval '12 hours','보안팀','critical 취약점 존재',now()+interval '5 days'),
  ('cc-06','A.5.15','account','acct-admin','pass',now()-interval '2 days','IT팀','관리자 권한 적정',NULL),
  ('cc-07','A.5.15','account','acct-dev01','warning',now()-interval '2 days','IT팀','sudo 권한 검토 필요',now()+interval '14 days'),
  ('cc-08','A.8.15','host','h-db-01','pass',now()-interval '3 days','DBA팀','로그 수집 정상',NULL),
  ('cc-09','A.8.15','host','h-pc-03','fail',now()-interval '3 days','보안팀','3일간 로그 미수집',now()-interval '1 day'),
  ('cc-10','A.5.23','policy','policy-backup','pass',now()-interval '5 days','인프라팀','백업 정책 준수',NULL),
  ('cc-11','A.8.9','host','h-web-02','not_applicable',now()-interval '1 day','보안팀','해당 없음',NULL),
  ('cc-12','2.5.1','host','h-fw-01','pass',now()-interval '6 hours','네트워크팀','방화벽 정책 점검 완료',NULL)
ON CONFLICT (check_id) DO NOTHING;
"

# ── 7) Directory Accounts ────────────────────────────────────────────────────
echo "   👤 Directory Accounts..."
run_sql "
INSERT INTO directory_accounts (account_id, username, display_name, email, department, status, is_privileged, last_login_at) VALUES
  ('acct-admin','admin','시스템관리자','admin@mori.local','IT팀','active',true,now()-interval '1 hour'),
  ('acct-sec01','security01','보안담당자','sec01@mori.local','보안팀','active',true,now()-interval '3 hours'),
  ('acct-dev01','developer01','개발자1','dev01@mori.local','개발팀','active',false,now()-interval '2 hours'),
  ('acct-dev02','developer02','개발자2','dev02@mori.local','개발팀','active',false,now()-interval '5 hours'),
  ('acct-ops01','operator01','운영자1','ops01@mori.local','인프라팀','active',false,now()-interval '30 minutes'),
  ('acct-dba01','dba01','DBA','dba01@mori.local','DBA팀','active',true,now()-interval '4 hours'),
  ('acct-ext01','external01','외부인력','ext01@partner.com','외부','disabled',false,now()-interval '30 days')
ON CONFLICT (account_id) DO NOTHING;
"

# ── 8) Privilege Bindings ────────────────────────────────────────────────────
echo "   🔐 Privilege Bindings..."
run_sql "
INSERT INTO privilege_bindings (binding_id, account_id, privilege_type, target, granted_at, granted_by) VALUES
  ('pb-01','acct-admin','domain_admin','*',now()-interval '365 days','system'),
  ('pb-02','acct-sec01','sudo','h-web-01',now()-interval '90 days','acct-admin'),
  ('pb-03','acct-sec01','sudo','h-web-02',now()-interval '90 days','acct-admin'),
  ('pb-04','acct-dba01','db_admin','h-db-01',now()-interval '180 days','acct-admin'),
  ('pb-05','acct-dba01','db_admin','h-db-02',now()-interval '180 days','acct-admin'),
  ('pb-06','acct-dev01','sudo','h-app-01',now()-interval '60 days','acct-admin')
ON CONFLICT (binding_id) DO NOTHING;
"

# ── 9) Group Memberships ────────────────────────────────────────────────────
echo "   👥 Group Memberships..."
run_sql "
INSERT INTO group_memberships (membership_id, account_id, group_name, source, synced_at) VALUES
  ('gm-01','acct-admin','Domain Admins','ldap',now()),
  ('gm-02','acct-sec01','Security Team','ldap',now()),
  ('gm-03','acct-sec01','SOC Operators','ldap',now()),
  ('gm-04','acct-dev01','Developers','ldap',now()),
  ('gm-05','acct-dev02','Developers','ldap',now()),
  ('gm-06','acct-ops01','Operations','ldap',now()),
  ('gm-07','acct-dba01','DBA Group','ldap',now()),
  ('gm-08','acct-dba01','Domain Admins','ldap',now())
ON CONFLICT (membership_id) DO NOTHING;
"

# ── 10) Fleet Query Results (osquery) ────────────────────────────────────────
echo "   🔍 Fleet Query Results..."
run_sql "
INSERT INTO query_results (query_result_id, source, host_id, query_name, query_text, observed_at, result_json) VALUES
  ('qr-01','fleet','h-pc-01','installed_apps','SELECT name, version FROM apps;',now()-interval '20 minutes',
    '{\"rows\":[{\"name\":\"Slack\",\"version\":\"4.40.121\"},{\"name\":\"Chrome\",\"version\":\"131.0.6778\"}]}'::jsonb),
  ('qr-02','fleet','h-pc-02','installed_apps','SELECT name, version FROM apps;',now()-interval '12 minutes',
    '{\"rows\":[{\"name\":\"VS Code\",\"version\":\"1.95.3\"},{\"name\":\"Docker Desktop\",\"version\":\"4.36.0\"}]}'::jsonb),
  ('qr-03','fleet','h-pc-03','windows_security','SELECT * FROM windows_security_center;',now()-interval '3 days',
    '{\"rows\":[{\"firewall\":\"Good\",\"antivirus\":\"Snoozed\",\"autoupdate\":\"Off\"}]}'::jsonb),
  ('qr-04','fleet','h-pc-01','disk_encryption','SELECT name, encrypted FROM disk_encryption;',now()-interval '15 minutes',
    '{\"rows\":[{\"name\":\"/dev/disk1s1\",\"encrypted\":1}]}'::jsonb),
  ('qr-05','fleet','h-pc-02','disk_encryption','SELECT name, encrypted FROM disk_encryption;',now()-interval '8 minutes',
    '{\"rows\":[{\"name\":\"/dev/disk1s1\",\"encrypted\":1}]}'::jsonb),
  ('qr-06','fleet','h-pc-03','disk_encryption','SELECT name, encrypted FROM disk_encryption;',now()-interval '3 days',
    '{\"rows\":[{\"name\":\"C:\\\\\",\"encrypted\":0}]}'::jsonb),
  ('qr-07','fleet','h-pc-01','logged_in_users','SELECT user, host, time FROM logged_in_users;',now()-interval '5 minutes',
    '{\"rows\":[{\"user\":\"developer01\",\"host\":\"console\",\"time\":1714286400}]}'::jsonb),
  ('qr-08','fleet','h-pc-03','startup_items','SELECT name, path FROM startup_items;',now()-interval '3 days',
    '{\"rows\":[{\"name\":\"OneDrive\",\"path\":\"C:\\\\Program Files\\\\Microsoft OneDrive\"},{\"name\":\"Unknown.exe\",\"path\":\"C:\\\\Users\\\\Public\\\\unknown.exe\"}]}'::jsonb)
ON CONFLICT (query_result_id) DO NOTHING;
"

# ── 11) Source Syncs ─────────────────────────────────────────────────────────
echo "   🔄 Source Syncs..."
run_sql "
INSERT INTO source_syncs (source, status, last_sync_at, last_success_at, records_collected, envelopes_normalized, entities_saved) VALUES
  ('zabbix','success',now()-interval '1 minute',now()-interval '1 minute',47,47,94),
  ('fleet','success',now()-interval '2 minutes',now()-interval '2 minutes',23,23,46),
  ('trivy','success',now()-interval '5 minutes',now()-interval '5 minutes',8,8,8),
  ('wazuh','success',now()-interval '3 minutes',now()-interval '3 minutes',31,31,39)
ON CONFLICT (source) DO UPDATE SET
  status=EXCLUDED.status, last_sync_at=EXCLUDED.last_sync_at,
  last_success_at=EXCLUDED.last_success_at, records_collected=EXCLUDED.records_collected,
  envelopes_normalized=EXCLUDED.envelopes_normalized, entities_saved=EXCLUDED.entities_saved;
"

echo ""
echo "   ✅ Sample data seeded successfully!"
echo "   📊 10 hosts, 8 alerts, 8 vulnerabilities, 9 observations, 8 fleet queries, 12 control checks, 7 accounts"

