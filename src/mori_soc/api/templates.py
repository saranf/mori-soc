"""HTML page templates for the MORI SOC web UI (Task J-2 modularization).

The render functions here build the standalone HTML pages served by the FastAPI
app in :mod:`mori_soc.api.server`. They depend only on the i18n runtime helpers
(:mod:`mori_soc.api.i18n`) so they can be imported without pulling in the route
layer. The larger dashboard/console templates are moved here incrementally.
"""

import json
import os

from mori_soc.api.i18n import (
    _i18n_script,
    _i18n_toggle_html,
    _DASHBOARD_I18N,
    _ADMIN_I18N,
    _LOGIN_I18N,
    _SIGNUP_I18N,
)
from mori_soc.services.intent_parser import QUERY_GUIDE_EXAMPLES


DOCS_PORTAL_URL = os.getenv("MORI_DOCS_PORTAL_URL", "http://mori.rmstudio.co.kr:37854/")
FLEET_UI_URL = os.getenv("MORI_FLEET_UI_URL", "")
ZABBIX_UI_URL = os.getenv("MORI_ZABBIX_UI_URL", "")
WAZUH_UI_URL = os.getenv("MORI_WAZUH_UI_URL", "")
USER_DASHBOARD_CARD_LABELS = {
    "total_hosts": "Total Hosts",
    "offline_hosts": "Offline Hosts",
    "alerts_24h": "High Alerts 24h",
    "critical_vulns": "Critical Vulns",
    "sources_reporting": "Sources Reporting",
    "sources_healthy": "Healthy Collectors",
    "ingested_records": "Ingested Records",
}
USER_DASHBOARD_SECTION_LABELS = {
    "security_hero": "🛡️ Security Overview",
    "infra_status": "Infra Status (24h/12h)",
    "source_coverage": "Source Coverage",
    "latest_status": "Latest Host Status",
    "risk_summary": "Risk Summary",
    "recent_activity": "Recent Activity",
}
USER_DASHBOARD_ASSET_COLUMN_LABELS = {
    "show_importance": "중요도 컬럼",
    "show_isms_control": "ISMS-P 통제 컬럼",
    "show_iso27001_control": "ISO 27001 통제 컬럼",
}
USER_DASHBOARD_GUIDE_LABELS = {
    "zabbix_setup": "🖧 Zabbix 에이전트 설정",
    "fleet_install": "🖥️ Fleet 에이전트 설치",
    "isms_criteria": "📋 ISMS-P 심사 기준",
    "iso27001_criteria": "🌐 ISO 27001 기준",
    "ldap_setup": "🔐 LDAP 통합 설정",
    "incident_response": "🚨 인시던트 대응 절차",
    "security_policy": "📜 보안 정책 가이드",
    "risk_methodology": "🎯 위험성 평가 기준",
}
DEFAULT_USER_DASHBOARD_PREFERENCES = {
    "cards": {
        "total_hosts": True,
        "offline_hosts": True,
        "alerts_24h": True,
        "critical_vulns": True,
        "sources_reporting": False,
        "sources_healthy": False,
        "ingested_records": False,
    },
    "sections": {
        "security_hero": True,
        "infra_status": True,
        "source_coverage": False,
        "latest_status": False,
        "risk_summary": True,
        "recent_activity": False,
    },
    "asset_columns": {
        "show_importance": True,
        "show_isms_control": True,
        "show_iso27001_control": True,
    },
    "guides": {
        "zabbix_setup": True,
        "fleet_install": True,
        "isms_criteria": True,
        "iso27001_criteria": True,
        "ldap_setup": True,
        "incident_response": True,
        "security_policy": True,
        "risk_methodology": True,
    },
}


DEFAULT_UI_PAYLOAD = {
    "intent": "offline_hosts",
    "scope": {"time_range": "24h"},
    "filters": {},
}


def render_query_console_html(docs_url: str = DOCS_PORTAL_URL) -> str:
    payload_json = json.dumps(DEFAULT_UI_PAYLOAD, indent=2, ensure_ascii=False)
    default_payload_json = json.dumps(DEFAULT_UI_PAYLOAD, ensure_ascii=False)
    guide_examples_json = json.dumps(list(QUERY_GUIDE_EXAMPLES), ensure_ascii=False)
    default_preferences_json = json.dumps(DEFAULT_USER_DASHBOARD_PREFERENCES, ensure_ascii=False)
    card_labels_json = json.dumps(USER_DASHBOARD_CARD_LABELS, ensure_ascii=False)
    section_labels_json = json.dumps(USER_DASHBOARD_SECTION_LABELS, ensure_ascii=False)
    asset_column_labels_json = json.dumps(USER_DASHBOARD_ASSET_COLUMN_LABELS, ensure_ascii=False)
    guide_labels_json = json.dumps(USER_DASHBOARD_GUIDE_LABELS, ensure_ascii=False)
    html = """<!doctype html>
<html lang=\"ko\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title data-i18n-doctitle=\"admin.doctitle\">MORI Security Dashboard</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0b1220; color: #e5e7eb; }
    .wrap { max-width: 1440px; margin: 0 auto; padding: 28px 20px 48px; }
    .hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 18px; }
    .hero h1 { margin: 0 0 8px; font-size: 32px; }
    .hero p { margin: 0; color: #94a3b8; max-width: 860px; line-height: 1.5; }
    .links { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
    .links a { color: #cfe3ff; text-decoration: none; border: 1px solid #334155; padding: 8px 12px; border-radius: 999px; background: #0f172a; }
    .top-actions { display: flex; gap: 10px; flex-wrap: wrap; }
    .layout { display: grid; grid-template-columns: minmax(0, 2fr) minmax(340px, 420px); gap: 16px; align-items: start; }
    .stack { display: grid; gap: 16px; }
    .metrics { display: grid; gap: 12px; grid-template-columns: repeat(6, minmax(0, 1fr)); }
    .card { background: linear-gradient(180deg, #101827 0%, #0f172a 100%); border: 1px solid #233046; border-radius: 16px; padding: 18px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.18); }
    .metric-card { cursor: pointer; transition: transform 0.15s ease, border-color 0.15s ease; }
    .metric-card:hover { transform: translateY(-1px); border-color: #38bdf8; }
    .metric-card:focus-visible { outline: 2px solid #38bdf8; outline-offset: 2px; }
    .metric-label { color: #94a3b8; font-size: 13px; margin-bottom: 8px; }
    .metric-value { font-size: 28px; font-weight: 800; }
    .metric-sub { margin-top: 6px; color: #7dd3fc; font-size: 13px; }
    .card h2 { margin: 0 0 12px; font-size: 18px; }
    .subtext { color: #94a3b8; font-size: 13px; margin-bottom: 12px; }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #1f2937; vertical-align: top; }
    th { color: #94a3b8; font-weight: 600; }
    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .badge.online { background: rgba(34, 197, 94, 0.12); color: #86efac; }
    .badge.offline { background: rgba(248, 113, 113, 0.12); color: #fca5a5; }
    .badge.unknown { background: rgba(250, 204, 21, 0.12); color: #fde68a; }
    .coverage { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .coverage-item { background: #0b1220; border: 1px solid #223148; border-radius: 14px; padding: 14px; }
    .coverage-item strong { display: block; font-size: 22px; margin-top: 8px; }
    .list { display: grid; gap: 10px; }
    .list-item { border: 1px solid #1f2937; border-radius: 12px; padding: 12px; background: #0b1220; }
    .list-item .top { display: flex; gap: 12px; justify-content: space-between; margin-bottom: 6px; }
    .list-item .meta { color: #94a3b8; font-size: 12px; }
    .empty { color: #94a3b8; font-size: 14px; padding: 6px 0; }
    .row { display: grid; gap: 8px; margin-bottom: 12px; }
    label { font-size: 13px; color: #cbd5e1; }
    input, select, textarea, button { width: 100%; box-sizing: border-box; border-radius: 12px; border: 1px solid #334155; background: #0b1220; color: #e5e7eb; padding: 10px 12px; }
    textarea { resize: vertical; min-height: 120px; font-family: ui-monospace, SFMono-Regular, monospace; }
    /* 버튼 계층: primary(저장/실행) / secondary(보조) / ghost(중립) / danger(삭제) */
    button { border: 1px solid #1e3a5f; background: #1e3a5f; color: #93c5fd; font-weight: 600; cursor: pointer; font-size: 13px; }
    button:hover { background: #1e4a7a; border-color: #2563eb; color: #bfdbfe; }
    button.primary { background: #1d4ed8; border-color: #2563eb; color: #fff; }
    button.primary:hover { background: #2563eb; }
    button.secondary { background: #1e293b; border: 1px solid #334155; color: #94a3b8; }
    button.secondary:hover { background: #263345; color: #cbd5e1; }
    button.ghost { background: transparent; border: 1px solid #334155; color: #64748b; }
    button.ghost:hover { background: #0f172a; color: #94a3b8; }
    button.danger { background: #450a0a; border: 1px solid #7f1d1d; color: #fca5a5; }
    button.danger:hover { background: #7f1d1d; }
    .actions { display: grid; gap: 10px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .actions a, .top-actions a { display: inline-flex; align-items: center; justify-content: center; border-radius: 12px; border: 1px solid #334155; background: #172033; color: #94a3b8; padding: 10px 12px; text-decoration: none; font-weight: 600; font-size: 13px; }
    .actions a:hover, .top-actions a:hover { background: #1e293b; color: #e5e7eb; }
    .quick-actions { display: grid; gap: 8px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .status-line { color: #94a3b8; font-size: 13px; margin-top: 8px; }
    .mono { font-family: ui-monospace, SFMono-Regular, monospace; }
    .query-result-area { min-height: 80px; background: #0b1220; border: 1px solid #334155; border-radius: 12px; padding: 12px; overflow: auto; font-size: 13px; }
    .result-placeholder { color: #64748b; font-style: italic; }
    .result-error { color: #f87171; font-family: ui-monospace, SFMono-Regular, monospace; white-space: pre-wrap; font-size: 12px; }
    .result-summary { color: #7dd3fc; font-size: 13px; margin-bottom: 10px; padding: 8px 12px; background: #0f2035; border-radius: 8px; border-left: 3px solid #3b82f6; }
    .result-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 4px; }
    .result-table th { background: #0f2035; color: #93c5fd; font-weight: 600; text-align: left; padding: 8px 10px; border-bottom: 1px solid #1e3a5f; }
    .result-table td { padding: 7px 10px; border-bottom: 1px solid #1a2d45; color: #e5e7eb; vertical-align: top; word-break: break-all; }
    .result-table tr:last-child td { border-bottom: none; }
    .result-table tr:hover td { background: #0d1d30; }
    .result-badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: #1e3a5f; color: #93c5fd; }
    .result-badge.wazuh { background: #2d1f5e; color: #c4b5fd; }
    .result-badge.zabbix { background: #1e3a5f; color: #93c5fd; }
    .result-badge.fleet { background: #1a3324; color: #6ee7b7; }
    .result-badge.trivy { background: #3b1f0e; color: #fbbf24; }
    .result-badge.hosts { background: #0f2035; color: #7dd3fc; }
    .top-actions button, .guide-chips button, .guide-list button { width: auto; }
    .guide-chips, .guide-list { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .chip { padding: 8px 12px; border-radius: 999px; }
    .toggle-grid { display: grid; gap: 8px; }
    .toggle-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; border: 1px solid #223148; border-radius: 12px; background: #0b1220; }
    .toggle-item input { width: auto; margin: 0; }
    .guide-banner { margin-top: 12px; border-radius: 12px; padding: 12px; border: 1px solid #334155; background: #111827; }
    .guide-banner strong { display: block; margin-bottom: 6px; }
    .guide-banner.need-guide { border-color: #f59e0b; background: rgba(245, 158, 11, 0.12); }
    .guide-banner.warning { border-color: #38bdf8; background: rgba(56, 189, 248, 0.1); }
    dialog { border: 1px solid #334155; border-radius: 18px; padding: 0; background: #0f172a; color: #e5e7eb; width: min(760px, calc(100vw - 32px)); }
    dialog::backdrop { background: rgba(2, 6, 23, 0.74); }
    .guide-dialog { padding: 20px; }
    .guide-dialog-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    .guide-dialog-head h3 { margin: 0; font-size: 20px; }
    .guide-dialog-copy { color: #94a3b8; font-size: 14px; line-height: 1.5; }
    .dialog-body { padding: 0 20px 20px; max-height: 60vh; overflow: auto; }
    /* Admin tabs */
    .atab-panel { display: none; margin-top: 16px; }
    .atab-panel.active { display: block; }
    #admin_tabs_nav { margin: 16px 0 0; }
    /* Tab nav buttons must never stretch to 100% width */
    .tabs-nav button { width: auto; display: inline-flex; align-items: center; white-space: nowrap; }
    /* Bottom nav (mobile only) */
    .admin-bottom-nav { display: none; }
    @media (max-width: 1240px) {
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .layout { grid-template-columns: 1fr; }
    }
    @media (max-width: 768px) {
      html, body { overflow-x: hidden; }
      .wrap { padding: 16px 12px 80px; max-width: 100%; box-sizing: border-box; }
      .hero { flex-direction: column; gap: 10px; margin-bottom: 12px; }
      .hero h1 { font-size: 22px; }
      .hero p { font-size: 13px; }
      .links, .top-actions { flex-wrap: wrap; gap: 8px; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .coverage, .quick-actions, .actions { grid-template-columns: 1fr; }
      .card { padding: 14px 12px; border-radius: 12px; }
      .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
      table { min-width: 480px; }
      /* 상단 탭 숨기고 하단 탭 표시 */
      .tabs-nav { display: none !important; }
      .admin-bottom-nav {
        display: flex;
        position: fixed;
        bottom: 0; left: 0; right: 0;
        z-index: 1000;
        background: #0f172a;
        border-top: 1px solid #233046;
        padding: 0;
        box-shadow: 0 -4px 20px rgba(0,0,0,.4);
      }
      .admin-bottom-nav button {
        flex: 1;
        width: auto;
        background: none;
        border: none;
        border-top: 2px solid transparent;
        padding: 8px 4px 10px;
        color: #64748b;
        font-size: 10px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
        border-radius: 0;
        transition: color 0.15s;
      }
      .admin-bottom-nav button .bn-icon { font-size: 20px; line-height: 1; }
      .admin-bottom-nav button.active { color: #38bdf8; border-top-color: #38bdf8; }
    }
    @media (max-width: 480px) {
      .metrics { grid-template-columns: 1fr 1fr; }
      .metric-value { font-size: 22px; }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <div>
        <h1 data-i18n=\"admin.hero.title\">MORI — 점검·통제 운영 콘솔</h1>
        <p data-i18n=\"admin.hero.intro\">통제 항목 점검 결과를 관리하고, 수집 데이터를 교차 검증하며, 사용자 대시보드 노출 범위를 제어하는 관리자 운영 콘솔입니다.</p>
        <div class=\"links\">
          <a href=\"__DOCS_PORTAL_URL__\" target=\"_blank\" rel=\"noreferrer\" data-i18n=\"admin.links.docs\">운영 문서 / 포털</a>
          <a href=\"/docs\" target=\"_blank\" rel=\"noreferrer\" data-i18n=\"admin.links.api\">📋 API 문서 (Swagger)</a>
          <a href=\"/health\" target=\"_blank\" rel=\"noreferrer\">Health JSON</a>
          <a href=\"/dashboard/summary\" target=\"_blank\" rel=\"noreferrer\">Dashboard JSON</a>
          <a href=\"/catalog\" target=\"_blank\" rel=\"noreferrer\">Query Catalog JSON</a>
        </div>
      </div>
      <div class=\"top-actions\">
        <span id=\"admin_user_badge\" style=\"font-size:13px;color:#94a3b8\"></span>
        <a href=\"/ui\" data-i18n=\"admin.actions.user_dashboard\">사용자 대시보드</a>
        <button id=\"query_guide\" class=\"ghost\" data-i18n=\"admin.actions.query_guide\">Query Guide</button>
        <button id=\"refresh_dashboard\" class=\"ghost\" data-i18n=\"admin.actions.refresh\">Refresh Dashboard</button>
        <div class=\"account-wrap\" style=\"position:relative\">
          <button id=\"account_btn\" type=\"button\" onclick=\"toggleAccountMenu()\" class=\"ghost\" data-i18n=\"admin.actions.account\">⚙️ 계정 ▾</button>
          <div id=\"account_menu\" style=\"display:none;position:absolute;right:0;top:calc(100% + 6px);background:#0f2035;border:1px solid #1e3a5f;border-radius:10px;padding:12px;min-width:220px;z-index:9998;box-shadow:0 8px 24px rgba(0,0,0,0.45)\">
            <div style=\"font-size:12px;color:#94a3b8;margin-bottom:6px\" data-i18n=\"admin.account.language\">언어 / Language</div>
            __I18N_TOGGLE__
            <div style=\"border-top:1px solid #1e3a5f;margin:10px 0\"></div>
            <a href=\"/auth/logout\" style=\"display:block;text-align:center;color:#ef4444;font-size:13px\" data-i18n=\"admin.actions.logout\">로그아웃</a>
          </div>
        </div>
      </div>
    </section>

    <!-- ── Admin Tab Nav (8 tabs, Phase 2 정렬) ────────────────────────── -->
    <nav class=\"tabs-nav\" id=\"admin_tabs_nav\">
      <button class=\"active\" data-atab=\"overview\" onclick=\"switchAdminTab('overview')\" data-i18n=\"admin.tab.overview\">📊 Overview</button>
      <button data-atab=\"compliance\" onclick=\"switchAdminTab('compliance')\" data-i18n=\"admin.tab.compliance\">✅ Compliance</button>
      <button data-atab=\"triage\" onclick=\"switchAdminTab('triage')\" data-i18n=\"admin.tab.triage\">🚨 Triage &amp; Incidents</button>
      <button data-atab=\"remediation\" onclick=\"switchAdminTab('remediation')\" data-i18n=\"admin.tab.remediation\">🔧 Remediation</button>
      <button data-atab=\"assets\" onclick=\"switchAdminTab('assets')\" data-i18n=\"admin.tab.assets\">👤 자산 / Owners</button>
      <button data-atab=\"access\" onclick=\"switchAdminTab('access')\" data-i18n=\"admin.tab.access\">🛡️ Access Control</button>
      <button data-atab=\"logs\" onclick=\"switchAdminTab('logs')\" data-i18n=\"admin.tab.logs\">📝 Audit &amp; Logs</button>
      <button data-atab=\"settings\" onclick=\"switchAdminTab('settings')\" data-i18n=\"admin.tab.settings\">⚙️ Settings</button>
    </nav>

    <!-- ── Tab: Overview ──────────────────────────────────────────────────── -->
    <div class=\"atab-panel active\" id=\"atab_overview\">
      <section class=\"metrics\" id=\"overview_cards\"></section>
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.phase2_health\">📦 Phase 2 데이터 헬스</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.phase2_health\">PostgreSQL → InMemoryQueryStore 로 로드된 Phase 2 시드 데이터의 현재 카운트입니다. 0이면 시드 누락 또는 schema 002 미적용일 수 있습니다.</div>
          <div class=\"coverage\" id=\"phase2_health\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.source_coverage\">Source Coverage</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.source_coverage\">Fleet / Wazuh / Zabbix / Trivy / host logs 기준으로 현재 MORI에 연결된 호스트 수입니다.</div>
          <div class=\"coverage\" id=\"source_coverage\"></div>
          <div class=\"status-line\" id=\"dashboard_status\">dashboard loading...</div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.collector_health\">📡 Collector Health · Source Freshness</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.collector_health\">수집기별 마지막 성공 시각과 SLA 임계 대비 지연(lag)을 표시합니다. SLA 초과 시 🟡 STALE, 마지막 sync가 error면 🔴 표시됩니다.</div>
          <div class=\"actions\" style=\"margin-bottom:10px\">
            <button id=\"admin_reload_freshness\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div class=\"table-wrap\" id=\"admin_source_freshness\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.latest_status\">Latest Host Status</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.latest_status\">offline / unknown 호스트를 우선 배치합니다.</div>
          <div class=\"table-wrap\" id=\"latest_status\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.risk_summary\">Risk Summary</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.risk_summary\">24시간 alert와 누적 취약점 기준 상위 호스트입니다.</div>
          <div class=\"table-wrap\" id=\"risk_summary\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.recent_activity\">Recent Activity</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.recent_activity\">최근 alert / observation / fleet query 결과를 시간순으로 합쳐 보여줍니다.</div>
          <div class=\"list\" id=\"recent_activity\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: Compliance (Phase 2 control_checks) ──────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_compliance\">
      <section class=\"metrics\" id=\"admin_compliance_cards\"></section>
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.pdca_status\">📋 통제 점검 현황 (PDCA)</h2>
          <div class=\"subtext\" data-i18n-html=\"admin.s.sub.pdca\">
            <code>control_check_results</code> 테이블 기준 ISMS-P / ISO 27001 통제 점검 결과입니다.
            상세 시각화와 미조치 항목 편집은 <a href=\"/ui#compliance\" style=\"color:#7dd3fc\">사용자 대시보드 Compliance 탭 ↗</a>에서 가능합니다.
          </div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"admin_reload_compliance\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
            <a href=\"/compliance/pdca/pending.csv\" class=\"ghost\" style=\"display:inline-flex;align-items:center;justify-content:center;text-decoration:none\" data-i18n=\"admin.s.btn.pending_csv\">📥 미조치 CSV</a>
          </div>
          <div class=\"table-wrap\" id=\"admin_compliance_categories\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.pending\">🔧 미조치 항목 (통제 + Trivy + Alert)</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.pending\">기한 초과는 🔴 표시. 통제 점검 fail/warning + Trivy critical/high + Alert critical/high (7일) 통합.</div>
          <div class=\"table-wrap\" id=\"admin_compliance_pending\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: Triage & Incidents ───────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_triage\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.triage\">🚨 Alert Triage 현황</h2>
          <div class=\"subtext\" data-i18n-html=\"admin.s.sub.triage\">
            triage 상태가 설정된 alert 목록입니다. 편집은
            <a href=\"/ui#triage\" style=\"color:#7dd3fc\">사용자 대시보드 Triage 탭 ↗</a>에서 가능합니다.
          </div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"admin_reload_triage\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div class=\"table-wrap\" id=\"admin_triage_list\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.incidents\">📋 인시던트 (incident_store)</h2>
          <div class=\"subtext\" data-i18n-html=\"admin.s.sub.incidents\">
            등록된 인시던트와 처리 상태입니다. 생성·노트는
            <a href=\"/ui#incidents\" style=\"color:#7dd3fc\">사용자 대시보드 Incidents 탭 ↗</a>에서 가능합니다.
          </div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"admin_reload_incidents\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
            <a href=\"/incidents?format=csv\" class=\"ghost\" style=\"display:inline-flex;align-items:center;justify-content:center;text-decoration:none\" data-i18n=\"admin.s.btn.incidents_csv\">📥 인시던트 CSV</a>
          </div>
          <div class=\"table-wrap\" id=\"admin_incidents_list\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: Remediation (vuln_actions + action_plans) ────────────────── -->
    <div class=\"atab-panel\" id=\"atab_remediation\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.trivy_remediation\">🔧 Trivy 취약점 조치 상태</h2>
          <div class=\"subtext\" data-i18n-html=\"admin.s.sub.trivy\">
            Critical / High 취약점과 등록된 조치 계획(plan) · 예외(exception) 입니다.
            편집은 <a href=\"/ui#assets\" style=\"color:#7dd3fc\">사용자 대시보드 Assets 탭의 취약점 카드 ↗</a>에서 가능합니다.
          </div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"admin_reload_vulns\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
            <a href=\"/trivy/vulnerabilities?format=csv&amp;severity=critical\" class=\"ghost\" style=\"display:inline-flex;align-items:center;justify-content:center;text-decoration:none\" data-i18n=\"admin.s.btn.critical_csv\">📥 Critical CSV</a>
          </div>
          <div class=\"table-wrap\" id=\"admin_vuln_actions\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.action_plans\">📝 자산 조치 계획 (action_plans)</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.action_plans\">호스트별 등록된 조치 계획(target_date / text)을 표시합니다.</div>
          <div class=\"table-wrap\" id=\"admin_action_plans\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 자산 관리 ────────────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_assets\">
      <section class=\"card\">
        <h2 data-i18n=\"admin.h.asset_owners\">👤 자산 담당자 관리</h2>
        <div class=\"subtext\" data-i18n=\"admin.s.sub.asset_owners\">서버·PC 자산의 담당자와 팀을 등록합니다. 호스트명과 정확히 일치해야 합니다.</div>
        <div id=\"owners_list\" class=\"list\" style=\"margin-bottom:16px;max-height:360px;overflow-y:auto\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
        <div id=\"owner_form_title\" style=\"font-size:14px;font-weight:700;color:#38bdf8;margin-bottom:8px;\" data-i18n=\"admin.dyn.new_asset\">➕ 새 자산 등록</div>
        <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.hostname\">호스트명</label><input id=\"own_hostname\" placeholder=\"예: db-prod-01\" data-i18n-placeholder=\"admin.s.ph.hostname\" /></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.owner\">담당자</label><input id=\"own_owner\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"admin.s.ph.owner\" /></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.email\">이메일</label><input id=\"own_email\" placeholder=\"예: hong@company.com\" data-i18n-placeholder=\"admin.s.ph.email\" /></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.team\">팀</label><input id=\"own_team\" placeholder=\"예: 인프라팀\" data-i18n-placeholder=\"admin.s.ph.team\" /></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.category\">분류 (카테고리)</label><input id=\"own_category\" placeholder=\"예: DB서버, 웹서버, AP서버\" data-i18n-placeholder=\"admin.s.ph.category\" /></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.importance\">중요도</label><select id=\"own_importance\"><option value=\"\" data-i18n=\"admin.s.opt.auto\">자동 (기본)</option><option value=\"상\" data-i18n=\"admin.s.opt.high\">상</option><option value=\"중\" data-i18n=\"admin.s.opt.mid\">중</option><option value=\"하\" data-i18n=\"admin.s.opt.low\">하</option></select></div>
        </div>
        <div class=\"actions\">
          <button id=\"add_owner\" data-i18n=\"admin.s.btn.add_edit\">등록 / 수정</button>
          <button id=\"cancel_edit_owner\" class=\"ghost\" style=\"display:none\" data-i18n=\"admin.dyn.cancel\">취소</button>
          <button id=\"reload_owners\" class=\"secondary\" data-i18n=\"admin.s.btn.reload_list\">목록 새로고침</button>
        </div>
        <div class=\"status-line\" id=\"owner_status\"></div>
      </section>
    </div>

    <!-- ── Tab: 쿼리 ─────────────────────────────────────────────────────── -->
    <!-- ── Tab: 설정 (대시보드 / Webhook / 가이드 / Dev Tools 통합) ───── -->
    <div class=\"atab-panel\" id=\"atab_settings\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.dashboard_prefs\">🖥️ 사용자 대시보드 설정</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.dashboard_prefs\">`/ui` 에서 사용자에게 보이는 카드와 섹션을 제어합니다. 재시작 시 초기값으로 돌아갑니다.</div>
          <div class=\"row\"><label for=\"docs_portal_url\" data-i18n=\"admin.s.lbl.docs_url\">문서 / 포털 URL</label><input id=\"docs_portal_url\" value=\"__DOCS_PORTAL_URL__\" /></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.user_cards\">사용자 요약 카드</label><div class=\"toggle-grid\" id=\"user_dashboard_cards\"></div></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.user_sections\">사용자 섹션</label><div class=\"toggle-grid\" id=\"user_dashboard_sections\"></div></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.asset_columns\">자빅스 자산 테이블 컬럼 표시</label><div class=\"toggle-grid\" id=\"user_dashboard_asset_columns\"></div></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.guide_tabs\">가이드 탭 노출 설정</label><div class=\"toggle-grid\" id=\"user_dashboard_guides\"></div></div>
          <div class=\"actions\">
            <button id=\"save_dashboard_preferences\" class=\"primary\" data-i18n=\"admin.s.btn.save\">저장</button>
            <a href=\"/ui\" data-i18n=\"admin.s.btn.open_user_ui\">사용자 화면 열기 ↗</a>
          </div>
          <div class=\"status-line\" id=\"dashboard_preferences_status\">user dashboard settings loading...</div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.slack\">🔔 Slack Webhook 관리</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.slack\">Critical 경보 발생 시 자동으로 알림을 전송할 Slack Incoming Webhook을 등록합니다.</div>
          <div id=\"webhooks_list\" class=\"list\" style=\"margin-bottom:12px\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">
            <div class=\"row\"><label for=\"wh_name\" data-i18n=\"admin.s.lbl.channel_name\">채널 이름 (식별용)</label><input id=\"wh_name\" placeholder=\"예: #soc-alerts\" data-i18n-placeholder=\"admin.s.ph.channel\" /></div>
            <div class=\"row\"><label for=\"wh_url\">Webhook URL</label><input id=\"wh_url\" placeholder=\"https://hooks.slack.com/services/...\" /></div>
          </div>
          <div class=\"actions\">
            <button id=\"add_webhook\" data-i18n=\"admin.s.btn.add\">추가</button>
            <button id=\"reload_webhooks\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div class=\"status-line\" id=\"webhook_status\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.guides_editor\">📖 가이드 &amp; 메뉴얼 편집</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.guides_editor\">사용자 UI에 표시되는 가이드 내용을 수정합니다. 마크다운 형식을 지원합니다.</div>
          <div class=\"row\"><label for=\"guide_edit_select\" data-i18n=\"admin.s.lbl.guide_select\">가이드 선택</label>
            <select id=\"guide_edit_select\">
              <option value=\"zabbix_setup\" data-i18n=\"admin.s.gopt.zabbix_setup\">🖧 Zabbix 에이전트 설정</option>
              <option value=\"fleet_install\" data-i18n=\"admin.s.gopt.fleet_install\">🖥️ Fleet 에이전트 설치</option>
              <option value=\"isms_criteria\" data-i18n=\"admin.s.gopt.isms_criteria\">📋 ISMS-P 심사 기준</option>
              <option value=\"iso27001_criteria\" data-i18n=\"admin.s.gopt.iso27001_criteria\">🌐 ISO 27001 심사 기준</option>
              <option value=\"ldap_setup\" data-i18n=\"admin.s.gopt.ldap_setup\">🔐 LDAP 통합 설정</option>
              <option value=\"incident_response\" data-i18n=\"admin.s.gopt.incident_response\">🚨 인시던트 대응 절차</option>
              <option value=\"security_policy\" data-i18n=\"admin.s.gopt.security_policy\">📜 보안 정책 가이드</option>
            </select>
          </div>
          <div class=\"row\"><label for=\"guide_edit_title\" data-i18n=\"admin.s.lbl.title\">제목</label><input id=\"guide_edit_title\" placeholder=\"가이드 제목\" data-i18n-placeholder=\"admin.s.ph.guide_title\" /></div>
          <div class=\"row\"><label for=\"guide_edit_content\" data-i18n=\"admin.s.lbl.content_md\">내용 (마크다운)</label><textarea id=\"guide_edit_content\" style=\"min-height:280px;font-family:monospace;font-size:12px\"></textarea></div>
          <div class=\"actions\">
            <button id=\"guide_edit_load\" class=\"secondary\" data-i18n=\"admin.s.btn.load\">불러오기</button>
            <button id=\"guide_edit_save\" data-i18n=\"admin.s.btn.save\">저장</button>
          </div>
          <div class=\"status-line\" id=\"guide_edit_status\"></div>
        </section>

        <!-- ── Dev Tools (자연어 / 구조화 질의 — 접기 기본) ───────────── -->
        <details class=\"card\" style=\"padding:0\">
          <summary style=\"cursor:pointer;padding:18px 22px;font-size:18px;font-weight:700;color:#e2e8f0;list-style:none\">
            🛠️ Dev Tools <span style=\"color:#94a3b8;font-weight:400;font-size:13px\" data-i18n=\"admin.s.devtools_tag\">— 자연어 / 구조화 질의 (개발자용)</span>
          </summary>
          <div style=\"padding:0 22px 22px 22px\">
            <div class=\"subtext\" style=\"margin-bottom:12px\" data-i18n-html=\"admin.s.sub.devtools\">관리자가 직접 백엔드 질의를 시험하기 위한 도구입니다. 일반 사용자 화면은 <a href=\"/ui\" style=\"color:#7dd3fc\">/ui</a> 를 참고하세요.</div>
            <section style=\"margin-bottom:18px\">
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#cbd5e1\" data-i18n=\"admin.h.quick_actions\">⚡ Quick Actions</h3>
              <div class=\"quick-actions\" id=\"quick_queries\"></div>
            </section>
            <section style=\"margin-bottom:18px\">
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#cbd5e1\" data-i18n=\"admin.h.nlq\">🗣️ Natural Language Query</h3>
              <div class=\"subtext\"><span data-i18n=\"admin.s.sub.nlq\">자연스럽게 질문하면 의도를 해석해 실행합니다.</span> <a href=\"#\" id=\"query_guide_link\" style=\"color:#7dd3fc;\" data-i18n=\"admin.s.link.query_guide\">질의 가이드 ↗</a></div>
              <div class=\"row\">
                <label for=\"nlp_text\" data-i18n=\"admin.s.lbl.question\">질문</label>
                <textarea id=\"nlp_text\" data-i18n=\"admin.s.nlq_default\">오프라인 호스트 보여줘</textarea>
              </div>
              <div class=\"guide-chips\" id=\"guide_examples\"></div>
              <div class=\"actions\">
                <button id=\"interpret\" class=\"secondary\">Interpret Text</button>
                <button id=\"run\">Run Query</button>
                <button id=\"download_csv\" class=\"ghost\">Download CSV</button>
              </div>
              <div id=\"interpretation_hint\"></div>
              <div class=\"status-line\" id=\"query_status\">catalog loading...</div>
            </section>
            <section style=\"margin-bottom:18px\">
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#cbd5e1\" data-i18n=\"admin.h.query_builder\">🔧 Structured Query Builder</h3>
              <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">
                <div class=\"row\"><label for=\"intent\">Intent</label><select id=\"intent\"></select></div>
                <div class=\"row\"><label for=\"time_range\">time_range</label><input id=\"time_range\" value=\"24h\" /></div>
                <div class=\"row\"><label for=\"host_id\">host_id</label><input id=\"host_id\" placeholder=\"예: host-1\" data-i18n-placeholder=\"admin.s.ph.host_id\" /></div>
                <div class=\"row\"><label for=\"hostname\">hostname</label><input id=\"hostname\" placeholder=\"예: mbp-01\" data-i18n-placeholder=\"admin.s.ph.dev_hostname\" /></div>
                <div class=\"row\"><label for=\"severity\">severity</label><input id=\"severity\" placeholder=\"예: high,critical\" data-i18n-placeholder=\"admin.s.ph.severity\" /></div>
                <div class=\"row\"><label for=\"source\">source</label><input id=\"source\" placeholder=\"예: wazuh\" data-i18n-placeholder=\"admin.s.ph.source\" /></div>
              </div>
              <div class=\"row\"><label for=\"filters\">filters (JSON)</label><textarea id=\"filters\">{}</textarea></div>
              <div class=\"actions\">
                <button id=\"reset\" class=\"secondary\">Reset</button>
                <button id=\"copy_payload\" class=\"ghost\">Copy Payload</button>
              </div>
            </section>
            <section>
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#cbd5e1\" data-i18n=\"admin.h.request_response\">📨 Request / Response</h3>
              <div class=\"row\"><label for=\"payload\">Request Payload</label><textarea id=\"payload\">__PAYLOAD_JSON__</textarea></div>
              <div class=\"row\"><label>Response</label><div id=\"result\" class=\"query-result-area\"><span class=\"result-placeholder\" data-i18n=\"admin.dyn.not_run_yet\">아직 실행 전입니다.</span></div></div>
            </section>
          </div>
        </details>
      </div>
    </div>

    <!-- ── Tab: Access Control (가입 요청 + RBAC 통합) ─────────────────── -->
    <div class=\"atab-panel\" id=\"atab_access\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.signup_requests\">🙋 가입 요청 관리</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.signup_requests\">사용자가 제출한 가입 요청 목록입니다. 승인하면 운영자가 별도로 계정을 생성해야 합니다.</div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"reload_signup_requests\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div id=\"signup_requests_list\" class=\"list\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"signup_requests_status\"></div>
        </section>

        <section class=\"card\">
          <h2 data-i18n=\"admin.h.role_perms\">🔐 역할별 탭 권한 관리</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.role_perms\">각 계정 역할에서 보이는 탭을 설정합니다. 저장 후 다음 로그인부터 적용됩니다.</div>
          <div id=\"roleperm_list\" style=\"display:grid;gap:16px;margin-bottom:16px\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"actions\">
            <button id=\"save_roleperm\" data-i18n=\"admin.s.btn.save\">저장</button>
            <button id=\"reload_roleperm\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div class=\"status-line\" id=\"roleperm_status\"></div>
        </section>

        <section class=\"card\">
          <h2 data-i18n=\"admin.h.user_tabs\">👤 유저별 대시보드 탭 관리</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.user_tabs\">개별 유저에게 역할 기본값과 다른 탭을 지정합니다. 유저별 설정이 있으면 역할 기본값보다 우선 적용됩니다.</div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"reload_usertab\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh_icon\">🔄 새로고침</button>
          </div>
          <div id=\"usertab_list\" style=\"display:grid;gap:14px;margin-bottom:16px\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"usertab_status\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: Audit & Logs (자산 변경 이력 + 사용자 행동 로그 통합) ─── -->
    <div class=\"atab-panel\" id=\"atab_logs\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.asset_audit\">📝 자산 변경 이력</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.asset_audit\">사용자가 수정한 담당자·카테고리 변경 이력입니다. 최신 순으로 표시됩니다.</div>
          <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px\">
            <input id=\"audit_filter_hostname\" placeholder=\"호스트명으로 검색\" data-i18n-placeholder=\"admin.s.ph.audit_host\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:6px 10px;font-size:13px;width:180px\" />
            <select id=\"audit_filter_field\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:6px 10px;font-size:13px\">
              <option value=\"\" data-i18n=\"admin.s.opt.all_items\">전체 항목</option>
              <option value=\"owner\" data-i18n=\"admin.s.opt.owner\">담당자</option>
              <option value=\"category\" data-i18n=\"admin.s.opt.category\">카테고리</option>
            </select>
            <button id=\"audit_search_btn\" class=\"secondary\" style=\"padding:6px 14px\" data-i18n=\"admin.s.btn.search\">🔍 검색</button>
            <button id=\"reload_audit_log\" class=\"secondary\" style=\"padding:6px 14px\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div id=\"audit_log_list\" class=\"list\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"audit_log_status\"></div>
        </section>

        <section class=\"card\">
          <h2 data-i18n=\"admin.h.user_activity\">👤 사용자 행동 로그</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.user_activity\">로그인·로그아웃·탭 전환·쿼리 실행 등 모든 사용자 행동이 기록됩니다.</div>
          <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px\">
            <input id=\"userlog_filter_user\" placeholder=\"사용자명으로 검색\" data-i18n-placeholder=\"admin.s.ph.userlog_user\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:6px 10px;font-size:13px;width:180px\" />
            <select id=\"userlog_filter_action\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:6px 10px;font-size:13px\">
              <option value=\"\" data-i18n=\"admin.s.opt.all_actions\">전체 액션</option>
              <option value=\"LOGIN\">LOGIN</option>
              <option value=\"LOGIN_FAIL\">LOGIN_FAIL</option>
              <option value=\"LOGOUT\">LOGOUT</option>
              <option value=\"TAB_SWITCH\">TAB_SWITCH</option>
              <option value=\"QUERY\">QUERY</option>
              <option value=\"INTERPRET\">INTERPRET</option>
            </select>
            <button id=\"userlog_search_btn\" class=\"secondary\" style=\"padding:6px 14px\" data-i18n=\"admin.s.btn.search\">🔍 검색</button>
            <button id=\"reload_userlog\" class=\"secondary\" style=\"padding:6px 14px\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div id=\"userlog_list\" class=\"list\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>
    </div>
  </div>

  <!-- ── 어드민 하단 탭 바 (모바일 전용) ────────────────────────────────── -->
  <nav class=\"admin-bottom-nav\" id=\"admin_bottom_nav\">
    <button class=\"active\" data-atab=\"overview\" onclick=\"switchAdminTab('overview')\">
      <span class=\"bn-icon\">📊</span><span data-i18n=\"admin.s.bn.overview\">Overview</span>
    </button>
    <button data-atab=\"compliance\" onclick=\"switchAdminTab('compliance')\">
      <span class=\"bn-icon\">✅</span><span data-i18n=\"admin.s.bn.compliance\">Compliance</span>
    </button>
    <button data-atab=\"triage\" onclick=\"switchAdminTab('triage')\">
      <span class=\"bn-icon\">🚨</span><span data-i18n=\"admin.s.bn.triage\">Triage</span>
    </button>
    <button data-atab=\"remediation\" onclick=\"switchAdminTab('remediation')\">
      <span class=\"bn-icon\">🔧</span><span data-i18n=\"admin.s.bn.remediation\">조치</span>
    </button>
    <button data-atab=\"assets\" onclick=\"switchAdminTab('assets')\">
      <span class=\"bn-icon\">👤</span><span data-i18n=\"admin.s.bn.assets\">자산</span>
    </button>
    <button data-atab=\"access\" onclick=\"switchAdminTab('access')\">
      <span class=\"bn-icon\">🛡️</span><span data-i18n=\"admin.s.bn.access\">권한</span>
    </button>
    <button data-atab=\"logs\" onclick=\"switchAdminTab('logs')\">
      <span class=\"bn-icon\">📝</span><span data-i18n=\"admin.s.bn.logs\">로그</span>
    </button>
    <button data-atab=\"settings\" onclick=\"switchAdminTab('settings')\">
      <span class=\"bn-icon\">⚙️</span><span data-i18n=\"admin.s.bn.settings\">설정</span>
    </button>
  </nav>

  <dialog id=\"query_guide_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 data-i18n=\"admin.s.dlg.nlq_guide_title\">Natural Language Query Guide</h3>
        <form method=\"dialog\"><button class=\"secondary\" data-i18n=\"admin.s.btn.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"query_guide_message\" data-i18n=\"admin.dyn.guide_default_msg\">질문 의도를 정확히 해석하지 못하면 아래 예시를 눌러 다시 시작할 수 있습니다.</div>
      <div class=\"guide-list\" id=\"query_guide_list\"></div>
    </div>
  </dialog>

  <dialog id=\"overview_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"overview_modal_title\">Overview Details</h3>
        <form method=\"dialog\"><button class=\"secondary\" data-i18n=\"admin.s.btn.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"overview_modal_copy\" data-i18n=\"admin.s.dlg.overview_copy\">선택한 카드의 상세 목록입니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"overview_modal_body\"></div>
  </dialog>



  <script>
    const defaultPayload = __DEFAULT_PAYLOAD_JSON__;
    const guideExamples = __GUIDE_EXAMPLES__;
    // i18n helper — resolves via window.t() with a Korean fallback
    const tt = (k, f) => (window.t ? window.t(k, f) : f);
    const overviewCardsEl = document.getElementById('overview_cards');
    const sourceCoverageEl = document.getElementById('source_coverage');
    const latestStatusEl = document.getElementById('latest_status');
    const riskSummaryEl = document.getElementById('risk_summary');
    const recentActivityEl = document.getElementById('recent_activity');
    const quickQueriesEl = document.getElementById('quick_queries');
    const dashboardStatusEl = document.getElementById('dashboard_status');
    const queryStatusEl = document.getElementById('query_status');
    const intentEl = document.getElementById('intent');
    const nlpTextEl = document.getElementById('nlp_text');
    const timeRangeEl = document.getElementById('time_range');
    const hostIdEl = document.getElementById('host_id');
    const hostnameEl = document.getElementById('hostname');
    const severityEl = document.getElementById('severity');
    const sourceEl = document.getElementById('source');
    const filtersEl = document.getElementById('filters');
    const payloadEl = document.getElementById('payload');
    const resultEl = document.getElementById('result');
    const interpretationHintEl = document.getElementById('interpretation_hint');
    const guideExamplesEl = document.getElementById('guide_examples');
    const guideModalEl = document.getElementById('query_guide_modal');
    const guideMessageEl = document.getElementById('query_guide_message');
    const guideListEl = document.getElementById('query_guide_list');
    const overviewModalEl = document.getElementById('overview_modal');
    const overviewModalTitleEl = document.getElementById('overview_modal_title');
    const overviewModalCopyEl = document.getElementById('overview_modal_copy');
    const overviewModalBodyEl = document.getElementById('overview_modal_body');
    const docsPortalUrlEl = document.getElementById('docs_portal_url');
    const userDashboardCardsEl = document.getElementById('user_dashboard_cards');
    const userDashboardSectionsEl = document.getElementById('user_dashboard_sections');
    const userDashboardAssetColumnsEl = document.getElementById('user_dashboard_asset_columns');
    const userDashboardGuidesEl = document.getElementById('user_dashboard_guides');
    const dashboardPreferencesStatusEl = document.getElementById('dashboard_preferences_status');

    // Webhooks
    const webhooksListEl = document.getElementById('webhooks_list');
    const whNameEl = document.getElementById('wh_name');
    const whUrlEl = document.getElementById('wh_url');
    const webhookStatusEl = document.getElementById('webhook_status');


    const defaultUserDashboardPreferences = __USER_DASHBOARD_PREFS_JSON__;
    const userDashboardCardLabels = __CARD_LABELS_JSON__;
    const userDashboardSectionLabels = __SECTION_LABELS_JSON__;
    const userDashboardAssetColumnLabels = __ASSET_COLUMN_LABELS_JSON__;
    const userDashboardGuideLabels = __GUIDE_LABELS_JSON__;
    let dashboardDetails = {};
    let userDashboardPreferences = JSON.parse(JSON.stringify(defaultUserDashboardPreferences));
    let queryMode = 'natural';

    // ── 전역 함수 노출 (onclick 속성에서 직접 호출 — 함수 선언은 호이스팅됨) ──
    window.switchAdminTab       = switchAdminTab;
    window.deleteOwner          = deleteOwner;
    window.editOwner            = editOwner;
    window.testWebhook          = testWebhook;
    window.deleteWebhook        = deleteWebhook;
    window.handleSignupRequest  = handleSignupRequest;

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function logUserAction(action, detail) {
      fetch('/admin/action-audit-log', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ action, detail }),
      }).catch(() => {});
    }

    function formatTime(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString('ko-KR', { hour12: false });
    }

    function renderPreferenceGroup(container, labels, values, prefix) {
      container.innerHTML = Object.entries(labels).map(([key, label]) => `
        <label class=\"toggle-item\" for=\"${prefix}_${escapeHtml(key)}\">
          <span>${escapeHtml(tt('admin.dyn.pref.' + prefix + '.' + key, label))}</span>
          <input type=\"checkbox\" id=\"${prefix}_${escapeHtml(key)}\" data-pref-key=\"${escapeHtml(key)}\" ${values[key] !== false ? 'checked' : ''} />
        </label>
      `).join('');
    }

    function renderDashboardPreferences() {
      renderPreferenceGroup(userDashboardCardsEl, userDashboardCardLabels, userDashboardPreferences.cards || {}, 'user_card');
      renderPreferenceGroup(userDashboardSectionsEl, userDashboardSectionLabels, userDashboardPreferences.sections || {}, 'user_section');
      renderPreferenceGroup(userDashboardAssetColumnsEl, userDashboardAssetColumnLabels, userDashboardPreferences.asset_columns || {}, 'user_asset_col');
      renderPreferenceGroup(userDashboardGuidesEl, userDashboardGuideLabels, userDashboardPreferences.guides || {}, 'user_guide');
    }

    function readPreferenceGroup(container) {
      return Object.fromEntries(Array.from(container.querySelectorAll('[data-pref-key]')).map((input) => [input.dataset.prefKey, input.checked]));
    }

    async function loadDashboardPreferences() {
      dashboardPreferencesStatusEl.textContent = 'user dashboard settings loading...';
      try {
        const response = await fetch('/admin/dashboard/preferences');
        const data = await response.json();
        if (!response.ok) {
          dashboardPreferencesStatusEl.textContent = `settings load failed: HTTP ${response.status}`;
          return;
        }
        docsPortalUrlEl.value = data.docs_url || '__DOCS_PORTAL_URL__';
        userDashboardPreferences = data.user_dashboard || JSON.parse(JSON.stringify(defaultUserDashboardPreferences));
        renderDashboardPreferences();
        dashboardPreferencesStatusEl.textContent = 'user dashboard settings loaded';
      } catch (error) {
        dashboardPreferencesStatusEl.textContent = `settings load failed: ${error.message}`;
      }
    }

    async function saveDashboardPreferences() {
      dashboardPreferencesStatusEl.textContent = 'saving user dashboard settings...';
      const payload = {
        docs_url: docsPortalUrlEl.value.trim() || '__DOCS_PORTAL_URL__',
        user_dashboard: {
          cards: readPreferenceGroup(userDashboardCardsEl),
          sections: readPreferenceGroup(userDashboardSectionsEl),
          asset_columns: readPreferenceGroup(userDashboardAssetColumnsEl),
          guides: readPreferenceGroup(userDashboardGuidesEl),
        },
      };
      try {
        const response = await fetch('/admin/dashboard/preferences', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) {
          dashboardPreferencesStatusEl.textContent = `settings save failed: HTTP ${response.status}`;
          setResultError(JSON.stringify(data, null, 2));
          return;
        }
        docsPortalUrlEl.value = data.docs_url || payload.docs_url;
        userDashboardPreferences = data.user_dashboard || payload.user_dashboard;
        renderDashboardPreferences();
        dashboardPreferencesStatusEl.textContent = 'user dashboard settings saved';
      } catch (error) {
        dashboardPreferencesStatusEl.textContent = `settings save failed: ${error.message}`;
      }
    }

    function compactScope() {
      const scope = {
        time_range: timeRangeEl.value.trim() || '24h',
        host_id: hostIdEl.value.trim(),
        hostname: hostnameEl.value.trim(),
        severity: severityEl.value.trim(),
        source: sourceEl.value.trim(),
      };
      return Object.fromEntries(Object.entries(scope).filter(([, value]) => value));
    }

    function setQueryMode(mode) {
      queryMode = mode;
    }

    function populateFormFromPayload(payload, options = {}) {
      intentEl.value = payload.intent || defaultPayload.intent;
      const scope = payload.scope || {};
      timeRangeEl.value = scope.time_range || '24h';
      hostIdEl.value = scope.host_id || '';
      hostnameEl.value = scope.hostname || '';
      severityEl.value = scope.severity || '';
      sourceEl.value = scope.source || '';
      filtersEl.value = JSON.stringify(payload.filters || {}, null, 2);
      setQueryMode(options.mode || 'structured');
      syncPayload();
    }

    function syncPayload() {
      let filters = {};
      try {
        filters = filtersEl.value.trim() ? JSON.parse(filtersEl.value) : {};
      } catch (error) {
        queryStatusEl.textContent = `${tt('admin.dyn.filters_json_error','filters JSON 오류: ')}${error.message}`;
        return null;
      }
      const payload = { intent: intentEl.value, scope: compactScope(), filters };
      payloadEl.value = JSON.stringify(payload, null, 2);
      queryStatusEl.textContent = 'payload ready';
      return payload;
    }

    function normalizeGuideExamples(examples) {
      return Array.isArray(examples) && examples.length ? examples : guideExamples;
    }

    function renderGuideButtons(container, examples) {
      const items = normalizeGuideExamples(examples);
      container.innerHTML = items.map((example, index) => `
        <button class=\"ghost chip\" type=\"button\" data-guide-index=\"${index}\">${escapeHtml(tt('admin.dyn.nlq_ex.' + index, example))}</button>
      `).join('');
      container.querySelectorAll('[data-guide-index]').forEach((button) => {
        button.addEventListener('click', () => {
          const idx = Number(button.dataset.guideIndex);
          const example = tt('admin.dyn.nlq_ex.' + idx, items[idx] || '');
          nlpTextEl.value = example;
          setQueryMode('natural');
          queryStatusEl.textContent = `guide loaded: ${example}`;
          if (guideModalEl.open) {
            guideModalEl.close();
          }
        });
      });
    }

    function renderInterpretationHint(data) {
      const warnings = Array.isArray(data?.warnings) ? data.warnings : [];
      if (!warnings.length && data?.recognized !== false) {
        interpretationHintEl.innerHTML = '';
        return;
      }
      const tone = data?.recognized === false ? 'need-guide' : 'warning';
      const title = data?.recognized === false ? tt('admin.dyn.hint_rewrite','이 질문은 다시 써주는 편이 좋습니다.') : tt('admin.dyn.hint_more','추가 힌트가 있습니다.');
      interpretationHintEl.innerHTML = `
        <div class=\"guide-banner ${escapeHtml(tone)}\">
          <strong>${escapeHtml(title)}</strong>
          ${warnings.map((warning) => `<div>${escapeHtml(warning)}</div>`).join('')}
        </div>
      `;
    }

    function openGuideModal(message, examples) {
      guideMessageEl.textContent = message || tt('admin.dyn.guide_default_msg','질문 의도를 정확히 해석하지 못하면 아래 예시를 눌러 다시 시작할 수 있습니다.');
      renderGuideButtons(guideListEl, examples);
      if (guideModalEl.open) {
        return;
      }
      if (typeof guideModalEl.showModal === 'function') {
        guideModalEl.showModal();
        return;
      }
      guideModalEl.setAttribute('open', 'open');
    }

    function openOverviewModal(title, description, bodyHtml) {
      overviewModalTitleEl.textContent = title;
      overviewModalCopyEl.textContent = description;
      overviewModalBodyEl.innerHTML = bodyHtml;
      if (overviewModalEl.open) {
        return;
      }
      if (typeof overviewModalEl.showModal === 'function') {
        overviewModalEl.showModal();
        return;
      }
      overviewModalEl.setAttribute('open', 'open');
    }

    function renderDetailTable(columns, items, emptyText) {
      if (!items.length) {
        return `<div class="empty">${escapeHtml(emptyText)}</div>`;
      }
      return `
        <div class="table-wrap">
          <table>
            <thead>
              <tr>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('')}</tr>
            </thead>
            <tbody>
              ${items.map((item) => `
                <tr>
                  ${columns.map((column) => `<td>${column.render(item)}</td>`).join('')}
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    function renderHostCell(item) {
      const name = item.source_url
        ? `<a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer"><strong>${escapeHtml(item.hostname)}</strong></a>`
        : `<strong>${escapeHtml(item.hostname)}</strong>`;
      return `${name}<br /><span class="subtext">${escapeHtml(item.host_id)}</span>`;
    }

    function renderStatusDetailTable(items) {
      return renderDetailTable([
        { label: 'Host', render: (item) => renderHostCell(item) },
        { label: 'Status', render: (item) => `<span class="badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>` },
        { label: 'Risk', render: (item) => escapeHtml(item.risk_score) },
        { label: 'Last Seen', render: (item) => escapeHtml(formatTime(item.last_seen_at)) },
        { label: 'Last Alert', render: (item) => escapeHtml(formatTime(item.last_alert_at)) },
      ], items, tt('admin.dyn.none_show_hosts','표시할 호스트가 없습니다.'));
    }

    const UI_TRIAGE_COLORS = {new:'#f59e0b', acknowledged:'#38bdf8', investigating:'#a78bfa', closed:'#6ee7b7', false_positive:'#94a3b8'};
    let uiTriageData = {};
    async function loadUiTriageData() {
      try { const r = await fetch('/alerts'); const d = await r.json(); (d.alerts||[]).forEach(a => { uiTriageData[a.alert_id] = a.triage || {status:'pending'}; }); } catch(_) {}
    }

    function renderAlertDetailTable(items) {
      return renderDetailTable([
        { label: 'Time', render: (item) => escapeHtml(formatTime(item.observed_at)) },
        {
          label: 'Host',
          render: (item) => `<strong>${escapeHtml(item.hostname || '-')}</strong><br /><span class="subtext">${escapeHtml(item.host_id || '-')}</span>`,
        },
        { label: tt('admin.dyn.col.owner','담당자'), render: (item) => `<span style="color:#a3e635">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Severity', render: (item) => escapeHtml(item.severity) },
        { label: 'Message', render: (item) => escapeHtml(item.message) },
        {
          label: 'Triage',
          render: (item) => {
            const tr = uiTriageData[item.alert_id] || {status:'new'};
            const st = tr.status || 'new';
            const color = UI_TRIAGE_COLORS[st] || '#94a3b8';
            return `<span style="background:${color}22;color:${color};padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">${escapeHtml(st)}</span>`;
          }
        },
      ], items, tt('admin.dyn.none_alert_24h','최근 24시간 high / critical alert가 없습니다.'));
    }

    function renderVulnerabilityDetailTable(items) {
      return renderDetailTable([
        { label: 'Detected', render: (item) => escapeHtml(formatTime(item.detected_at)) },
        {
          label: 'Host',
          render: (item) => `<strong>${escapeHtml(item.hostname || item.host_id)}</strong><br /><span class="subtext">${escapeHtml(item.host_id)}</span>`,
        },
        { label: tt('admin.dyn.col.owner','담당자'), render: (item) => `<span style="color:#a3e635">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'CVE', render: (item) => escapeHtml(item.cve || '-') },
        { label: 'Package', render: (item) => escapeHtml(item.package_name || '-') },
        { label: tt('admin.dyn.col.action_plan','조치 계획'), render: (item) => {
          if (!item.plan_text) return `<span style="color:#64748b;font-size:11px">${tt('admin.dyn.unset','미설정')}</span>`;
          const tgt = item.plan_target_date ? `<br /><span style="color:#64748b;font-size:11px">~${escapeHtml(item.plan_target_date)}</span>` : '';
          const by = item.plan_updated_by ? ` <span style="color:#94a3b8;font-size:11px">(${escapeHtml(item.plan_updated_by)})</span>` : '';
          return `<span style="color:#a3e635;font-size:12px" title="${escapeHtml(item.plan_text)}">${escapeHtml(item.plan_text.substring(0,30))}${item.plan_text.length>30?'…':''}</span>${by}${tgt}`;
        }},
        { label: tt('admin.dyn.col.exception','조치 예외'), render: (item) => {
          if (!item.exception_until) return `<span style="color:#64748b;font-size:11px">${tt('admin.dyn.none_word','없음')}</span>`;
          const reason = item.exception_reason ? `<br /><span style="color:#94a3b8;font-size:11px">${escapeHtml(item.exception_reason.substring(0,30))}${item.exception_reason.length>30?'…':''}</span>` : '';
          return `<span style="color:#fbbf24;font-size:12px">~${escapeHtml(item.exception_until)}</span>${reason}`;
        }},
      ], items, tt('admin.dyn.none_critical_vuln2','critical 취약점이 없습니다.'));
    }

    function renderSourceDetailTable(items) {
      return renderDetailTable([
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Hosts', render: (item) => escapeHtml(item.host_count) },
        { label: 'Status', render: (item) => escapeHtml(item.status) },
        { label: 'Last Sync', render: (item) => escapeHtml(formatTime(item.last_sync_at)) },
        { label: 'Message', render: (item) => escapeHtml(item.message || '-') },
      ], items, tt('admin.dyn.none_show_source','표시할 source 상태가 없습니다.'));
    }

    function renderIngestedDetailTable(items) {
      return renderDetailTable([
        { label: 'Entity', render: (item) => escapeHtml(item.entity_type) },
        { label: 'Count', render: (item) => escapeHtml(item.count) },
      ], items, tt('admin.dyn.none_records','수집된 레코드가 없습니다.'));
    }

    async function showOverviewDetail(key, label) {
      const items = Array.isArray(dashboardDetails[key]) ? dashboardDetails[key] : [];
      const renderers = {
        total_hosts: [renderStatusDetailTable, tt('admin.dyn.desc.total_hosts','현재 알려진 전체 호스트 목록입니다.')],
        offline_hosts: [renderStatusDetailTable, tt('admin.dyn.desc.offline_hosts','즉시 확인이 필요한 offline 호스트 목록입니다.')],
        alerts_24h: [renderAlertDetailTable, tt('admin.dyn.desc.alerts_24h','최근 24시간 high / critical alert 목록입니다.')],
        critical_vulns: [renderVulnerabilityDetailTable, tt('admin.dyn.desc.critical_vulns','현재 critical 취약점 목록입니다.')],
        sources_reporting: [renderSourceDetailTable, tt('admin.dyn.desc.sources_reporting','호스트를 보고 중인 source 목록입니다.')],
        sources_healthy: [renderSourceDetailTable, tt('admin.dyn.desc.sources_healthy','최근 sync가 success인 collector 목록입니다.')],
        ingested_records: [renderIngestedDetailTable, tt('admin.dyn.desc.ingested_records','저장된 엔터티 타입별 레코드 수입니다.')],
      };
      if (key === 'alerts_24h') await loadUiTriageData();
      const [renderer, description] = renderers[key] || [renderIngestedDetailTable, tt('admin.dyn.desc.default','선택한 카드의 상세 데이터입니다.')];
      openOverviewModal(label, description, renderer(items));
    }

    function renderOverview(overview) {
      if (!overview || typeof overview !== 'object') overview = {};
      const o = {
        total_hosts: overview.total_hosts ?? 0, online_hosts: overview.online_hosts ?? 0,
        offline_hosts: overview.offline_hosts ?? 0, unknown_hosts: overview.unknown_hosts ?? 0,
        alerts_24h: overview.alerts_24h ?? 0, critical_vulns: overview.critical_vulns ?? 0,
        high_vulns: overview.high_vulns ?? 0, sources_reporting: overview.sources_reporting ?? 0,
        sources_healthy: overview.sources_healthy ?? 0, ingested_records: overview.ingested_records ?? 0,
      };
      const cards = [
        ['total_hosts', 'Total Hosts', o.total_hosts, `${o.online_hosts} online / ${o.unknown_hosts} unknown`],
        ['offline_hosts', 'Offline Hosts', o.offline_hosts, tt('admin.dyn.sub.offline','즉시 확인 대상')],
        ['alerts_24h', 'High Alerts 24h', o.alerts_24h, 'high + critical'],
        ['critical_vulns', 'Critical Vulns', o.critical_vulns, `high ${o.high_vulns}`],
        ['sources_reporting', 'Sources Reporting', o.sources_reporting, 'fleet / wazuh / zabbix / trivy / host_log'],
        ['sources_healthy', 'Healthy Collectors', o.sources_healthy, tt('admin.dyn.sub.healthy','최근 sync success 기준')],
        ['ingested_records', 'Ingested Records', o.ingested_records, 'alerts + vulns + queries + observations'],
      ];
      overviewCardsEl.innerHTML = cards.map(([key, label, value, sub]) => `
        <section class=\"card metric-card\" role=\"button\" tabindex=\"0\" data-overview-key=\"${escapeHtml(key)}\" data-overview-label=\"${escapeHtml(label)}\">
          <div class=\"metric-label\">${escapeHtml(label)}</div>
          <div class=\"metric-value\">${escapeHtml(value)}</div>
          <div class=\"metric-sub\">${escapeHtml(sub)}</div>
        </section>
      `).join('');
      overviewCardsEl.querySelectorAll('[data-overview-key]').forEach((card) => {
        const open = () => showOverviewDetail(card.dataset.overviewKey, card.dataset.overviewLabel || 'Overview');
        card.addEventListener('click', open);
        card.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            open();
          }
        });
      });
    }

    function renderSourceCoverage(items) {
      if (!items.length) {
        sourceCoverageEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_source_alias','아직 연결된 source alias가 없습니다.')}</div>`;
        return;
      }
      const statusToBadge = { success: 'online', error: 'offline', running: 'unknown', unknown: 'unknown' };
      sourceCoverageEl.innerHTML = items.map((item) => {
        const staleBadge = item.is_stale ? ' <span class=\"badge\" style=\"background:#f59e0b;color:#000\">STALE</span>' : '';
        return `
        <div class=\"coverage-item\">
          <div class=\"metric-label\">${escapeHtml(item.source.toUpperCase())}</div>
          <strong>${escapeHtml(item.host_count)}</strong>
          <div class=\"metric-sub\">${tt('admin.dyn.host_word','호스트')} · <span class=\"badge ${escapeHtml(statusToBadge[item.status] || 'unknown')}\">${escapeHtml(item.status)}</span>${staleBadge}</div>
          <div class=\"metric-sub\">last sync: ${escapeHtml(formatTime(item.last_sync_at))}</div>
          <div class=\"metric-sub\">records ${escapeHtml(item.records_collected)} / entities ${escapeHtml(item.entities_saved)}</div>
          <div class=\"status-line\">${escapeHtml(item.message || tt('admin.dyn.no_sync_record','아직 sync 기록 없음'))}</div>
        </div>`;
      }).join('');
    }

    function renderLatestStatus(items) {
      if (!items.length) {
        latestStatusEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_hosts','아직 호스트 데이터가 없습니다.')}</div>`;
        return;
      }
      latestStatusEl.innerHTML = `
        <table>
          <thead>
            <tr><th>Host</th><th>Status</th><th>Risk</th><th>Last Seen</th><th>Last Alert</th></tr>
          </thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${renderHostCell(item)}</td>
                <td><span class=\"badge ${escapeHtml(item.status)}\">${escapeHtml(item.status)}</span></td>
                <td>${escapeHtml(item.risk_score)}</td>
                <td>${escapeHtml(formatTime(item.last_seen_at))}</td>
                <td>${escapeHtml(formatTime(item.last_alert_at))}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderRiskSummary(items) {
      if (!items.length) {
        riskSummaryEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_risk','아직 위험 요약 데이터가 없습니다.')}</div>`;
        return;
      }
      riskSummaryEl.innerHTML = `
        <table>
          <thead>
            <tr><th>Host</th><th>Risk</th><th>Alerts 24h</th><th>Critical</th><th>High</th><th>Vulns</th></tr>
          </thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td><strong>${escapeHtml(item.hostname)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span></td>
                <td>${escapeHtml(item.risk_score)}</td>
                <td>${escapeHtml(item.alert_count_24h)}</td>
                <td>${escapeHtml(item.critical_alert_count_24h)}</td>
                <td>${escapeHtml(item.high_alert_count_24h)}</td>
                <td>${escapeHtml(item.vuln_count)} (C:${escapeHtml(item.critical_vuln_count)} / H:${escapeHtml(item.high_vuln_count)})</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderRecentActivity(items) {
      if (!items.length) {
        recentActivityEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_recent','아직 최근 활동 데이터가 없습니다.')}</div>`;
        return;
      }
      recentActivityEl.innerHTML = items.map((item) => `
        <div class=\"list-item\">
          <div class=\"top\">
            <strong>${escapeHtml(item.summary)}</strong>
            <span class=\"meta\">${escapeHtml(formatTime(item.observed_at))}</span>
          </div>
          <div class=\"meta\">${escapeHtml(item.entity_type)} · ${escapeHtml(item.source)} · ${escapeHtml(item.host_id || '-')}</div>
        </div>
      `).join('');
    }

    function renderQuickQueries(items) {
      if (!items.length) {
        quickQueriesEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_quick','추천 질의가 없습니다.')}</div>`;
        return;
      }
      quickQueriesEl.innerHTML = items.map((item, index) => `
        <button class=\"ghost\" type=\"button\" data-quick-index=\"${index}\">${escapeHtml(item.label)}</button>
      `).join('');
      quickQueriesEl.querySelectorAll('[data-quick-index]').forEach((button) => {
        button.addEventListener('click', () => {
          const item = items[Number(button.dataset.quickIndex)];
          nlpTextEl.value = item.text || '';
          populateFormFromPayload(item.payload || defaultPayload, { mode: 'natural' });
          queryStatusEl.textContent = `quick query loaded: ${item.label}`;
        });
      });
    }

    async function loadCatalog() {
      try {
        const response = await fetch('/catalog');
        const data = await response.json();
        const queries = data.queries || [];
        intentEl.innerHTML = queries.map((query) => `<option value=\"${query.intent}\">${escapeHtml(query.name)} (${escapeHtml(query.intent)})</option>`).join('');
        populateFormFromPayload(defaultPayload, { mode: 'natural' });
        queryStatusEl.textContent = `catalog loaded: ${queries.length} queries`;
      } catch (error) {
        queryStatusEl.textContent = `catalog load failed: ${error.message}`;
      }
    }

    async function loadDashboard() {
      dashboardStatusEl.textContent = 'dashboard loading...';
      try {
        const response = await fetch('/dashboard/summary');
        const data = await response.json();
        if (!response.ok) {
          dashboardStatusEl.textContent = `dashboard load failed: HTTP ${response.status}`;
          return;
        }
        dashboardDetails = data.overview_details || {};
        renderOverview(data.overview || {});
        renderSourceCoverage(data.source_coverage || []);
        renderLatestStatus(data.latest_status || []);
        renderRiskSummary(data.risk_summary || []);
        renderRecentActivity(data.recent_activity || []);
        renderQuickQueries(data.recommended_queries || []);
        dashboardStatusEl.textContent = `dashboard updated at ${formatTime(data.generated_at)}`;
      } catch (error) {
        dashboardStatusEl.textContent = `dashboard load failed: ${error.message}`;
      }
    }

    async function interpretNaturalText(options = {}) {
      const text = nlpTextEl.value.trim();
      if (!text) {
        queryStatusEl.textContent = tt('admin.dyn.enter_nlq','자연어 질문을 입력하세요.');
        renderInterpretationHint({ warnings: [tt('admin.dyn.enter_question_first','질문을 먼저 입력해 주세요.')], recognized: false });
        return null;
      }
      queryStatusEl.textContent = options.statusText || 'interpreting text...';
      try {
        const response = await fetch('/interpret', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text }),
        });
        const data = await response.json();
        if (!response.ok) {
          queryStatusEl.textContent = `interpret failed: HTTP ${response.status}`;
          return null;
        }
        renderInterpretationHint(data);
        const examples = normalizeGuideExamples(data.guide_examples);
        renderGuideButtons(guideExamplesEl, examples);
        if (data.recognized === false) {
          if (options.openGuideOnUnrecognized !== false) {
            openGuideModal((data.warnings || [])[0], examples);
          }
          queryStatusEl.textContent = 'interpret needs guide examples';
          return { recognized: false, data };
        }
        const payload = { intent: data.intent, scope: data.scope || {}, filters: data.filters || {} };
        populateFormFromPayload(payload, { mode: 'natural' });
        logUserAction('INTERPRET', text.substring(0, 200));
        queryStatusEl.textContent = (data.warnings || []).length ? 'interpret completed with hints' : 'interpret completed';
        return { recognized: true, data, payload };
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `interpret failed: ${error.message}`;
        return null;
      }
    }

    async function resolvePayloadForRun() {
      if (queryMode === 'natural' && nlpTextEl.value.trim()) {
        const interpreted = await interpretNaturalText({ statusText: 'interpreting text before query...' });
        if (!interpreted || interpreted.recognized === false) {
          return null;
        }
        return interpreted.payload;
      }
      return syncPayload();
    }

    function extractFilename(response) {
      const disposition = response.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="?([^";]+)"?/i);
      return match ? match[1] : 'mori-query.csv';
    }

    function queryResultCount(data) {
      if (typeof data?.meta?.count === 'number') {
        return data.meta.count;
      }
      return Array.isArray(data?.evidence) ? data.evidence.length : 0;
    }

    function hasQueryResults(data) {
      return queryResultCount(data) > 0;
    }

    function showNoResultsAlert(data) {
      const message = typeof data?.summary === 'string' && data.summary.trim()
        ? data.summary.trim()
        : tt('admin.dyn.none_query_result','조회 결과가 없습니다.');
      window.alert(message);
    }

    function downloadTextFile(text, filename, mimeType = 'text/csv;charset=utf-8') {
      const blob = new Blob([text], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    }

    function setResultText(msg) {
      resultEl.innerHTML = `<span class=\"result-placeholder\">${escapeHtml(String(msg))}</span>`;
    }

    function setResultError(msg) {
      resultEl.innerHTML = `<div class=\"result-error\">${escapeHtml(String(msg))}</div>`;
    }

    function renderQueryResult(data) {
      const evidence = Array.isArray(data?.evidence) ? data.evidence : [];
      const summary = typeof data?.summary === 'string' ? data.summary : '';
      const count = typeof data?.meta?.count === 'number' ? data.meta.count : evidence.length;

      let html = '';
      if (summary) {
        html += `<div class=\"result-summary\">${escapeHtml(summary)}</div>`;
      }
      if (!evidence.length) {
        html += `<span class=\"result-placeholder\">${tt('admin.dyn.none_query_result','조회 결과가 없습니다.')}</span>`;
        resultEl.innerHTML = html;
        return;
      }

      const badgeClass = (src) => {
        const s = (src || '').toLowerCase();
        if (s.includes('wazuh')) return 'wazuh';
        if (s.includes('zabbix')) return 'zabbix';
        if (s.includes('fleet')) return 'fleet';
        if (s.includes('trivy')) return 'trivy';
        if (s.includes('host')) return 'hosts';
        return '';
      };

      html += `
        <table class=\"result-table\">
          <thead><tr>
            <th>#</th><th>Source</th><th>Summary</th><th>Record ID</th>
          </tr></thead>
          <tbody>
            ${evidence.map((ev, i) => `
              <tr>
                <td>${i + 1}</td>
                <td><span class=\"result-badge ${escapeHtml(badgeClass(ev.source))}\">${escapeHtml(ev.source || '-')}</span></td>
                <td>${escapeHtml(ev.summary || ev.raw_ref || '-')}</td>
                <td><span class=\"mono\" style=\"font-size:11px;color:#64748b;\">${escapeHtml(ev.record_id || '-')}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <div class=\"status-line\" style=\"margin-top:8px;\">${tt('admin.dyn.total_prefix','총 ')}${escapeHtml(String(count))}${tt('admin.dyn.queried_suffix','건 조회됨')}</div>`;
      resultEl.innerHTML = html;
    }

    async function runQuery() {
      const payload = await resolvePayloadForRun();
      if (!payload) return;
      queryStatusEl.textContent = 'query running...';
      try {
        const response = await fetch('/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            const data = await response.json();
            setResultError(JSON.stringify(data, null, 2));
          } else {
            setResultError(await response.text());
          }
          queryStatusEl.textContent = `query failed: HTTP ${response.status}`;
          return;
        }
        const data = await response.json();
        if (!hasQueryResults(data)) {
          setResultText(tt('admin.dyn.none_query_result','조회 결과가 없습니다.'));
          queryStatusEl.textContent = 'query returned no results';
          showNoResultsAlert(data);
          return;
        }
        renderQueryResult(data);
        queryStatusEl.textContent = 'query completed';
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `query failed: ${error.message}`;
      }
    }

    async function downloadCsv() {
      const payload = await resolvePayloadForRun();
      if (!payload) return;
      queryStatusEl.textContent = 'checking query results before csv download...';
      try {
        const previewResponse = await fetch('/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const previewData = await previewResponse.json();
        if (!previewResponse.ok) {
          setResultError(JSON.stringify(previewData, null, 2));
          queryStatusEl.textContent = `query failed: HTTP ${previewResponse.status}`;
          return;
        }
        if (!hasQueryResults(previewData)) {
          setResultText(tt('admin.dyn.none_query_result','조회 결과가 없습니다.'));
          queryStatusEl.textContent = 'csv download skipped: no results';
          showNoResultsAlert(previewData);
          return;
        }

        const response = await fetch('/query?format=csv', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            const data = await response.json();
            setResultError(JSON.stringify(data, null, 2));
          } else {
            setResultError(await response.text());
          }
          queryStatusEl.textContent = `csv download failed: HTTP ${response.status}`;
          return;
        }
        const csvText = await response.text();
        const filename = extractFilename(response);
        downloadTextFile(csvText, filename, response.headers.get('content-type') || 'text/csv;charset=utf-8');
        renderQueryResult(previewData);
        queryStatusEl.textContent = `csv download started: ${filename}`;
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `csv download failed: ${error.message}`;
      }
    }

    async function interpretText() {
      await interpretNaturalText();
    }

    function resetForm() {
      nlpTextEl.value = tt('admin.s.nlq_default','오프라인 호스트 보여줘');
      populateFormFromPayload(defaultPayload, { mode: 'natural' });
      setResultText(tt('admin.dyn.not_run_yet','아직 실행 전입니다.'));
      interpretationHintEl.innerHTML = '';
      queryStatusEl.textContent = 'form reset';
    }

    async function copyPayload() {
      try {
        await navigator.clipboard.writeText(payloadEl.value);
        queryStatusEl.textContent = 'payload copied';
      } catch (error) {
        queryStatusEl.textContent = `copy failed: ${error.message}`;
      }
    }

    nlpTextEl.addEventListener('input', () => setQueryMode('natural'));
    [intentEl, timeRangeEl, hostIdEl, hostnameEl, severityEl, sourceEl].forEach((element) => {
      const handleStructuredInput = () => {
        setQueryMode('structured');
        syncPayload();
      };
      element.addEventListener('input', handleStructuredInput);
      element.addEventListener('change', handleStructuredInput);
    });
    filtersEl.addEventListener('input', () => {
      setQueryMode('structured');
      syncPayload();
    });
    document.getElementById('interpret')?.addEventListener('click', interpretText);
    document.getElementById('run')?.addEventListener('click', runQuery);
    document.getElementById('download_csv')?.addEventListener('click', downloadCsv);
    document.getElementById('reset')?.addEventListener('click', resetForm);
    document.getElementById('copy_payload')?.addEventListener('click', copyPayload);
    document.getElementById('query_guide')?.addEventListener('click', () => openGuideModal('', guideExamples));
    document.getElementById('refresh_dashboard')?.addEventListener('click', loadDashboard);
    document.getElementById('save_dashboard_preferences')?.addEventListener('click', saveDashboardPreferences);
    filtersEl.value = JSON.stringify(defaultPayload.filters, null, 2);
    renderGuideButtons(guideExamplesEl, guideExamples);

    // ── Asset Owners ───────────────────────────────────────────────────────
    const ownersListEl = document.getElementById('owners_list');
    const ownerStatusEl = document.getElementById('owner_status');
    const ownHostnameEl = document.getElementById('own_hostname');
    const ownOwnerEl = document.getElementById('own_owner');
    const ownEmailEl = document.getElementById('own_email');
    const ownTeamEl = document.getElementById('own_team');
    const ownCategoryEl = document.getElementById('own_category');
    const ownImportanceEl = document.getElementById('own_importance');
    const ownerFormTitleEl = document.getElementById('owner_form_title');
    const cancelEditBtn = document.getElementById('cancel_edit_owner');
    let _editingHostname = null; // track if we are editing

    const impLabel = { '\uc0c1':tt('admin.s.opt.high','상'), '\uc911':tt('admin.s.opt.mid','중'), '\ud558':tt('admin.s.opt.low','하') };
    const impColor = { '\uc0c1':'#fca5a5', '\uc911':'#fde68a', '\ud558':'#86efac' };

    async function loadOwners() {
      ownersListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/assets/owners');
        const data = await res.json();
        const list = data.owners || [];
        if (!list.length) { ownersListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.none_owners','등록된 담당자 없음')}</span>`; return; }
        ownersListEl.innerHTML = list.map(o => {
          const imp = o.importance || '';
          const impBadge = imp ? `<span style=\"background:#1e293b;color:${impColor[imp]||'#94a3b8'};padding:1px 6px;border-radius:4px;font-size:11px;font-weight:700;margin-left:6px\">${escapeHtml(impLabel[imp]||imp)}</span>` : '';
          const catBadge = o.category ? `<span style=\"color:#7dd3fc;font-size:11px;margin-left:6px\">[${escapeHtml(o.category)}]</span>` : '';
          return `<div style=\"display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-bottom:1px solid #1e293b;font-size:13px;gap:8px\">
            <div style=\"flex:1;min-width:0\">
              <strong style=\"color:#e2e8f0\">${escapeHtml(o.hostname)}</strong>${catBadge}${impBadge}
              <br><span style=\"color:#a3e635;font-size:12px\">${escapeHtml(o.owner||'-')}</span>
              ${o.team ? `<span style=\"color:#64748b;margin-left:6px;font-size:12px\">(${escapeHtml(o.team)})</span>` : ''}
              ${o.email ? `<span style=\"color:#64748b;font-size:11px;margin-left:6px\">${escapeHtml(o.email)}</span>` : ''}
            </div>
            <div style=\"display:flex;gap:6px;flex-shrink:0\">
              <button onclick=\"editOwner('${escapeHtml(o.hostname)}')\" style=\"background:#1e3a5f;border:1px solid #334155;color:#93c5fd;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px\">${tt('admin.dyn.edit','✏️ 수정')}</button>
              <button onclick=\"deleteOwner('${escapeHtml(o.hostname)}')\" style=\"background:#7f1d1d;border:none;color:#fca5a5;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px\">${tt('admin.dyn.delete','삭제')}</button>
            </div>
          </div>`;
        }).join('');
      } catch(e) { ownersListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`; }
    }

    // ── 자산 정보를 폼에 채워서 수정 모드 진입 ──
    let _ownersCache = [];
    async function editOwner(hostname) {
      // fetch latest owner data
      try {
        const res = await fetch('/assets/owners');
        const data = await res.json();
        _ownersCache = data.owners || [];
      } catch(e) { /* use empty */ }
      const o = _ownersCache.find(x => x.hostname === hostname);
      if (!o) { ownerStatusEl.textContent = `'${hostname}' ${tt('admin.dyn.info_not_found','정보를 찾을 수 없습니다.')}`; return; }
      _editingHostname = hostname;
      ownHostnameEl.value = o.hostname;
      ownHostnameEl.readOnly = true;
      ownHostnameEl.style.opacity = '0.6';
      ownOwnerEl.value = o.owner || '';
      ownEmailEl.value = o.email || '';
      ownTeamEl.value = o.team || '';
      ownCategoryEl.value = o.category || '';
      ownImportanceEl.value = o.importance || '';
      ownerFormTitleEl.textContent = `✏️ ${hostname} ${tt('admin.dyn.editing','수정 중')}`;
      ownerFormTitleEl.style.color = '#fde68a';
      cancelEditBtn.style.display = '';
      ownerStatusEl.textContent = '';
      // scroll form into view
      ownerFormTitleEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function _resetOwnerForm() {
      _editingHostname = null;
      ownHostnameEl.value = ''; ownOwnerEl.value = ''; ownEmailEl.value = '';
      ownTeamEl.value = ''; ownCategoryEl.value = ''; ownImportanceEl.value = '';
      ownHostnameEl.readOnly = false;
      ownHostnameEl.style.opacity = '1';
      ownerFormTitleEl.textContent = tt('admin.dyn.new_asset','➕ 새 자산 등록');
      ownerFormTitleEl.style.color = '#38bdf8';
      cancelEditBtn.style.display = 'none';
    }

    cancelEditBtn?.addEventListener('click', () => { _resetOwnerForm(); ownerStatusEl.textContent = tt('admin.dyn.edit_cancelled','수정 취소됨'); });

    async function deleteOwner(hostname) {
      if (!confirm(`'${hostname}' ${tt('admin.dyn.confirm_delete_owner','자산 정보를 삭제하시겠습니까?')}`)) return;
      try {
        await fetch(`/assets/owners/${encodeURIComponent(hostname)}`, {method:'DELETE'});
        if (_editingHostname === hostname) _resetOwnerForm();
        await loadOwners();
      } catch(e) { ownerStatusEl.textContent = `${tt('admin.dyn.delete_fail_prefix','삭제 실패: ')}${e.message}`; }
    }

    document.getElementById('add_owner')?.addEventListener('click', async () => {
      const hostname = ownHostnameEl.value.trim();
      if (!hostname) { ownerStatusEl.textContent = tt('admin.dyn.enter_hostname','호스트명을 입력하세요.'); return; }
      ownerStatusEl.textContent = tt('admin.dyn.saving','저장 중…');
      try {
        const res = await fetch('/assets/owners', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({
            hostname,
            owner: ownOwnerEl.value.trim(),
            email: ownEmailEl.value.trim(),
            team: ownTeamEl.value.trim(),
            category: ownCategoryEl.value.trim(),
            importance: ownImportanceEl.value,
          })
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        _resetOwnerForm();
        ownerStatusEl.textContent = tt('admin.dyn.save_done','저장 완료 ✓');
        await loadOwners();
      } catch(e) { ownerStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
    });
    document.getElementById('reload_owners')?.addEventListener('click', loadOwners);

    // ── Webhooks ───────────────────────────────────────────────────────────
    async function loadWebhooks() {
      webhooksListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/webhooks');
        const data = await res.json();
        const whs = data.webhooks || [];
        if (!whs.length) { webhooksListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.none_webhooks','등록된 webhook 없음')}</span>`; return; }
        webhooksListEl.innerHTML = whs.map(w => `
          <div class=\"list-item\">
            <div class=\"top\"><strong>${escapeHtml(w.name)}</strong><span class=\"meta\">${escapeHtml(w.created_at||'')}</span></div>
            <div class=\"meta mono\" style=\"word-break:break-all\">${escapeHtml(w.url)}</div>
            <div style=\"margin-top:8px;display:flex;gap:8px\">
              <button class=\"secondary\" style=\"width:auto;padding:4px 12px;font-size:12px\" onclick=\"testWebhook('${escapeHtml(w.id)}', this)\">${tt('admin.dyn.test','테스트')}</button>
              <button class=\"ghost\" style=\"width:auto;padding:4px 12px;font-size:12px;border-color:#ef4444;color:#fca5a5\" onclick=\"deleteWebhook('${escapeHtml(w.id)}', this)\">${tt('admin.dyn.delete','삭제')}</button>
            </div>
          </div>
        `).join('');
      } catch(e) { webhooksListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`; }
    }
    async function testWebhook(id, btn) {
      btn.textContent = tt('admin.dyn.sending','전송 중…'); btn.disabled = true;
      try {
        const res = await fetch(`/webhooks/${id}/test`, {method:'POST'});
        btn.textContent = res.ok ? tt('admin.dyn.success_check','✓ 성공') : tt('admin.dyn.fail_check','✗ 실패');
      } catch(e) { btn.textContent = tt('admin.dyn.error_check','✗ 오류'); }
      setTimeout(() => { btn.textContent = tt('admin.dyn.test','테스트'); btn.disabled = false; }, 2000);
    }
    async function deleteWebhook(id, btn) {
      if (!confirm(tt('admin.dyn.confirm_delete_webhook','이 webhook을 삭제하시겠습니까?'))) return;
      btn.textContent = tt('admin.dyn.deleting','삭제 중…'); btn.disabled = true;
      try {
        const res = await fetch(`/webhooks/${id}`, {method:'DELETE'});
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        await loadWebhooks();
      } catch(e) { webhookStatusEl.textContent = `${tt('admin.dyn.delete_fail_prefix','삭제 실패: ')}${e.message}`; btn.disabled = false; btn.textContent = tt('admin.dyn.delete','삭제'); }
    }
    document.getElementById('add_webhook')?.addEventListener('click', async () => {
      const url = whUrlEl.value.trim();
      if (!url) { webhookStatusEl.textContent = tt('admin.dyn.enter_url','URL을 입력하세요.'); return; }
      webhookStatusEl.textContent = tt('admin.dyn.adding','추가 중…');
      try {
        const res = await fetch('/webhooks', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name: whNameEl.value.trim() || 'Slack Webhook', url})});
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        whNameEl.value = ''; whUrlEl.value = '';
        webhookStatusEl.textContent = tt('admin.dyn.add_done','추가 완료 ✓');
        await loadWebhooks();
      } catch(e) { webhookStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
    });
    document.getElementById('reload_webhooks')?.addEventListener('click', loadWebhooks);

    // ── Guide Editor ───────────────────────────────────────────────────────
    const guideEditSelectEl = document.getElementById('guide_edit_select');
    const guideEditTitleEl = document.getElementById('guide_edit_title');
    const guideEditContentEl = document.getElementById('guide_edit_content');
    const guideEditStatusEl = document.getElementById('guide_edit_status');

    async function loadGuideForEdit(guideId) {
      guideEditStatusEl.textContent = tt('admin.dyn.loading_data','불러오는 중…');
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`);
        if (!res.ok) throw new Error(res.status);
        const g = await res.json();
        guideEditTitleEl.value = g.title || '';
        guideEditContentEl.value = g.content || '';
        guideEditStatusEl.textContent = g.updated_at ? `${tt('admin.dyn.last_saved_prefix','마지막 저장: ')}${g.updated_at.slice(0,19).replace('T',' ')}` : tt('admin.dyn.default_content','(기본 내용)');
      } catch(e) { guideEditStatusEl.textContent = `${tt('admin.dyn.load_data_fail_prefix','불러오기 실패: ')}${e.message}`; }
    }

    document.getElementById('guide_edit_load')?.addEventListener('click', () => {
      loadGuideForEdit(guideEditSelectEl.value);
    });
    guideEditSelectEl.addEventListener('change', () => {
      loadGuideForEdit(guideEditSelectEl.value);
    });
    document.getElementById('guide_edit_save')?.addEventListener('click', async () => {
      const guideId = guideEditSelectEl.value;
      const title = guideEditTitleEl.value.trim();
      const content = guideEditContentEl.value;
      if (!title) { guideEditStatusEl.textContent = tt('admin.dyn.enter_title','제목을 입력하세요.'); return; }
      guideEditStatusEl.textContent = tt('admin.dyn.saving','저장 중…');
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`, {
          method: 'PUT', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({title, content}),
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        guideEditStatusEl.textContent = tt('admin.dyn.save_done','저장 완료 ✓');
      } catch(e) { guideEditStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
    });

    /* ── Admin Tab switching ──────────────────────────────── */
    function switchAdminTab(tab) {
      document.querySelectorAll('.atab-panel').forEach(el => el.classList.remove('active'));
      // 상단 탭 + 하단 탭 모두 active 동기화
      document.querySelectorAll('#admin_tabs_nav button, #admin_bottom_nav button').forEach(btn => btn.classList.remove('active'));
      const panel = document.getElementById('atab_' + tab);
      if (panel) panel.classList.add('active');
      document.querySelectorAll('[data-atab="' + tab + '"]').forEach(btn => btn.classList.add('active'));
      window.scrollTo({ top: 0, behavior: 'smooth' });
      // 탭별 lazy 로더 dispatch (Phase 2)
      if (tab === 'logs') { loadAuditLog(); loadUserActivityLog(); }
      if (tab === 'compliance') loadAdminCompliance();
      if (tab === 'triage') { loadAdminTriage(); loadAdminIncidents(); }
      if (tab === 'remediation') { loadAdminVulnActions(); loadAdminActionPlans(); }
      if (tab === 'overview') { loadAdminPhase2Health(); loadAdminSourceFreshness(); }
    }

    // i18n: refresh the active admin tab's dynamic content when the language changes
    window.onLangChange = function() {
      const activePanel = document.querySelector('.atab-panel.active');
      const tab = activePanel ? activePanel.id.replace('atab_', '') : 'overview';
      try {
        switchAdminTab(tab);
        // settings/access 탭은 init 시 1회 렌더되므로 언어 변경 시 직접 재렌더
        if (tab === 'settings') { renderDashboardPreferences(); renderGuideButtons(guideExamplesEl, guideExamples); }
        if (tab === 'access') { loadRolePermissions(); loadUserTabPermissions(); loadSignupRequests(); }
      } catch (e) { /* best-effort */ }
    };

    // ── 계정 메뉴 (언어 설정 등) ───────────────────────────────────────────────
    window.toggleAccountMenu = function() {
      const m = document.getElementById('account_menu');
      if (m) m.style.display = (!m.style.display || m.style.display === 'none') ? 'block' : 'none';
    };
    document.addEventListener('click', function(e) {
      const wrap = document.querySelector('.account-wrap');
      const menu = document.getElementById('account_menu');
      if (wrap && menu && !wrap.contains(e.target)) menu.style.display = 'none';
    });

    // ── Signup Requests ────────────────────────────────────────────────────
    const signupListEl = document.getElementById('signup_requests_list');
    const signupStatusEl = document.getElementById('signup_requests_status');

    async function loadSignupRequests() {
      if (!signupListEl) return;
      signupListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/auth/signup-requests');
        const data = await res.json();
        const reqs = data.requests || [];
        if (reqs.length === 0) {
          signupListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_signup','가입 요청이 없습니다.')}</span>`;
          return;
        }
        const statusBadge = s => ({pending:tt('admin.dyn.signup.pending','🟡 대기중'), approved:tt('admin.dyn.signup.approved','🟢 승인됨'), rejected:tt('admin.dyn.signup.rejected','🔴 거절됨')}[s] || s);
        signupListEl.innerHTML = reqs.map(r => `
          <div class="owner-row" style="border:1px solid #1e3a5f;border-radius:10px;padding:12px;margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
              <div>
                <strong>${r.name}</strong> <span style="color:#94a3b8;font-size:12px;">${r.email}</span>
                ${r.department ? `<span style="color:#64748b;font-size:12px;margin-left:6px;">[${r.department}]</span>` : ''}
                <div style="font-size:12px;color:#94a3b8;margin-top:4px;">${r.reason || tt('admin.dyn.no_reason','(사유 없음)')}</div>
                <div style="font-size:11px;color:#475569;margin-top:4px;">${tt('admin.dyn.col.created','요청일')}: ${r.created_at || '-'}${r.reviewed_at ? ' / ' + tt('admin.dyn.col.reviewed','처리일') + ': ' + r.reviewed_at : ''}</div>
              </div>
              <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                <span>${statusBadge(r.status)}</span>
                ${r.status === 'pending' ? `
                  <button class="secondary" style="font-size:12px;padding:4px 10px" onclick="handleSignupRequest('${r.id}','approved')">${tt('admin.dyn.approve','승인')}</button>
                  <button class="danger" style="font-size:12px;padding:4px 10px" onclick="handleSignupRequest('${r.id}','rejected')">${tt('admin.dyn.reject','거절')}</button>
                ` : ''}
              </div>
            </div>
          </div>`).join('');
      } catch(e) {
        signupListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${e.message}</span>`;
      }
    }

    async function handleSignupRequest(id, status) {
      if (!signupStatusEl) return;
      signupStatusEl.textContent = tt('admin.dyn.processing','처리 중…');
      try {
        const res = await fetch(`/auth/signup-requests/${id}`, {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({status})
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        signupStatusEl.textContent = status === 'approved' ? tt('admin.dyn.approve_done','✅ 승인 완료') : tt('admin.dyn.reject_done','❌ 거절 완료');
        await loadSignupRequests();
      } catch(e) {
        signupStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
      }
    }

    if (document.getElementById('reload_signup_requests')) {
      document.getElementById('reload_signup_requests')?.addEventListener('click', loadSignupRequests);
    }

    // ── Asset Audit Log ────────────────────────────────────────────────────
    const auditLogListEl = document.getElementById('audit_log_list');
    const auditLogStatusEl = document.getElementById('audit_log_status');

    async function loadAuditLog() {
      if (!auditLogListEl) return;
      auditLogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      const hostname = (document.getElementById('audit_filter_hostname')?.value || '').trim();
      const field = document.getElementById('audit_filter_field')?.value || '';
      let url = '/admin/audit-log';
      const params = new URLSearchParams();
      if (hostname) params.set('hostname', hostname);
      if (field) params.set('field', field);
      if (params.toString()) url += '?' + params.toString();
      try {
        const res = await fetch(url);
        if (!res.ok) { auditLogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.load_fail','로드 실패')}</span>`; return; }
        const data = await res.json();
        const logs = data.audit_log || [];
        if (!logs.length) { auditLogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_audit','변경 이력 없음')}</span>`; return; }
        const FIELD_LABEL = { owner: tt('admin.dyn.field.owner','담당자'), category: tt('admin.dyn.field.category','카테고리') };
        auditLogListEl.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead><tr style="background:#0f2035;">
            <th style="padding:8px;color:#7dd3fc;text-align:left">${tt('admin.dyn.col.time','시각')}</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">${tt('admin.dyn.col.host','호스트')}</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">${tt('admin.dyn.col.field','항목')}</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">${tt('admin.dyn.col.old_value','이전 값')}</th>
            <th style="padding:8px;color:#a3e635;text-align:left">${tt('admin.dyn.col.new_value','변경 값')}</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">${tt('admin.dyn.col.changed_by','변경자')}</th>
          </tr></thead>
          <tbody>
          ${logs.map(l => `<tr style="border-bottom:1px solid #1e293b;">
            <td style="padding:7px 8px;color:#64748b;white-space:nowrap">${escapeHtml(formatTime(l.changed_at))}</td>
            <td style="padding:7px 8px;color:#e2e8f0;font-weight:600">${escapeHtml(l.hostname)}</td>
            <td style="padding:7px 8px;color:#fbbf24">${escapeHtml(FIELD_LABEL[l.field] || l.field)}</td>
            <td style="padding:7px 8px;color:#94a3b8">${escapeHtml(l.old_value || '-')}</td>
            <td style="padding:7px 8px;color:#a3e635">${escapeHtml(l.new_value || '-')}</td>
            <td style="padding:7px 8px;color:#93c5fd">${escapeHtml(l.changed_by)}</td>
          </tr>`).join('')}
          </tbody></table>`;
        if (auditLogStatusEl) auditLogStatusEl.textContent = `${tt('admin.dyn.col.total','총')} ${data.total}${tt('admin.dyn.count_suffix','건')}`;
      } catch(e) {
        auditLogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
    }

    if (document.getElementById('reload_audit_log')) {
      document.getElementById('reload_audit_log')?.addEventListener('click', loadAuditLog);
    }
    if (document.getElementById('audit_search_btn')) {
      document.getElementById('audit_search_btn')?.addEventListener('click', loadAuditLog);
    }

    // ── Role Permissions ─────────────────────────────────────────────────────
    const ROLE_PERM_TABS = [
      { id: 'dashboard', label: '📊 대시보드', labelKey: 'admin.dyn.tab.dashboard' },
      { id: 'triage', label: '🚨 Alert Triage', labelKey: 'admin.dyn.tab.triage' },
      { id: 'incidents', label: '📋 인시던트', labelKey: 'admin.dyn.tab.incidents' },
      { id: 'assets', label: '📡 자산 현황', labelKey: 'admin.dyn.tab.assets' },
      { id: 'compliance', label: '✅ Compliance PDCA', labelKey: 'admin.dyn.tab.compliance' },
      { id: 'guides', label: '📖 가이드', labelKey: 'admin.dyn.tab.guides' },
    ];
    const ROLE_PERM_ROLES = [
      { key: 'security', label: '보안담당자 (security)', labelKey: 'admin.dyn.role.security' },
      { key: 'monitor', label: '서버모니터 (monitor)', labelKey: 'admin.dyn.role.monitor' },
      { key: 'auditor', label: '감사자 (auditor)', labelKey: 'admin.dyn.role.auditor' },
      { key: 'helpdesk', label: '헬프데스크 (helpdesk)', labelKey: 'admin.dyn.role.helpdesk' },
      { key: 'user', label: '일반사용자 (user)', labelKey: 'admin.dyn.role.user' },
    ];

    async function loadRolePermissions() {
      const listEl = document.getElementById('roleperm_list');
      const statusEl = document.getElementById('roleperm_status');
      if (!listEl) return;
      listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/admin/role-permissions');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const perms = data.permissions || {};
        listEl.innerHTML = ROLE_PERM_ROLES.map(role => {
          const allowed = perms[role.key] || [];
          const checks = ROLE_PERM_TABS.map(tab => {
            const checked = allowed.includes(tab.id) ? 'checked' : '';
            return `<label style=\"display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid #223148;border-radius:8px;background:#0b1220;cursor:pointer\">
              <input type=\"checkbox\" data-role=\"${role.key}\" data-tab=\"${tab.id}\" ${checked} style=\"width:auto;margin:0\" />
              <span style=\"font-size:13px\">${tt(tab.labelKey, tab.label)}</span>
            </label>`;
          }).join('');
          return `<div style=\"background:#0f172a;border:1px solid #233046;border-radius:12px;padding:14px\">
            <div style=\"font-weight:700;color:#38bdf8;margin-bottom:10px\">${escapeHtml(tt(role.labelKey, role.label))}</div>
            <div style=\"display:flex;flex-wrap:wrap;gap:8px\">${checks}</div>
          </div>`;
        }).join('');
      } catch(e) {
        listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span>`;
      }
    }

    if (document.getElementById('reload_roleperm')) {
      document.getElementById('reload_roleperm')?.addEventListener('click', loadRolePermissions);
    }
    if (document.getElementById('save_roleperm')) {
      document.getElementById('save_roleperm')?.addEventListener('click', async () => {
        const statusEl = document.getElementById('roleperm_status');
        const checkboxes = document.querySelectorAll('#roleperm_list input[type=checkbox]');
        const payload = {};
        checkboxes.forEach(cb => {
          const role = cb.dataset.role;
          const tab = cb.dataset.tab;
          if (!payload[role]) payload[role] = [];
          if (cb.checked) payload[role].push(tab);
        });
        statusEl.textContent = tt('admin.dyn.saving','저장 중...');
        try {
          const res = await fetch('/admin/role-permissions', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
          });
          if (!res.ok) throw new Error(await res.text());
          statusEl.style.color = '#86efac';
          statusEl.textContent = tt('admin.dyn.roleperm_saved','✅ 권한이 저장되었습니다. 해당 역할 사용자 재로그인 후 적용됩니다.');
        } catch(e) {
          statusEl.style.color = '#fca5a5';
          statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
        }
      });
    }

    // ── 유저별 탭 권한 관리 ────────────────────────────────────────────────
    async function loadUserTabPermissions() {
      const listEl = document.getElementById('usertab_list');
      const statusEl = document.getElementById('usertab_status');
      if (!listEl) return;
      listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/admin/user-tab-permissions');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const users = data.users || [];
        if (users.length === 0) {
          listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.none_users','등록된 사용자가 없습니다.')}</span>`;
          return;
        }
        listEl.innerHTML = users.map(u => {
          const activeTabs = u.has_override ? u.user_tabs : u.role_default_tabs;
          const overrideBadge = u.has_override
            ? `<span style=\"background:#854d0e;color:#fbbf24;padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px\">${tt('admin.dyn.override_custom','개별 설정')}</span>`
            : `<span style=\"background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px\">${tt('admin.dyn.override_default','역할 기본값')}</span>`;
          const checks = ROLE_PERM_TABS.map(tab => {
            const checked = activeTabs.includes(tab.id) ? 'checked' : '';
            return `<label style=\"display:flex;align-items:center;gap:6px;padding:5px 8px;border:1px solid #223148;border-radius:6px;background:#0b1220;cursor:pointer;font-size:12px\">
              <input type=\"checkbox\" data-user=\"${escapeHtml(u.username)}\" data-utab=\"${tab.id}\" ${checked} style=\"width:auto;margin:0\" onchange=\"_onUserTabChange('${escapeHtml(u.username)}')\" />
              <span>${tt(tab.labelKey, tab.label)}</span>
            </label>`;
          }).join('');
          const resetBtn = u.has_override
            ? `<button onclick=\"_resetUserTabs('${escapeHtml(u.username)}')\" style=\"font-size:11px;padding:3px 10px;background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d;border-radius:6px;cursor:pointer;margin-left:8px\">${tt('admin.dyn.reset','초기화')}</button>`
            : '';
          return `<div style=\"background:#0f172a;border:1px solid #233046;border-radius:12px;padding:14px\" id=\"usertab_row_${escapeHtml(u.username)}\">
            <div style=\"display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px\">
              <div>
                <strong style=\"color:#e2e8f0\">${escapeHtml(u.username)}</strong>
                <span style=\"color:#64748b;font-size:12px;margin-left:6px\">(${escapeHtml(u.role)})</span>
                ${overrideBadge}
              </div>
              <div style=\"display:flex;gap:6px;align-items:center\">${resetBtn}</div>
            </div>
            <div style=\"display:flex;flex-wrap:wrap;gap:6px\">${checks}</div>
            <div class=\"status-line\" id=\"usertab_status_${escapeHtml(u.username)}\" style=\"margin-top:6px;font-size:12px\"></div>
          </div>`;
        }).join('');
      } catch(e) {
        listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span>`;
      }
    }

    async function _onUserTabChange(username) {
      const checkboxes = document.querySelectorAll(`input[data-user="${username}"][data-utab]`);
      const tabs = [];
      checkboxes.forEach(cb => { if (cb.checked) tabs.push(cb.dataset.utab); });
      const statusEl = document.getElementById('usertab_status_' + username);
      if (statusEl) { statusEl.style.color = '#94a3b8'; statusEl.textContent = tt('admin.dyn.saving','저장 중…'); }
      try {
        const res = await fetch(`/admin/user-tab-permissions/${encodeURIComponent(username)}`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ tabs }),
        });
        if (!res.ok) throw new Error(await res.text());
        if (statusEl) { statusEl.style.color = '#86efac'; statusEl.textContent = tt('admin.dyn.saved_relogin','✅ 저장됨 (재로그인 후 적용)'); }
        // 배지 업데이트
        setTimeout(() => loadUserTabPermissions(), 500);
      } catch(e) {
        if (statusEl) { statusEl.style.color = '#fca5a5'; statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
      }
    }
    window._onUserTabChange = _onUserTabChange;

    async function _resetUserTabs(username) {
      if (!confirm(`${username}${tt('admin.dyn.confirm_reset_usertabs',' 유저의 개별 탭 설정을 초기화하시겠습니까?\\n역할 기본값으로 돌아갑니다.')}`)) return;
      const statusEl = document.getElementById('usertab_status_' + username);
      try {
        const res = await fetch(`/admin/user-tab-permissions/${encodeURIComponent(username)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await res.text());
        if (statusEl) { statusEl.style.color = '#86efac'; statusEl.textContent = tt('admin.dyn.reset_done','✅ 초기화됨'); }
        setTimeout(() => loadUserTabPermissions(), 500);
      } catch(e) {
        if (statusEl) { statusEl.style.color = '#fca5a5'; statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
      }
    }
    window._resetUserTabs = _resetUserTabs;

    if (document.getElementById('reload_usertab')) {
      document.getElementById('reload_usertab')?.addEventListener('click', loadUserTabPermissions);
    }

    // ── 사용자 행동 로그 ──────────────────────────────────────────────────
    async function loadUserActivityLog(filterUser, filterAction) {
      const listEl = document.getElementById('userlog_list');
      if (!listEl) return;
      listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        let url = '/admin/action-audit-log?limit=500';
        if (filterUser) url += `&username=${encodeURIComponent(filterUser)}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        let logs = data.logs || [];
        if (filterAction) logs = logs.filter(e => e.action === filterAction);
        if (!logs.length) { listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.none_userlog','로그 없음')}</span>`; return; }
        const ACTION_COLOR = {
          LOGIN:'#86efac', LOGIN_FAIL:'#fca5a5', LOGOUT:'#94a3b8',
          TAB_SWITCH:'#7dd3fc', QUERY:'#fbbf24', INTERPRET:'#c4b5fd', UNKNOWN:'#cbd5e1',
        };
        listEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
          <thead><tr style=\"color:#94a3b8;border-bottom:1px solid #334155\">
            <th style=\"text-align:left;padding:6px 10px;white-space:nowrap\">${tt('admin.dyn.col.time','시각')}</th>
            <th style=\"text-align:left;padding:6px 10px\">${tt('admin.dyn.col.user','사용자')}</th>
            <th style=\"text-align:left;padding:6px 10px\">${tt('admin.dyn.col.action','액션')}</th>
            <th style=\"text-align:left;padding:6px 10px\">${tt('admin.dyn.col.detail','상세')}</th>
          </tr></thead>
          <tbody>${logs.map(e => {
            const col = ACTION_COLOR[e.action] || ACTION_COLOR.UNKNOWN;
            return `<tr style=\"border-bottom:1px solid #1e293b\">
              <td style=\"padding:5px 10px;color:#64748b;white-space:nowrap\">${escapeHtml(e.ts)}</td>
              <td style=\"padding:5px 10px;color:#f1f5f9;font-weight:600\">${escapeHtml(e.username)}</td>
              <td style=\"padding:5px 10px\"><span style=\"color:${col};font-weight:700\">${escapeHtml(e.action)}</span></td>
              <td style=\"padding:5px 10px;color:#94a3b8\">${escapeHtml(e.detail||'')}</td>
            </tr>`;
          }).join('')}</tbody>
        </table>`;
      } catch(e) {
        listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span>`;
      }
    }

    if (document.getElementById('reload_userlog')) {
      document.getElementById('reload_userlog')?.addEventListener('click', () => {
        const u = (document.getElementById('userlog_filter_user')||{}).value||'';
        const a = (document.getElementById('userlog_filter_action')||{}).value||'';
        loadUserActivityLog(u, a);
      });
    }
    if (document.getElementById('userlog_search_btn')) {
      document.getElementById('userlog_search_btn')?.addEventListener('click', () => {
        const u = (document.getElementById('userlog_filter_user')||{}).value||'';
        const a = (document.getElementById('userlog_filter_action')||{}).value||'';
        loadUserActivityLog(u, a);
      });
    }

    // ── Phase 2: Overview · Compliance · Triage · Remediation 로더 ───────────
    const STATUS_BADGE = {
      pass:'<span style=\"background:rgba(34,197,94,.12);color:#86efac;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">PASS</span>',
      fail:'<span style=\"background:rgba(248,113,113,.12);color:#fca5a5;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">FAIL</span>',
      warning:'<span style=\"background:rgba(250,204,21,.12);color:#fde68a;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">WARN</span>',
      not_applicable:'<span style=\"background:rgba(148,163,184,.12);color:#cbd5e1;padding:2px 8px;border-radius:6px;font-size:12px\">N/A</span>',
      not_checked:`<span style=\"background:rgba(100,116,139,.12);color:#94a3b8;padding:2px 8px;border-radius:6px;font-size:12px\">${tt('admin.dyn.metric.not_checked','미점검')}</span>`,
    };
    const _statusBadge = (s) => STATUS_BADGE[s] || `<span>${escapeHtml(s||'')}</span>`;
    const _sourceBadge = (src) => {
      const map = { control_check:'#7dd3fc', trivy:'#fbbf24', alert:'#fca5a5' };
      const color = map[src] || '#94a3b8';
      return `<span style=\"background:rgba(56,189,248,.08);color:${color};padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700\">${escapeHtml(src||'-')}</span>`;
    };

    async function loadAdminPhase2Health() {
      const el = document.getElementById('phase2_health');
      if (!el) return;
      el.innerHTML = `<div class=\"coverage-item\"><span style=\"color:#94a3b8\">${tt('admin.dyn.loading','로딩 중…')}</span></div>`;
      try {
        const res = await fetch('/compliance/pdca');
        const data = res.ok ? await res.json() : { summary: {}, pending_count: 0 };
        const summary = data.summary || {};
        const total = Object.values(summary).reduce((a,b)=>a+(b||0),0);
        const items = [
          { label: 'Control Checks', value: total, hint: 'control_check_results' },
          { label: tt('admin.dyn.metric.pending','미조치'), value: data.pending_count || 0, hint: 'fail + warning + Trivy + Alert' },
          { label: tt('admin.dyn.metric.overdue','기한 초과'), value: data.overdue_count || 0, hint: `remediation_due_at ${tt('admin.dyn.elapsed','경과')}` },
        ];
        const inc = await fetch('/incidents').then(r => r.ok ? r.json() : { total: 0 }).catch(() => ({ total: 0 }));
        items.push({ label: 'Incidents', value: inc.total || (inc.incidents||[]).length, hint: 'incident_store' });
        el.innerHTML = items.map(it => `
          <div class=\"coverage-item\">
            <div style=\"color:#94a3b8;font-size:12px\">${escapeHtml(it.label)}</div>
            <strong style=\"color:${it.value>0?'#86efac':'#fca5a5'}\">${it.value}</strong>
            <div style=\"color:#64748b;font-size:11px;margin-top:4px\">${escapeHtml(it.hint)}</div>
          </div>`).join('');
      } catch (e) {
        el.innerHTML = `<div class=\"coverage-item\"><span style=\"color:#fca5a5\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span></div>`;
      }
    }

    // 초 단위 lag을 사람이 읽을 수 있는 문자열로 변환
    function _humanizeLag(seconds) {
      if (seconds == null || !isFinite(seconds)) return '-';
      const s = Math.max(0, Math.floor(seconds));
      const U = (k, f) => tt('admin.dyn.unit.' + k, f);
      if (s < 60) return s + U('sec','초');
      if (s < 3600) return Math.floor(s/60) + U('min','분');
      if (s < 86400) {
        const h = Math.floor(s/3600); const m = Math.floor((s%3600)/60);
        return m ? `${h}${U('hour','시간')} ${m}${U('min','분')}` : `${h}${U('hour','시간')}`;
      }
      const d = Math.floor(s/86400); const h = Math.floor((s%86400)/3600);
      return h ? `${d}${U('day','일')} ${h}${U('hour','시간')}` : `${d}${U('day','일')}`;
    }

    async function loadAdminSourceFreshness() {
      const el = document.getElementById('admin_source_freshness');
      if (!el) return;
      el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/dashboard');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const rows = data.source_coverage || [];
        if (!rows.length) {
          el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_source_syncs','source_syncs 기록 없음')}</div>`;
          return;
        }
        const nowMs = Date.now();
        const fmt = (rec) => {
          const lastOk = rec.last_success_at ? new Date(rec.last_success_at).getTime() : null;
          const lastErr = rec.last_error_at ? new Date(rec.last_error_at).getTime() : null;
          const lagSec = lastOk != null ? (nowMs - lastOk) / 1000 : null;
          const sla = rec.stale_threshold_seconds || null;
          let statusColor = '#86efac', statusLabel = (rec.status||'unknown').toUpperCase();
          if (rec.status === 'error') { statusColor = '#fca5a5'; }
          else if (rec.is_stale) { statusColor = '#fde68a'; statusLabel = 'STALE'; }
          else if (rec.status === 'running') { statusColor = '#93c5fd'; }
          const lagColor = rec.is_stale ? '#fbbf24' : (lagSec != null ? '#cbd5e1' : '#64748b');
          const slaText = sla ? _humanizeLag(sla) : '-';
          const errBadge = lastErr ? `<div style=\"color:#fca5a5;font-size:11px;margin-top:2px\">${tt('admin.dyn.recent_error_prefix','⚠ 최근 에러: ')}${escapeHtml(formatTime(rec.last_error_at))}</div>` : '';
          return `<tr>
            <td><strong>${escapeHtml((rec.source||'-').toUpperCase())}</strong></td>
            <td><span style=\"background:rgba(56,189,248,.08);color:${statusColor};padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">${escapeHtml(statusLabel)}</span></td>
            <td style=\"text-align:right\">${rec.host_count||0}</td>
            <td style=\"color:${lagColor}\">${lagSec != null ? _humanizeLag(lagSec) + tt('admin.dyn.ago_suffix',' 전') : '-'}</td>
            <td style=\"color:#94a3b8;font-size:12px\">${escapeHtml(slaText)}</td>
            <td style=\"text-align:right;color:#cbd5e1\">${rec.records_collected||0}<div style=\"color:#64748b;font-size:11px\">env ${rec.envelopes_normalized||0} · save ${rec.entities_saved||0}</div></td>
            <td style=\"color:#64748b;font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis\">${escapeHtml(rec.message||'-')}${errBadge}</td>
          </tr>`;
        };
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>Source</th><th>Status</th><th style=\"text-align:right\">${tt('admin.dyn.col.host','호스트')}</th><th>Lag</th><th>SLA</th><th style=\"text-align:right\">${tt('admin.dyn.col.collected','수집')}</th><th>${tt('admin.dyn.col.message','메시지')}</th></tr></thead>
          <tbody>${rows.map(fmt).join('')}</tbody></table>`;
      } catch (e) {
        el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_freshness')) {
      document.getElementById('admin_reload_freshness').addEventListener('click', loadAdminSourceFreshness);
    }

    async function loadAdminCompliance() {
      const cardsEl = document.getElementById('admin_compliance_cards');
      const catEl = document.getElementById('admin_compliance_categories');
      const pendingEl = document.getElementById('admin_compliance_pending');
      if (!cardsEl) return;
      cardsEl.innerHTML = `<div class=\"metric-card card\"><span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span></div>`;
      try {
        const res = await fetch('/compliance/pdca');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const s = data.summary || {};
        const total = (s.pass||0)+(s.fail||0)+(s.warning||0)+(s.not_applicable||0)+(s.not_checked||0);
        const passRate = total > 0 ? Math.round(((s.pass||0)/total)*100) : null;
        const ps = data.pending_sources || {};
        cardsEl.innerHTML = `
          <div class=\"metric-card card\"><div class=\"metric-label\">${tt('admin.dyn.metric.total_checks','📋 전체 점검')}</div><div class=\"metric-value\">${total}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">✅ Pass</div><div class=\"metric-value\" style=\"color:#86efac\">${s.pass||0}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">❌ Fail</div><div class=\"metric-value\" style=\"color:#fca5a5\">${s.fail||0}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">⚠️ Warning</div><div class=\"metric-value\" style=\"color:#fde68a\">${s.warning||0}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">📊 Pass Rate</div><div class=\"metric-value\" style=\"color:#a78bfa\">${passRate===null?'—':passRate+'%'}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">${tt('admin.dyn.metric.pending_icon','🔧 미조치')}</div><div class=\"metric-value\" style=\"color:#fb923c\">${data.pending_count||0}</div><div class=\"metric-sub\">${tt('admin.dyn.col.control','통제')} ${ps.control_check||0} · Trivy ${ps.trivy||0} · Alert ${ps.alert||0}</div></div>
        `;
        const cats = data.categories || [];
        if (!cats.length) {
          catEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_category','카테고리 데이터 없음 — 시드 누락 가능성')}</div>`;
        } else {
          catEl.innerHTML = `<table class=\"result-table\">
            <thead><tr><th>${tt('admin.dyn.col.category','카테고리')}</th><th>${tt('admin.dyn.col.total','총')}</th><th style=\"color:#86efac\">Pass</th><th style=\"color:#fca5a5\">Fail</th><th style=\"color:#fde68a\">Warning</th><th style=\"color:#cbd5e1\">N/A</th><th style=\"color:#94a3b8\">${tt('admin.dyn.col.not_checked','미점검')}</th></tr></thead>
            <tbody>${cats.map(c => `<tr>
              <td><strong>${escapeHtml(c.category||'-')}</strong></td>
              <td>${c.total||0}</td>
              <td style=\"color:#86efac\">${c.pass||0}</td>
              <td style=\"color:#fca5a5\">${c.fail||0}</td>
              <td style=\"color:#fde68a\">${c.warning||0}</td>
              <td style=\"color:#cbd5e1\">${c.not_applicable||0}</td>
              <td style=\"color:#94a3b8\">${c.not_checked||0}</td>
            </tr>`).join('')}</tbody></table>`;
        }
        const pending = data.pending_remediations || [];
        if (!pending.length) {
          pendingEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_pending','미조치 항목 없음 🎉')}</div>`;
        } else {
          pendingEl.innerHTML = `<table class=\"result-table\">
            <thead><tr><th>${tt('admin.dyn.col.source','출처')}</th><th>${tt('admin.dyn.col.control_id','통제 ID')}</th><th>${tt('admin.dyn.col.target','대상')}</th><th>${tt('admin.dyn.col.status','상태')}</th><th>${tt('admin.dyn.col.owner','담당자')}</th><th>${tt('admin.dyn.col.due','조치기한')}</th><th>${tt('admin.dyn.col.note','비고')}</th></tr></thead>
            <tbody>${pending.slice(0,100).map(p => `<tr>
              <td>${_sourceBadge(p.source)}</td>
              <td><strong>${escapeHtml(p.control_id||'-')}</strong></td>
              <td>${escapeHtml(p.entity_id||'-')}</td>
              <td>${_statusBadge(p.status)}</td>
              <td>${escapeHtml(p.owner||'-')}</td>
              <td style=\"${p.overdue?'color:#fca5a5;font-weight:700':''}\">${p.overdue?'🔴 ':''}${escapeHtml(p.remediation_due_at?formatTime(p.remediation_due_at):'-')}</td>
              <td style=\"color:#94a3b8;font-size:12px\">${escapeHtml(p.note||'')}</td>
            </tr>`).join('')}${pending.length>100?`<tr><td colspan=\"7\" style=\"color:#64748b;text-align:center;padding:8px\">… ${pending.length-100}${tt('admin.dyn.more_rows_suffix','건 더 (CSV 다운로드 권장)')}</td></tr>`:''}</tbody></table>`;
        }
      } catch (e) {
        cardsEl.innerHTML = `<div class=\"metric-card card\"><span class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span></div>`;
        if (catEl) catEl.innerHTML = '';
        if (pendingEl) pendingEl.innerHTML = '';
      }
    }
    if (document.getElementById('admin_reload_compliance')) {
      document.getElementById('admin_reload_compliance').addEventListener('click', loadAdminCompliance);
    }

    // ── Triage 로더 (alert triage_store 상태 요약) ────────────────────────
    async function loadAdminTriage() {
      const el = document.getElementById('admin_triage_list');
      if (!el) return;
      el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/alerts');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const alerts = data.alerts || [];
        // triage가 pending이 아닌 항목 우선 + critical/high만 표시 (최대 100건)
        const rows = alerts
          .filter(a => (a.triage && a.triage.status && a.triage.status !== 'pending') || ['critical','high'].includes(a.severity))
          .slice(0, 100);
        if (!rows.length) {
          el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_alert','표시할 alert 없음')}</div>`;
          return;
        }
        const TRIAGE_LABEL = { pending:tt('admin.dyn.atriage.pending','🟡 대기'), reviewing:tt('admin.dyn.atriage.reviewing','🔵 검토중'), resolved:tt('admin.dyn.atriage.resolved','🟢 조치') };
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>${tt('admin.dyn.col.severity','심각도')}</th><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.message','메시지')}</th><th>Triage</th><th>${tt('admin.dyn.col.analyst','분석관')}</th><th>${tt('admin.dyn.col.observed','발생 시각')}</th></tr></thead>
          <tbody>${rows.map(a => {
            const sev = a.severity || '-';
            const sevColor = sev==='critical'?'#fca5a5':sev==='high'?'#fbbf24':'#94a3b8';
            const t = a.triage || {};
            return `<tr>
              <td><strong style=\"color:${sevColor}\">${escapeHtml(sev.toUpperCase())}</strong></td>
              <td>${escapeHtml(a.hostname||a.host_id||'-')}</td>
              <td style=\"color:#cbd5e1;max-width:380px;overflow:hidden;text-overflow:ellipsis\">${escapeHtml(a.message||'')}</td>
              <td>${escapeHtml(TRIAGE_LABEL[t.status]||t.status||tt('admin.dyn.atriage.pending','🟡 대기'))}</td>
              <td style=\"color:#93c5fd\">${escapeHtml(t.analyst||'-')}</td>
              <td style=\"color:#64748b;font-size:12px\">${escapeHtml(formatTime(a.observed_at))}</td>
            </tr>`;
          }).join('')}</tbody></table>`;
      } catch (e) {
        el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_triage')) {
      document.getElementById('admin_reload_triage').addEventListener('click', loadAdminTriage);
    }

    // ── Incidents 로더 (incident_store 요약) ──────────────────────────────
    async function loadAdminIncidents() {
      const el = document.getElementById('admin_incidents_list');
      if (!el) return;
      el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/incidents');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const list = data.incidents || [];
        if (!list.length) {
          el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_incidents','등록된 인시던트 없음')}</div>`;
          return;
        }
        const STATUS_COLOR = { open:'#ef4444', investigating:'#f59e0b', resolved:'#22c55e', closed:'#6b7280' };
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>${tt('admin.dyn.col.title','제목')}</th><th>${tt('admin.dyn.col.status','상태')}</th><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.handler','담당자')}</th><th>${tt('admin.dyn.col.analyst','분석관')}</th><th>${tt('admin.dyn.col.created','등록일')}</th><th>${tt('admin.dyn.col.updated','업데이트')}</th></tr></thead>
          <tbody>${list.slice(0,100).map(i => `<tr>
            <td><strong>${escapeHtml(i.title||'-')}</strong></td>
            <td><span style=\"background:rgba(56,189,248,.08);color:${STATUS_COLOR[i.status]||'#94a3b8'};padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">${escapeHtml((i.status||'').toUpperCase())}</span></td>
            <td>${escapeHtml(i.hostname||'-')}</td>
            <td>${escapeHtml(i.handler||'-')}</td>
            <td style=\"color:#93c5fd\">${escapeHtml(i.analyst||'-')}</td>
            <td style=\"color:#64748b;font-size:12px\">${escapeHtml(formatTime(i.created_at))}</td>
            <td style=\"color:#64748b;font-size:12px\">${escapeHtml(formatTime(i.status_updated_at))}</td>
          </tr>`).join('')}</tbody></table>`;
      } catch (e) {
        el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_incidents')) {
      document.getElementById('admin_reload_incidents').addEventListener('click', loadAdminIncidents);
    }

    // ── Remediation: vuln_actions (Trivy 조치) ────────────────────────────
    async function loadAdminVulnActions() {
      const el = document.getElementById('admin_vuln_actions');
      if (!el) return;
      el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/trivy/vulnerabilities?severity=critical');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const hosts = data.hosts || [];
        // by_host 구조: { host_id, hostname, vulnerabilities: [{vuln_id, cve, severity, package_name, action: {plan_text,...}}] }
        const flatRows = [];
        hosts.forEach(h => {
          (h.vulnerabilities || []).forEach(v => flatRows.push({ ...v, hostname: h.hostname || h.host_id }));
        });
        if (!flatRows.length) {
          el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_critical_vuln','Critical 취약점 없음')}</div>`;
          return;
        }
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>${tt('admin.dyn.col.host','호스트')}</th><th>CVE</th><th>${tt('admin.dyn.col.package','패키지')}</th><th>${tt('admin.dyn.col.severity','심각도')}</th><th>${tt('admin.dyn.col.action_plan','조치 계획')}</th><th>${tt('admin.dyn.col.exception','예외')}</th></tr></thead>
          <tbody>${flatRows.slice(0,150).map(v => {
            const act = v.action || {};
            const planTxt = act.plan_text ? `<div>${escapeHtml(act.plan_text.substring(0,80))}${act.plan_text.length>80?'…':''}</div><div style=\"color:#64748b;font-size:11px\">${tt('admin.dyn.due_prefix','기한 ')}${escapeHtml(act.plan_target_date||'-')} · ${escapeHtml(act.plan_updated_by||'-')}</div>` : `<span style=\"color:#64748b\">${tt('admin.dyn.unregistered','미등록')}</span>`;
            const excTxt = act.exception_until ? `<div style=\"color:#fde68a\">~${escapeHtml(act.exception_until)}</div><div style=\"color:#64748b;font-size:11px\">${escapeHtml((act.exception_reason||'').substring(0,60))}</div>` : '<span style=\"color:#64748b\">-</span>';
            return `<tr>
              <td><strong>${escapeHtml(v.hostname||'-')}</strong></td>
              <td style=\"font-family:ui-monospace\">${escapeHtml(v.cve||v.vuln_id||'-')}</td>
              <td style=\"color:#cbd5e1\">${escapeHtml(v.package_name||'-')}</td>
              <td><strong style=\"color:${v.severity==='critical'?'#fca5a5':'#fbbf24'}\">${escapeHtml((v.severity||'').toUpperCase())}</strong></td>
              <td style=\"color:#cbd5e1;font-size:12px\">${planTxt}</td>
              <td style=\"font-size:12px\">${excTxt}</td>
            </tr>`;
          }).join('')}${flatRows.length>150?`<tr><td colspan=\"6\" style=\"color:#64748b;text-align:center;padding:8px\">… ${flatRows.length-150}${tt('admin.dyn.more_rows_short','건 더')}</td></tr>`:''}</tbody></table>`;
      } catch (e) {
        el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_vulns')) {
      document.getElementById('admin_reload_vulns').addEventListener('click', loadAdminVulnActions);
    }

    // ── Remediation: asset action_plans (host별 계획) ────────────────────
    async function loadAdminActionPlans() {
      const el = document.getElementById('admin_action_plans');
      if (!el) return;
      el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/assets');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        // build_assets_payload returns nested structure; collect plans from zabbix/fleet/trivy hosts
        const seen = new Set();
        const rows = [];
        const collect = (arr) => {
          (arr || []).forEach(h => {
            const plan = h.plan || {};
            if (plan.text || plan.target_date) {
              const key = h.host_id || h.hostname;
              if (seen.has(key)) return;
              seen.add(key);
              rows.push({ hostname: h.hostname || h.host_id, plan });
            }
          });
        };
        collect((data.zabbix||{}).by_host);
        collect((data.fleet||{}).by_host);
        collect((data.trivy||{}).by_host);
        if (!rows.length) {
          el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_action_plans','등록된 조치 계획 없음')}</div>`;
          return;
        }
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.target_date','목표일')}</th><th>${tt('admin.dyn.col.plan_content','계획 내용')}</th><th>${tt('admin.dyn.col.updated','업데이트')}</th></tr></thead>
          <tbody>${rows.slice(0,100).map(r => `<tr>
            <td><strong>${escapeHtml(r.hostname)}</strong></td>
            <td style=\"color:#fde68a\">${escapeHtml(r.plan.target_date||'-')}</td>
            <td style=\"color:#cbd5e1\">${escapeHtml((r.plan.text||'').substring(0,200))}${(r.plan.text||'').length>200?'…':''}</td>
            <td style=\"color:#64748b;font-size:12px\">${escapeHtml(formatTime(r.plan.updated_at)||'-')} · ${escapeHtml(r.plan.updated_by||'-')}</td>
          </tr>`).join('')}</tbody></table>`;
      } catch (e) {
        el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }

    /* ── 관리자 콘솔 역할별 탭 제한 ────────────────────────────────────────── */
    const _adminRoleLabel = (r) => tt('admin.dyn.rolename.' + r, ({ admin: '어드민', security: '보안담당자', monitor: '서버모니터', auditor: '감사자', helpdesk: '헬프데스크', user: '사용자' })[r] || r);
    // admin: 전체, monitor: 모니터링/자산, security: 모니터링/자산/권한관리,
    // auditor: 모니터링/변경이력(읽기전용), helpdesk: 모니터링/자산
    const _ADMIN_TAB_BY_ROLE = {
      admin:    ['overview','compliance','triage','remediation','assets','access','logs','settings'],
      monitor:  ['overview','compliance','triage','assets'],
      security: ['overview','compliance','triage','remediation','assets','access'],
      auditor:  ['overview','compliance','logs'],
      helpdesk: ['overview','assets'],
      user:     ['overview'],
    };
    let _adminCurrentRole = 'user';
    async function applyAdminRoleTabs() {
      try {
        const res = await fetch('/auth/me');
        if (!res.ok) return;
        const me = await res.json();
        const role = me.role || 'user';
        _adminCurrentRole = role;
        const allowed = _ADMIN_TAB_BY_ROLE[role] || _ADMIN_TAB_BY_ROLE['user'];
        const allTabs = ['overview','compliance','triage','remediation','assets','access','logs','settings'];
        allTabs.forEach(tab => {
          const visible = allowed.includes(tab);
          document.querySelectorAll('[data-atab="'+tab+'"]').forEach(btn => btn.style.display = visible ? '' : 'none');
        });
        // 현재 활성 탭이 허용되지 않으면 첫 번째 허용 탭으로 전환
        const activePanel = document.querySelector('.atab-panel.active');
        const activeId = activePanel ? activePanel.id.replace('atab_','') : 'overview';
        if (!allowed.includes(activeId) && allowed.length > 0) {
          switchAdminTab(allowed[0]);
        }
        // 상단 헤더에 사용자/역할 배지 표시
        const badge = document.getElementById('admin_user_badge');
        if (badge && me.username) {
          const roleLabel = _adminRoleLabel(role);
          badge.innerHTML = '<strong style="color:#38bdf8">' + me.username + '</strong> <span style="background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:6px;font-size:12px">' + roleLabel + '</span>';
        }
      } catch(e) { /* ignore */ }
    }

    async function initialize() {
      await applyAdminRoleTabs();
      await loadDashboardPreferences();
      await loadCatalog();
      await loadDashboard();
      await loadOwners();
      await loadWebhooks();
      await loadGuideForEdit(guideEditSelectEl.value);
      await loadSignupRequests();
      await loadRolePermissions();
      await loadUserTabPermissions();
      // Phase 2 lazy loaders: overview는 즉시, 나머지는 탭 전환 시
      loadAdminPhase2Health().catch(() => {});
      loadAdminSourceFreshness().catch(() => {});
    }

    initialize().catch(err => {
      console.error('[MORI Admin] initialize error:', err);
      if (dashboardStatusEl) dashboardStatusEl.textContent = `${tt('admin.dyn.init_error','초기화 오류: ')}${err.message}`;
    });
  </script>
  __I18N_SCRIPT__
</body>
</html>"""
    return (
        html.replace("__PAYLOAD_JSON__", payload_json)
        .replace("__DEFAULT_PAYLOAD_JSON__", default_payload_json)
        .replace("__GUIDE_EXAMPLES__", guide_examples_json)
        .replace("__DOCS_PORTAL_URL__", docs_url)
        .replace("__USER_DASHBOARD_PREFS_JSON__", default_preferences_json)
        .replace("__CARD_LABELS_JSON__", card_labels_json)
        .replace("__SECTION_LABELS_JSON__", section_labels_json)
        .replace("__ASSET_COLUMN_LABELS_JSON__", asset_column_labels_json)
        .replace("__GUIDE_LABELS_JSON__", guide_labels_json)
        .replace("__I18N_TOGGLE__", _i18n_toggle_html(fixed=False))
        .replace("__I18N_SCRIPT__", _i18n_script(_ADMIN_I18N))
    )


def render_user_dashboard_html(
    docs_url: str = DOCS_PORTAL_URL,
    fleet_ui_url: str = FLEET_UI_URL,
    zabbix_ui_url: str = ZABBIX_UI_URL,
    wazuh_ui_url: str = WAZUH_UI_URL,
) -> str:
    default_preferences_json = json.dumps(DEFAULT_USER_DASHBOARD_PREFERENCES, ensure_ascii=False)
    card_labels_json = json.dumps(USER_DASHBOARD_CARD_LABELS, ensure_ascii=False)
    section_labels_json = json.dumps(USER_DASHBOARD_SECTION_LABELS, ensure_ascii=False)
    guide_labels_json = json.dumps(USER_DASHBOARD_GUIDE_LABELS, ensure_ascii=False)
    nlq_guide_examples_json = json.dumps(list(QUERY_GUIDE_EXAMPLES), ensure_ascii=False)
    html = """<!doctype html>
<html lang=\"ko\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title data-i18n-doctitle=\"dash.doctitle\">MORI Security Dashboard</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0b1220; color: #e5e7eb; }
    .wrap { max-width: 1280px; margin: 0 auto; padding: 28px 20px 48px; }
    .hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 18px; }
    .hero h1 { margin: 0 0 8px; font-size: 32px; }
    .hero p { margin: 0; color: #94a3b8; max-width: 860px; line-height: 1.5; }
    .links { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
    .links a, .top-actions button { display: inline-flex; align-items: center; justify-content: center; color: #cfe3ff; text-decoration: none; border: 1px solid #334155; padding: 8px 12px; border-radius: 999px; background: #0f172a; }
    .top-actions { display: flex; gap: 10px; flex-wrap: wrap; }
    .metrics { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 16px; }
    .layout { display: grid; gap: 16px; }
    .stack { display: grid; gap: 16px; }
    .card { background: linear-gradient(180deg, #101827 0%, #0f172a 100%); border: 1px solid #233046; border-radius: 16px; padding: 18px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.18); }
    .metric-card { cursor: pointer; transition: transform 0.15s ease, border-color 0.15s ease; }
    .metric-card:hover { transform: translateY(-1px); border-color: #38bdf8; }
    .metric-card:focus-visible { outline: 2px solid #38bdf8; outline-offset: 2px; }
    .metric-label { color: #94a3b8; font-size: 13px; margin-bottom: 8px; }
    .metric-value { font-size: 28px; font-weight: 800; }
    .metric-sub { margin-top: 6px; color: #7dd3fc; font-size: 13px; }
    .card h2 { margin: 0 0 12px; font-size: 18px; }
    .subtext { color: #94a3b8; font-size: 13px; margin-bottom: 12px; }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #1f2937; vertical-align: top; }
    th { color: #94a3b8; font-weight: 600; }
    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .badge.online { background: rgba(34, 197, 94, 0.12); color: #86efac; }
    .badge.offline { background: rgba(248, 113, 113, 0.12); color: #fca5a5; }
    .badge.unknown { background: rgba(250, 204, 21, 0.12); color: #fde68a; }
    .coverage { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .coverage-item { background: #0b1220; border: 1px solid #223148; border-radius: 14px; padding: 14px; }
    .coverage-item strong { display: block; font-size: 22px; margin-top: 8px; }
    .list { display: grid; gap: 10px; }
    .list-item { border: 1px solid #1f2937; border-radius: 12px; padding: 12px; background: #0b1220; }
    .list-item .top { display: flex; gap: 12px; justify-content: space-between; margin-bottom: 6px; }
    .list-item .meta { color: #94a3b8; font-size: 12px; }
    .status-line, .empty { color: #94a3b8; font-size: 14px; }
    .hidden { display: none !important; }
    dialog { border: 1px solid #334155; border-radius: 18px; padding: 0; background: #0f172a; color: #e5e7eb; width: min(760px, calc(100vw - 32px)); }
    dialog::backdrop { background: rgba(2, 6, 23, 0.74); }
    .guide-dialog { padding: 20px; }
    .guide-dialog-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    .guide-dialog-head h3 { margin: 0; font-size: 20px; }
    .guide-dialog-copy { color: #94a3b8; font-size: 14px; line-height: 1.5; }
    .dialog-body { padding: 0 20px 20px; max-height: 60vh; overflow: auto; }
    .row { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
    .row label { font-size: 13px; color: #94a3b8; }
    .row input, .row select, .row textarea { background: #0b1220; color: #e5e7eb; border: 1px solid #334155; border-radius: 8px; padding: 8px 10px; font-size: 14px; width: 100%; box-sizing: border-box; }
    .actions { display: flex; gap: 10px; margin-top: 12px; }
    button { cursor: pointer; padding: 8px 16px; border-radius: 999px; border: 1px solid #334155; background: #1d4ed8; color: #fff; font-size: 14px; font-weight: 600; }
    button.secondary { background: #0f172a; color: #cfe3ff; }
    button.ghost { background: transparent; color: #94a3b8; }
    .tabs-nav { display: flex; gap: 0; border-bottom: 1px solid #233046; margin-bottom: 20px; overflow-x: auto; }
    .tabs-nav button { background: none; border: none; border-bottom: 2px solid transparent; padding: 10px 22px; color: #94a3b8; font-size: 15px; font-weight: 600; cursor: pointer; margin-bottom: -1px; border-radius: 0; white-space: nowrap; }
    .tabs-nav button.active { color: #38bdf8; border-bottom-color: #38bdf8; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .result-badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }
    .result-badge.wazuh { background: rgba(167,139,250,.15); color: #c4b5fd; }
    .result-badge.zabbix { background: rgba(56,189,248,.15); color: #7dd3fc; }
    .result-badge.fleet { background: rgba(52,211,153,.15); color: #6ee7b7; }
    .result-badge.trivy { background: rgba(251,146,60,.15); color: #fdba74; }
    .result-badge.hosts { background: rgba(148,163,184,.15); color: #cbd5e1; }
    /* ── NLQ FAB ── */
    .nlq-fab { position: fixed; bottom: 88px; right: 20px; z-index: 1001; background: linear-gradient(135deg,#1d4ed8,#0ea5e9); color: #fff; border: none; border-radius: 999px; padding: 14px 20px; font-size: 14px; font-weight: 700; box-shadow: 0 6px 24px rgba(14,165,233,.45); cursor: pointer; display: flex; align-items: center; gap: 8px; transition: transform 0.15s, box-shadow 0.15s; }
    .nlq-fab:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(14,165,233,.55); }
    @media (min-width: 769px) { .nlq-fab { bottom: 32px; } }
    .nlq-dialog { width: min(640px, calc(100vw - 24px)); }
    .nlq-dialog-body { padding: 20px; }
    /* ── Logout button ── */
    .logout-btn { background: rgba(239,68,68,.12); color: #fca5a5; border: 1px solid rgba(239,68,68,.3); border-radius: 999px; padding: 7px 16px; font-size: 13px; font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; cursor: pointer; transition: background .15s; white-space: nowrap; }
    .logout-btn:hover { background: rgba(239,68,68,.22); }
    /* ── Asset sub-tabs (scrollable on mobile) ── */
    .asset-sub-nav { display: flex; gap: 0; border-bottom: 1px solid #233046; margin-bottom: 16px; overflow-x: auto; -webkit-overflow-scrolling: touch; }
    .asset-sub-nav button { background: none; border: none; border-bottom: 2px solid transparent; padding: 8px 20px; color: #94a3b8; font-size: 14px; font-weight: 600; cursor: pointer; border-radius: 0; margin-bottom: -1px; white-space: nowrap; }
    .asset-sub-nav button.active { color: #38bdf8; border-bottom-color: #38bdf8; }
    /* ── Asset search bar ── */
    .asset-search-bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; padding: 8px 10px; background: #0b1220; border: 1px solid #1e293b; border-radius: 8px; }
    .asset-search-bar input[type="text"] { flex: 1; min-width: 140px; background: #1e293b; border: 1px solid #334155; color: #f1f5f9; border-radius: 6px; padding: 6px 10px; font-size: 13px; }
    .asset-search-bar input[type="text"]::placeholder { color: #64748b; }
    .asset-search-bar select { background: #1e293b; border: 1px solid #334155; color: #f1f5f9; border-radius: 6px; padding: 6px 8px; font-size: 13px; cursor: pointer; }
    .asset-search-count { color: #64748b; font-size: 12px; white-space: nowrap; }
    /* ── Responsive summary grids (asset/trivy) ── */
    .summary-grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
    .summary-grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
    /* ── Bottom Nav (mobile only) ── */
    .bottom-nav { display: none; }
    @media (max-width: 960px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .coverage { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .summary-grid-4 { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 768px) {
      html, body { overflow-x: hidden; }
      .wrap { padding: 16px 10px 84px; max-width: 100vw; box-sizing: border-box; overflow-x: hidden; }
      .hero { flex-direction: column; gap: 8px; margin-bottom: 12px; }
      .hero h1 { font-size: 20px; }
      .hero p { font-size: 12px; line-height: 1.45; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
      .hero .links { gap: 6px; margin-top: 8px; }
      .hero .links a { font-size: 12px; padding: 6px 10px; }
      .top-actions { display: flex; align-items: center; gap: 8px; flex-wrap: nowrap; }
      .top-actions button { font-size: 12px; padding: 6px 12px; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
      .coverage { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
      .summary-grid-3 { grid-template-columns: repeat(2, 1fr); gap: 8px; }
      .summary-grid-4 { grid-template-columns: repeat(2, 1fr); gap: 8px; }
      .card { padding: 12px 10px; border-radius: 12px; box-sizing: border-box; overflow: hidden; }
      .card h2 { font-size: 15px; }
      .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
      table { min-width: 480px; }
      .list-item { padding: 10px; }
      .list-item .top { flex-direction: column; gap: 4px; }
      .list-item .top .meta { font-size: 11px; }
      .list-item .meta { font-size: 11px; word-break: break-all; overflow-wrap: break-word; }
      .asset-sub-nav button { padding: 8px 14px; font-size: 13px; }
      /* 인라인 flex 필터 바 모바일 처리 */
      [style*=\"display:flex\"][style*=\"gap:10px\"] { flex-wrap: wrap !important; }
      /* 상단 탭 숨기고 하단 탭 표시 */
      .tabs-nav { display: none !important; }
      .bottom-nav {
        display: flex;
        position: fixed;
        bottom: 0; left: 0; right: 0;
        z-index: 1000;
        background: #0f172a;
        border-top: 1px solid #233046;
        padding: 0;
        box-shadow: 0 -4px 20px rgba(0,0,0,.4);
      }
      .bottom-nav button {
        flex: 1;
        background: none;
        border: none;
        border-top: 2px solid transparent;
        padding: 8px 4px 10px;
        color: #64748b;
        font-size: 10px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
        border-radius: 0;
        transition: color 0.15s;
      }
      .bottom-nav button .bn-icon { font-size: 20px; line-height: 1; }
      .bottom-nav button.active { color: #38bdf8; border-top-color: #38bdf8; }
    }
    @media (max-width: 480px) {
      .metrics { grid-template-columns: 1fr 1fr; gap: 6px; }
      .coverage { grid-template-columns: 1fr; }
      .summary-grid-3 { grid-template-columns: 1fr 1fr; }
      .summary-grid-4 { grid-template-columns: 1fr 1fr; }
      .metric-value { font-size: 22px; }
      .hero h1 { font-size: 18px; }
      .card { padding: 10px 8px; }
      .list-item .top strong { font-size: 13px; line-height: 1.4; }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <div>
        <h1 data-i18n=\"dash.hero.title\">MORI — 보안 점검 현황</h1>
        <p data-i18n=\"dash.hero.intro\">ISMS-P / ISO 27001 통제 항목 기준으로 자산·경보·취약점 현황을 한눈에 확인하고, 증적 데이터를 내보낼 수 있는 대시보드입니다.</p>
        <div class=\"links\">
          <a href=\"__DOCS_PORTAL_URL__\" target=\"_blank\" rel=\"noreferrer\" data-i18n=\"dash.links.docs\">운영 문서 / 포털</a>
        </div>
      </div>
      <div class=\"top-actions\">
        <button id=\"refresh_dashboard\" type=\"button\" data-i18n=\"dash.actions.refresh\">🔄 새로고침</button>
        <div class=\"account-wrap\" style=\"position:relative\">
          <button id=\"account_btn\" type=\"button\" onclick=\"toggleAccountMenu()\" style=\"background:#0f2035;border:1px solid #1e3a5f;color:#cbd5e1;font-size:13px;font-weight:600;padding:6px 12px;border-radius:8px;cursor:pointer\">👤 <span id=\"ui_user_badge\" data-i18n=\"dash.account.title\">계정</span> ▾</button>
          <div id=\"account_menu\" style=\"display:none;position:absolute;right:0;top:calc(100% + 6px);background:#0f2035;border:1px solid #1e3a5f;border-radius:10px;padding:12px;min-width:220px;z-index:9998;box-shadow:0 8px 24px rgba(0,0,0,0.45)\">
            <button type=\"button\" onclick=\"openProfileModal()\" style=\"display:block;width:100%;text-align:left;background:transparent;border:none;color:#cbd5e1;font-size:13px;font-weight:600;padding:6px 4px;cursor:pointer\" data-i18n=\"dash.account.edit_profile\">👤 프로필 편집</button>
            <button type=\"button\" onclick=\"shortcutMyServers()\" style=\"display:block;width:100%;text-align:left;background:transparent;border:none;color:#cbd5e1;font-size:13px;font-weight:600;padding:6px 4px;cursor:pointer\" data-i18n=\"dash.account.my_servers\">⭐ 내 서버</button>
            <div style=\"border-top:1px solid #1e3a5f;margin:10px 0\"></div>
            <div style=\"font-size:12px;color:#94a3b8;margin-bottom:6px\" data-i18n=\"dash.account.language\">언어 / Language</div>
            __I18N_TOGGLE__
            <div style=\"border-top:1px solid #1e3a5f;margin:10px 0\"></div>
            <a href=\"/auth/logout\" class=\"logout-btn\" style=\"display:block;text-align:center\" data-i18n=\"dash.actions.logout\">🚪 로그아웃</a>
          </div>
        </div>
      </div>
    </section>

    <nav class=\"tabs-nav\">
      <button class=\"active\" data-tab=\"dashboard\" onclick=\"switchTab('dashboard')\" data-i18n=\"dash.tab.dashboard\">📊 대시보드</button>
      <button data-tab=\"triage\" onclick=\"switchTab('triage')\" data-i18n=\"dash.tab.triage\">🚨 Alert Triage</button>
      <button data-tab=\"incidents\" onclick=\"switchTab('incidents')\" data-i18n=\"dash.tab.incidents\">📋 인시던트</button>
      <button data-tab=\"assets\" onclick=\"switchTab('assets')\" data-i18n=\"dash.tab.assets\">📡 자산 현황</button>
      <button data-tab=\"compliance\" onclick=\"switchTab('compliance')\" data-i18n=\"dash.tab.compliance\">✅ Compliance PDCA</button>
      <button data-tab=\"guides\" onclick=\"switchTab('guides')\" data-i18n=\"dash.tab.guides\">📖 가이드 &amp; 기준</button>
    </nav>

    <!-- ── Tab: Dashboard ──────────────────────────────────────────────── -->
    <div class=\"tab-panel active\" id=\"tab_dashboard\">
      <div style=\"display:flex;justify-content:flex-end;align-items:center;gap:8px;margin-bottom:10px;\">
        <span style=\"font-size:11px;color:#64748b;margin-right:auto\" data-i18n=\"dash.panel.resize_hint\">↔ 패널 오른쪽-아래 모서리를 드래그해 크기를 조절할 수 있어요 (브라우저에 저장)</span>
        <button id=\"panel_layout_reset\" class=\"secondary\" onclick=\"resetPanelLayout()\" style=\"width:auto;padding:6px 12px;font-size:13px\" data-i18n=\"dash.panel.reset_layout\">↔️ 크기 초기화</button>
        <button id=\"panel_edit_toggle\" class=\"secondary\" onclick=\"togglePanelEdit()\" data-i18n=\"dash.panel.edit\">🧩 패널 편집</button>
      </div>
      <div id=\"panel_edit_box\" class=\"card hidden\" style=\"margin-bottom:12px;\">
        <div style=\"font-weight:600;color:#7dd3fc;margin-bottom:4px\" data-i18n=\"dash.panel.edit_title\">표시할 패널 선택</div>
        <div class=\"subtext\" data-i18n=\"dash.panel.edit_sub\">보고 싶은 항목만 켜세요. 변경은 자동 저장되어 다음 접속에도 유지됩니다.</div>
        <div style=\"margin-top:10px;font-size:12px;color:#94a3b8\" data-i18n=\"dash.panel.group.cards\">요약 카드</div>
        <div id=\"panel_edit_cards\" style=\"display:flex;flex-wrap:wrap;gap:12px;margin:6px 0 12px\"></div>
        <div style=\"font-size:12px;color:#94a3b8\" data-i18n=\"dash.panel.group.sections\">패널</div>
        <div id=\"panel_edit_sections\" style=\"display:flex;flex-wrap:wrap;gap:12px;margin-top:6px\"></div>
      </div>
      <!-- 🛡️ 보안 요약 히어로 (Toss형: 보안 KPI + 위험 TOP 랭킹) — 보안 우선, 인프라는 아래 -->
      <section class=\"card\" id=\"security_hero_section\" style=\"background:linear-gradient(135deg,#0b1220,#101a33);border:1px solid #1e3a5f\">
        <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
          <h2 style=\"margin:0\" data-i18n=\"dash.hero.section\">🛡️ 지금 봐야 할 보안 현황</h2>
          <button onclick=\"switchTab('assets');switchAssetTab('trivy')\" class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" data-i18n=\"dash.hero.goto_risk\">위험 매트릭스 →</button>
        </div>
        <div id=\"security_hero_body\" style=\"margin-top:12px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
      </section>
      <section class=\"metrics\" id=\"overview_cards\"><div class=\"empty\" style=\"padding:16px;color:#64748b\" data-i18n=\"dash.status.overview_loading\">⏳ 요약 카드를 불러오는 중…</div></section>
      <style>
        /* 패널 자유조절: flex-wrap + 네이티브 드래그 리사이즈. 반응형(좁으면 100%로 접힘). */
        #dash_grid { display:flex; flex-wrap:wrap; gap:16px; align-items:flex-start; }
        #dash_grid > section {
          flex:0 1 auto; width:460px; max-width:100%; min-width:300px;
          box-sizing:border-box; resize:horizontal; overflow:auto;
        }
        #dash_grid > section > * { min-width:0; }
        #dash_grid > section .table-wrap { overflow-x:auto; }
        #dash_grid > section table { max-width:100%; }
        /* 표가 있는 패널은 기본을 넓게 (드래그로 자유 조절 가능) */
        #latest_status_section, #risk_summary_section, #recent_activity_section { width:620px; }
        @media (max-width:640px){ #dash_grid > section { width:100%!important; resize:none; } }
      </style>
      <div id=\"dash_grid\">
          <!-- 🖥️ 인프라 현황 (24h/12h 전환 + Zabbix/Wazuh 딥링크) -->
          <section class=\"card\" id=\"infra_status_section\">
            <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
              <h2 style=\"margin:0\" data-i18n=\"dash.infra.title\">🖥️ 인프라 현황</h2>
              <div style=\"display:flex;gap:4px;background:#0b1322;border:1px solid #1e293b;border-radius:8px;padding:2px\">
                <button id=\"infra_win_24\" onclick=\"setInfraWindow('24h')\" style=\"padding:3px 10px;border:none;border-radius:6px;font-size:12px;cursor:pointer;background:#1e3a5f;color:#e2e8f0\">24h</button>
                <button id=\"infra_win_12\" onclick=\"setInfraWindow('12h')\" style=\"padding:3px 10px;border:none;border-radius:6px;font-size:12px;cursor:pointer;background:transparent;color:#94a3b8\">12h</button>
              </div>
            </div>
            <div id=\"infra_status_body\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.status.loading\">⏳ 로딩 중…</span></div>
          </section>
          <section class=\"card\" id=\"source_coverage_section\">
            <h2 data-i18n=\"dash.card.source_coverage\">Source Coverage</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.source_coverage.sub\">운영자가 노출을 허용한 경우에만 source 상태를 표시합니다.</div>
            <div class=\"coverage\" id=\"source_coverage\"><span class=\"empty\" data-i18n=\"dash.status.loading\">⏳ 로딩 중…</span></div>
          </section>

          <section class=\"card\" id=\"latest_status_section\">
            <h2 data-i18n=\"dash.card.latest_status\">Latest Host Status</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.latest_status.sub\">조치가 필요한 offline / unknown 호스트를 우선 확인합니다.</div>
            <div class=\"table-wrap\" id=\"latest_status\"><span class=\"empty\" data-i18n=\"dash.status.loading\">⏳ 로딩 중…</span></div>
          </section>

          <section class=\"card\" id=\"risk_summary_section\">
            <h2 data-i18n=\"dash.card.risk_summary\">Risk Summary</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.risk_summary.sub\">alert, 취약점, 상태를 기준으로 우선 대응 대상을 확인합니다.</div>
            <div class=\"table-wrap\" id=\"risk_summary\"><span class=\"empty\" data-i18n=\"dash.status.loading\">⏳ 로딩 중…</span></div>
          </section>

          <section class=\"card\" id=\"recent_activity_section\">
            <h2 data-i18n=\"dash.card.recent_activity\">Recent Activity</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.recent_activity.sub\">운영자가 허용한 범위에서 최근 이벤트와 관측값을 보여줍니다.</div>
            <div class=\"list\" id=\"recent_activity\"><span class=\"empty\" data-i18n=\"dash.status.loading\">⏳ 로딩 중…</span></div>
          </section>

          <!-- NLQ section moved to floating button -->
      </div>
      <div class=\"status-line\" id=\"dashboard_status\" data-i18n=\"dash.status.initializing\">⏳ 초기화 중…</div>
    </div>

    <!-- ── Tab: Alert Triage ───────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_triage\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.triage\">🚨 Alert Triage</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.triage.sub\">최근 24h 경보 목록입니다. 상태를 클릭해 Triage 처리하세요.</div>
        <div class=\"table-wrap\" id=\"triage_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        <div style=\"margin-top:10px\"><button id=\"reload_triage\" class=\"secondary\" data-i18n=\"dash.btn.reload\">새로고침</button></div>
      </section>
    </div>

    <!-- ── Tab: Incidents ─────────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_incidents\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.incidents\">📋 인시던트 관리</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.incidents.sub\">여러 경보를 하나의 인시던트로 묶고 조사 노트를 남깁니다.</div>
        <!-- 검색 + 날짜 필터 + CSV 다운로드 -->
        <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px;padding:10px 12px;background:#0f172a;border-radius:8px;border:1px solid #1e293b\">
          <input type=\"text\" id=\"inc_search\" placeholder=\"제목 · 담당자 · 상태 검색\" data-i18n-placeholder=\"dash.inc.search_ph\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:5px 10px;font-size:13px;min-width:180px;flex:1\" />
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#94a3b8;font-size:13px;white-space:nowrap\" data-i18n=\"dash.inc.date_from\">시작일</label>
            <input type=\"date\" id=\"inc_date_from\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#94a3b8;font-size:13px;white-space:nowrap\" data-i18n=\"dash.inc.date_to\">종료일</label>
            <input type=\"date\" id=\"inc_date_to\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <button id=\"inc_filter_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px\" data-i18n=\"dash.inc.filter_btn\">🔍 조회</button>
          <button id=\"inc_csv_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px;background:#1d3a5f;color:#93c5fd\" data-i18n=\"dash.inc.csv_btn\">⬇️ CSV 다운로드</button>
        </div>
        <div id=\"incidents_list\" class=\"list\" style=\"margin-bottom:14px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        <div style=\"background:#0c1827;border:1px solid #1e3a5f;border-radius:8px;padding:16px;margin-bottom:10px\">
          <div style=\"font-size:13px;font-weight:600;color:#7dd3fc;margin-bottom:10px\" data-i18n=\"dash.inc.create_title\">➕ 새 인시던트 생성</div>
          <div class=\"row\">
            <label for=\"inc_title\" data-i18n=\"dash.f.title\">제목</label>
            <input id=\"inc_title\" placeholder=\"예: 특정 서버 무단 접근 시도\" data-i18n-placeholder=\"dash.inc.title_ph\" />
          </div>
          <div class=\"row\" style=\"position:relative\">
            <label for=\"inc_hostname\"><span data-i18n=\"dash.inc.host\">관련 호스트</span> <span style=\"color:#64748b;font-size:11px\" data-i18n=\"dash.inc.host_hint\">(검색)</span></label>
            <input id=\"inc_hostname\" placeholder=\"호스트명 입력…\" data-i18n-placeholder=\"dash.inc.host_ph\" autocomplete=\"off\" oninput=\"_incHostSearch(this.value)\" />
            <div id=\"inc_host_suggestions\" style=\"display:none;position:absolute;top:100%;left:0;right:0;background:#1e293b;border:1px solid #334155;border-radius:6px;max-height:160px;overflow-y:auto;z-index:100\"></div>
          </div>
          <div class=\"row\">
            <label for=\"inc_analyst\"><span data-i18n=\"dash.f.analyst\">담당자</span> <span style=\"color:#64748b;font-size:11px\" data-i18n=\"dash.inc.analyst_hint\">(호스트 담당자 자동 입력)</span></label>
            <input id=\"inc_analyst\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"dash.ph.name_example\" />
          </div>
          <div style=\"margin:8px 0\">
            <label style=\"display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;color:#94a3b8\">
              <input type=\"checkbox\" id=\"inc_diff_handler\" onchange=\"document.getElementById('inc_handler_row').style.display=this.checked?'':'none'\" />
              <span data-i18n=\"dash.inc.diff_handler\">담당자와 조치자가 다름</span>
            </label>
          </div>
          <div class=\"row\" id=\"inc_handler_row\" style=\"display:none\">
            <label for=\"inc_handler\" data-i18n=\"dash.f.handler\">조치자</label>
            <input id=\"inc_handler\" placeholder=\"예: 김보안\" data-i18n-placeholder=\"dash.ph.handler_example\" />
          </div>
          <div class=\"actions\">
            <button id=\"create_incident\" data-i18n=\"dash.inc.create_btn\">인시던트 생성</button>
            <button id=\"reload_incidents\" class=\"secondary\" data-i18n=\"dash.btn.reload\">새로고침</button>
          </div>
        </div>
        <div class=\"status-line\" id=\"incident_status\"></div>
      </section>
    </div>

    <!-- ── Tab: 자산 현황 ─────────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_assets\">
      <!-- Sub-nav -->
      <nav class=\"asset-sub-nav\">
        <button class=\"active\" id=\"asset_tab_fleet\" onclick=\"switchAssetTab('fleet')\"><span data-i18n=\"dash.assets.tab.fleet\">🖥️ PC 자산 (Fleet)</span></button>
        <button id=\"asset_tab_zabbix\" onclick=\"switchAssetTab('zabbix')\"><span data-i18n=\"dash.assets.tab.zabbix\">🖧 서버 자산 (Zabbix)</span></button>
        <button id=\"asset_tab_trivy\" onclick=\"switchAssetTab('trivy')\"><span data-i18n=\"dash.assets.tab.trivy\">🔍 취약점 (Trivy)</span></button>
        <button id=\"asset_tab_mine\" onclick=\"switchAssetTab('mine')\"><span data-i18n=\"dash.assets.tab.mine\">⭐ 내 서버</span></button>
      </nav>

      <!-- Fleet PC Section -->
      <div id=\"assets_fleet_section\">
        <div class=\"summary-grid-3\">
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.fleet_total\">전체 PC</div><div class=\"metric-value\" id=\"fleet_total\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.online\">온라인</div><div class=\"metric-value\" style=\"color:#86efac\" id=\"fleet_online\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.offline\">오프라인</div><div class=\"metric-value\" style=\"color:#fca5a5\" id=\"fleet_offline\">-</div></section>
        </div>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;\">
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.fleet\">🖥️ PC 자산 목록 (Fleet)</h2>
            <div style=\"display:flex;gap:6px;\">
              <button onclick=\"onDemandRefresh('fleet')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.assets.refresh\">🔄 새로고침</button>
              <button onclick=\"downloadAssetsCSV('fleet')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv\">📥 CSV 내보내기</button>
            </div>
          </div>
          <div class=\"asset-search-bar\">
            <input type=\"text\" id=\"fleet_search_hostname\" placeholder=\"호스트명 검색…\" data-i18n-placeholder=\"dash.assets.host_search_ph\" oninput=\"filterAssetTable('fleet')\" />
            <select id=\"fleet_search_status\" onchange=\"filterAssetTable('fleet')\"><option value=\"\" data-i18n=\"dash.assets.all_status\">전체 상태</option><option value=\"online\" data-i18n=\"dash.assets.online\">온라인</option><option value=\"offline\" data-i18n=\"dash.assets.offline\">오프라인</option><option value=\"unknown\" data-i18n=\"dash.assets.unknown\">알 수 없음</option></select>
            <span class=\"asset-search-count\" id=\"fleet_search_count\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.assets.fleet_sub\">Fleet에서 관리되는 PC 엔드포인트 현황입니다.</div>
          <div class=\"table-wrap\" id=\"fleet_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>

      <!-- Zabbix Server Section -->
      <div id=\"assets_zabbix_section\" class=\"hidden\">
        <div class=\"summary-grid-3\">
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.zabbix_total\">전체 서버</div><div class=\"metric-value\" id=\"zabbix_total\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.online\">온라인</div><div class=\"metric-value\" style=\"color:#86efac\" id=\"zabbix_online\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.offline\">오프라인</div><div class=\"metric-value\" style=\"color:#fca5a5\" id=\"zabbix_offline\">-</div></section>
        </div>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;\">
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.zabbix\">🖧 서버 자산 목록 (Zabbix)</h2>
            <div style=\"display:flex;gap:6px;\">
              <button onclick=\"onDemandRefresh('zabbix')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.assets.refresh\">🔄 새로고침</button>
              <button onclick=\"downloadAssetsCSV('zabbix')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv\">📥 CSV 내보내기</button>
            </div>
          </div>
          <div class=\"asset-search-bar\">
            <input type=\"text\" id=\"zabbix_search_hostname\" placeholder=\"호스트명 검색…\" data-i18n-placeholder=\"dash.assets.host_search_ph\" oninput=\"filterAssetTable('zabbix')\" />
            <select id=\"zabbix_search_category\" onchange=\"filterAssetTable('zabbix')\"><option value=\"\" data-i18n=\"dash.assets.all_category\">전체 분류</option></select>
            <select id=\"zabbix_search_status\" onchange=\"filterAssetTable('zabbix')\"><option value=\"\" data-i18n=\"dash.assets.all_status\">전체 상태</option><option value=\"online\" data-i18n=\"dash.assets.online\">온라인</option><option value=\"offline\" data-i18n=\"dash.assets.offline\">오프라인</option><option value=\"unknown\" data-i18n=\"dash.assets.unknown\">알 수 없음</option></select>
            <span class=\"asset-search-count\" id=\"zabbix_search_count\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.assets.zabbix_sub\">Zabbix에서 모니터링 중인 서버 현황과 최근 메트릭입니다.</div>
          <div class=\"table-wrap\" id=\"zabbix_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>

      <!-- Trivy Vulnerability Section -->
      <div id=\"assets_trivy_section\" class=\"hidden\">
        <div class=\"summary-grid-4\">
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.trivy_affected\">영향받는 호스트</div><div class=\"metric-value\" id=\"trivy_affected_hosts\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\" data-i18n=\"dash.assets.trivy_total\">전체 취약점</div><div class=\"metric-value\" id=\"trivy_total_vulns\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">Critical</div><div class=\"metric-value\" style=\"color:#fca5a5\" id=\"trivy_critical\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">High</div><div class=\"metric-value\" style=\"color:#fdba74\" id=\"trivy_high\">-</div></section>
        </div>
        <!-- 🎯 증적 공백 / 오늘의 작업 큐 (admin·security 전용) -->
        <section class=\"card\" id=\"evidence_gap_card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
            <h2 style=\"margin:0\" data-i18n=\"dash.gap.title\">🎯 오늘의 작업 큐 (증적 공백)</h2>
            <span id=\"evidence_gap_ts\" style=\"font-size:12px;color:#94a3b8\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.gap.sub\">증적으로 이어지지 않은 미조치 항목입니다. 타일을 클릭하면 해당 탭으로 이동합니다.</div>
          <div id=\"evidence_gap_box\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
        <!-- 📚 통제 카탈로그 트리 (ISMS-P × ISO, admin·security 전용) -->
        <section class=\"card\" id=\"control_tree_card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
            <h2 style=\"margin:0\" data-i18n=\"dash.ctl.title\">📚 통제 카탈로그 (ISMS-P × ISO 27001)</h2>
            <span id=\"control_tree_coverage\" style=\"font-size:12px;color:#94a3b8\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.ctl.sub\">인증기준별 증적 소스 매핑·커버리지. 회색 항목은 아직 증적 소스가 연결되지 않은 골격입니다.</div>
          <div id=\"control_tree_box\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
        <!-- 🎯 위험성 평가 매트릭스 (R-4) -->
        <section class=\"card\" id=\"risk_matrix_card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
            <h2 style=\"margin:0\" data-i18n=\"dash.risk.matrix_title\">🎯 위험성 평가 매트릭스</h2>
            <div style=\"display:flex;align-items:center;gap:10px\">
              <span id=\"risk_matrix_assessed\" style=\"font-size:12px;color:#94a3b8\"></span>
              <button id=\"risk_matrix_toggle\" onclick=\"toggleRiskMatrix()\" class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" data-i18n=\"dash.risk.collapse_hide\">▲ 접기</button>
            </div>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.risk.matrix_sub\">위험도 = 영향도(자산 중요도) × 발생가능성(심각도+보정). 미평가 항목은 자동 제안 등급으로 집계됩니다.</div>
          <div id=\"risk_matrix_box\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;\">
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.trivy\">🔍 취약점 현황 (Trivy)</h2>
            <button onclick=\"downloadAssetsCSV('trivy')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv\">📥 CSV 내보내기</button>
          </div>
          <div class=\"asset-search-bar\" style=\"flex-wrap:wrap;\">
            <input type=\"text\" id=\"trivy_search_hostname\" placeholder=\"호스트명 검색…\" data-i18n-placeholder=\"dash.assets.host_search_ph\" oninput=\"filterAssetTable('trivy')\" />
            <select id=\"trivy_search_severity\" onchange=\"filterAssetTable('trivy')\"><option value=\"\" data-i18n=\"dash.assets.all_severity\">전체 심각도</option><option value=\"critical\">Critical &gt; 0</option><option value=\"high\">High &gt; 0</option><option value=\"medium\">Medium &gt; 0</option></select>
            <span style=\"color:#94a3b8;font-size:12px;margin-left:4px\" data-i18n=\"dash.assets.detected_date\">탐지일:</span>
            <input type=\"date\" id=\"trivy_search_date_from\" onchange=\"filterAssetTable('trivy')\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:4px;padding:4px 6px;font-size:12px\" title=\"시작일\" data-i18n-title=\"dash.inc.date_from\" />
            <span style=\"color:#64748b;font-size:12px\">~</span>
            <input type=\"date\" id=\"trivy_search_date_to\" onchange=\"filterAssetTable('trivy')\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:4px;padding:4px 6px;font-size:12px\" title=\"종료일\" data-i18n-title=\"dash.inc.date_to\" />
            <span class=\"asset-search-count\" id=\"trivy_search_count\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.assets.trivy_sub\">Trivy가 탐지한 취약점을 호스트별로 집계한 현황입니다. Critical/High 우선 정렬.</div>
          <div class=\"table-wrap\" id=\"trivy_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>

      <!-- My Servers Section -->
      <div id=\"assets_mine_section\" class=\"hidden\">
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;\">
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.mine\">⭐ 내 담당 서버</h2>
            <div style=\"display:flex;align-items:center;gap:8px\">
              <label style=\"color:#94a3b8;font-size:13px;white-space:nowrap\" data-i18n=\"dash.assets.mine.groupby\">그룹 기준</label>
              <select id=\"mine_group_by\" onchange=\"renderMyServers()\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:4px 8px;font-size:13px\">
                <option value=\"category\" data-i18n=\"dash.assets.mine.group.category\">카테고리</option>
                <option value=\"team\" data-i18n=\"dash.assets.mine.group.team\">팀</option>
                <option value=\"importance\" data-i18n=\"dash.assets.mine.group.importance\">중요도</option>
                <option value=\"status\" data-i18n=\"dash.assets.mine.group.status\">상태</option>
                <option value=\"none\" data-i18n=\"dash.assets.mine.group.flat\">없음(전체)</option>
              </select>
              <span class=\"asset-search-count\" id=\"mine_search_count\"></span>
            </div>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.assets.mine.sub\">프로필의 담당 서버 목록 또는 담당자(이름)가 일치하는 PC·서버 자산을 모아 보여줍니다.</div>
          <div class=\"table-wrap\" id=\"mine_table\"><span class=\"empty\" data-i18n=\"dash.assets.mine.empty\">담당 자산이 없습니다. 계정 메뉴 → 프로필 편집에서 담당 서버를 등록하세요.</span></div>
        </section>
      </div>
      <div class=\"status-line\" id=\"assets_status\"></div>
    </div>

    <!-- ── Tab: Compliance PDCA ──────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_compliance\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.compliance\">✅ Compliance PDCA 대시보드</h2>
        <div class=\"subtext\" data-i18n=\"dash.compliance.sub_short\">ISMS-P / ISO 27001 통제 점검을 PDCA 관점으로 요약합니다. 지금 할 일(미조치·기한초과)부터 처리하세요.</div>
        <details style=\"margin-top:8px\">
          <summary style=\"cursor:pointer;color:#7dd3fc;font-size:12px\" data-i18n=\"dash.pdca.criteria\">ⓘ 집계 기준 자세히</summary>
          <div class=\"subtext\" style=\"margin-top:6px\" data-i18n-html=\"dash.compliance.sub\">※ 상단 카드의 <strong>📋 전체 점검 / Pass / Fail / Warning / Pass Rate</strong>는 <strong>통제 점검(control_checks)</strong> 결과만 집계합니다. <strong>🔧 미조치 합계</strong>와 <strong>🔴 기한초과</strong>는 통제 점검 + Trivy 취약점(critical/high) + Alert(critical/high, 7일) 미조치 항목을 통합 집계합니다.</div>
        </details>
      </section>

      <!-- PDCA Summary Cards -->
      <section class=\"metrics\" id=\"pdca_cards\">
        <div class=\"empty\" style=\"padding:16px;color:#64748b\" data-i18n=\"dash.status.pdca_loading\">⏳ PDCA 데이터를 불러오는 중…</div>
      </section>

      <!-- 지금 할 일: 미조치 / 기한초과 (항상 표시, 최우선) -->
      <section class=\"card\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap\">
          <h2 style=\"margin:0\" data-i18n=\"dash.pdca.pending_title\">⚠️ 미조치 / 기한 초과 항목</h2>
          <a id=\"pdca_pending_csv_btn\" href=\"/compliance/pdca/pending.csv\" download style=\"background:#0c2a4a;border:1px solid #1e3a5f;color:#7dd3fc;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none;cursor:pointer\">📥 CSV</a>
        </div>
        <div class=\"subtext\" data-i18n=\"dash.pdca.pending_sub\">fail 또는 warning 상태인 통제 항목입니다. 기한 초과는 🔴로 표시됩니다.</div>
        <div id=\"pdca_pending_table\" style=\"margin-top:8px;overflow-x:auto\"></div>
      </section>

      <!-- 상세 분석 (기본 접힘 — 처음 보는 담당자에겐 과부하라 뒤로) -->
      <details class=\"card\" style=\"padding:0\">
        <summary style=\"cursor:pointer;padding:16px 18px;font-weight:700;color:#e2e8f0;font-size:15px\" data-i18n=\"dash.pdca.detail_toggle\">📊 상세 분석 — 통제 상태 · 카테고리 · PDCA Cycle (펼치기)</summary>
        <div class=\"layout\" style=\"padding:0 16px 16px\">
          <div class=\"stack\">
            <section class=\"card\">
              <h2 data-i18n=\"dash.pdca.status_title\">📊 통제 항목 상태</h2>
              <div id=\"pdca_status_chart\" style=\"display:flex;flex-wrap:wrap;gap:12px;margin-top:12px\"></div>
            </section>
            <section class=\"card\">
              <h2 data-i18n=\"dash.pdca.category_title\">📈 카테고리별 현황</h2>
              <div id=\"pdca_category_table\" style=\"margin-top:8px;overflow-x:auto\"></div>
            </section>
          </div>
          <div class=\"stack\">
            <section class=\"card\">
              <h2>🔄 PDCA Cycle</h2>
              <div id=\"pdca_cycle_chart\" style=\"margin-top:12px\"></div>
            </section>
          </div>
        </div>
      </details>

      <!-- ── 증적 리포트 다운로드 ────────────────────────────────────── -->
      <section class=\"card\" style=\"margin-top:20px\">
        <h2 data-i18n=\"dash.card.reports\">📥 감사 증적 리포트 다운로드</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.reports.sub\">ISMS-P / ISO 27001 감사 증적으로 사용할 수 있는 리포트를 CSV로 다운로드합니다. 미리보기를 통해 CSV의 컬럼 구성을 먼저 확인할 수 있습니다.</div>
        <div id=\"report_download_area\" style=\"margin-top:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px\">
        </div>
      </section>

      <!-- ── 교차 검증 (Cross-verification) ─────────────────────────── -->
      <section class=\"card\" style=\"margin-top:20px\">
        <h2 data-i18n=\"dash.card.crosscheck\">🔀 소스 간 교차 검증</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.crosscheck.sub\">서로 다른 수집 소스의 데이터를 교차 비교하여 누락·불일치를 확인합니다.</div>
        <div id=\"crosscheck_area\" style=\"margin-top:16px\">
          <div class=\"empty\" style=\"padding:16px;color:#64748b\" data-i18n=\"dash.status.crosscheck_loading\">⏳ 교차 검증 데이터를 불러오는 중…</div>
        </div>
      </section>
    </div>

    <!-- ── Tab: 가이드 & 기준 ────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_guides\">
      <div id=\"guide_sub_tabs\" style=\"display:flex;gap:0;border-bottom:1px solid #233046;margin-bottom:20px;flex-wrap:wrap;\"></div>
      <section class=\"card\" style=\"padding:0\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;padding:16px 20px 0;\">
          <h2 id=\"guide_content_title\" style=\"margin:0;font-size:16px\"></h2>
          <span id=\"guide_updated_at\" style=\"font-size:12px;color:#64748b\"></span>
        </div>
        <div id=\"guide_content_body\" style=\"padding:16px 20px 20px;color:#cbd5e1;line-height:1.8;white-space:pre-wrap;font-size:14px;font-family:inherit\"></div>
      </section>
    </div>
  </div>

  <dialog id=\"overview_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"overview_modal_title\">Overview Details</h3>
        <form method=\"dialog\"><button type=\"submit\" style=\"padding:6px 16px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;\" data-i18n=\"dash.f.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"overview_modal_copy\" data-i18n=\"dash.modal.overview_copy\">선택한 카드의 상세 목록입니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"overview_modal_body\"></div>
  </dialog>

  <dialog id=\"info_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"info_modal_title\" data-i18n=\"dash.modal.info_title\">알림</h3>
        <form method=\"dialog\"><button type=\"submit\" style=\"padding:6px 16px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;\" data-i18n=\"dash.f.confirm\">확인</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"info_modal_body\" style=\"padding:0 0 8px;\"></div>
    </div>
  </dialog>

  <dialog id=\"nlq_guide_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 data-i18n=\"dash.modal.guide_title\">질의 가이드</h3>
        <form method=\"dialog\"><button type=\"submit\" class=\"secondary\" data-i18n=\"dash.f.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" data-i18n=\"dash.modal.guide_copy\">아래 예시를 클릭하면 입력창에 바로 채워집니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"nlq_guide_list\" style=\"display:flex;flex-wrap:wrap;gap:8px;padding:16px;\"></div>
  </dialog>

  <dialog id=\"triage_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3>Alert Triage</h3>
        <form method=\"dialog\"><button class=\"secondary\" data-i18n=\"dash.f.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\">
        <div id=\"triage_modal_alert_info\" style=\"margin-bottom:12px\"></div>
        <div class=\"row\"><label data-i18n=\"dash.f.status\">상태</label>
          <select id=\"triage_modal_status\">
            <option value=\"pending\" data-i18n=\"dash.opt.triage_pending\">🔴 미확인 (Pending)</option>
            <option value=\"reviewing\" data-i18n=\"dash.opt.triage_reviewing\">🟡 검토중 (Reviewing)</option>
            <option value=\"resolved\" data-i18n=\"dash.opt.triage_resolved\">🟢 조치예정/완료 (Resolved)</option>
          </select>
        </div>
        <div class=\"row\"><label><span data-i18n=\"dash.f.analyst\">담당자</span> <span style=\"color:#64748b;font-size:11px\" data-i18n=\"dash.modal.analyst_default_hint\">(서버 담당자 기본)</span></label><input id=\"triage_modal_analyst\" placeholder=\"예: alice\" data-i18n-placeholder=\"dash.ph.alice\" /></div>
        <div class=\"row\"><label data-i18n=\"dash.f.changed_by\">변경자(작성)</label><input id=\"triage_modal_actor\" placeholder=\"예: alice (미입력 시 로그인 사용자)\" data-i18n-placeholder=\"dash.ph.alice_login\" /></div>
        <div class=\"row\"><label data-i18n=\"dash.f.note\">메모</label><textarea id=\"triage_modal_note\" style=\"min-height:80px\"></textarea></div>
        <div class=\"actions\">
          <button id=\"triage_modal_save\" data-i18n=\"dash.f.save\">저장</button>
          <form method=\"dialog\"><button class=\"secondary\" data-i18n=\"dash.f.cancel\">취소</button></form>
        </div>
        <div class=\"status-line\" id=\"triage_modal_status_line\"></div>
        <hr style=\"border-color:#334155;margin:12px 0\" />
        <div style=\"margin-bottom:8px;font-size:13px;font-weight:600;color:#7dd3fc\" data-i18n=\"dash.modal.history_title\">📋 상태 변경 히스토리</div>
        <div id=\"triage_modal_history\" style=\"max-height:200px;overflow-y:auto\"><div style=\"color:#64748b;font-size:13px\" data-i18n=\"dash.modal.no_history\">변경 이력 없음</div></div>
      </div>
    </div>
  </dialog>

  <dialog id=\"incident_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"incident_modal_title\" data-i18n=\"dash.modal.incident_detail_title\">인시던트 상세</h3>
        <form method=\"dialog\"><button class=\"secondary\" data-i18n=\"dash.f.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\">
        <div id=\"incident_modal_info\" style=\"margin-bottom:12px;font-size:13px;color:#94a3b8\"></div>
        <div class=\"row\"><label data-i18n=\"dash.f.status_change\">상태 변경</label>
          <select id=\"incident_modal_status\">
            <option value=\"open\">open</option>
            <option value=\"investigating\">investigating</option>
            <option value=\"resolved\">resolved</option>
            <option value=\"closed\">closed</option>
          </select>
        </div>
        <div class=\"row\"><label data-i18n=\"dash.modal.analyst_label\">담당자(분석)</label><input id=\"incident_modal_edit_analyst\" placeholder=\"비워두면 변경 없음\" data-i18n-placeholder=\"dash.ph.no_change\" /></div>
        <div class=\"row\"><label data-i18n=\"dash.f.handler\">조치자</label><input id=\"incident_modal_edit_handler\" placeholder=\"비워두면 변경 없음\" data-i18n-placeholder=\"dash.ph.no_change\" /></div>
        <div class=\"row\"><label data-i18n=\"dash.f.changed_by\">변경자(작성)</label><input id=\"incident_modal_status_analyst\" placeholder=\"예: alice (미입력 시 로그인 사용자)\" data-i18n-placeholder=\"dash.ph.alice_login\" /></div>
        <button id=\"incident_modal_update_status\" style=\"margin-bottom:12px\" data-i18n=\"dash.f.save_change\">변경 저장</button>
        <hr style=\"border-color:#334155;margin:12px 0\" />
        <div style=\"margin-bottom:8px;font-size:13px;font-weight:600;color:#7dd3fc\" data-i18n=\"dash.modal.history_title\">📋 상태 변경 히스토리</div>
        <div id=\"incident_modal_history\" style=\"margin-bottom:12px\"></div>
        <hr style=\"border-color:#334155;margin:12px 0\" />
        <div style=\"margin-bottom:8px;font-size:13px;font-weight:600;color:#a3e635\" data-i18n=\"dash.modal.notes_title\">📝 조사 노트</div>
        <div id=\"incident_modal_notes\" style=\"margin-bottom:12px\"></div>
        <div class=\"row\"><label data-i18n=\"dash.f.note_content\">노트 내용</label><textarea id=\"incident_modal_note_text\" style=\"min-height:72px\"></textarea></div>
        <div class=\"row\"><label data-i18n=\"dash.f.author\">작성자</label><input id=\"incident_modal_analyst\" placeholder=\"예: alice\" data-i18n-placeholder=\"dash.ph.alice\" /></div>
        <button id=\"incident_modal_add_note\" data-i18n=\"dash.modal.add_note\">노트 추가</button>
        <div class=\"status-line\" id=\"incident_modal_status_line\"></div>
      </div>
    </div>
  </dialog>

  <!-- 조치 계획 모달 -->
  <div id=\"plan_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:28px 32px;width:500px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"plan_modal_title\" style=\"color:#a3e635;margin:0\" data-i18n=\"dash.modal.action_plan\">조치 계획</h3>
        <button onclick=\"closePlanModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.plan_content\">조치 계획 내용</label>
          <textarea id=\"plan_text\" rows=\"4\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 2024년 2분기 내 패키지 업그레이드 예정\" data-i18n-placeholder=\"dash.ph.plan_example\"></textarea>
        </div>
        <div style=\"display:flex;gap:12px\">
          <div style=\"flex:1\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.target_date\">목표 완료일</label>
            <input type=\"date\" id=\"plan_target_date\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
          </div>
          <div style=\"flex:1\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.author\">작성자</label>
            <input id=\"plan_updated_by\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 김보안\" data-i18n-placeholder=\"dash.ph.author_example\" />
          </div>
        </div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"plan_modal_save\" style=\"background:#16a34a;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
          <button onclick=\"closePlanModal()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 프로필 편집 모달 -->
  <div id=\"profile_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:28px 32px;width:440px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"profile_modal_title\" style=\"color:#38bdf8;margin:0\" data-i18n=\"dash.profile.title\">내 프로필 편집</h3>
        <button onclick=\"closeProfileModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.profile.display_name\">이름</label>
          <input id=\"profile_display_name\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"dash.profile.display_name_ph\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.profile.department\">부서</label>
          <input id=\"profile_department\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 인프라팀\" data-i18n-placeholder=\"dash.profile.department_ph\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.profile.assigned_servers\">담당 서버 (호스트명)</label>
          <textarea id=\"profile_assigned_servers\" rows=\"4\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"한 줄에 하나씩 또는 쉼표로 구분\" data-i18n-placeholder=\"dash.profile.assigned_servers_ph\"></textarea>
          <span style=\"color:#64748b;font-size:11px\" data-i18n=\"dash.profile.assigned_servers_hint\">⭐ 내 서버 탭에서 이 호스트만 모아 볼 수 있습니다.</span>
        </div>
        <div id=\"profile_modal_status\" style=\"font-size:13px;color:#94a3b8;\"></div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"profile_modal_save\" onclick=\"saveProfile()\" style=\"background:#1d4ed8;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.profile.save\">저장</button>
          <button onclick=\"closeProfileModal()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.profile.cancel\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 담당자 편집 모달 (사용자용) -->
  <div id=\"owner_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:28px 32px;width:440px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"owner_modal_title\" style=\"color:#a3e635;margin:0\" data-i18n=\"dash.modal.edit_owner_title\">담당자/카테고리 수정</h3>
        <button onclick=\"closeOwnerModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.hostname\">호스트명</label>
          <input id=\"owner_modal_hostname\" readonly style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#94a3b8;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.analyst\">담당자</label>
          <input id=\"owner_modal_owner\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"dash.ph.owner_example\" />
        </div>
        <div id=\"owner_modal_category_row\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.category\">카테고리 (서버 분류)</label>
          <input id=\"owner_modal_category\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 웹 서버\" data-i18n-placeholder=\"dash.ph.category_example\" />
        </div>
        <div id=\"owner_modal_importance_row\"><label style=\"color:#94a3b8;font-size:13px\"><span data-i18n=\"dash.f.importance\">중요도</span> <span style=\"color:#64748b;font-size:11px\" data-i18n=\"dash.modal.importance_hint\">(자동 분류 재정의)</span></label>
          <select id=\"owner_modal_importance\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\">
            <option value=\"\" data-i18n=\"dash.opt.auto\">자동 (기본)</option>
            <option value=\"상\" data-i18n=\"dash.opt.high\">상</option>
            <option value=\"중\" data-i18n=\"dash.opt.mid\">중</option>
            <option value=\"하\" data-i18n=\"dash.opt.low\">하</option>
          </select>
        </div>
        <div id=\"owner_modal_exception_row\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.exception_until\">처리 예외 기한</label>
          <input type=\"date\" id=\"owner_modal_exception_until\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
          <span style=\"color:#64748b;font-size:11px\" data-i18n=\"dash.modal.exception_hint\">이 날짜까지 점검/알림 예외 처리됩니다</span>
          <label style=\"color:#94a3b8;font-size:13px;margin-top:8px;display:block\" data-i18n=\"dash.f.exception_reason\">예외 사유</label>
          <textarea id=\"owner_modal_exception_reason\" rows=\"2\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 레거시 시스템으로 패치 불가, 2분기 교체 예정\" data-i18n-placeholder=\"dash.ph.exception_reason_example\"></textarea>
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.team\">팀</label>
          <input id=\"owner_modal_team\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 인프라팀\" data-i18n-placeholder=\"dash.ph.team_example\" />
        </div>

        <div id=\"owner_modal_status\" style=\"font-size:13px;color:#94a3b8;\"></div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"owner_modal_save\" style=\"background:#1d4ed8;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
          <button onclick=\"closeOwnerModal()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Trivy 호스트별 취약점 리스트 모달 -->
  <div id=\"vuln_list_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px 28px;width:980px;max-width:96vw;max-height:88vh;overflow:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 id=\"vuln_list_modal_title\" style=\"color:#fdba74;margin:0\" data-i18n=\"dash.modal.vuln_detail_title\">취약점 상세</h3>
        <button onclick=\"closeVulnListModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div id=\"vuln_list_modal_subtitle\" style=\"color:#94a3b8;font-size:12px;margin-bottom:10px\"></div>
      <div id=\"vuln_list_modal_body\"></div>
    </div>
  </div>

  <!-- 호스트 단위 조치 계획 안내 모달 (CVE별 상세 계획 존재 시) -->
  <div id=\"vuln_plans_notice_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #78350f;border-radius:10px;padding:28px 32px;width:480px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 style=\"color:#fbbf24;margin:0\" data-i18n=\"dash.modal.plan_exists_title\">📋 상세 계획이 정해져 있습니다</h3>
        <button onclick=\"closeVulnPlansNotice()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div id=\"vuln_plans_notice_body\" style=\"color:#e2e8f0;font-size:13px;line-height:1.6;margin-bottom:18px\"></div>
      <div style=\"display:flex;gap:10px;justify-content:flex-end\">
        <button onclick=\"closeVulnPlansNotice()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px\" data-i18n=\"dash.f.close\">닫기</button>
        <button id=\"vuln_plans_notice_open_list\" style=\"background:#1e3a5f;border:1px solid #334155;color:#7dd3fc;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600\" data-i18n=\"dash.modal.open_summary_tab\">합계 탭 열기 ↗</button>
      </div>
    </div>
  </div>

  <!-- PDCA Do(조치) 항목 상세 모달 -->
  <div id=\"pdca_do_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #f59e0b;border-radius:10px;padding:24px 28px;width:1080px;max-width:96vw;max-height:88vh;overflow:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 style=\"color:#f59e0b;margin:0\" data-i18n=\"dash.modal.pdca_do_title\">🔧 Do — 조치가 필요한 항목</h3>
        <button onclick=\"closePdcaDoModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div id=\"pdca_do_modal_subtitle\" style=\"color:#94a3b8;font-size:12px;margin-bottom:10px\"></div>
      <div id=\"pdca_do_modal_body\"></div>
    </div>
  </div>

  <!-- 감사 증적 리포트 미리보기 모달 (CSV 미리보기 + 다운로드) -->
  <div id=\"report_preview_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px 28px;width:1080px;max-width:96vw;max-height:88vh;overflow:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;gap:12px;flex-wrap:wrap\">
        <h3 id=\"report_preview_title\" style=\"color:#67e8f9;margin:0\" data-i18n=\"dash.modal.report_preview_title\">📄 리포트 미리보기</h3>
        <div style=\"display:flex;gap:8px;align-items:center\">
          <a id=\"report_preview_download\" href=\"#\" download style=\"background:#164e63;border:1px solid #155e75;color:#67e8f9;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none\" data-i18n=\"dash.modal.csv_download\">📥 CSV 다운로드</a>
          <a id=\"report_preview_download_pdf\" href=\"#\" download style=\"background:#7c2d12;border:1px solid #9a3412;color:#fed7aa;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none\" data-i18n=\"dash.modal.pdf_download\">📄 PDF 다운로드</a>
          <button onclick=\"closeReportPreview()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
        </div>
      </div>
      <div id=\"report_preview_subtitle\" style=\"color:#94a3b8;font-size:12px;margin-bottom:10px\" data-i18n=\"dash.modal.report_preview_sub\">CSV 파일이 아래와 같은 형태로 생성됩니다. (상위 50행만 표시)</div>
      <div id=\"report_preview_body\"></div>
    </div>
  </div>

  <!-- 인시던트 CSV 다운로드 안내 모달 -->
  <div id=\"incident_csv_notice_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #78350f;border-radius:10px;padding:28px 32px;width:520px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 style=\"color:#fbbf24;margin:0\" data-i18n=\"dash.modal.incident_csv_title\">📥 인시던트 CSV 다운로드</h3>
        <button onclick=\"closeIncidentCsvNotice()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div style=\"color:#e2e8f0;font-size:13px;line-height:1.7;margin-bottom:18px\">
        <div style=\"margin-bottom:10px\" data-i18n-html=\"dash.modal.incident_csv_warn_html\">⚠️ <strong style=\"color:#fbbf24\">변경 내역(history)은 CSV 내역에 포함되지 않습니다.</strong></div>
        <div style=\"color:#cbd5e1\" data-i18n-html=\"dash.modal.incident_csv_desc_html\">각 인시던트는 <strong style=\"color:#7dd3fc\">변경 일자</strong>와 <strong style=\"color:#7dd3fc\">최신 내역</strong>(현재 상태 / 담당자 / 영향도 등)만 1행으로 표시됩니다.</div>
        <div style=\"color:#94a3b8;margin-top:10px;font-size:12px\" data-i18n-html=\"dash.modal.incident_csv_hint_html\">전체 변경 이력은 인시던트 상세 모달의 \"📋 변경 이력\" 섹션 또는 <code style=\"background:#1e293b;padding:1px 6px;border-radius:3px\">/incidents/{id}/history</code> API를 이용해 주세요.</div>
      </div>
      <div style=\"display:flex;gap:10px;justify-content:flex-end\">
        <button onclick=\"closeIncidentCsvNotice()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px\" data-i18n=\"dash.f.cancel\">취소</button>
        <button id=\"incident_csv_confirm_btn\" style=\"background:#164e63;border:1px solid #155e75;color:#67e8f9;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600\" data-i18n=\"dash.modal.download\">📥 다운로드</button>
      </div>
    </div>
  </div>

  <!-- 취약점별 조치 계획 / 조치 예외 편집 모달 -->
  <div id=\"vuln_action_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px 28px;width:520px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 id=\"vuln_action_modal_title\" style=\"color:#a3e635;margin:0\" data-i18n=\"dash.modal.vuln_action_title\">취약점 조치</h3>
        <button onclick=\"closeVulnActionModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div id=\"vuln_action_modal_meta\" style=\"color:#94a3b8;font-size:12px;margin-bottom:12px;border:1px solid #1e293b;border-radius:6px;padding:8px 10px;background:#0b1322\"></div>

      <!-- 조치 계획 영역 -->
      <div id=\"vuln_plan_section\" style=\"display:none;flex-direction:column;gap:10px\">
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.plan_content\">조치 계획 내용</label>
          <textarea id=\"vuln_plan_text\" rows=\"4\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 다음 정기 패치 일정에 openssh 9.3p2로 업그레이드\" data-i18n-placeholder=\"dash.ph.vuln_plan_example\"></textarea>
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.target_date\">목표 완료일</label>
          <input type=\"date\" id=\"vuln_plan_target_date\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.author\">작성자</label>
          <input id=\"vuln_plan_updated_by\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: security\" data-i18n-placeholder=\"dash.ph.security_example\" />
        </div>
      </div>

      <!-- 조치 예외 영역 -->
      <div id=\"vuln_exception_section\" style=\"display:none;flex-direction:column;gap:10px\">
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.modal.exception_period\">예외 처리 기한</label>
          <input type=\"date\" id=\"vuln_exception_until\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
          <span style=\"color:#64748b;font-size:11px\" data-i18n=\"dash.modal.vuln_exception_hint\">이 날짜까지 해당 취약점 점검/알림에서 제외됩니다</span>
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.exception_reason\">예외 사유</label>
          <textarea id=\"vuln_exception_reason\" rows=\"3\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 종속 라이브러리 호환성 이슈로 차분기 교체 예정\" data-i18n-placeholder=\"dash.ph.vuln_exception_reason_example\"></textarea>
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.f.author\">작성자</label>
          <input id=\"vuln_exception_updated_by\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: security\" data-i18n-placeholder=\"dash.ph.security_example\" />
        </div>
      </div>

      <div id=\"vuln_action_modal_status\" style=\"font-size:13px;color:#94a3b8;margin-top:10px\"></div>
      <div style=\"display:flex;gap:8px;justify-content:flex-end;margin-top:12px\">
        <button id=\"vuln_action_modal_clear\" style=\"display:none;background:#3f1d1d;border:1px solid #7f1d1d;color:#fca5a5;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px\" data-i18n=\"dash.modal.clear_exception\">예외 해제</button>
        <button id=\"vuln_action_modal_save\" style=\"background:#16a34a;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
        <button onclick=\"closeVulnActionModal()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
      </div>
    </div>
  </div>

  <!-- 🎯 위험성 평가 모달 (R-4) -->
  <div id=\"risk_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px 28px;width:560px;max-width:95vw;max-height:88vh;overflow-y:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 id=\"risk_modal_title\" style=\"color:#c4b5fd;margin:0\" data-i18n=\"dash.risk.modal_title\">🎯 위험성 평가</h3>
        <button onclick=\"closeRiskModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div id=\"risk_modal_meta\" style=\"color:#94a3b8;font-size:12px;margin-bottom:12px;border:1px solid #1e293b;border-radius:6px;padding:8px 10px;background:#0b1322\"></div>
      <!-- 현재 등급 배지 + 자동 제안 -->
      <div id=\"risk_modal_grade\" style=\"margin-bottom:6px\"></div>
      <div style=\"font-size:11px;color:#64748b;margin-bottom:12px;line-height:1.5\" data-i18n=\"dash.risk.basis_note\">산정 기준: 영향도(자산 중요도 상/중/하) × 발생가능성(취약점 심각도·Trivy CVSS 기반). ISMS-P 위험관리 / ISO 27001 6.1.2·8.8 방법론. 조직 DoA(수용가능 위험수준)에 맞춰 등급 조정 가능.</div>
      <div style=\"display:flex;flex-direction:column;gap:10px\">
        <div style=\"display:flex;gap:10px;flex-wrap:wrap\">
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.impact\">영향도 (자산 중요도)</label>
            <select id=\"risk_impact\" onchange=\"_riskRecalc()\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px\">
              <option value=\"3\">상 (3)</option><option value=\"2\">중 (2)</option><option value=\"1\">하 (1)</option>
            </select></div>
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.likelihood\">발생가능성 (심각도 기반)</label>
            <select id=\"risk_likelihood\" onchange=\"_riskRecalc()\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px\">
              <option value=\"3\">상 (3)</option><option value=\"2\">중 (2)</option><option value=\"1\">하 (1)</option>
            </select></div>
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.treatment\">위험 처리 결정</label>
          <select id=\"risk_treatment\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px\">
            <option value=\"\" data-i18n=\"dash.risk.t.none\">미정</option>
            <option value=\"mitigate\" data-i18n=\"dash.risk.t.mitigate\">조치(경감)</option>
            <option value=\"accept\" data-i18n=\"dash.risk.t.accept\">수용</option>
            <option value=\"transfer\" data-i18n=\"dash.risk.t.transfer\">이관</option>
            <option value=\"avoid\" data-i18n=\"dash.risk.t.avoid\">회피</option>
          </select></div>
        <div style=\"display:flex;gap:10px;flex-wrap:wrap\">
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.accept_approver\">승인자</label>
            <input id=\"risk_accept_approver\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.review_due\">재평가 예정일</label>
            <input type=\"date\" id=\"risk_review_due\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.accept_reason\">수용 사유</label>
          <textarea id=\"risk_accept_reason\" rows=\"2\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\"></textarea></div>
        <div style=\"display:flex;gap:10px;flex-wrap:wrap\">
          <div style=\"flex:1;min-width:160px\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.residual\">잔여 위험</label>
            <input id=\"risk_residual\" placeholder=\"예: 중간 / 낮음\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
          <div style=\"flex:1;min-width:160px\"><label style=\"color:#94a3b8;font-size:13px\" data-i18n=\"dash.risk.f.assessed_by\">평가자</label>
            <input id=\"risk_assessed_by\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
        </div>
      </div>
      <!-- 🔎 산정 근거 (관리자 전용) -->
      <div id=\"risk_provenance\" style=\"display:none;margin-top:14px;border:1px solid #3730a3;border-radius:8px;padding:10px 12px;background:#0b1230\"></div>
      <div id=\"risk_modal_status\" style=\"font-size:13px;color:#94a3b8;margin-top:10px\"></div>
      <div style=\"display:flex;gap:8px;justify-content:flex-end;margin-top:12px\">
        <button id=\"risk_modal_save\" onclick=\"saveRiskAssessment()\" style=\"background:#7c3aed;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
        <button onclick=\"closeRiskModal()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
      </div>
    </div>
  </div>

  <!-- 🎯 위험 버킷 드릴다운 모달 (매트릭스 셀/칩 클릭) -->
  <div id=\"risk_bucket_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px 28px;width:660px;max-width:95vw;max-height:82vh;overflow-y:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px\">
        <h3 id=\"risk_bucket_modal_title\" style=\"color:#c4b5fd;margin:0\">🎯 위험 상세</h3>
        <button onclick=\"closeRiskBucketModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div id=\"risk_bucket_modal_body\"></div>
    </div>
  </div>

  <!-- 감사 이력 모달 -->
  <div id=\"audit_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:28px 32px;width:600px;max-width:95vw;max-height:80vh;overflow-y:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"audit_modal_title\" style=\"color:#a3e635;margin:0\" data-i18n=\"dash.modal.audit_title\">변경 이력</h3>
        <button onclick=\"closeAuditModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div id=\"audit_modal_body\" style=\"color:#e2e8f0;font-size:13px\" data-i18n=\"dash.modal.loading\">로딩 중...</div>
    </div>
  </div>

  <!-- ── 하단 탭 바 (모바일 전용) ────────────────────────────────────────── -->
  <nav class=\"bottom-nav\" id=\"bottom_nav\">
    <button class=\"active\" data-tab=\"dashboard\" onclick=\"switchTab('dashboard')\">
      <span class=\"bn-icon\">📊</span><span data-i18n=\"dash.bn.dashboard\">대시보드</span>
    </button>
    <button data-tab=\"triage\" onclick=\"switchTab('triage')\">
      <span class=\"bn-icon\">🚨</span><span data-i18n=\"dash.bn.triage\">Triage</span>
    </button>
    <button data-tab=\"assets\" onclick=\"switchTab('assets')\">
      <span class=\"bn-icon\">📡</span><span data-i18n=\"dash.bn.assets\">자산</span>
    </button>
    <button data-tab=\"incidents\" onclick=\"switchTab('incidents')\">
      <span class=\"bn-icon\">📋</span><span data-i18n=\"dash.bn.incidents\">인시던트</span>
    </button>
    <button data-tab=\"compliance\" onclick=\"switchTab('compliance')\">
      <span class=\"bn-icon\">✅</span><span data-i18n=\"dash.bn.compliance\">PDCA</span>
    </button>
    <button data-tab=\"guides\" onclick=\"switchTab('guides')\">
      <span class=\"bn-icon\">📖</span><span data-i18n=\"dash.bn.guides\">가이드</span>
    </button>
  </nav>

  <script>
    const defaultPreferences = __USER_DASHBOARD_PREFS_JSON__;
    const cardLabels = __CARD_LABELS_JSON__;
    const sectionLabels = __SECTION_LABELS_JSON__;
    const guideLabels = __GUIDE_LABELS_JSON__;
    let assetColumnPrefs = Object.assign({}, defaultPreferences.asset_columns || { show_importance: true, show_isms_control: true, show_iso27001_control: true });
    const nlqGuideExamples = __NLQ_GUIDE_EXAMPLES__;
    const overviewCardsEl = document.getElementById('overview_cards');
    const sourceCoverageEl = document.getElementById('source_coverage');
    const latestStatusEl = document.getElementById('latest_status');
    const riskSummaryEl = document.getElementById('risk_summary');
    const recentActivityEl = document.getElementById('recent_activity');
    const dashboardStatusEl = document.getElementById('dashboard_status');
    const overviewModalEl = document.getElementById('overview_modal');
    const overviewModalTitleEl = document.getElementById('overview_modal_title');
    const overviewModalCopyEl = document.getElementById('overview_modal_copy');
    const overviewModalBodyEl = document.getElementById('overview_modal_body');
    const nlqGuideModalEl = document.getElementById('nlq_guide_modal');
    const nlqGuideListEl = document.getElementById('nlq_guide_list');
    // Triage
    const triageTableEl = document.getElementById('triage_table');
    const triageModalEl = document.getElementById('triage_modal');
    const triageModalAlertInfoEl = document.getElementById('triage_modal_alert_info');
    const triageModalStatusEl = document.getElementById('triage_modal_status');
    const triageModalAnalystEl = document.getElementById('triage_modal_analyst');
    const triageModalNoteEl = document.getElementById('triage_modal_note');
    const triageModalSaveEl = document.getElementById('triage_modal_save');
    const triageModalStatusLineEl = document.getElementById('triage_modal_status_line');
    // Incidents
    const incidentsListEl = document.getElementById('incidents_list');
    const incTitleEl = document.getElementById('inc_title');
    const incidentStatusEl = document.getElementById('incident_status');
    const incidentModalEl = document.getElementById('incident_modal');
    const incidentModalTitleEl = document.getElementById('incident_modal_title');
    const incidentModalInfoEl = document.getElementById('incident_modal_info');
    const incidentModalStatusEl = document.getElementById('incident_modal_status');
    const incidentModalNotesEl = document.getElementById('incident_modal_notes');
    const incidentModalNoteTextEl = document.getElementById('incident_modal_note_text');
    const incidentModalAnalystEl = document.getElementById('incident_modal_analyst');
    const incidentModalStatusLineEl = document.getElementById('incident_modal_status_line');

    let userPreferences = JSON.parse(JSON.stringify(defaultPreferences));
    let dashboardDetails = {};
    let _lastOverviewData = {};
    let _panelEditOpen = false;
    let _panelSaveTimer = null;
    let currentTriageAlertId = null;
    let currentIncidentId = null;
    let triageDataCache = {};
    const TRIAGE_STATUS_COLORS = {
      pending: '#ef4444', reviewing: '#f59e0b', resolved: '#22c55e',
      // legacy (backward compat)
      new: '#ef4444', acknowledged: '#f59e0b', investigating: '#f59e0b',
      closed: '#22c55e', false_positive: '#94a3b8'
    };
    const tt = (k, f) => (window.t ? window.t(k, f) : f);
    const TRIAGE_STATUS_LABELS = { pending:tt('dash.dyn.triage.pending','🔴 미확인'), reviewing:tt('dash.dyn.triage.reviewing','🟡 검토중'), resolved:tt('dash.dyn.triage.resolved','🟢 조치예정/완료') };
    const triageLabel = (s) => tt('dash.dyn.triage.' + s, TRIAGE_STATUS_LABELS[s] || s);
    const INC_STATUS_COLORS = {open:'#f59e0b', investigating:'#a78bfa', resolved:'#6ee7b7', closed:'#94a3b8'};

    // ── 전역 함수 노출 (onclick 속성에서 직접 호출 — 함수 선언은 호이스팅됨) ──
    window.switchTab         = switchTab;
    window.switchAssetTab    = switchAssetTab;
    window.downloadAssetsCSV = downloadAssetsCSV;
    window.onDemandRefresh   = onDemandRefresh;
    window.filterAssetTable  = filterAssetTable;
    window.openTriageModal   = openTriageModal;
    window.openIncidentModal = openIncidentModal;
    window.openOwnerModal    = openOwnerModal;
    window.openPlanModal     = openPlanModal;
    window.closePlanModal    = closePlanModal;
    window.closeOwnerModal   = closeOwnerModal;
    window.openAuditModal    = openAuditModal;
    window.closeAuditModal   = closeAuditModal;
    window.loadTriage        = loadTriage;
    window.loadIncidents     = loadIncidents;
    window.loadAssets        = loadAssets;
    window.loadDashboard     = loadDashboard;
    window.buildGuideSubTabs = buildGuideSubTabs;
    window.switchGuideTab    = switchGuideTab;
    window.logUserAction     = logUserAction;

    // ── Tab Navigation ─────────────────────────────────────────────────────
    function logUserAction(action, detail) {
      fetch('/admin/action-audit-log', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ action, detail }),
      }).catch(() => {});
    }

    function switchTab(tabName) {
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      // 상단 탭 + 하단 탭 모두 active 동기화
      document.querySelectorAll('.tabs-nav button, .bottom-nav button').forEach(b => b.classList.remove('active'));
      const panel = document.getElementById(`tab_${tabName}`);
      if (panel) panel.classList.add('active');
      document.querySelectorAll(`[data-tab="${tabName}"]`).forEach(b => b.classList.add('active'));
      // 페이지 상단으로 스크롤 (모바일에서 탭 전환 시 편의)
      window.scrollTo({ top: 0, behavior: 'smooth' });
      logUserAction('TAB_SWITCH', tabName);
      if (tabName === 'triage') loadTriage();
      if (tabName === 'incidents') loadIncidents();
      if (tabName === 'assets') loadAssets();
      if (tabName === 'compliance') loadCompliance();
      if (tabName === 'guides') {
        buildGuideSubTabs();
        if (currentGuideId) switchGuideTab(currentGuideId);
      }
    }

    // i18n: re-render the active tab's dynamic content when the language changes
    window.onLangChange = function() {
      const activeBtn = document.querySelector('.tabs-nav button.active');
      const tab = activeBtn ? activeBtn.dataset.tab : 'dashboard';
      try {
        if (tab === 'dashboard') loadDashboard();
        else if (tab === 'triage') loadTriage();
        else if (tab === 'incidents') loadIncidents();
        else if (tab === 'assets') loadAssets();
        else if (tab === 'compliance') loadCompliance();
        else if (tab === 'guides') { buildGuideSubTabs(); if (currentGuideId) switchGuideTab(currentGuideId); }
      } catch (e) { /* re-render best-effort */ }
    };

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function formatTime(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString('ko-KR', { hour12: false });
    }

    function setSectionVisible(key, visible) {
      const element = document.getElementById(`${key}_section`);
      if (!element) return;
      element.classList.toggle('hidden', !visible);
    }

    function applyUserPreferences() {
      const sections = userPreferences.sections || {};
      Object.keys(sectionLabels).forEach((key) => setSectionVisible(key, sections[key] !== false));
    }

    function openOverviewModal(title, description, bodyHtml) {
      overviewModalTitleEl.textContent = title;
      overviewModalCopyEl.textContent = description;
      overviewModalBodyEl.innerHTML = bodyHtml;
      if (overviewModalEl.open) return;
      if (typeof overviewModalEl.showModal === 'function') {
        overviewModalEl.showModal();
        return;
      }
      overviewModalEl.setAttribute('open', 'open');
    }

    function renderDetailTable(columns, items, emptyText) {
      if (!items.length) return `<div class=\"empty\">${escapeHtml(emptyText)}</div>`;
      return `
        <div class=\"table-wrap\">
          <table>
            <thead><tr>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('')}</tr></thead>
            <tbody>
              ${items.map((item) => `<tr>${columns.map((column) => `<td>${column.render(item)}</td>`).join('')}</tr>`).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    function renderHostCell(item) {
      const name = item.source_url
        ? `<a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer"><strong>${escapeHtml(item.hostname)}</strong></a>`
        : `<strong>${escapeHtml(item.hostname)}</strong>`;
      return `${name}<br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span>`;
    }

    function renderStatusDetailTable(items) {
      return renderDetailTable([
        { label: 'Host', render: (item) => renderHostCell(item) },
        { label: 'Status', render: (item) => `<span class=\"badge ${escapeHtml(item.status)}\">${escapeHtml(item.status)}</span>` },
        { label: 'Risk', render: (item) => escapeHtml(item.risk_score) },
        { label: 'Last Seen', render: (item) => escapeHtml(formatTime(item.last_seen_at)) },
      ], items, tt('dash.dyn.empty.hosts', '표시할 호스트가 없습니다.'));
    }

    function renderAlertDetailTable(items) {
      return renderDetailTable([
        { label: 'Time', render: (item) => escapeHtml(formatTime(item.observed_at)) },
        { label: 'Host', render: (item) => `<strong>${escapeHtml(item.hostname || '-')}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id || '-')}</span>` },
        { label: tt('dash.dyn.col.owner', '담당자'), render: (item) => `<span style=\"color:#a3e635\">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Severity', render: (item) => escapeHtml(item.severity) },
        { label: 'Message', render: (item) => escapeHtml(item.message) },
      ], items, tt('dash.dyn.empty.alerts_24h', '최근 24시간 high / critical alert가 없습니다.'));
    }

    function renderVulnerabilityDetailTable(items) {
      return renderDetailTable([
        { label: 'Detected', render: (item) => escapeHtml(formatTime(item.detected_at)) },
        { label: 'Host', render: (item) => `<strong>${escapeHtml(item.hostname || item.host_id)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span>` },
        { label: tt('dash.dyn.col.owner', '담당자'), render: (item) => `<span style=\"color:#a3e635\">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'CVE', render: (item) => escapeHtml(item.cve || '-') },
        { label: 'Package', render: (item) => escapeHtml(item.package_name || '-') },
        { label: tt('dash.dyn.col.plan', '조치 계획'), render: (item) => {
          if (!item.plan_text) return `<span style=\"color:#64748b;font-size:11px\">${tt('dash.dyn.plan.unset', '미설정')}</span>`;
          const tgt = item.plan_target_date ? `<br /><span style=\"color:#64748b;font-size:11px\">~${escapeHtml(item.plan_target_date)}</span>` : '';
          const by = item.plan_updated_by ? ` <span style=\"color:#94a3b8;font-size:11px\">(${escapeHtml(item.plan_updated_by)})</span>` : '';
          return `<span style=\"color:#a3e635;font-size:12px\" title=\"${escapeHtml(item.plan_text)}\">${escapeHtml(item.plan_text.substring(0,30))}${item.plan_text.length>30?'…':''}</span>${by}${tgt}`;
        }},
        { label: tt('dash.dyn.col.exception', '조치 예외'), render: (item) => {
          if (!item.exception_until) return `<span style=\"color:#64748b;font-size:11px\">${tt('dash.dyn.exception.none', '없음')}</span>`;
          const reason = item.exception_reason ? `<br /><span style=\"color:#94a3b8;font-size:11px\">${escapeHtml(item.exception_reason.substring(0,30))}${item.exception_reason.length>30?'…':''}</span>` : '';
          return `<span style=\"color:#fbbf24;font-size:12px\">~${escapeHtml(item.exception_until)}</span>${reason}`;
        }},
      ], items, tt('dash.dyn.empty.critical_vulns', 'critical 취약점이 없습니다.'));
    }

    function renderSourceDetailTable(items) {
      return renderDetailTable([
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Hosts', render: (item) => escapeHtml(item.host_count) },
        { label: 'Status', render: (item) => escapeHtml(item.status) },
        { label: 'Last Sync', render: (item) => escapeHtml(formatTime(item.last_sync_at)) },
      ], items, tt('dash.dyn.empty.sources', '표시할 source 상태가 없습니다.'));
    }

    function renderIngestedDetailTable(items) {
      return renderDetailTable([
        { label: 'Entity', render: (item) => escapeHtml(item.entity_type) },
        { label: 'Count', render: (item) => escapeHtml(item.count) },
      ], items, tt('dash.dyn.empty.ingested', '수집된 레코드가 없습니다.'));
    }

    function showOverviewDetail(key) {
      const items = Array.isArray(dashboardDetails[key]) ? dashboardDetails[key] : [];
      const renderers = {
        total_hosts: [renderStatusDetailTable, tt('dash.dyn.desc.total_hosts', '현재 알려진 전체 호스트 목록입니다.')],
        offline_hosts: [renderStatusDetailTable, tt('dash.dyn.desc.offline_hosts', '즉시 확인이 필요한 offline 호스트 목록입니다.')],
        alerts_24h: [renderAlertDetailTable, tt('dash.dyn.desc.alerts_24h', '최근 24시간 high / critical alert 목록입니다.')],
        critical_vulns: [renderVulnerabilityDetailTable, tt('dash.dyn.desc.critical_vulns', '현재 critical 취약점 목록입니다.')],
        sources_reporting: [renderSourceDetailTable, tt('dash.dyn.desc.sources_reporting', '호스트를 보고 중인 source 목록입니다.')],
        sources_healthy: [renderSourceDetailTable, tt('dash.dyn.desc.sources_healthy', '최근 sync가 success인 collector 목록입니다.')],
        ingested_records: [renderIngestedDetailTable, tt('dash.dyn.desc.ingested_records', '저장된 엔터티 타입별 레코드 수입니다.')],
      };
      const [renderer, description] = renderers[key] || [renderIngestedDetailTable, tt('dash.dyn.desc.default', '선택한 카드의 상세 데이터입니다.')];
      openOverviewModal(cardLabels[key] || key, description, renderer(items));
    }

    /* 🛡️ 보안 요약 히어로 — 역할별로 다르게.
       보안/어드민: 위험 KPI(클릭→드릴다운) + 위험 TOP.
       인프라/헬프데스크: 내 담당 서버 취약점 + 조치율(읽기 전용). */
    const _heroKpi = (label, val, color, onclick) => `<div onclick=\"${onclick||''}\" style=\"flex:1;min-width:130px;background:#0b1322;border:1px solid #1e293b;border-radius:10px;padding:12px 14px;${onclick?'cursor:pointer':''}\">
        <div style=\"font-size:12px;color:#94a3b8\">${label}</div>
        <div style=\"font-size:26px;font-weight:800;color:${color};margin-top:2px\">${val}</div></div>`;

    function _computeMyVulnSummary(rows) {
      const assigned = new Set((_currentProfile.assigned_servers || []).map(s => String(s).toLowerCase()));
      const myName = (_currentProfile.display_name || '').trim().toLowerCase();
      const mine = (rows || []).filter(r =>
        assigned.has(String(r.hostname || '').toLowerCase()) ||
        (myName && String(r.owner || '').trim().toLowerCase() === myName));
      let total = 0, done = 0;
      const hosts = mine.map(r => {
        const t = r.total || 0;
        const d = Math.min((r.vuln_plans_count || 0) + (r.vuln_exceptions_count || 0), t);
        total += t; done += d;
        return { hostname: r.hostname, host_id: r.host_id, total: t, done: d, critical: r.critical || 0, high: r.high || 0 };
      }).filter(h => h.total > 0).sort((a, b) => b.critical - a.critical || b.total - a.total);
      return { hosts, total, done, pct: total ? Math.round(done / total * 100) : 100 };
    }

    /* 내 서버 취약점·조치율 배너 (인프라·헬프데스크도 열람) */
    function _myServersVulnBanner() {
      const s = _computeMyVulnSummary(_assetCache.trivy);
      if (!s.total) return '';
      const barColor = s.pct >= 80 ? '#22c55e' : (s.pct >= 50 ? '#f59e0b' : '#ef4444');
      return `<div style=\"background:#0f2035;border:1px solid #1e3a5f;border-radius:8px;padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;gap:14px;flex-wrap:wrap\">
        <span style=\"color:#e2e8f0;font-weight:600\">${tt('dash.mine.remediation_summary','🐞 내 서버 취약점 {n}건 · 조치 {m}건 ({p}%)').replace('{n}', s.total).replace('{m}', s.done).replace('{p}', s.pct)}</span>
        <span style=\"flex:1;min-width:120px;max-width:280px;height:8px;background:#1e293b;border-radius:4px;overflow:hidden\"><span style=\"display:block;height:100%;width:${s.pct}%;background:${barColor}\"></span></span>
      </div>`;
    }

    async function renderSecurityHero() {
      const el = document.getElementById('security_hero_body');
      if (!el) return;
      const o = _lastOverviewData || {};
      if (_canAssessRisk()) {
        let risk = { by_level: {}, items: [], total: 0, assessed: 0 };
        try { const r = await fetch('/vulnerabilities/risk-summary?source=trivy'); if (r.ok) risk = await r.json(); } catch (e) {}
        _riskSummary = risk; _riskSummary.map = {};
        (risk.items || []).forEach(it => { _riskSummary.map[it.vuln_id] = it; });
        const bl = risk.by_level || {};
        const kpis = `<div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px\">
          ${_heroKpi(tt('dash.hero.critical_risk','🔴 매우높음 위험'), (bl['매우높음']||0), '#f87171', \"openRiskLevelModal('매우높음')\")}
          ${_heroKpi(tt('dash.hero.high_risk','🟠 높음 위험'), (bl['높음']||0), '#fb923c', \"openRiskLevelModal('높음')\")}
          ${_heroKpi(tt('dash.hero.alerts','🚨 24h 경보'), (o.alerts_24h??0), '#fca5a5', \"switchTab('triage')\")}
          ${_heroKpi(tt('dash.hero.crit_vulns','🐞 Critical 취약점'), (o.critical_vulns??0), '#fca5a5', \"switchTab('assets');switchAssetTab('trivy')\")}
        </div>`;
        const top = (risk.items || []).slice(0, 6);
        const rankColor = (i) => i===0?'#f87171':i===1?'#fb923c':i===2?'#fbbf24':'#64748b';
        const list = !top.length
          ? `<div class=\"empty\" style=\"color:#64748b\">${tt('dash.hero.no_risk','평가 대상 취약점이 없습니다.')}</div>`
          : `<style>.hero-rank-row{border-bottom:1px solid #16233b}.hero-rank-row:last-child{border-bottom:none}.hero-rank-row:hover{background:#0f2035}</style>
             <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:4px\">
               <span style=\"font-size:13px;font-weight:700;color:#e2e8f0\">${tt('dash.hero.top_title','위험 TOP')} <span style=\"color:#64748b;font-weight:400;font-size:11px\">· ${tt('dash.hero.by_score','위험점수순')}</span></span>
               <button onclick=\"switchTab('assets');switchAssetTab('trivy')\" style=\"background:none;border:none;color:#7dd3fc;font-size:12px;cursor:pointer\">${tt('dash.hero.view_all','전체 보기 →')}</button>
             </div>` + top.map((it, i) => `
              <div class=\"hero-rank-row\" onclick=\"openRiskModal('${escapeHtml(it.vuln_id)}')\" style=\"display:flex;align-items:center;gap:12px;padding:9px 6px;cursor:pointer\">
                <span style=\"width:20px;text-align:center;font-weight:800;font-size:15px;color:${rankColor(i)}\">${i+1}</span>
                <div style=\"min-width:0;flex:1\">
                  <div style=\"display:flex;align-items:center;gap:8px\">${_riskBadge(it.level, true)}<strong style=\"color:#e2e8f0;font-size:13px\">${escapeHtml(it.cve)}</strong></div>
                  <div style=\"color:#64748b;font-size:11px;margin-top:2px\">${escapeHtml(it.hostname)} · <span style=\"text-transform:uppercase;color:${it.severity==='critical'?'#fca5a5':'#fdba74'}\">${escapeHtml(it.severity)}</span></div>
                </div>
                <div style=\"text-align:right;white-space:nowrap\">
                  <div style=\"font-weight:800;font-size:15px;color:${RISK_LEVEL_COLORS[it.level]||'#e2e8f0'}\">${it.score}</div>
                  <div style=\"font-size:10px;color:#64748b\">${tt('dash.hero.score','위험점수')}</div>
                </div>
              </div>`).join('');
        el.innerHTML = kpis + list;
      } else {
        // 인프라/헬프데스크: 내 담당 서버 취약점 + 조치율(위험등급 없이)
        let rows = _assetCache.trivy;
        if (!rows || !rows.length) { try { const r = await fetch('/assets'); if (r.ok) { rows = (await r.json()).trivy?.rows || []; _assetCache.trivy = rows; } } catch (e) { rows = []; } }
        const s = _computeMyVulnSummary(rows);
        const kpis = `<div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px\">
          ${_heroKpi(tt('dash.hero.my_vulns','🐞 내 서버 취약점'), s.total, s.total?'#fca5a5':'#86efac', \"shortcutMyServers()\")}
          ${_heroKpi(tt('dash.hero.my_remediation','🛠️ 내 서버 조치율'), s.pct + '%', s.pct>=80?'#86efac':(s.pct>=50?'#fdba74':'#fca5a5'), \"shortcutMyServers()\")}
          ${_heroKpi(tt('dash.hero.alerts','🚨 24h 경보'), (o.alerts_24h??0), '#fca5a5', \"switchTab('triage')\")}
        </div>`;
        const list = !s.hosts.length
          ? `<div class=\"empty\" style=\"color:#64748b\">${tt('dash.mine.no_vulns','취약점 없음')}</div>`
          : `<div style=\"font-size:12px;color:#94a3b8;margin-bottom:6px\">${tt('dash.hero.my_servers_title','내 담당 서버 조치 현황')}</div>` + s.hosts.slice(0,6).map(h => {
              const pct = h.total ? Math.round(h.done/h.total*100) : 100;
              return `<div onclick=\"openVulnListModal('${escapeHtml(h.host_id)}')\" style=\"display:flex;align-items:center;gap:10px;padding:7px 10px;border:1px solid #1e293b;border-radius:8px;margin-bottom:6px;cursor:pointer;background:#0b1322\">
                <strong style=\"color:#e2e8f0;font-size:13px;min-width:120px\">${escapeHtml(h.hostname)}</strong>
                <span style=\"color:#fca5a5;font-size:11px\">C ${h.critical}</span><span style=\"color:#fdba74;font-size:11px\">H ${h.high}</span>
                <span style=\"margin-left:auto;display:flex;align-items:center;gap:6px\">
                  <span style=\"width:90px;height:7px;background:#1e293b;border-radius:4px;overflow:hidden\"><span style=\"display:block;height:100%;width:${pct}%;background:${pct>=80?'#22c55e':(pct>=50?'#f59e0b':'#ef4444')}\"></span></span>
                  <span style=\"font-size:11px;color:#94a3b8;width:60px;text-align:right\">${h.done}/${h.total} (${pct}%)</span></span>
              </div>`;
            }).join('');
        el.innerHTML = kpis + list;
      }
    }
    window.renderSecurityHero = renderSecurityHero;

    /* 🖥️ 인프라 현황 위젯 — 24h/12h 전환 + Zabbix/Wazuh 딥링크 (대시보드=인프라 뷰) */
    let _infraWindow = '24h';
    function setInfraWindow(w) {
      _infraWindow = w;
      const b24 = document.getElementById('infra_win_24'), b12 = document.getElementById('infra_win_12');
      if (b24) { b24.style.background = w==='24h'?'#1e3a5f':'transparent'; b24.style.color = w==='24h'?'#e2e8f0':'#94a3b8'; }
      if (b12) { b12.style.background = w==='12h'?'#1e3a5f':'transparent'; b12.style.color = w==='12h'?'#e2e8f0':'#94a3b8'; }
      renderInfraStatus();
    }
    window.setInfraWindow = setInfraWindow;
    function renderInfraStatus() {
      const el = document.getElementById('infra_status_body');
      if (!el) return;
      const o = _lastOverviewData || {};
      const alertsWin = _infraWindow==='12h' ? (o.alerts_12h??0) : (o.alerts_24h??0);
      const zbx = ZABBIX_URL ? `<a href=\"${escapeHtml(ZABBIX_URL)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#7dd3fc;font-size:11px;text-decoration:none\">Zabbix ↗</a>` : '';
      const wzh = WAZUH_URL ? `<a href=\"${escapeHtml(WAZUH_URL)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#a78bfa;font-size:11px;text-decoration:none\">Wazuh ↗</a>` : '';
      const tile = (label, val, color, extra) => `<div style=\"flex:1;min-width:110px;background:#0b1322;border:1px solid #1e293b;border-radius:10px;padding:12px\">
        <div style=\"font-size:12px;color:#94a3b8\">${label}</div>
        <div style=\"font-size:24px;font-weight:800;color:${color};margin-top:2px\">${val}</div>
        <div style=\"margin-top:4px\">${extra||''}</div></div>`;
      el.innerHTML = `<div style=\"display:flex;gap:10px;flex-wrap:wrap\">
        ${tile(tt('dash.infra.online','🟢 온라인'), (o.online_hosts??0), '#86efac', zbx)}
        ${tile(tt('dash.infra.offline','🔴 오프라인'), (o.offline_hosts??0), '#fca5a5', zbx)}
        ${tile(tt('dash.infra.unknown','⚪ 미상'), (o.unknown_hosts??0), '#cbd5e1', '')}
        ${tile(_infraWindow==='12h'?tt('dash.infra.alerts_12','🚨 경보 12h'):tt('dash.infra.alerts_24','🚨 경보 24h'), alertsWin, '#fca5a5', wzh)}
      </div>
      <div style=\"margin-top:8px;font-size:11px;color:#64748b\">${tt('dash.infra.hint','타일의 Zabbix / Wazuh 링크로 원본 도구에서 상세를 확인하세요.')}</div>`;
    }
    window.renderInfraStatus = renderInfraStatus;

    function renderOverview(overview) {
      if (!overview || typeof overview !== 'object') overview = {};
      _lastOverviewData = overview;
      renderSecurityHero();
      renderInfraStatus();
      const o = {
        total_hosts: overview.total_hosts ?? 0, online_hosts: overview.online_hosts ?? 0,
        offline_hosts: overview.offline_hosts ?? 0, unknown_hosts: overview.unknown_hosts ?? 0,
        alerts_24h: overview.alerts_24h ?? 0, critical_vulns: overview.critical_vulns ?? 0,
        high_vulns: overview.high_vulns ?? 0, sources_reporting: overview.sources_reporting ?? 0,
        sources_healthy: overview.sources_healthy ?? 0, ingested_records: overview.ingested_records ?? 0,
      };
      const cards = [
        ['total_hosts', o.total_hosts, `${o.online_hosts} online / ${o.unknown_hosts} unknown`],
        ['offline_hosts', o.offline_hosts, tt('dash.dyn.sub.offline', '즉시 확인 대상')],
        ['alerts_24h', o.alerts_24h, 'high + critical'],
        ['critical_vulns', o.critical_vulns, `high ${o.high_vulns}`],
        ['sources_reporting', o.sources_reporting, 'fleet / wazuh / zabbix / trivy / host_log'],
        ['sources_healthy', o.sources_healthy, tt('dash.dyn.sub.sources_healthy', '최근 sync success 기준')],
        ['ingested_records', o.ingested_records, 'alerts + vulns + queries + observations'],
      ].filter(([key]) => (userPreferences.cards || {})[key] !== false);
      if (!cards.length) {
        overviewCardsEl.innerHTML = `<div class=\"empty\">${tt('dash.dyn.empty.cards', '운영자가 공개한 요약 카드가 없습니다.')}</div>`;
        return;
      }
      overviewCardsEl.innerHTML = cards.map(([key, value, sub]) => `
        <section class=\"card metric-card\" role=\"button\" tabindex=\"0\" data-overview-key=\"${escapeHtml(key)}\">
          <div class=\"metric-label\">${escapeHtml(cardLabels[key] || key)}</div>
          <div class=\"metric-value\">${escapeHtml(value)}</div>
          <div class=\"metric-sub\">${escapeHtml(sub)}</div>
        </section>
      `).join('');
      overviewCardsEl.querySelectorAll('[data-overview-key]').forEach((card) => {
        const open = () => showOverviewDetail(card.dataset.overviewKey || '');
        card.addEventListener('click', open);
        card.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            open();
          }
        });
      });
    }

    /* 🧩 패널 편집: 사용자가 직접 표시할 카드/패널을 선택 (개인별 자동 저장) */
    function togglePanelEdit() {
      _panelEditOpen = !_panelEditOpen;
      const box = document.getElementById('panel_edit_box');
      const btn = document.getElementById('panel_edit_toggle');
      if (box) box.classList.toggle('hidden', !_panelEditOpen);
      if (btn) btn.textContent = _panelEditOpen ? tt('dash.panel.done', '✓ 완료') : tt('dash.panel.edit', '🧩 패널 편집');
      if (_panelEditOpen) renderPanelEditor();
    }
    window.togglePanelEdit = togglePanelEdit;

    /* ↔ 패널 사이즈 자유조절 — 네이티브 드래그 리사이즈 + localStorage 영속(브라우저별) */
    const _DASH_W_KEY = 'mori_panel_widths';
    let _panelWTimer = null;
    function _applyPanelWidths() {
      let saved = {};
      try { saved = JSON.parse(localStorage.getItem(_DASH_W_KEY) || '{}'); } catch (e) {}
      document.querySelectorAll('#dash_grid > section').forEach((sec) => {
        if (saved[sec.id]) sec.style.width = saved[sec.id] + 'px';
      });
    }
    function _savePanelWidths() {
      const w = {};
      // 사용자가 드래그해 inline width 가 잡힌 패널만 저장(리플로우 폭은 저장하지 않음)
      document.querySelectorAll('#dash_grid > section').forEach((sec) => {
        if (sec.style.width) w[sec.id] = parseInt(sec.style.width, 10);
      });
      try { localStorage.setItem(_DASH_W_KEY, JSON.stringify(w)); } catch (e) {}
    }
    function resetPanelLayout() {
      try { localStorage.removeItem(_DASH_W_KEY); } catch (e) {}
      document.querySelectorAll('#dash_grid > section').forEach((sec) => { sec.style.width = ''; });
      if (typeof dashboardStatusEl !== 'undefined' && dashboardStatusEl) {
        dashboardStatusEl.textContent = tt('dash.panel.layout_reset', '↔️ 패널 크기 초기화됨');
      }
    }
    window.resetPanelLayout = resetPanelLayout;
    // 드래그(마우스 업) 후 잠시 뒤 저장
    document.addEventListener('mouseup', () => {
      if (_panelWTimer) clearTimeout(_panelWTimer);
      _panelWTimer = setTimeout(_savePanelWidths, 300);
    });
    _applyPanelWidths();

    function renderPanelEditor() {
      const mk = (key, label, kind, on) => `
        <label style=\"display:flex;align-items:center;gap:6px;font-size:13px;color:#e2e8f0;cursor:pointer\">
          <input type=\"checkbox\" data-panel-${kind}=\"${escapeHtml(key)}\" ${on ? 'checked' : ''} onchange=\"onPanelToggle('${kind}', this)\" />
          ${escapeHtml(label)}
        </label>`;
      const cardsEl = document.getElementById('panel_edit_cards');
      const sectionsEl = document.getElementById('panel_edit_sections');
      if (cardsEl) {
        cardsEl.innerHTML = Object.keys(cardLabels)
          .map((key) => mk(key, cardLabels[key] || key, 'card', (userPreferences.cards || {})[key] !== false))
          .join('');
      }
      if (sectionsEl) {
        sectionsEl.innerHTML = Object.keys(sectionLabels)
          .map((key) => mk(key, sectionLabels[key] || key, 'section', (userPreferences.sections || {})[key] !== false))
          .join('');
      }
    }

    function onPanelToggle(kind, input) {
      const checked = !!input.checked;
      if (kind === 'card') {
        userPreferences.cards = userPreferences.cards || {};
        userPreferences.cards[input.dataset.panelCard] = checked;
        renderOverview(_lastOverviewData);
      } else {
        userPreferences.sections = userPreferences.sections || {};
        userPreferences.sections[input.dataset.panelSection] = checked;
        setSectionVisible(input.dataset.panelSection, checked);
      }
      savePanelPreferences();
    }
    window.onPanelToggle = onPanelToggle;

    function savePanelPreferences() {
      if (_panelSaveTimer) clearTimeout(_panelSaveTimer);
      _panelSaveTimer = setTimeout(async () => {
        try {
          const response = await fetch('/dashboard/preferences', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_dashboard: { cards: userPreferences.cards || {}, sections: userPreferences.sections || {} } }),
          });
          dashboardStatusEl.textContent = response.ok
            ? tt('dash.panel.saved', '✅ 패널 설정 저장됨')
            : `${tt('dash.panel.save_fail', '❌ 패널 설정 저장 실패')}: HTTP ${response.status}`;
        } catch (error) {
          dashboardStatusEl.textContent = `${tt('dash.panel.save_fail', '❌ 패널 설정 저장 실패')}: ${error.message}`;
        }
      }, 400);
    }

    function renderSourceCoverage(items) {
      if (!items.length) {
        sourceCoverageEl.innerHTML = `<div class=\"empty\">${tt('dash.dyn.empty.source_alias', '아직 연결된 source alias가 없습니다.')}</div>`;
        return;
      }
      const statusToBadge = { success: 'online', error: 'offline', running: 'unknown', unknown: 'unknown' };
      sourceCoverageEl.innerHTML = items.map((item) => {
        const staleBadge = item.is_stale ? ' <span class=\"badge\" style=\"background:#f59e0b;color:#000\">STALE</span>' : '';
        return `
        <div class=\"coverage-item\">
          <div class=\"metric-label\">${escapeHtml(item.source.toUpperCase())}</div>
          <strong>${escapeHtml(item.host_count)}</strong>
          <div class=\"metric-sub\">${tt('dash.dyn.unit.hosts', '호스트')} · <span class=\"badge ${escapeHtml(statusToBadge[item.status] || 'unknown')}\">${escapeHtml(item.status)}</span>${staleBadge}</div>
          <div class=\"metric-sub\">last sync: ${escapeHtml(formatTime(item.last_sync_at))}</div>
        </div>`;
      }).join('');
    }

    function renderLatestStatus(items) {
      if (!items.length) {
        latestStatusEl.innerHTML = `<div class=\"empty\">${tt('dash.dyn.empty.host_data', '아직 호스트 데이터가 없습니다.')}</div>`;
        return;
      }
      latestStatusEl.innerHTML = `
        <table>
          <thead><tr><th>Host</th><th>Status</th><th>Risk</th><th>Last Seen</th></tr></thead>
          <tbody>${items.map((item) => `
            <tr>
              <td>${renderHostCell(item)}</td>
              <td><span class=\"badge ${escapeHtml(item.status)}\">${escapeHtml(item.status)}</span></td>
              <td>${escapeHtml(item.risk_score)}</td>
              <td>${escapeHtml(formatTime(item.last_seen_at))}</td>
            </tr>`).join('')}</tbody>
        </table>`;
    }

    function renderRiskSummary(items) {
      if (!items.length) {
        riskSummaryEl.innerHTML = `<div class=\"empty\">${tt('dash.dyn.empty.risk_summary', '아직 위험 요약 데이터가 없습니다.')}</div>`;
        return;
      }
      riskSummaryEl.innerHTML = `
        <table>
          <thead><tr><th>Host</th><th>Risk</th><th>Alerts 24h</th><th>Critical</th><th>High</th><th>Vulns</th></tr></thead>
          <tbody>${items.map((item) => `
            <tr>
              <td><strong>${escapeHtml(item.hostname)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span></td>
              <td>${escapeHtml(item.risk_score)}</td>
              <td>${escapeHtml(item.alert_count_24h)}</td>
              <td>${escapeHtml(item.critical_alert_count_24h)}</td>
              <td>${escapeHtml(item.high_alert_count_24h)}</td>
              <td>${escapeHtml(item.vuln_count)} (C:${escapeHtml(item.critical_vuln_count)} / H:${escapeHtml(item.high_vuln_count)})</td>
            </tr>`).join('')}</tbody>
        </table>`;
    }

    function renderRecentActivity(items) {
      if (!items.length) {
        recentActivityEl.innerHTML = `<div class=\"empty\">${tt('dash.dyn.empty.recent_activity', '아직 최근 활동 데이터가 없습니다.')}</div>`;
        return;
      }
      recentActivityEl.innerHTML = items.map((item) => {
        let grafanaLink = '';
        if (item.grafana_url) {
          if (_canViewGrafanaFull()) {
            grafanaLink = `<a href=\"${escapeHtml(item.grafana_url)}\" target=\"_blank\" rel=\"noreferrer\" style=\"color:#38bdf8;font-size:12px;margin-left:8px;\">${tt('dash.dyn.grafana_full', 'Grafana 상세 로그 ↗')}</a>`;
          } else if (_canViewGrafanaLimited()) {
            grafanaLink = `<a href=\"${escapeHtml(item.grafana_url)}\" target=\"_blank\" rel=\"noreferrer\" style=\"color:#94a3b8;font-size:12px;margin-left:8px;\">${tt('dash.dyn.grafana_limited', 'Grafana 제한 보기 ↗')}</a>`;
          } else {
            grafanaLink = `<span style=\"color:#475569;font-size:11px;margin-left:8px\" title=\"${tt('dash.dyn.grafana_no_access', '상세 로그 접근 권한 없음')}\">${tt('dash.dyn.grafana_summary', '📊 요약')}</span>`;
          }
        }
        return `
        <div class=\"list-item\">
          <div class=\"top\"><strong>${escapeHtml(item.summary)}</strong><span class=\"meta\">${escapeHtml(formatTime(item.observed_at))}</span></div>
          <div class=\"meta\">${escapeHtml(item.entity_type)} · ${escapeHtml(item.source)} · ${escapeHtml(item.host_id || '-')}${grafanaLink}</div>
        </div>`;
      }).join('');
    }

    function showInfoModal(title, message) {
      const modal = document.getElementById('info_modal');
      document.getElementById('info_modal_title').textContent = title;
      document.getElementById('info_modal_body').textContent = message;
      if (!modal.open) modal.showModal();
    }

    // --- NLQ guide modal ---
    function openNlqGuideModal() {
      nlqGuideListEl.innerHTML = nlqGuideExamples.map((ex, idx) =>
        `<button type=\"button\" class=\"nlq-guide-chip\" data-idx=\"${idx}\" style=\"padding:8px 14px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;font-size:13px;\">${escapeHtml(tt('dash.dyn.nlq_ex.' + idx, ex))}</button>`
      ).join('');
      if (typeof nlqGuideModalEl.showModal === 'function') nlqGuideModalEl.showModal();
      else nlqGuideModalEl.setAttribute('open', 'open');
    }
    nlqGuideListEl.addEventListener('click', (e) => {
      const btn = e.target.closest('.nlq-guide-chip');
      if (!btn) return;
      const idx = Number(btn.dataset.idx);
      nlqTextarea.value = tt('dash.dyn.nlq_ex.' + idx, nlqGuideExamples[idx] || '');
      lastInterpretedPayload = null;
      nlqInterpretResult.textContent = '';
      if (nlqGuideModalEl.open) nlqGuideModalEl.close();
    });
    // --- NLQ section ---
    // NLQ 요소들은 script 태그 이후 dialog 안에 있으므로 스크립트 실행 시점에는 존재하지 않음.
    // 변수는 let으로 선언하고 DOMContentLoaded에서 할당·핸들러 등록 (아래 참조).
    let nlqTextarea = null;
    let nlqInterpretBtn = null;
    let nlqRunBtn = null;
    let nlqCsvBtn = null;
    let nlqInterpretResult = null;
    let nlqResultArea = null;
    let lastInterpretedPayload = null;

    async function runNlqQuery(format) {
      const text = nlqTextarea.value.trim();
      if (!text) { showInfoModal(tt('dash.dyn.nlq.need_input_title', '입력 필요'), tt('dash.dyn.nlq.need_input_msg', '질의할 내용을 입력해 주세요.')); return null; }
      let payload = lastInterpretedPayload;
      if (!payload) {
        // auto-interpret first
        try {
          const res = await fetch('/interpret', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text}) });
          const data = await res.json();
          if (!res.ok) { showInfoModal(tt('dash.dyn.nlq.interpret_err', '해석 오류'), data.detail || String(res.status)); return null; }
          payload = { intent: data.intent, scope: data.scope || {time_range:'24h'}, filters: data.filters || {} };
          lastInterpretedPayload = payload;
          nlqInterpretResult.textContent = `${tt('dash.dyn.nlq.interpret_result', '해석 결과')}: ${data.intent}`;
        } catch (err) { showInfoModal(tt('dash.dyn.nlq.interpret_err', '해석 오류'), err.message); return null; }
      }
      try {
        const url = format === 'csv' ? '/query?format=csv' : '/query';
        const res = await fetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        if (format === 'csv') {
          if (!res.ok) { const d = await res.json(); showInfoModal(tt('dash.dyn.err_generic', '오류'), d.detail || String(res.status)); return null; }
          const blob = await res.blob();
          const cd = res.headers.get('content-disposition') || '';
          const match = cd.match(/filename=\"([^\"]+)\"/);
          const filename = match ? match[1] : 'mori-query.csv';
          const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename; a.click();
          return 'csv_downloaded';
        }
        const data = await res.json();
        if (!res.ok) { showInfoModal(tt('dash.dyn.nlq.query_err', '질의 오류'), data.detail || String(res.status)); return null; }
        return data;
      } catch (err) { showInfoModal(tt('dash.dyn.err_generic', '오류'), err.message); return null; }
    }

    function renderNlqResult(result) {
      const evidence = result.evidence || [];
      const summary = result.summary || '';
      const count = result.meta?.count ?? evidence.length;
      if (!evidence.length) {
        nlqResultArea.textContent = '';
        showInfoModal(tt('dash.dyn.nlq.no_result_title', '결과 없음'), summary || tt('dash.dyn.nlq.no_result_msg', '조건에 맞는 데이터가 없습니다.'));
        nlqCsvBtn.style.display = 'none';
        return;
      }
      nlqCsvBtn.style.display = '';
      const srcBadge = (src) => {
        const s = (src || '').toLowerCase();
        const cls = s.includes('wazuh') ? 'wazuh' : s.includes('zabbix') ? 'zabbix' : s.includes('fleet') ? 'fleet' : s.includes('trivy') ? 'trivy' : s.includes('host') ? 'hosts' : '';
        return `<span style=\"display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;background:#1e3a5f;color:#93c5fd;\" class=\"${cls}\">${escapeHtml(src||'-')}</span>`;
      };
      const rows = evidence.map((ev, i) => `
        <tr style=\"border-bottom:1px solid #1a2d45;\">
          <td style=\"padding:7px 10px;color:#64748b\">${i+1}</td>
          <td style=\"padding:7px 10px\">${srcBadge(ev.source)}</td>
          <td style=\"padding:7px 10px;font-size:13px\">${escapeHtml(ev.summary || ev.raw_ref || '-')}</td>
          <td style=\"padding:7px 10px;font-size:11px;color:#64748b;font-family:monospace\">${escapeHtml(ev.record_id || '-')}</td>
        </tr>`).join('');
      nlqResultArea.innerHTML = `
        ${summary ? `<div style=\"color:#7dd3fc;font-size:13px;margin-bottom:10px;padding:8px 12px;background:#0f2035;border-radius:8px;border-left:3px solid #3b82f6\">${escapeHtml(summary)}</div>` : ''}
        <div style=\"overflow:auto\">
          <table style=\"width:100%;border-collapse:collapse;font-size:13px\">
            <thead><tr style=\"background:#0f2035\">
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">#</th>
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">Source</th>
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">Summary</th>
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">Record ID</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div style=\"color:#94a3b8;font-size:13px;margin-top:8px\">${tt('dash.dyn.nlq.total_prefix', '총')} ${count}${tt('dash.dyn.nlq.total_suffix', '건 조회됨')}</div>`;
    }

    // nlqRunBtn / nlqCsvBtn 핸들러는 DOMContentLoaded 블록에서 등록 (아래 참조)

    async function loadPreferences() {
      try {
        const response = await fetch('/dashboard/preferences');
        const data = await response.json();
        if (response.ok && data.user_dashboard) {
          userPreferences = data.user_dashboard;
          if (data.user_dashboard.asset_columns) {
            assetColumnPrefs = Object.assign({}, assetColumnPrefs, data.user_dashboard.asset_columns);
          }
        }
      } catch (error) {
        dashboardStatusEl.textContent = `preferences load failed: ${error.message}`;
      }
      applyUserPreferences();
    }

    async function loadDashboard() {
      dashboardStatusEl.textContent = tt('dash.dyn.dash_requesting', '📡 대시보드 데이터 요청 중…');
      try {
        const response = await fetch('/dashboard/summary');
        if (!response.ok) {
          let detail = `HTTP ${response.status}`;
          try { const e = await response.json(); detail = e.detail || detail; } catch(_){}
          dashboardStatusEl.textContent = `${tt('dash.dyn.dash_load_fail', '❌ 대시보드 로드 실패')}: ${detail}`;
          overviewCardsEl.innerHTML = `<div class=\"empty\" style=\"padding:16px;color:#fca5a5\">${tt('dash.dyn.dash_no_data', '⚠️ 서버가 데이터를 반환하지 못했습니다')} (${escapeHtml(detail)})</div>`;
          return;
        }
        const data = await response.json();
        dashboardDetails = data.overview_details || {};
        renderOverview(data.overview || {});
        renderSourceCoverage(data.source_coverage || []);
        renderLatestStatus(data.latest_status || []);
        renderRiskSummary(data.risk_summary || []);
        renderRecentActivity(data.recent_activity || []);
        applyUserPreferences();
        dashboardStatusEl.textContent = `✅ dashboard updated at ${formatTime(data.generated_at)}`;
      } catch (error) {
        console.error('[MORI] loadDashboard fetch error:', error);
        dashboardStatusEl.textContent = `${tt('dash.dyn.dash_load_fail', '❌ 대시보드 로드 실패')}: ${error.message}`;
        overviewCardsEl.innerHTML = `<div class=\"empty\" style=\"padding:16px;color:#fca5a5\">${tt('dash.dyn.network_err', '⚠️ 네트워크 오류 — 서버 연결을 확인하세요.')}</div>`;
      }
    }

    document.getElementById('refresh_dashboard')?.addEventListener('click', loadDashboard);

    // ── Triage ──────────────────────────────────────────────────────────────
    async function loadTriage() {
      triageTableEl.innerHTML = '<span class=\"empty\">' + tt('dash.dyn.loading', '로딩 중…') + '</span>';
      try {
        const res = await fetch('/alerts');
        if (!res.ok) { triageTableEl.innerHTML = '<span class=\"empty\">' + tt('dash.dyn.alerts_load_fail', '경보 로드 실패') + '</span>'; return; }
        const data = await res.json();
        const alerts = data.alerts || [];
        if (!alerts.length) { triageTableEl.innerHTML = '<span class=\"empty\">' + tt('dash.dyn.alerts_empty', '최근 24h 경보 없음') + '</span>'; return; }
        // Cache triage data for history display in modal
        alerts.forEach(a => { if (a.triage) triageDataCache[a.alert_id] = a.triage; });
        const rows = alerts.map(a => {
          const triage = a.triage || {};
          const rawStatus = triage.status || 'pending';
          const triageAnalyst = triage.analyst || '';
          const triageNote = triage.note || '';
          const triageChangedBy = triage.changed_by || '';
          const color = TRIAGE_STATUS_COLORS[rawStatus] || '#6b7280';
          const label = triageLabel(rawStatus);
          const alertOwner = _ownerForHost(a.hostname || '');
          return `<tr>
            <td>${escapeHtml(formatTime(a.observed_at))}</td>
            <td><span style=\"background:#1e293b;color:#93c5fd;padding:2px 8px;border-radius:4px;font-size:12px\">${escapeHtml(a.source)}</span>${(a.source==='zabbix' && ZABBIX_URL && a.source_event_id)?`<br><a href=\"${escapeHtml(ZABBIX_URL)}/tr_events.php?triggerid=${encodeURIComponent(a.rule_id||'')}&eventid=${encodeURIComponent(a.source_event_id)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#7dd3fc;font-size:11px;text-decoration:none\">Zabbix ↗</a>`:''}</td>
            <td><strong>${escapeHtml(a.hostname || a.host_id || '-')}</strong></td>
            <td style=\"color:#a3e635;font-size:12px\">${escapeHtml(alertOwner)}</td>
            <td><span style=\"background:#111827;padding:2px 6px;border-radius:4px;font-size:12px\">${escapeHtml(a.severity)}</span>${a.resolved_at?`<br><span title=\"${escapeHtml(formatTime(a.resolved_at))}\" style=\"background:#052e16;color:#86efac;border:1px solid #14532d;padding:1px 6px;border-radius:4px;font-size:10px\">${tt('dash.triage.source_resolved','✓ 소스 해소')}</span>`:''}</td>
            <td style=\"max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">${escapeHtml(a.message)}</td>
            <td style=\"color:#94a3b8;font-size:12px\">${escapeHtml(triageAnalyst || '-')}</td>
            <td style=\"color:#fde68a;font-size:12px\">${escapeHtml(triageChangedBy || '-')}</td>
            <td><button onclick=\"openTriageModal('${escapeHtml(a.alert_id)}','${escapeHtml(rawStatus)}','${escapeHtml(triageAnalyst)}','${escapeHtml(triageNote)}','${escapeHtml(a.message||'').replace(/'/g,\"&#39;\")}','${escapeHtml(alertOwner)}')\" style=\"background:${color};color:#fff;border:none;border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px;white-space:nowrap\">${label}</button></td>
          </tr>`;
        }).join('');
        triageTableEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
          <thead><tr style=\"background:#0f2035\">
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">${tt('dash.dyn.lbl.time', '시각')}</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">${tt('dash.dyn.lbl.source', '소스')}</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">${tt('dash.dyn.lbl.host', '호스트')}</th>
            <th style=\"padding:8px;color:#a3e635;text-align:left\">${tt('dash.dyn.lbl.server_owner', '서버 담당자')}</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">${tt('dash.dyn.lbl.severity', '심각도')}</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">${tt('dash.dyn.lbl.message', '메시지')}</th>
            <th style=\"padding:8px;color:#94a3b8;text-align:left\">${tt('dash.dyn.lbl.analyst', '분석관')}</th>
            <th style=\"padding:8px;color:#fde68a;text-align:left\">${tt('dash.dyn.lbl.changed_by', '변경자')}</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">${tt('dash.dyn.lbl.status', '상태')}</th>
          </tr></thead><tbody>${rows}</tbody></table>`;
      } catch (err) { triageTableEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix', '오류: ')}${escapeHtml(err.message)}</span>`; }
    }

    function openTriageModal(alertId, status, analyst, note, message, serverOwner) {
      currentTriageAlertId = alertId;
      triageModalAlertInfoEl.innerHTML = `<strong>Alert ID:</strong> ${escapeHtml(alertId)}<br><span style=\"color:#94a3b8\">${escapeHtml(message)}</span>`;
      triageModalStatusEl.value = status || 'pending';
      // 서버 담당자가 기본, 기존 analyst가 있으면 그 값 유지
      triageModalAnalystEl.value = analyst || serverOwner || '';
      triageModalNoteEl.value = note || '';
      const actorEl = document.getElementById('triage_modal_actor');
      if (actorEl) actorEl.value = '';
      triageModalStatusLineEl.textContent = '';
      // Render triage history
      const cached = triageDataCache[alertId] || {};
      const history = cached.history || [];
      const historyEl = document.getElementById('triage_modal_history');
      if (historyEl) {
        historyEl.innerHTML = history.length
          ? [...history].reverse().map(h => {
              const fromLabel = triageLabel(h.from_status);
              const toLabel = triageLabel(h.to_status);
              const arrow = `${fromLabel} → <strong>${toLabel}</strong>`;
              const noteText = h.note ? `<div style=\"color:#cbd5e1;margin-top:2px;font-size:11px\">📝 ${escapeHtml(h.note)}</div>` : '';
              const actorText = h.changed_by ? ` &nbsp;·&nbsp; <span style=\"color:#fde68a\">${tt('dash.dyn.lbl.changed_by', '변경자')}: ${escapeHtml(h.changed_by)}</span>` : '';
              return `<div style=\"background:#0c1827;border-left:3px solid #334155;padding:7px 12px;margin-bottom:5px;border-radius:4px;font-size:12px\">
                <div style=\"color:#64748b\">${escapeHtml(formatTime(h.changed_at))} &nbsp;·&nbsp; ${tt('dash.dyn.lbl.analyst', '분석관')}: ${escapeHtml(h.analyst || '-')}${actorText}</div>
                <div style=\"color:#e2e8f0;margin-top:2px\">${arrow}</div>${noteText}
              </div>`;
            }).join('')
          : `<div style=\"color:#64748b;font-size:13px\">${tt('dash.dyn.no_history', '변경 이력 없음')}</div>`;
      }
      if (typeof triageModalEl.showModal === 'function') triageModalEl.showModal();
      else triageModalEl.setAttribute('open', 'open');
    }

    document.getElementById('triage_modal_save')?.addEventListener('click', async () => {
      if (!currentTriageAlertId) return;
      const actor = (document.getElementById('triage_modal_actor')?.value || '').trim();
      const body = { status: triageModalStatusEl.value, analyst: triageModalAnalystEl.value, note: triageModalNoteEl.value, actor };
      triageModalStatusLineEl.textContent = tt('dash.dyn.saving', '저장 중...');
      try {
        const res = await fetch(`/alerts/${encodeURIComponent(currentTriageAlertId)}/triage`, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        });
        if (!res.ok) { const d = await res.json(); triageModalStatusLineEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${d.detail || res.status}`; return; }
        triageModalStatusLineEl.textContent = tt('dash.dyn.saved', '저장 완료');
        setTimeout(() => { if (triageModalEl.open) triageModalEl.close(); loadTriage(); }, 800);
      } catch (err) { triageModalStatusLineEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${err.message}`; }
    });

    // Auto-save triage status when dropdown changes
    triageModalStatusEl.addEventListener('change', async () => {
      if (!currentTriageAlertId) return;
      const actor = (document.getElementById('triage_modal_actor')?.value || '').trim();
      const body = { status: triageModalStatusEl.value, analyst: triageModalAnalystEl.value, note: triageModalNoteEl.value, actor };
      triageModalStatusLineEl.textContent = tt('dash.dyn.autosaving', '자동 저장 중...');
      try {
        const res = await fetch(`/alerts/${encodeURIComponent(currentTriageAlertId)}/triage`, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        });
        if (!res.ok) { const d = await res.json(); triageModalStatusLineEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${d.detail || res.status}`; return; }
        triageModalStatusLineEl.style.color = '#86efac';
        triageModalStatusLineEl.textContent = tt('dash.dyn.autosaved', '✅ 자동 저장됨');
        loadTriage();
      } catch (err) { triageModalStatusLineEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${err.message}`; }
    });

    document.getElementById('reload_triage')?.addEventListener('click', loadTriage);

    // ── Incidents ────────────────────────────────────────────────────────────
    function buildIncidentParams() {
      const params = new URLSearchParams();
      const search = document.getElementById('inc_search')?.value?.trim();
      const from = document.getElementById('inc_date_from')?.value;
      const to = document.getElementById('inc_date_to')?.value;
      if (search) params.set('search', search);
      if (from) params.set('date_from', from);
      if (to) params.set('date_to', to);
      return params;
    }

    async function loadIncidents() {
      incidentsListEl.innerHTML = '<span class=\"empty\">' + tt('dash.dyn.loading', '로딩 중…') + '</span>';
      try {
        const params = buildIncidentParams();
        const url = '/incidents' + (params.toString() ? '?' + params.toString() : '');
        const res = await fetch(url);
        if (!res.ok) { incidentsListEl.innerHTML = '<span class=\"empty\">' + tt('dash.dyn.incidents_load_fail', '인시던트 로드 실패') + '</span>'; return; }
        const data = await res.json();
        const list = data.incidents || [];
        if (!list.length) { incidentsListEl.innerHTML = '<span class=\"empty\">' + tt('dash.dyn.incidents_empty', '인시던트 없음') + '</span>'; return; }
        const STATUS_COLOR = { open: '#ef4444', investigating: '#f59e0b', resolved: '#22c55e', closed: '#6b7280' };
        incidentsListEl.innerHTML = list.map(inc => {
          const color = STATUS_COLOR[inc.status] || '#6b7280';
          const ownerLabel = (inc.related_owners || []).join(', ') || '-';
          const hostLabel = (inc.related_hosts || []).join(', ') || '';
          const incHost = inc.hostname || '';
          const incAnalyst = inc.analyst || '';
          const incHandler = inc.handler || '';
          const handlerInfo = (incHandler && incHandler !== incAnalyst) ? ` · ${tt('dash.dyn.lbl.handler', '조치자')}: <span style=\"color:#fbbf24\">${escapeHtml(incHandler)}</span>` : '';
          return `<div style=\"background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:12px 16px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center\">
            <div>
              <strong>${escapeHtml(inc.title)}</strong>
              <div style=\"color:#94a3b8;font-size:12px;margin-top:4px\">${escapeHtml(formatTime(inc.created_at))} · ${tt('dash.dyn.notes_label', '노트')} ${(inc.notes||[]).length}${tt('dash.dyn.notes_unit', '개')}${incHost ? ' · ' + tt('dash.dyn.lbl.host', '호스트') + ': <span style=\"color:#93c5fd\">' + escapeHtml(incHost) + '</span>' : ''}${hostLabel ? ' · <span style=\"color:#93c5fd\">' + escapeHtml(hostLabel) + '</span>' : ''}</div>
              <div style=\"color:#a3e635;font-size:12px;margin-top:2px\">${tt('dash.dyn.col.owner', '담당자')}: ${escapeHtml(incAnalyst || ownerLabel)}${handlerInfo}</div>
            </div>
            <div style=\"display:flex;gap:8px;align-items:center\">
              <span style=\"background:${color};color:#fff;padding:3px 10px;border-radius:6px;font-size:12px\">${escapeHtml(inc.status)}</span>
              <button onclick=\"openIncidentModal('${escapeHtml(inc.incident_id)}')\" style=\"background:#1e293b;color:#93c5fd;border:1px solid #334155;border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px\">${tt('dash.dyn.detail_btn', '상세')}</button>
            </div>
          </div>`;
        }).join('');
      } catch (err) { incidentsListEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix', '오류: ')}${escapeHtml(err.message)}</span>`; }
    }

    async function openIncidentModal(incidentId) {
      currentIncidentId = incidentId;
      document.getElementById('incident_modal_title').textContent = tt('dash.dyn.incident_detail_title', '인시던트 상세');
      document.getElementById('incident_modal_status_line').textContent = '';
      document.getElementById('incident_modal_note_text').value = '';
      document.getElementById('incident_modal_analyst').value = '';
      document.getElementById('incident_modal_status_analyst').value = '';
      const editAnalystEl = document.getElementById('incident_modal_edit_analyst');
      const editHandlerEl = document.getElementById('incident_modal_edit_handler');
      if (editAnalystEl) editAnalystEl.value = '';
      if (editHandlerEl) editHandlerEl.value = '';
      try {
        const res = await fetch('/incidents');
        if (!res.ok) return;
        const data = await res.json();
        const inc = (data.incidents || []).find(i => i.incident_id === incidentId);
        if (!inc) return;
        document.getElementById('incident_modal_title').textContent = inc.title;
        const statusUpdatedLine = inc.status_updated_at
          ? `<br>🕐 <strong style="color:#fbbf24">${tt('dash.dyn.status_changed_at', '상태 변경 시각')}:</strong> ${escapeHtml(formatTime(inc.status_updated_at))}`
          : '';
        const hostLine = inc.hostname ? `<br>🖥️ <strong style="color:#93c5fd">${tt('dash.dyn.lbl.host', '호스트')}:</strong> ${escapeHtml(inc.hostname)}` : '';
        const analystLine = inc.analyst ? `<br>👤 <strong style="color:#a3e635">${tt('dash.dyn.col.owner', '담당자')}:</strong> ${escapeHtml(inc.analyst)}` : '';
        const handlerLine = (inc.handler && inc.handler !== inc.analyst) ? `<br>🔧 <strong style="color:#fbbf24">${tt('dash.dyn.lbl.handler', '조치자')}:</strong> ${escapeHtml(inc.handler)}` : '';
        document.getElementById('incident_modal_info').innerHTML = `<span style="color:#64748b">ID: ${escapeHtml(inc.incident_id)}</span><br>${tt('dash.dyn.created_label', '생성')}: ${escapeHtml(formatTime(inc.created_at))} &nbsp;|&nbsp; ${tt('dash.dyn.updated_label', '수정')}: ${escapeHtml(formatTime(inc.updated_at))}${statusUpdatedLine}${hostLine}${analystLine}${handlerLine}`;
        document.getElementById('incident_modal_status').value = inc.status;
        // 상태 / 담당자 / 조치자 변경 히스토리
        const history = inc.history || [];
        const statusLabels = { open: '🔵 open', investigating: '🟡 investigating', resolved: '🟢 resolved', closed: '⚫ closed', created: tt('dash.dyn.inc_status_created', '🆕 생성됨') };
        document.getElementById('incident_modal_history').innerHTML = history.length
          ? [...history].reverse().map(h => {
              let arrow;
              if (h.event === 'created') {
                arrow = `<span style=\"color:#94a3b8\">${tt('dash.dyn.created_label', '생성')}:</span> <strong>${statusLabels[h.to_status] || h.to_status}</strong>`;
              } else if (h.event === 'analyst_changed') {
                arrow = `<span style=\"color:#a3e635\">👤 ${tt('dash.dyn.col.owner', '담당자')}:</span> ${escapeHtml(h.from_analyst || '-')} → <strong>${escapeHtml(h.to_analyst || '-')}</strong>`;
              } else if (h.event === 'handler_changed') {
                arrow = `<span style=\"color:#fbbf24\">🔧 ${tt('dash.dyn.lbl.handler', '조치자')}:</span> ${escapeHtml(h.from_handler || '-')} → <strong>${escapeHtml(h.to_handler || '-')}</strong>`;
              } else {
                arrow = `${statusLabels[h.from_status] || h.from_status} → <strong>${statusLabels[h.to_status] || h.to_status}</strong>`;
              }
              return `<div style=\"background:#0c1827;border-left:3px solid #334155;padding:7px 12px;margin-bottom:5px;border-radius:4px;font-size:12px\">
                <div style=\"color:#64748b\">${escapeHtml(formatTime(h.changed_at))} &nbsp;·&nbsp; ${escapeHtml(h.analyst || '-')}</div>
                <div style=\"color:#e2e8f0;margin-top:2px\">${arrow}</div>
              </div>`;
            }).join('')
          : `<div style=\"color:#64748b;font-size:13px\">${tt('dash.dyn.no_history', '변경 이력 없음')}</div>`;
        // 조사 노트
        const notes = inc.notes || [];
        document.getElementById('incident_modal_notes').innerHTML = notes.length
          ? notes.map(n => `<div style=\"background:#0f172a;border-left:3px solid #334155;padding:8px 12px;margin-bottom:6px;border-radius:4px\"><div style=\"color:#94a3b8;font-size:12px\">${escapeHtml(formatTime(n.created_at))} · ${escapeHtml(n.analyst||'-')}</div><div>${escapeHtml(n.text)}</div></div>`).join('')
          : `<div style=\"color:#64748b;font-size:13px\">${tt('dash.dyn.no_notes', '조사 노트 없음')}</div>`;
      } catch (_) {}
      if (typeof incidentModalEl.showModal === 'function') incidentModalEl.showModal();
      else incidentModalEl.setAttribute('open', 'open');
    }

    document.getElementById('incident_modal_update_status')?.addEventListener('click', async () => {
      if (!currentIncidentId) return;
      const status = document.getElementById('incident_modal_status').value;
      const actor = document.getElementById('incident_modal_status_analyst').value.trim();
      const newAnalyst = document.getElementById('incident_modal_edit_analyst').value.trim();
      const newHandler = document.getElementById('incident_modal_edit_handler').value.trim();
      const sl = document.getElementById('incident_modal_status_line');
      const body = { status };
      if (actor) body.actor = actor;
      if (newAnalyst) body.analyst = newAnalyst;
      if (newHandler) body.handler = newHandler;
      sl.textContent = tt('dash.dyn.saving', '저장 중...');
      try {
        const res = await fetch(`/incidents/${encodeURIComponent(currentIncidentId)}`, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        });
        sl.textContent = res.ok ? tt('dash.dyn.saved', '저장 완료') : `${tt('dash.dyn.error_prefix', '오류: ')}${res.status}`;
        if (res.ok) { loadIncidents(); openIncidentModal(currentIncidentId); }
      } catch (err) { sl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${err.message}`; }
    });

    document.getElementById('incident_modal_add_note')?.addEventListener('click', async () => {
      if (!currentIncidentId) return;
      const text = document.getElementById('incident_modal_note_text').value.trim();
      const analyst = document.getElementById('incident_modal_analyst').value.trim();
      const sl = document.getElementById('incident_modal_status_line');
      if (!text) { sl.textContent = tt('dash.dyn.note_required', '노트 내용을 입력하세요.'); return; }
      sl.textContent = tt('dash.dyn.adding', '추가 중...');
      try {
        const res = await fetch(`/incidents/${encodeURIComponent(currentIncidentId)}/notes`, {
          method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ text, analyst }),
        });
        if (res.ok) { sl.textContent = tt('dash.dyn.note_added', '노트 추가 완료'); openIncidentModal(currentIncidentId); loadIncidents(); }
        else sl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${res.status}`;
      } catch (err) { sl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${err.message}`; }
    });

    document.getElementById('create_incident')?.addEventListener('click', async () => {
      const title = incTitleEl.value.trim();
      if (!title) { incidentStatusEl.textContent = tt('dash.dyn.title_required', '제목을 입력하세요.'); return; }
      const hostname = document.getElementById('inc_hostname')?.value.trim() || '';
      const analyst = document.getElementById('inc_analyst')?.value.trim() || '';
      const diffHandler = document.getElementById('inc_diff_handler')?.checked;
      const handler = diffHandler ? (document.getElementById('inc_handler')?.value.trim() || '') : '';
      incidentStatusEl.textContent = tt('dash.dyn.creating', '생성 중...');
      try {
        const res = await fetch('/incidents', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ title, hostname, analyst: analyst || undefined, handler: handler || undefined }),
        });
        if (res.ok) {
          incidentStatusEl.textContent = tt('dash.dyn.incident_created', '인시던트 생성 완료');
          incTitleEl.value = '';
          document.getElementById('inc_hostname').value = '';
          document.getElementById('inc_analyst').value = '';
          document.getElementById('inc_handler').value = '';
          document.getElementById('inc_diff_handler').checked = false;
          document.getElementById('inc_handler_row').style.display = 'none';
          loadIncidents();
        }
        else { const d = await res.json(); incidentStatusEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${d.detail || res.status}`; }
      } catch (err) { incidentStatusEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${err.message}`; }
    });

    document.getElementById('reload_incidents')?.addEventListener('click', loadIncidents);

    // 검색 + 날짜 필터 조회 버튼
    document.getElementById('inc_filter_btn')?.addEventListener('click', loadIncidents);
    // 검색창 Enter 키
    document.getElementById('inc_search')?.addEventListener('keydown', e => { if (e.key === 'Enter') loadIncidents(); });

    // CSV 다운로드 — 변경 이력은 미포함 안내 모달 표시 후 다운로드
    if (document.getElementById('inc_csv_btn')) {
      document.getElementById('inc_csv_btn')?.addEventListener('click', () => {
        const params = buildIncidentParams();
        params.set('format', 'csv');
        const url = '/incidents?' + params.toString();
        showIncidentCsvNotice(() => {
          const a = document.createElement('a');
          a.href = url;
          a.download = 'incidents.csv';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
        });
      });
    }

    /* ── 인시던트 호스트 검색 자동완성 ──────────────────────────────────── */
    let _incHostCacheLoaded = false;
    async function _ensureAssetCacheForIncident() {
      if (_incHostCacheLoaded) return;
      if ((_assetCache.fleet || []).length === 0 && (_assetCache.zabbix || []).length === 0) {
        try {
          const res = await fetch('/assets');
          if (res.ok) {
            const data = await res.json();
            _assetCache.fleet = data.fleet?.hosts || [];
            _assetCache.zabbix = data.zabbix?.hosts || [];
            if (!_assetCache.trivy?.length) _assetCache.trivy = data.trivy?.rows || [];
          }
        } catch(e) { console.warn('[MORI] asset cache load for incidents failed:', e); }
      }
      _incHostCacheLoaded = true;
    }
    async function _incHostSearch(val) {
      const sugEl = document.getElementById('inc_host_suggestions');
      if (!val || val.length < 1) { sugEl.style.display = 'none'; return; }
      await _ensureAssetCacheForIncident();
      const q = val.toLowerCase();
      const allHosts = [...(_assetCache.fleet || []), ...(_assetCache.zabbix || [])];
      const seen = new Set();
      const matches = allHosts.filter(h => {
        if (seen.has(h.hostname)) return false;
        seen.add(h.hostname);
        return h.hostname.toLowerCase().includes(q);
      }).slice(0, 10);
      if (!matches.length) { sugEl.style.display = 'none'; return; }
      sugEl.innerHTML = matches.map(h => {
        const ownerLabel = [h.owner, h.team].filter(Boolean).join(' / ') || '-';
        return `<div onclick=\"_incSelectHost('${escapeHtml(h.hostname)}','${escapeHtml(h.owner||'')}')\" style=\"padding:8px 12px;cursor:pointer;border-bottom:1px solid #334155;font-size:13px;color:#e2e8f0\" onmouseover=\"this.style.background='#1e3a5f'\" onmouseout=\"this.style.background=''\">
          <strong>${escapeHtml(h.hostname)}</strong> <span style=\"color:#64748b;font-size:11px\">${tt('dash.dyn.lbl.owner_short', '담당')}: ${escapeHtml(ownerLabel)}</span>
        </div>`;
      }).join('');
      sugEl.style.display = 'block';
    }
    function _incSelectHost(hostname, owner) {
      document.getElementById('inc_hostname').value = hostname;
      document.getElementById('inc_analyst').value = owner || '';
      document.getElementById('inc_host_suggestions').style.display = 'none';
    }
    // 외부 클릭 시 닫기
    document.addEventListener('click', e => {
      const sugEl = document.getElementById('inc_host_suggestions');
      if (sugEl && !sugEl.contains(e.target) && e.target.id !== 'inc_hostname') sugEl.style.display = 'none';
    });

    // ── Asset Collection Board ────────────────────────────────────────────────
    let currentAssetTab = 'fleet';

    function switchAssetTab(tab) {
      currentAssetTab = tab;
      ['fleet', 'zabbix', 'trivy', 'mine'].forEach(t => {
        const sec = document.getElementById(`assets_${t}_section`);
        const btn = document.getElementById(`asset_tab_${t}`);
        if (sec) sec.classList.toggle('hidden', t !== tab);
        if (btn) btn.classList.toggle('active', t === tab);
      });
      if (tab === 'mine') renderMyServers();
      if (tab === 'trivy') loadRiskMatrix();
    }

    /* ⭐ 내 서버: assigned_servers(호스트명) 또는 owner==display_name 인 자산만 모아 렌더 */
    function renderMyServers() {
      const containerEl = document.getElementById('mine_table');
      const countEl = document.getElementById('mine_search_count');
      if (!containerEl) return;
      const assigned = new Set((_currentProfile.assigned_servers || []).map(s => String(s).toLowerCase()));
      const myName = (_currentProfile.display_name || '').trim().toLowerCase();
      const matches = h => {
        if (assigned.has(String(h.hostname || '').toLowerCase())) return true;
        if (myName && String(h.owner || '').trim().toLowerCase() === myName) return true;
        return false;
      };
      const fleetHosts = (_assetCache.fleet || []).filter(matches);
      const zabbixHosts = (_assetCache.zabbix || []).filter(matches);
      const total = fleetHosts.length + zabbixHosts.length;
      if (countEl) countEl.textContent = total ? `${total}` : '';
      if (!total) {
        containerEl.innerHTML = `<span class=\"empty\">${tt('dash.assets.mine.empty', '담당 자산이 없습니다. 계정 메뉴 → 프로필 편집에서 담당 서버를 등록하세요.')}</span>`;
        return;
      }
      const vulnBanner = _myServersVulnBanner();
      const groupBy = document.getElementById('mine_group_by')?.value || 'category';
      if (groupBy === 'none') {
        containerEl.innerHTML = vulnBanner + _renderMineTables(fleetHosts, zabbixHosts);
        return;
      }
      const undef = tt('dash.assets.mine.group.none', '미지정');
      const keyOf = (h, kind) => {
        if (groupBy === 'team') return (h.team || '').trim() || undef;
        if (groupBy === 'importance') return (h.importance || '').trim() || undef;
        if (groupBy === 'status') return (h.status || '').trim() || undef;
        if (kind === 'fleet') return tt('dash.assets.tab.fleet', 'PC 자산 (Fleet)');
        return (h.category || '').trim() || tt('dash.assets.mine.group.uncategorized', '미분류');
      };
      const groups = {};
      fleetHosts.forEach(h => { const k = keyOf(h, 'fleet'); (groups[k] = groups[k] || { fleet: [], zabbix: [] }).fleet.push(h); });
      zabbixHosts.forEach(h => { const k = keyOf(h, 'zabbix'); (groups[k] = groups[k] || { fleet: [], zabbix: [] }).zabbix.push(h); });
      const names = Object.keys(groups).sort((a, b) => a.localeCompare(b, 'ko'));
      containerEl.innerHTML = vulnBanner + names.map(name => {
        const g = groups[name];
        const cnt = g.fleet.length + g.zabbix.length;
        return `<details open style=\"margin:8px 0;border:1px solid #1e293b;border-radius:8px;overflow:hidden\">
          <summary style=\"cursor:pointer;padding:8px 12px;background:#0f172a;font-weight:600;color:#e2e8f0\">${escapeHtml(name)} <span style=\"color:#64748b;font-weight:400\">(${cnt})</span></summary>
          <div style=\"padding:8px 12px\">${_renderMineTables(g.fleet, g.zabbix)}</div>
        </details>`;
      }).join('');
    }
    window.renderMyServers = renderMyServers;

    /* 내 서버 렌더 헬퍼: fleet/zabbix 컬럼이 달라 각각의 테이블 렌더러로 그려 합칩니다. */
    function _renderMineTables(fleetHosts, zabbixHosts) {
      let html = '';
      if (fleetHosts.length) {
        html += `<div class=\"subtext\" style=\"margin:4px 0\">🖥️ ${tt('dash.assets.tab.fleet','PC 자산 (Fleet)')} (${fleetHosts.length})</div>`;
        const wrap = document.createElement('div');
        renderFleetTable(fleetHosts, wrap);
        html += wrap.innerHTML;
      }
      if (zabbixHosts.length) {
        html += `<div class=\"subtext\" style=\"margin:12px 0 4px\">🖧 ${tt('dash.assets.tab.zabbix','서버 자산 (Zabbix)')} (${zabbixHosts.length})</div>`;
        const wrap = document.createElement('div');
        renderZabbixTable(zabbixHosts, wrap);
        html += wrap.innerHTML;
      }
      return html;
    }

    const FLEET_URL = '__FLEET_UI_URL__';
    const ZABBIX_URL = '__ZABBIX_UI_URL__';
    const WAZUH_URL = '__WAZUH_UI_URL__';

    /* hostname → 담당자 조회 (Fleet + Zabbix 캐시에서) */
    function _ownerForHost(hostname) {
      const allHosts = [...(_assetCache.fleet || []), ...(_assetCache.zabbix || [])];
      const found = allHosts.find(h => h.hostname === hostname);
      if (!found) return '-';
      return [found.owner, found.team].filter(Boolean).join(' / ') || '-';
    }
    /* hostname → 담당자/팀/예외 전체 데이터 */
    function _getOwnerData(hostname) {
      const allHosts = [...(_assetCache.fleet || []), ...(_assetCache.zabbix || [])];
      const found = allHosts.find(h => h.hostname === hostname);
      return found ? { owner: found.owner || '', team: found.team || '', exception_until: found.exception_until || '', exception_reason: found.exception_reason || '' } : { owner: '', team: '', exception_until: '', exception_reason: '' };
    }

    function renderFleetTable(hosts, containerEl) {
      if (!hosts.length) { containerEl.innerHTML = `<div class=\"empty\">${tt('dash.dyn.empty.fleet', 'Fleet에서 수집된 PC 자산이 없습니다.')}</div>`; return; }
      const rows = hosts.map(h => {
        const statusCls = h.status === 'online' ? 'online' : h.status === 'offline' ? 'offline' : 'unknown';
        const fleetLink = FLEET_URL ? `<a href=\"${escapeHtml(FLEET_URL)}/hosts?query=${encodeURIComponent(h.hostname)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#6ee7b7;font-size:12px;\">Fleet ↗</a>` : '';
        const ownerLabel = [h.owner, h.team].filter(Boolean).join(' / ') || '-';
        const ownerStr = `<span style=\"color:#a3e635;font-size:12px\">${escapeHtml(ownerLabel)}</span>
          <button onclick=\"openOwnerModal('${escapeHtml(h.hostname)}','${escapeHtml(h.owner||'')}','${escapeHtml(h.team||'')}','','pc','')\"
            style=\"margin-left:6px;padding:2px 6px;font-size:11px;border-radius:4px;background:#1e3a5f;color:#93c5fd;border:1px solid #334155;cursor:pointer;\">✏️</button>`;
        return `<tr>
          <td><strong>${escapeHtml(h.hostname)}</strong>${fleetLink ? '<br>' + fleetLink : ''}</td>
          <td><span style=\"background:#0d2137;color:#6ee7b7;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;\">🖥️ PC</span></td>
          <td>${escapeHtml(h.platform)}</td>
          <td>${escapeHtml(h.primary_ip)}</td>
          <td><span class=\"badge ${statusCls}\">${escapeHtml(h.status)}</span></td>
          <td>${escapeHtml(h.risk_score)}</td>
          <td>${escapeHtml(formatTime(h.last_seen_at))}</td>
          <td>${ownerStr}</td>
          <td><button onclick=\"openAuditModal('${escapeHtml(h.hostname)}')\" style=\"font-size:11px;padding:2px 7px;background:#1e293b;border:1px solid #334155;border-radius:4px;color:#94a3b8;cursor:pointer\">${tt('dash.dyn.history_btn','📋 이력')}</button></td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#0f2035;\">
          <th style=\"padding:8px;color:#6ee7b7\">${tt('dash.dyn.lbl.hostname','호스트명')}</th>
          <th style=\"padding:8px;color:#6ee7b7\">${tt('dash.dyn.lbl.type','유형')}</th>
          <th style=\"padding:8px;color:#93c5fd\">${tt('dash.dyn.lbl.platform','플랫폼')}</th>
          <th style=\"padding:8px;color:#93c5fd\">IP</th>
          <th style=\"padding:8px;color:#93c5fd\">${tt('dash.dyn.lbl.status','상태')}</th>
          <th style=\"padding:8px;color:#93c5fd\">${tt('dash.dyn.lbl.risk','리스크')}</th>
          <th style=\"padding:8px;color:#93c5fd\">${tt('dash.dyn.lbl.last_seen','마지막 확인')}</th>
          <th style=\"padding:8px;color:#a3e635\">${tt('dash.dyn.lbl.owner_team','담당자 / 팀')}</th>
          <th style=\"padding:8px;color:#94a3b8\">${tt('dash.dyn.lbl.history','이력')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function renderZabbixTable(hosts, containerEl) {
      if (!hosts.length) { containerEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.zabbix', 'Zabbix에서 수집된 서버 자산이 없습니다.') + '</div>'; return; }
      const showImp = assetColumnPrefs.show_importance !== false;
      const showIsms = assetColumnPrefs.show_isms_control !== false;
      const showIso = assetColumnPrefs.show_iso27001_control !== false;
      const impColor = { '\uc0c1': '#fca5a5', '\uc911': '#fde68a', '\ud558': '#86efac' };
      const impLabel = { '\uc0c1': tt('dash.dyn.imp.high','\uc0c1'), '\uc911': tt('dash.dyn.imp.mid','\uc911'), '\ud558': tt('dash.dyn.imp.low','\ud558') };
      const rows = hosts.map(h => {
        const statusCls = h.status === 'online' ? 'online' : h.status === 'offline' ? 'offline' : 'unknown';
        const zabbixLink = ZABBIX_URL ? `<a href=\"${escapeHtml(ZABBIX_URL)}/zabbix.php?action=host.list&filter_set=1&filter_host=${encodeURIComponent(h.hostname)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#7dd3fc;font-size:12px;\">Zabbix ↗</a>` : '';
        const metricStr = h.latest_metric ? `${escapeHtml(h.latest_metric)}: ${escapeHtml(h.latest_value || '-')}` : '-';
        const impBadge = h.importance ? `<span style=\"background:#1e293b;color:${impColor[h.importance]||'#94a3b8'};padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700\">${escapeHtml(impLabel[h.importance]||h.importance)}</span>` : '-';
        const ownerLabel = [h.owner, h.team].filter(Boolean).join(' / ') || '-';
        const ownerStr = `<span style=\"color:#a3e635;font-size:12px\">${escapeHtml(ownerLabel)}</span>
          <button onclick=\"openOwnerModal('${escapeHtml(h.hostname)}','${escapeHtml(h.owner||'')}','${escapeHtml(h.team||'')}','${escapeHtml(h.category||'')}','server','','','${escapeHtml(h.importance||'')}')\"
            style=\"margin-left:6px;padding:2px 6px;font-size:11px;border-radius:4px;background:#1e3a5f;color:#93c5fd;border:1px solid #334155;cursor:pointer;\">✏️</button>`;
        return `<tr>
          <td><strong>${escapeHtml(h.hostname)}</strong>${zabbixLink ? '<br>' + zabbixLink : ''}</td>
          <td style=\"font-size:12px\">${escapeHtml(h.category || '-')}</td>
          ${showImp ? `<td>${impBadge}</td>` : ''}
          ${showIsms ? `<td style=\"font-size:11px;color:#7dd3fc\">${escapeHtml(h.isms_control || '-')}</td>` : ''}
          ${showIso ? `<td style=\"font-size:11px;color:#a78bfa\">${escapeHtml(h.iso27001_control || '-')}</td>` : ''}
          <td>${escapeHtml(h.primary_ip)}</td>
          <td><span class=\"badge ${statusCls}\">${escapeHtml(h.status)}</span></td>
          <td style=\"font-size:12px;color:#94a3b8\">${metricStr}</td>
          <td>${ownerStr}</td>
          <td><button onclick=\"openAuditModal('${escapeHtml(h.hostname)}')\" style=\"font-size:11px;padding:2px 7px;background:#1e293b;border:1px solid #334155;border-radius:4px;color:#94a3b8;cursor:pointer\">${tt('dash.dyn.history_btn','📋 이력')}</button></td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#0f2035;\">
          <th style=\"padding:8px;color:#7dd3fc\">${tt('dash.dyn.lbl.hostname','호스트명')}</th>
          <th style=\"padding:8px;color:#7dd3fc\">${tt('dash.dyn.lbl.category','분류')}</th>
          ${showImp ? '<th style=\"padding:8px;color:#fde68a\">' + tt('dash.dyn.lbl.importance','중요도') + '</th>' : ''}
          ${showIsms ? '<th style=\"padding:8px;color:#7dd3fc\">' + tt('dash.dyn.lbl.isms_control','ISMS-P 통제') + '</th>' : ''}
          ${showIso ? '<th style=\"padding:8px;color:#a78bfa\">ISO 27001</th>' : ''}
          <th style=\"padding:8px;color:#93c5fd\">IP</th>
          <th style=\"padding:8px;color:#93c5fd\">${tt('dash.dyn.lbl.status','상태')}</th>
          <th style=\"padding:8px;color:#94a3b8\">${tt('dash.dyn.lbl.latest_metric','최근 메트릭')}</th>
          <th style=\"padding:8px;color:#a3e635\">${tt('dash.dyn.lbl.owner_team','담당자 / 팀')}</th>
          <th style=\"padding:8px;color:#94a3b8\">${tt('dash.dyn.lbl.history','이력')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function renderTrivyTable(rows, containerEl) {
      if (!rows.length) { containerEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.trivy_empty', 'Trivy 취약점 데이터가 없습니다.') + '</div>'; return; }
      const sevColor = { critical:'#fca5a5', high:'#fdba74', medium:'#fde68a', low:'#86efac', info:'#94a3b8' };
      const tableRows = rows.map(r => {
        const planText = r.action_plan ? escapeHtml(r.action_plan).substring(0, 30) + (r.action_plan.length > 30 ? '…' : '') : '';
        let planCell;
        if (r.has_vuln_plans) {
          const cnt = (r.vuln_plans_count || 0) + (r.vuln_exceptions_count || 0);
          planCell = `<span style=\"color:#fbbf24;font-size:12px;font-weight:600\">${tt('dash.dyn.cve_plan_detail','📋 CVE별 상세 계획')}</span>
            <br><span style=\"color:#94a3b8;font-size:11px\">${tt('dash.dyn.plan_count','계획')} ${r.vuln_plans_count||0} · ${tt('dash.dyn.exception_count','예외')} ${r.vuln_exceptions_count||0}</span>
            <br><button onclick=\"showVulnPlansNotice('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}',${cnt})\" style=\"font-size:10px;padding:1px 6px;background:#3b1f00;border:1px solid #78350f;border-radius:3px;color:#fbbf24;cursor:pointer;margin-top:2px\">${tt('dash.dyn.notice_btn','ℹ️ 안내')}</button>`;
        } else if (r.action_plan) {
          planCell = `<span style=\"color:#a3e635;font-size:12px\" title=\"${escapeHtml(r.action_plan)}\">${planText}</span>${r.action_target_date ? '<br><span style=\"color:#64748b;font-size:11px\">~' + escapeHtml(r.action_target_date) + '</span>' : ''}<br><button onclick=\"openPlanModal('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}')\" style=\"font-size:10px;padding:1px 6px;background:#1e3a5f;border:1px solid #334155;border-radius:3px;color:#7dd3fc;cursor:pointer;margin-top:2px\">${tt('dash.dyn.edit_btn','✏️ 수정')}</button>`;
        } else {
          planCell = `<button onclick=\"openPlanModal('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}')\" style=\"font-size:11px;padding:2px 7px;background:#1e3a5f;border:1px solid #334155;border-radius:4px;color:#7dd3fc;cursor:pointer\">${tt('dash.dyn.add_plan_btn','+ 계획 추가')}</button>`;
        }
        const ownerLabel = _ownerForHost(r.hostname);
        const ownerData = _getOwnerData(r.hostname);
        const exUntil = r.exception_until || ownerData.exception_until || '';
        const exReason = ownerData.exception_reason || '';
        let exCell;
        if (r.has_vuln_exceptions) {
          const cnt = (r.vuln_plans_count || 0) + (r.vuln_exceptions_count || 0);
          exCell = `<span style=\"color:#fbbf24;font-size:12px;font-weight:600\">${tt('dash.dyn.cve_exception_detail','📋 CVE별 상세 예외')}</span>
            <br><span style=\"color:#94a3b8;font-size:11px\">${tt('dash.dyn.exception_count','예외')} ${r.vuln_exceptions_count||0} · ${tt('dash.dyn.plan_count','계획')} ${r.vuln_plans_count||0}</span>
            <br><button onclick=\"showVulnExceptionsNotice('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}',${cnt})\" style=\"font-size:10px;padding:1px 6px;background:#3b1f00;border:1px solid #78350f;border-radius:3px;color:#fbbf24;cursor:pointer;margin-top:2px\">${tt('dash.dyn.notice_btn','ℹ️ 안내')}</button>`;
        } else if (exUntil) {
          exCell = `<span style=\"color:#fde68a;font-size:12px\">~${escapeHtml(exUntil)}</span>${exReason ? '<br><span style=\"color:#94a3b8;font-size:11px\" title=\"'+escapeHtml(exReason)+'\">'+escapeHtml(exReason.substring(0,20))+(exReason.length>20?'…':'')+'</span>' : ''}<br><button onclick=\"openOwnerModal('${escapeHtml(r.hostname)}','${escapeHtml(ownerData.owner||'')}','${escapeHtml(ownerData.team||'')}','','trivy','${escapeHtml(exUntil)}','${escapeHtml(exReason).replace(/'/g,"\\\\'")}')\" style=\"font-size:10px;padding:1px 6px;background:#3b1f00;border:1px solid #78350f;border-radius:3px;color:#fbbf24;cursor:pointer;margin-top:2px\">${tt('dash.dyn.edit_btn','✏️ 수정')}</button>`;
        } else {
          exCell = `<button onclick=\"openOwnerModal('${escapeHtml(r.hostname)}','${escapeHtml(ownerData.owner||'')}','${escapeHtml(ownerData.team||'')}','','trivy','','')\" style=\"font-size:11px;padding:2px 7px;background:#3b1f00;border:1px solid #78350f;border-radius:4px;color:#fbbf24;cursor:pointer\">${tt('dash.dyn.add_exception_btn','+ 예외 설정')}</button>`;
        }
        const totalCell = r.total > 0
          ? `<button onclick=\"openVulnListModal('${escapeHtml(r.host_id)}')\" title=\"${tt('dash.dyn.view_vuln_detail','취약점 상세 보기')}\" style=\"background:#1e3a5f;border:1px solid #334155;color:#7dd3fc;border-radius:6px;padding:3px 10px;cursor:pointer;font-size:13px;font-weight:700\">${r.total} ${tt('dash.dyn.cases_unit','건 ↗')}</button>`
          : `<span style=\"color:#64748b\">${r.total}</span>`;
        return `<tr>
          <td><strong>${escapeHtml(r.hostname)}</strong><br><span style=\"color:#64748b;font-size:11px\">${escapeHtml(r.host_id)}</span></td>
          <td style=\"color:#a3e635;font-size:12px\">${escapeHtml(ownerLabel)}</td>
          <td style=\"color:${sevColor.critical};font-weight:700;text-align:center\">${r.critical}</td>
          <td style=\"color:${sevColor.high};font-weight:700;text-align:center\">${r.high}</td>
          <td style=\"color:${sevColor.medium};text-align:center\">${r.medium}</td>
          <td style=\"color:${sevColor.low};text-align:center\">${r.low}</td>
          <td style=\"text-align:center\">${totalCell}</td>
          <td style=\"font-size:12px;color:#94a3b8\">${escapeHtml(r.latest_cve || '-')}</td>
          <td style=\"font-size:12px;color:#64748b\">${escapeHtml(formatTime(r.latest_detected_at))}</td>
          <td style=\"min-width:130px\">${planCell}</td>
          <td style=\"min-width:110px\">${exCell}</td>
          <td style=\"text-align:center\"><button onclick=\"openAuditModal('${escapeHtml(r.hostname)}')\" style=\"font-size:10px;padding:2px 6px;background:#1e293b;border:1px solid #334155;border-radius:3px;color:#94a3b8;cursor:pointer\" title=\"${tt('dash.dyn.edit_history','수정 이력')}\">📋</button></td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#0f2035;\">
          <th style=\"padding:8px;color:#fdba74\">${tt('dash.dyn.lbl.host','호스트')}</th>
          <th style=\"padding:8px;color:#a3e635\">${tt('dash.dyn.lbl.owner','담당자')}</th>
          <th style=\"padding:8px;color:#fca5a5\">Critical</th>
          <th style=\"padding:8px;color:#fdba74\">High</th>
          <th style=\"padding:8px;color:#fde68a\">Medium</th>
          <th style=\"padding:8px;color:#86efac\">Low</th>
          <th style=\"padding:8px;color:#93c5fd\">${tt('dash.dyn.lbl.total','합계')}</th>
          <th style=\"padding:8px;color:#94a3b8\">${tt('dash.dyn.lbl.latest_cve','최근 CVE')}</th>
          <th style=\"padding:8px;color:#64748b\">${tt('dash.dyn.lbl.detected_date','탐지일')}</th>
          <th style=\"padding:8px;color:#a3e635\">${tt('dash.dyn.lbl.action_plan','조치 계획')}</th>
          <th style=\"padding:8px;color:#fbbf24\">${tt('dash.dyn.lbl.action_exception','조치 예외')}</th>
          <th style=\"padding:8px;color:#94a3b8\">${tt('dash.dyn.lbl.history','이력')}</th>
        </tr></thead>
        <tbody>${tableRows}</tbody>
      </table>`;
    }

    // 조치계획 모달
    let _planHostId = null, _planHostname = null;
    function openPlanModal(hostId, hostname) {
      _planHostId = hostId; _planHostname = hostname;
      document.getElementById('plan_modal_title').textContent = hostname + ' ' + tt('dash.dyn.col.plan','조치 계획');
      document.getElementById('plan_text').value = '';
      document.getElementById('plan_target_date').value = '';
      document.getElementById('plan_updated_by').value = '';
      fetch(`/assets/plans/${encodeURIComponent(hostId)}`).then(r=>r.json()).then(d=>{
        document.getElementById('plan_text').value = d.text || '';
        document.getElementById('plan_target_date').value = d.target_date || '';
        document.getElementById('plan_updated_by').value = d.updated_by || '';
      }).catch(()=>{});
      document.getElementById('plan_modal').style.display = 'flex';
    }
    function closePlanModal() { document.getElementById('plan_modal').style.display = 'none'; }

    /* ── 호스트별 취약점 리스트 모달 ──────────────────────────────────────── */
    function _renderVulnListBody(hostRow) {
      const sevColor = { critical:'#fca5a5', high:'#fdba74', medium:'#fde68a', low:'#86efac', info:'#94a3b8' };
      const showRisk = _canAssessRisk();  // 위험등급 열은 어드민/보안만
      const vulns = hostRow.vulns || [];
      // 호스트 단위 계획/예외 (CVE별 vuln_actions와 별개)
      const hostPlan = (hostRow.action_plan || '').trim();
      const hostPlanDate = (hostRow.action_target_date || '').trim();
      const hostPlanBy = (hostRow.action_updated_by || '').trim();
      const hostEx = (hostRow.exception_until || '').trim();
      const hasHostPlan = !!hostPlan;
      const hasHostEx = !!hostEx;
      let hostBanner = '';
      if (hasHostPlan || hasHostEx) {
        const parts = [];
        if (hasHostPlan) {
          parts.push(`<div style=\"flex:1;min-width:240px\">
              <div style=\"color:#86efac;font-size:11px;font-weight:600;margin-bottom:3px\">${tt('dash.dyn.host_plan_title','📋 호스트 단위 조치 계획')}</div>
              <div style=\"color:#e2e8f0;font-size:13px\">${escapeHtml(hostPlan)}</div>
              <div style=\"color:#64748b;font-size:11px;margin-top:2px\">${hostPlanDate?tt('dash.dyn.target_date_label','목표일')+' '+escapeHtml(hostPlanDate):''}${hostPlanBy?(hostPlanDate?' · ':'')+tt('dash.dyn.author_label','작성자')+' '+escapeHtml(hostPlanBy):''}</div>
            </div>`);
        }
        if (hasHostEx) {
          parts.push(`<div style=\"flex:1;min-width:200px\">
              <div style=\"color:#fbbf24;font-size:11px;font-weight:600;margin-bottom:3px\">${tt('dash.dyn.host_exception_title','⚠️ 호스트 단위 조치 예외')}</div>
              <div style=\"color:#e2e8f0;font-size:13px\">~${escapeHtml(hostEx)}${tt('dash.dyn.until_suffix',' 까지')}</div>
            </div>`);
        }
        hostBanner = `<div style=\"background:#0f2035;border:1px solid #1e3a5f;border-radius:6px;padding:10px 14px;margin-bottom:12px;display:flex;flex-wrap:wrap;gap:18px\">
          ${parts.join('')}
          <div style=\"width:100%;color:#64748b;font-size:11px;margin-top:4px\">${tt('dash.dyn.cve_priority_note','※ 아래 CVE별 계획/예외가 설정된 경우 해당 CVE에 한해 우선 적용됩니다.')}</div>
        </div>`;
      }
      if (!vulns.length) {
        return hostBanner + '<div style=\"color:#64748b;text-align:center;padding:20px\">' + tt('dash.dyn.empty.vulns','취약점이 없습니다.') + '</div>';
      }
      const rows = vulns.map(v => {
        const planLabel = v.plan_text
          ? `<span style=\"color:#a3e635;font-size:12px\" title=\"${escapeHtml(v.plan_text)}\">${escapeHtml(v.plan_text.substring(0,30))}${v.plan_text.length>30?'…':''}</span>${v.plan_target_date?'<br><span style=\"color:#64748b;font-size:11px\">~'+escapeHtml(v.plan_target_date)+'</span>':''}`
          : (hasHostPlan
              ? `<span style=\"color:#86efac;font-size:11px;font-style:italic\">${tt('dash.dyn.host_level_applied','호스트 단위 적용')}</span>${hostPlanDate?'<br><span style=\"color:#64748b;font-size:11px\">~'+escapeHtml(hostPlanDate)+'</span>':''}`
              : '<span style=\"color:#64748b;font-size:11px\">' + tt('dash.dyn.not_set','미설정') + '</span>');
        const exLabel = v.exception_until
          ? `<span style=\"color:#fbbf24;font-size:12px\">~${escapeHtml(v.exception_until)}</span>${v.exception_reason?'<br><span style=\"color:#94a3b8;font-size:11px\" title=\"'+escapeHtml(v.exception_reason)+'\">'+escapeHtml(v.exception_reason.substring(0,24))+(v.exception_reason.length>24?'…':'')+'</span>':''}`
          : (hasHostEx
              ? `<span style=\"color:#fbbf24;font-size:11px;font-style:italic\">${tt('dash.dyn.host_level_applied','호스트 단위 적용')}</span><br><span style=\"color:#64748b;font-size:11px\">~${escapeHtml(hostEx)}</span>`
              : '<span style=\"color:#64748b;font-size:11px\">' + tt('dash.dyn.none','없음') + '</span>');
        const versionStr = v.installed_version
          ? `${escapeHtml(v.installed_version)}${v.fixed_version?' → <span style=\"color:#86efac\">'+escapeHtml(v.fixed_version)+'</span>':''}`
          : '-';
        const rk = (_riskSummary.map || {})[v.vuln_id];
        const riskCell = rk
          ? `${_riskBadge(rk.level, true)}${rk.assessed?'':`<div style=\"color:#64748b;font-size:9px;margin-top:2px\">${tt('dash.risk.badge_unassessed','미평가')}</div>`}`
          : `<span style=\"color:#64748b;font-size:11px\">-</span>`;
        const riskTd = showRisk
          ? `<td style=\"padding:6px 8px;text-align:center;white-space:nowrap\">${riskCell}<br><button onclick=\"openRiskModal('${escapeHtml(v.vuln_id)}')\" style=\"font-size:10px;padding:1px 6px;background:#2a1852;border:1px solid #4c1d95;border-radius:3px;color:#c4b5fd;cursor:pointer;margin-top:3px\">${tt('dash.risk.btn','🎯 평가')}</button></td>`
          : '';
        return `<tr>
          <td style=\"padding:6px 8px\"><strong style=\"color:#7dd3fc\">${escapeHtml(v.cve||'-')}</strong></td>
          <td style=\"padding:6px 8px;text-align:center\"><span style=\"color:${sevColor[v.severity]||'#94a3b8'};font-weight:700;text-transform:uppercase;font-size:11px\">${escapeHtml(v.severity)}</span></td>
          ${riskTd}
          <td style=\"padding:6px 8px;font-size:12px\">${escapeHtml(v.package_name||'-')}</td>
          <td style=\"padding:6px 8px;font-size:12px;color:#94a3b8\">${versionStr}</td>
          <td style=\"padding:6px 8px;font-size:11px;color:#64748b\">${escapeHtml(formatTime(v.detected_at))}</td>
          <td style=\"padding:6px 8px;min-width:140px\">${planLabel}<br><button onclick=\"openVulnActionModal('${escapeHtml(v.vuln_id)}','plan')\" style=\"font-size:10px;padding:1px 6px;background:#0f3a1d;border:1px solid #14532d;border-radius:3px;color:#86efac;cursor:pointer;margin-top:3px\">${tt('dash.dyn.edit_plan_btn','✏️ 조치 계획')}</button></td>
          <td style=\"padding:6px 8px;min-width:140px\">${exLabel}<br><button onclick=\"openVulnActionModal('${escapeHtml(v.vuln_id)}','exception')\" style=\"font-size:10px;padding:1px 6px;background:#3b1f00;border:1px solid #78350f;border-radius:3px;color:#fbbf24;cursor:pointer;margin-top:3px\">${tt('dash.dyn.edit_exception_btn','⚠️ 조치 예외')}</button></td>
        </tr>`;
      }).join('');
      return hostBanner + `<table style=\"width:100%;border-collapse:collapse;font-size:12px\">
        <thead><tr style=\"background:#0f2035\">
          <th style=\"padding:8px;color:#7dd3fc;text-align:left\">CVE</th>
          <th style=\"padding:8px;color:#fdba74\">${tt('dash.dyn.lbl.severity','심각도')}</th>
          ${showRisk?`<th style=\"padding:8px;color:#c4b5fd\">${tt('dash.risk.col','위험등급')}</th>`:''}
          <th style=\"padding:8px;color:#94a3b8;text-align:left\">${tt('dash.dyn.lbl.package','패키지')}</th>
          <th style=\"padding:8px;color:#94a3b8;text-align:left\">${tt('dash.dyn.lbl.install_recommend','설치 → 권장')}</th>
          <th style=\"padding:8px;color:#64748b\">${tt('dash.dyn.lbl.detected_date','탐지일')}</th>
          <th style=\"padding:8px;color:#a3e635;text-align:left\">${tt('dash.dyn.lbl.action_plan','조치 계획')}</th>
          <th style=\"padding:8px;color:#fbbf24;text-align:left\">${tt('dash.dyn.lbl.action_exception','조치 예외')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function openVulnListModal(hostId) {
      const row = (_assetCache.trivy || []).find(r => r.host_id === hostId);
      if (!row) { alert(tt('dash.dyn.host_not_found','호스트 데이터를 찾을 수 없습니다. 자산 새로고침 후 다시 시도해 주세요.')); return; }
      document.getElementById('vuln_list_modal_title').textContent = `🛡️ ${row.hostname}${tt('dash.dyn.vuln_count_suffix',' — 취약점 ')}${row.total}${tt('dash.dyn.unit_count','건')}`;
      document.getElementById('vuln_list_modal_subtitle').textContent =
        `Critical ${row.critical} · High ${row.high} · Medium ${row.medium} · Low ${row.low}`;
      document.getElementById('vuln_list_modal_body').innerHTML = _renderVulnListBody(row);
      document.getElementById('vuln_list_modal').style.display = 'flex';
    }
    function closeVulnListModal() { document.getElementById('vuln_list_modal').style.display = 'none'; }

    /* ── 호스트 단위 조치 계획 안내 (CVE별 상세 계획 존재 시) ──────────── */
    function showVulnPlansNotice(hostId, hostname, count) {
      document.getElementById('vuln_plans_notice_body').innerHTML =
        `<div style=\"margin-bottom:10px\"><strong style=\"color:#fdba74\">${escapeHtml(hostname)}</strong> 호스트에는 이미 <strong style=\"color:#a3e635\">CVE별 상세 조치 계획/예외</strong>가 ${count}건 설정되어 있습니다.</div>
         <div style=\"color:#94a3b8\">호스트 단위 일괄 계획 대신 <strong style=\"color:#7dd3fc\">합계 탭</strong>(예: <span style=\"background:#1e3a5f;color:#7dd3fc;padding:1px 8px;border-radius:4px\">N 건 ↗</span> 버튼)에서 각 CVE별 계획을 확인·수정해 주세요.</div>`;
      const openBtn = document.getElementById('vuln_plans_notice_open_list');
      openBtn.onclick = () => { closeVulnPlansNotice(); openVulnListModal(hostId); };
      document.getElementById('vuln_plans_notice_modal').style.display = 'flex';
    }
    function closeVulnPlansNotice() { document.getElementById('vuln_plans_notice_modal').style.display = 'none'; }

    /* ── 호스트 단위 조치 예외 안내 (CVE별 상세 예외 존재 시) ──────────── */
    function showVulnExceptionsNotice(hostId, hostname, count) {
      document.getElementById('vuln_plans_notice_body').innerHTML =
        `<div style=\"margin-bottom:10px\"><strong style=\"color:#fdba74\">${escapeHtml(hostname)}</strong> 호스트에는 이미 <strong style=\"color:#fbbf24\">CVE별 상세 조치 예외</strong>가 설정되어 있습니다. (총 ${count}건의 CVE별 계획/예외)</div>
         <div style=\"color:#94a3b8\">호스트 단위 일괄 예외 대신 <strong style=\"color:#7dd3fc\">합계 탭</strong>(예: <span style=\"background:#1e3a5f;color:#7dd3fc;padding:1px 8px;border-radius:4px\">N 건 ↗</span> 버튼)에서 각 CVE별 예외를 확인·수정해 주세요.</div>`;
      const openBtn = document.getElementById('vuln_plans_notice_open_list');
      openBtn.onclick = () => { closeVulnPlansNotice(); openVulnListModal(hostId); };
      document.getElementById('vuln_plans_notice_modal').style.display = 'flex';
    }

    /* ── PDCA Do(조치) 항목 상세 모달 ─────────────────────────────────────── */
    function openPdcaDoModal() {
      const items = window.__pdcaPending || [];
      const ps = window.__pdcaPendingSources || {};
      const subtitleEl = document.getElementById('pdca_do_modal_subtitle');
      const bodyEl = document.getElementById('pdca_do_modal_body');
      if (!bodyEl) return;
      const overdue = items.filter(i => i.overdue).length;
      subtitleEl.innerHTML = tt('dash.dyn.pdca.do_subtitle','총 {n}건 조치 필요 (기한 초과 {o}건) · ').replace('{n}','<strong style=\"color:#f59e0b\">'+items.length+'</strong>').replace('{o}','<strong style=\"color:#fca5a5\">'+overdue+'</strong>')
        + `<span style=\"color:#7dd3fc\">${tt('dash.dyn.pdca.control','통제')} ${ps.control_check||0}</span> ·
        <span style=\"color:#fdba74\">Trivy ${ps.trivy||0}</span> ·
        <span style=\"color:#fca5a5\">Alert ${ps.alert||0}</span>
        <a href=\"/compliance/pdca/pending.csv\" download style=\"margin-left:12px;background:#0c2a4a;border:1px solid #1e3a5f;color:#7dd3fc;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:600;text-decoration:none\">📥 CSV</a>`;
      if (items.length === 0) {
        bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#64748b;padding:24px;text-align:center\">' + tt('dash.dyn.pdca.do_no_items','조치가 필요한 항목이 없습니다. 🎉') + '</div>';
      } else {
        const sourceBadge = (s) => {
          if (s === 'trivy') return '<span style=\"background:#3b1f00;color:#fdba74;padding:2px 6px;border-radius:4px;font-size:10px\">🛡️ Trivy</span>';
          if (s === 'alert') return '<span style=\"background:#450a0a;color:#fca5a5;padding:2px 6px;border-radius:4px;font-size:10px\">🚨 Alert</span>';
          return '<span style=\"background:#0c2a4a;color:#7dd3fc;padding:2px 6px;border-radius:4px;font-size:10px\">' + tt('dash.dyn.pdca.control_badge','📋 통제') + '</span>';
        };
        bodyEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
          <thead><tr style=\"color:#94a3b8;border-bottom:1px solid #334155\">
            <th style=\"text-align:center;padding:6px 8px\">${tt('dash.dyn.pdca.source','출처')}</th>
            <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.control_id','통제 ID')}</th>
            <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.target','대상')}</th>
            <th style=\"text-align:center;padding:6px 8px\">${tt('dash.dyn.lbl.status','상태')}</th>
            <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.lbl.owner','담당자')}</th>
            <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.due','조치 기한')}</th>
            <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.note','비고')}</th>
          </tr></thead><tbody>`
          + items.map(i => {
            const statusBadge = i.status === 'fail'
              ? '<span style=\"background:#450a0a;color:#fca5a5;padding:2px 8px;border-radius:999px;font-size:11px\">Fail</span>'
              : '<span style=\"background:#451a03;color:#fbbf24;padding:2px 8px;border-radius:999px;font-size:11px\">Warning</span>';
            const due = i.remediation_due_at ? new Date(i.remediation_due_at).toLocaleDateString('ko-KR') : '-';
            const overdueFlag = i.overdue ? ' 🔴' : '';
            return `<tr style=\"border-bottom:1px solid #1e293b\">
              <td style=\"text-align:center;padding:6px 8px\">${sourceBadge(i.source)}</td>
              <td style=\"padding:6px 8px;color:#38bdf8;font-weight:600\">${escapeHtml(i.control_id)}</td>
              <td style=\"padding:6px 8px;color:#e2e8f0\">${escapeHtml(i.entity_type)}:${escapeHtml(i.entity_id)}</td>
              <td style=\"text-align:center;padding:6px 8px\">${statusBadge}</td>
              <td style=\"padding:6px 8px;color:#94a3b8\">${escapeHtml(i.owner) || '-'}</td>
              <td style=\"padding:6px 8px;color:#e2e8f0\">${due}${overdueFlag}</td>
              <td style=\"padding:6px 8px;color:#64748b\">${escapeHtml(i.note) || ''}</td>
            </tr>`;
          }).join('')
          + '</tbody></table>';
      }
      document.getElementById('pdca_do_modal').style.display = 'flex';
    }
    function closePdcaDoModal() { document.getElementById('pdca_do_modal').style.display = 'none'; }

    /* ── 취약점별 조치 계획 / 조치 예외 모달 ─────────────────────────────── */
    let _vulnActionId = null, _vulnActionMode = 'plan', _vulnActionHostId = null;
    function openVulnActionModal(vulnId, mode) {
      _vulnActionId = vulnId; _vulnActionMode = mode;
      // 현재 보고 있던 host row 찾기 (모달 닫혀도 list 갱신용)
      let foundVuln = null, foundHost = null;
      for (const row of (_assetCache.trivy || [])) {
        const v = (row.vulns || []).find(x => x.vuln_id === vulnId);
        if (v) { foundVuln = v; foundHost = row; break; }
      }
      _vulnActionHostId = foundHost ? foundHost.host_id : null;
      const meta = foundVuln
        ? `<div><strong style=\"color:#7dd3fc\">${escapeHtml(foundVuln.cve||vulnId)}</strong> · <span style=\"color:#fdba74;text-transform:uppercase\">${escapeHtml(foundVuln.severity)}</span></div>
           <div style=\"margin-top:3px\">${escapeHtml(foundVuln.package_name||'-')} ${foundVuln.installed_version?'('+escapeHtml(foundVuln.installed_version)+')':''} ${foundVuln.fixed_version?'→ <span style=\"color:#86efac\">'+escapeHtml(foundVuln.fixed_version)+'</span>':''}</div>
           <div style=\"margin-top:3px;color:#64748b\">호스트: ${escapeHtml(foundHost?foundHost.hostname:'-')}</div>`
        : `<div>vuln_id: ${escapeHtml(vulnId)}</div>`;
      document.getElementById('vuln_action_modal_meta').innerHTML = meta;
      document.getElementById('vuln_action_modal_status').textContent = '';
      const planSec = document.getElementById('vuln_plan_section');
      const exSec = document.getElementById('vuln_exception_section');
      const clearBtn = document.getElementById('vuln_action_modal_clear');
      if (mode === 'exception') {
        document.getElementById('vuln_action_modal_title').textContent = tt('dash.dyn.vuln_action.exception_title','⚠️ 조치 예외 설정');
        planSec.style.display = 'none';
        exSec.style.display = 'flex';
        clearBtn.style.display = (foundVuln && foundVuln.exception_until) ? 'inline-block' : 'none';
      } else {
        document.getElementById('vuln_action_modal_title').textContent = tt('dash.dyn.vuln_action.plan_title','✏️ 조치 계획 작성');
        planSec.style.display = 'flex';
        exSec.style.display = 'none';
        clearBtn.style.display = 'none';
      }
      // 기존 값 채우기
      fetch(`/vulnerabilities/${encodeURIComponent(vulnId)}/action`).then(r => r.ok?r.json():null).then(d => {
        if (!d) return;
        document.getElementById('vuln_plan_text').value = d.plan_text || '';
        document.getElementById('vuln_plan_target_date').value = d.plan_target_date || '';
        document.getElementById('vuln_plan_updated_by').value = d.plan_updated_by || '';
        document.getElementById('vuln_exception_until').value = d.exception_until || '';
        document.getElementById('vuln_exception_reason').value = d.exception_reason || '';
        document.getElementById('vuln_exception_updated_by').value = d.exception_updated_by || '';
      }).catch(()=>{});
      document.getElementById('vuln_action_modal').style.display = 'flex';
    }
    function closeVulnActionModal() { document.getElementById('vuln_action_modal').style.display = 'none'; }

    /* ── 🎯 위험성 평가 (R-4) ─────────────────────────────────────────────── */
    const RISK_LEVEL_COLORS = { '매우높음':'#dc2626', '높음':'#ea580c', '중간':'#d97706', '낮음':'#16a34a' };
    let _riskSummary = { items: [], map: {}, matrix: [[0,0,0],[0,0,0],[0,0,0]], by_level: {}, total: 0, assessed: 0 };
    let _riskModalVulnId = null;

    function _riskBadge(level, small) {
      const c = RISK_LEVEL_COLORS[level] || '#64748b';
      return `<span style=\"display:inline-block;background:${c}22;border:1px solid ${c};color:${c};font-weight:700;border-radius:6px;padding:${small?'1px 7px':'2px 10px'};font-size:${small?'11px':'12px'}\">${escapeHtml(level||'-')}</span>`;
    }
    window._riskBadge = _riskBadge;

    async function loadRiskMatrix() {
      const box = document.getElementById('risk_matrix_box');
      if (!box) return;
      try {
        const res = await fetch('/vulnerabilities/risk-summary?source=trivy');
        if (!res.ok) { box.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}HTTP ${res.status}</span>`; return; }
        const data = await res.json();
        _riskSummary = data;
        _riskSummary.map = {};
        (data.items || []).forEach(it => { _riskSummary.map[it.vuln_id] = it; });
        renderRiskMatrix(data);
      } catch (e) {
        box.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
    }
    window.loadRiskMatrix = loadRiskMatrix;

    let _riskMatrixOpen = true;
    function toggleRiskMatrix() {
      _riskMatrixOpen = !_riskMatrixOpen;
      const box = document.getElementById('risk_matrix_box');
      const btn = document.getElementById('risk_matrix_toggle');
      if (box) box.style.display = _riskMatrixOpen ? '' : 'none';
      if (btn) btn.textContent = _riskMatrixOpen ? tt('dash.risk.collapse_hide','▲ 접기') : tt('dash.risk.collapse_show','▼ 펼치기');
    }
    window.toggleRiskMatrix = toggleRiskMatrix;

    /* 🎯 매트릭스 셀/칩 클릭 → 해당 버킷의 실제 취약점·호스트 목록 모달 */
    function _riskBucketRows(items) {
      if (!items.length) return `<div class=\"empty\" style=\"color:#64748b;padding:16px\">${tt('dash.dyn.empty.vulns','취약점이 없습니다.')}</div>`;
      const rows = items.map(it => `<tr>
        <td style=\"padding:6px 8px\">${_riskBadge(it.level, true)}</td>
        <td style=\"padding:6px 8px\"><strong style=\"color:#7dd3fc\">${escapeHtml(it.cve)}</strong></td>
        <td style=\"padding:6px 8px;color:#94a3b8;font-size:12px\">${escapeHtml(it.hostname)}</td>
        <td style=\"padding:6px 8px;text-align:center\"><span style=\"color:${it.severity==='critical'?'#fca5a5':'#fdba74'};text-transform:uppercase;font-size:11px\">${escapeHtml(it.severity)}</span></td>
        <td style=\"padding:6px 8px;text-align:center;font-size:11px;color:#64748b\">${it.assessed?tt('dash.risk.assessed','평가됨'):tt('dash.risk.badge_unassessed','미평가')}</td>
        <td style=\"padding:6px 8px;text-align:center\">${_canAssessRisk()?`<button onclick=\"closeRiskBucketModal();openRiskModal('${escapeHtml(it.vuln_id)}')\" style=\"font-size:10px;padding:2px 8px;background:#2a1852;border:1px solid #4c1d95;border-radius:4px;color:#c4b5fd;cursor:pointer\">${tt('dash.risk.btn','🎯 평가')}</button>`:''}</td>
      </tr>`).join('');
      return `<table style=\"width:100%;border-collapse:collapse;font-size:12px\"><thead><tr style=\"background:#0f2035\">
        <th style=\"padding:8px;color:#c4b5fd\">${tt('dash.risk.col','위험등급')}</th><th style=\"padding:8px;color:#7dd3fc;text-align:left\">CVE</th>
        <th style=\"padding:8px;color:#94a3b8;text-align:left\">${tt('dash.risk.prov.host','자산')}</th><th style=\"padding:8px;color:#fdba74\">${tt('dash.dyn.lbl.severity','심각도')}</th>
        <th style=\"padding:8px;color:#94a3b8\">${tt('dash.risk.status','상태')}</th><th style=\"padding:8px\"></th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    function _openRiskBucket(pred, title) {
      const items = (_riskSummary.items || []).filter(pred);
      document.getElementById('risk_bucket_modal_title').textContent = `${title} (${items.length})`;
      document.getElementById('risk_bucket_modal_body').innerHTML = _riskBucketRows(items);
      document.getElementById('risk_bucket_modal').style.display = 'flex';
    }
    function openRiskLevelModal(level) { _openRiskBucket(it => it.level === level, `${tt('dash.risk.bucket_title','🎯 위험 상세')} · ${level}`); }
    function openRiskCellModal(impact, likelihood) { _openRiskBucket(it => it.impact === impact && it.likelihood === likelihood, `${tt('dash.risk.bucket_title','🎯 위험 상세')} · ${_levelForScore(impact*likelihood)}`); }
    function closeRiskBucketModal() { const m=document.getElementById('risk_bucket_modal'); if(m) m.style.display='none'; }
    window.openRiskLevelModal = openRiskLevelModal;
    window.openRiskCellModal = openRiskCellModal;
    window.closeRiskBucketModal = closeRiskBucketModal;

    function _levelForScore(s) { return s>=9?'매우높음':s>=5?'높음':s>=3?'중간':'낮음'; }

    function renderRiskMatrix(data) {
      const box = document.getElementById('risk_matrix_box');
      const assessedEl = document.getElementById('risk_matrix_assessed');
      if (assessedEl) assessedEl.textContent = tt('dash.risk.assessed_of','{a}/{t} 평가 완료').replace('{a}', data.assessed||0).replace('{t}', data.total||0);
      const m = data.matrix || [[0,0,0],[0,0,0],[0,0,0]];
      const impactByRow = [3,2,1], likeByCol = [1,2,3];
      const impLabel = {3:'상',2:'중',1:'하'}, likeLabel = {1:'하',2:'중',3:'상'};
      const header = `<tr><td></td>${likeByCol.map(l=>`<td style=\"text-align:center;color:#94a3b8;font-size:12px;padding-bottom:2px\">${likeLabel[l]}</td>`).join('')}</tr>`;
      let cells = '';
      for (let r=0;r<3;r++){
        let rowCells = `<td style=\"padding:6px 8px;color:#94a3b8;font-size:12px;text-align:right;white-space:nowrap\">${impLabel[impactByRow[r]]}</td>`;
        for (let c=0;c<3;c++){
          const imp = impactByRow[r], lk = likeByCol[c];
          const lvl = _levelForScore(imp*lk);
          const col = RISK_LEVEL_COLORS[lvl];
          const n = (m[r] && m[r][c]) || 0;
          const click = n ? `onclick=\"openRiskCellModal(${imp},${lk})\"` : '';
          rowCells += `<td style=\"padding:0\"><div ${click} style=\"margin:3px;border-radius:6px;background:${col}${n?'33':'12'};border:1px solid ${col}${n?'':'44'};width:58px;min-height:52px;display:flex;flex-direction:column;align-items:center;justify-content:center;${n?'cursor:pointer':''}\">
            <div style=\"font-size:18px;font-weight:800;color:${n?col:'#334155'}\">${n}</div>
            <div style=\"font-size:9px;color:${col}aa\">${lvl}</div></div></td>`;
        }
        cells += `<tr>${rowCells}</tr>`;
      }
      const order = ['매우높음','높음','중간','낮음'];
      const chips = order.map(lv => { const n=(data.by_level&&data.by_level[lv])||0; return `<span onclick=\"${n?`openRiskLevelModal('${lv}')`:''}\" style=\"display:inline-flex;align-items:center;gap:5px;margin:0 8px 8px 0;font-size:12px;padding:4px 10px;border:1px solid ${RISK_LEVEL_COLORS[lv]}44;border-radius:8px;background:${RISK_LEVEL_COLORS[lv]}12;${n?'cursor:pointer':'opacity:.5'}\"><span style=\"width:10px;height:10px;border-radius:2px;background:${RISK_LEVEL_COLORS[lv]};display:inline-block\"></span>${lv} <strong style=\"color:${RISK_LEVEL_COLORS[lv]}\">${n}</strong></span>`; }).join('');
      box.innerHTML = `<div style=\"display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start\">
        <div>
          <table style=\"border-collapse:collapse\">${header}${cells}</table>
          <div style=\"text-align:center;color:#64748b;font-size:11px;margin-top:4px\">${tt('dash.risk.likelihood','발생가능성')} →　　↑ ${tt('dash.risk.impact','영향도')}</div>
        </div>
        <div style=\"flex:1;min-width:220px\"><div>${chips}</div></div>
      </div>`;
    }

    function _riskRecalc() {
      const imp = parseInt(document.getElementById('risk_impact').value,10)||2;
      const lk = parseInt(document.getElementById('risk_likelihood').value,10)||1;
      const s = imp*lk, level = _levelForScore(s);
      const gradeEl = document.getElementById('risk_modal_grade');
      if (!gradeEl) return;
      const note = gradeEl.dataset.suggested === '1' ? ` <span style=\"color:#a78bfa;font-size:11px\">${tt('dash.risk.suggested_note','자동 제안 등급 (저장 전)')}</span>` : '';
      gradeEl.innerHTML = `${_riskBadge(level)} <span style=\"color:#94a3b8;font-size:13px;margin-left:6px\">${tt('dash.risk.impact','영향도')} ${imp} × ${tt('dash.risk.likelihood','발생가능성')} ${lk} = <strong style=\"color:#e2e8f0\">${s}</strong></span>${note}`;
    }
    window._riskRecalc = _riskRecalc;

    async function openRiskModal(vulnId) {
      _riskModalVulnId = vulnId;
      document.getElementById('risk_modal_status').textContent = '';
      const it = _riskSummary.map[vulnId];
      document.getElementById('risk_modal_meta').innerHTML = it
        ? `<strong style=\"color:#7dd3fc\">${escapeHtml(it.cve)}</strong> · <span style=\"color:#fdba74;text-transform:uppercase\">${escapeHtml(it.severity)}</span> · <span style=\"color:#64748b\">${escapeHtml(it.hostname)}</span>`
        : `vuln_id: ${escapeHtml(vulnId)}`;
      document.getElementById('risk_provenance').style.display = 'none';
      document.getElementById('risk_modal').style.display = 'flex';
      try {
        const res = await fetch(`/vulnerabilities/${encodeURIComponent(vulnId)}/risk`);
        if (!res.ok) throw new Error('HTTP '+res.status);
        const d = await res.json();
        document.getElementById('risk_modal_grade').dataset.suggested = d.suggested ? '1' : '0';
        document.getElementById('risk_impact').value = String(d.impact||2);
        document.getElementById('risk_likelihood').value = String(d.likelihood||1);
        document.getElementById('risk_treatment').value = d.treatment || '';
        document.getElementById('risk_accept_reason').value = d.accept_reason || '';
        document.getElementById('risk_accept_approver').value = d.accept_approver || '';
        document.getElementById('risk_residual').value = d.residual_level || '';
        document.getElementById('risk_review_due').value = d.review_due || '';
        document.getElementById('risk_assessed_by').value = d.assessed_by || (_currentProfile && _currentProfile.display_name) || '';
        _riskRecalc();
        if (_currentUserRole === 'admin' && d.suggestion && d.suggestion.provenance) {
          const p = d.suggestion.provenance, inp = d.suggestion.inputs || {};
          const row = (k,v) => `<div style=\"display:flex;justify-content:space-between;gap:10px;font-size:12px;padding:2px 0\"><span style=\"color:#94a3b8\">${k}</span><span style=\"color:#e2e8f0;text-align:right\">${escapeHtml(String(v==null||v===''?'-':v))}</span></div>`;
          const impSrc = p.importance_source === 'owner' ? tt('dash.risk.prov.owner',' (담당자 지정)') : tt('dash.risk.prov.auto',' (자동분류)');
          document.getElementById('risk_provenance').innerHTML =
            `<div style=\"color:#c4b5fd;font-weight:700;font-size:12px;margin-bottom:6px\">${tt('dash.risk.provenance_title','🔎 산정 근거 (관리자 전용)')}</div>`
            + row(tt('dash.risk.prov.source','데이터 소스'), p.data_source)
            + row(tt('dash.risk.prov.host','자산(호스트)'), p.hostname)
            + row(tt('dash.risk.prov.pkg','패키지'), (p.package_name||'-') + (p.installed_version?(' '+p.installed_version):'') + (p.fixed_version?(' → '+p.fixed_version):''))
            + row(tt('dash.risk.prov.importance','자산 중요도'), (p.importance||'-') + impSrc)
            + row(tt('dash.risk.prov.severity','심각도'), inp.severity)
            + row(tt('dash.risk.prov.fixed','패치 존재(보정)'), inp.fixed_available ? 'Y' : 'N')
            + row(tt('dash.risk.prov.exc','예외 만료(보정)'), inp.exception_expired ? 'Y' : 'N')
            + (p.detected_at ? row(tt('dash.risk.prov.detected','탐지일'), formatTime(p.detected_at)) : '');
          document.getElementById('risk_provenance').style.display = 'block';
        }
      } catch(e) {
        document.getElementById('risk_modal_status').textContent = `${tt('dash.dyn.error_prefix','오류: ')}${e.message}`;
      }
    }
    window.openRiskModal = openRiskModal;
    function closeRiskModal() { document.getElementById('risk_modal').style.display = 'none'; }
    window.closeRiskModal = closeRiskModal;

    async function saveRiskAssessment() {
      if (!_riskModalVulnId) return;
      const body = {
        impact: parseInt(document.getElementById('risk_impact').value,10),
        likelihood: parseInt(document.getElementById('risk_likelihood').value,10),
        treatment: document.getElementById('risk_treatment').value,
        accept_reason: document.getElementById('risk_accept_reason').value,
        accept_approver: document.getElementById('risk_accept_approver').value,
        residual_level: document.getElementById('risk_residual').value,
        review_due: document.getElementById('risk_review_due').value,
        assessed_by: document.getElementById('risk_assessed_by').value,
      };
      const statusEl = document.getElementById('risk_modal_status');
      statusEl.textContent = '…';
      try {
        const res = await fetch(`/vulnerabilities/${encodeURIComponent(_riskModalVulnId)}/risk`, {
          method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        if (!res.ok) { statusEl.textContent = `${tt('dash.risk.save_fail','❌ 위험성 평가 저장 실패')}: HTTP ${res.status}`; return; }
        statusEl.textContent = tt('dash.risk.saved','✅ 위험성 평가 저장됨');
        await loadRiskMatrix();
        const listModal = document.getElementById('vuln_list_modal');
        if (listModal && listModal.style.display === 'flex' && _vulnActionHostId != null) {
          const row = (_assetCache.trivy || []).find(r => r.host_id === _vulnActionHostId);
          if (row) document.getElementById('vuln_list_modal_body').innerHTML = _renderVulnListBody(row);
        }
        setTimeout(closeRiskModal, 700);
      } catch(e) {
        statusEl.textContent = `${tt('dash.risk.save_fail','❌ 위험성 평가 저장 실패')}: ${e.message}`;
      }
    }
    window.saveRiskAssessment = saveRiskAssessment;

    /* ⭐ 프로필 메뉴 → 내 서버 바로가기 */
    function shortcutMyServers() {
      const menu = document.getElementById('account_menu');
      if (menu) menu.style.display = 'none';
      switchTab('assets');
      switchAssetTab('mine');
    }
    window.shortcutMyServers = shortcutMyServers;

    /* ── 감사 이력 모달 ──────────────────────────────────────────────────── */
    async function openAuditModal(hostname) {
      document.getElementById('audit_modal_title').textContent = `${tt('dash.dyn.audit_title_prefix','변경 이력 — ')}${hostname}`;
      document.getElementById('audit_modal_body').innerHTML = '<span style=\"color:#94a3b8\">' + tt('dash.dyn.loading','로딩 중...') + '</span>';
      document.getElementById('audit_modal').style.display = 'flex';
      try {
        const res = await fetch(`/admin/audit-log?hostname=${encodeURIComponent(hostname)}`);
        const data = await res.json();
        const logs = data.audit_log || [];
        if (!logs.length) {
          document.getElementById('audit_modal_body').innerHTML = '<div style=\"color:#64748b;text-align:center;padding:20px\">' + tt('dash.dyn.no_audit_history','변경 이력이 없습니다.') + '</div>';
          return;
        }
        const fieldLabels = {owner:tt('dash.dyn.lbl.owner','담당자'), team:tt('dash.dyn.field.team','팀'), category:tt('dash.dyn.field.category','분류'), importance:tt('dash.dyn.field.importance','중요도'), exception_until:tt('dash.dyn.field.exception_until','예외기한'), exception_reason:tt('dash.dyn.field.exception_reason','예외사유')};
        const rows = logs.map(l => `<div style=\"border-bottom:1px solid #1e293b;padding:10px 0\">
          <div style=\"display:flex;justify-content:space-between;align-items:center\">
            <span style=\"color:#7dd3fc;font-weight:700\">${escapeHtml(fieldLabels[l.field]||l.field)}</span>
            <span style=\"color:#64748b;font-size:11px\">${escapeHtml(l.changed_at||'')}</span>
          </div>
          <div style=\"font-size:12px;margin-top:4px\">
            <span style=\"color:#fca5a5\">${escapeHtml(l.old_value||tt('dash.dyn.no_value','(없음)'))}</span>
            <span style=\"color:#64748b\"> → </span>
            <span style=\"color:#86efac\">${escapeHtml(l.new_value||tt('dash.dyn.no_value','(없음)'))}</span>
          </div>
          <div style=\"font-size:11px;color:#94a3b8;margin-top:2px\">${tt('dash.dyn.editor_prefix','수정자: ')}${escapeHtml(l.changed_by||'unknown')}</div>
        </div>`).join('');
        document.getElementById('audit_modal_body').innerHTML = rows;
      } catch(e) {
        document.getElementById('audit_modal_body').innerHTML = `<div style=\"color:#fca5a5\">${tt('dash.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    function closeAuditModal() { document.getElementById('audit_modal').style.display = 'none'; }

    /* ── 담당자/카테고리 편집 모달 ──────────────────────────────────────── */
    function openOwnerModal(hostname, owner, team, category, assetType, exceptionUntil, exceptionReason, importance) {
      document.getElementById('owner_modal_hostname').value = hostname;
      document.getElementById('owner_modal_owner').value = owner || '';
      document.getElementById('owner_modal_team').value = team || '';
      document.getElementById('owner_modal_category').value = category || '';
      document.getElementById('owner_modal_exception_until').value = exceptionUntil || '';
      document.getElementById('owner_modal_exception_reason').value = exceptionReason || '';
      const impEl = document.getElementById('owner_modal_importance');
      if (impEl) impEl.value = importance || '';
      document.getElementById('owner_modal_status').textContent = '';
      document.getElementById('owner_modal_status').style.color = '#94a3b8';
      // PC 자산은 카테고리 숨김, 서버만 표시
      const isServer = assetType === 'server';
      const isTrivy = assetType === 'trivy';
      document.getElementById('owner_modal_category_row').style.display = isServer ? '' : 'none';
      // 중요도 재정의는 서버 자산에서만 노출
      document.getElementById('owner_modal_importance_row').style.display = isServer ? '' : 'none';
      // 처리 예외 기한은 Trivy에서만 필요
      document.getElementById('owner_modal_exception_row').style.display = isTrivy ? '' : 'none';
      const titleMap = { server: tt('dash.dyn.asset_detail.server','서버 자산 상세페이지'), pc: tt('dash.dyn.asset_detail.pc','PC 자산 상세페이지'), trivy: tt('dash.dyn.asset_detail.trivy','취약점 상세페이지') };
      document.getElementById('owner_modal_title').textContent = `${titleMap[assetType] || tt('dash.dyn.asset_detail.default','자산 수정')} — ${hostname}`;
      document.getElementById('owner_modal').style.display = 'flex';
    }
    function closeOwnerModal() { document.getElementById('owner_modal').style.display = 'none'; }

    document.addEventListener('DOMContentLoaded', () => {
      const ownerSaveBtn = document.getElementById('owner_modal_save');
      if (ownerSaveBtn) ownerSaveBtn.addEventListener('click', async () => {
        const hostname = document.getElementById('owner_modal_hostname').value;
        const owner = document.getElementById('owner_modal_owner').value.trim();
        const team = document.getElementById('owner_modal_team').value.trim();
        const category = document.getElementById('owner_modal_category').value.trim();
        const exception_until = document.getElementById('owner_modal_exception_until').value.trim();
        const exception_reason = document.getElementById('owner_modal_exception_reason').value.trim();
        const impEl = document.getElementById('owner_modal_importance');
        const importance = (impEl && impEl.closest('#owner_modal_importance_row').style.display !== 'none') ? impEl.value : '';
        const statusEl = document.getElementById('owner_modal_status');
        statusEl.textContent = tt('dash.dyn.saving','저장 중...');
        try {
          const res = await fetch('/assets/owners', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ hostname, owner, team, category, importance, exception_until, exception_reason })
          });
          if (!res.ok) throw new Error(await res.text());
          statusEl.style.color = '#86efac';
          statusEl.textContent = tt('dash.dyn.saved','✅ 저장되었습니다.');
          setTimeout(() => { closeOwnerModal(); loadAssets(); }, 800);
        } catch(e) {
          statusEl.style.color = '#fca5a5';
          statusEl.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${e.message}`;
        }
      });
    });

    document.addEventListener('DOMContentLoaded', () => {
      const saveBtn = document.getElementById('plan_modal_save');
      if (saveBtn) saveBtn.addEventListener('click', async () => {
        if (!_planHostId) return;
        await fetch(`/assets/plans/${encodeURIComponent(_planHostId)}`, {
          method: 'PUT', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({
            text: document.getElementById('plan_text').value,
            target_date: document.getElementById('plan_target_date').value,
            updated_by: document.getElementById('plan_updated_by').value || tt('dash.dyn.operator','운영자'),
          })
        });
        closePlanModal();
        loadAssets();
      });

      // 취약점별 조치 계획/예외 저장
      const vulnSaveBtn = document.getElementById('vuln_action_modal_save');
      if (vulnSaveBtn) vulnSaveBtn.addEventListener('click', async () => {
        if (!_vulnActionId) return;
        const statusEl = document.getElementById('vuln_action_modal_status');
        statusEl.style.color = '#94a3b8'; statusEl.textContent = tt('dash.dyn.saving','저장 중...');
        try {
          let res;
          if (_vulnActionMode === 'exception') {
            res = await fetch(`/vulnerabilities/${encodeURIComponent(_vulnActionId)}/exception`, {
              method: 'PUT', headers: {'Content-Type':'application/json'},
              body: JSON.stringify({
                exception_until: document.getElementById('vuln_exception_until').value,
                exception_reason: document.getElementById('vuln_exception_reason').value,
                exception_updated_by: document.getElementById('vuln_exception_updated_by').value || tt('dash.dyn.operator','운영자'),
              })
            });
          } else {
            res = await fetch(`/vulnerabilities/${encodeURIComponent(_vulnActionId)}/plan`, {
              method: 'PUT', headers: {'Content-Type':'application/json'},
              body: JSON.stringify({
                plan_text: document.getElementById('vuln_plan_text').value,
                plan_target_date: document.getElementById('vuln_plan_target_date').value,
                plan_updated_by: document.getElementById('vuln_plan_updated_by').value || tt('dash.dyn.operator','운영자'),
              })
            });
          }
          if (!res.ok) { const d = await res.json().catch(()=>({})); throw new Error(d.detail || res.status); }
          const hostId = _vulnActionHostId;
          closeVulnActionModal();
          await loadAssets();
          if (hostId) openVulnListModal(hostId);
        } catch(err) {
          statusEl.style.color = '#fca5a5';
          statusEl.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${err.message}`;
        }
      });

      const vulnClearBtn = document.getElementById('vuln_action_modal_clear');
      if (vulnClearBtn) vulnClearBtn.addEventListener('click', async () => {
        if (!_vulnActionId) return;
        if (!confirm(tt('dash.dyn.confirm_clear_exception','이 취약점의 예외 처리를 해제하시겠습니까?'))) return;
        const statusEl = document.getElementById('vuln_action_modal_status');
        statusEl.style.color = '#94a3b8'; statusEl.textContent = tt('dash.dyn.clearing','해제 중...');
        try {
          const res = await fetch(`/vulnerabilities/${encodeURIComponent(_vulnActionId)}/exception`, { method: 'DELETE' });
          if (!res.ok) throw new Error(res.status);
          const hostId = _vulnActionHostId;
          closeVulnActionModal();
          await loadAssets();
          if (hostId) openVulnListModal(hostId);
        } catch(err) {
          statusEl.style.color = '#fca5a5';
          statusEl.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${err.message}`;
        }
      });
    });

    // ── Asset data cache for search/filter ──
    let _assetCache = { fleet: [], zabbix: [], trivy: [] };
    let _trivyFiltered = [];

    async function loadAssets() {
      const statusEl = document.getElementById('assets_status');
      statusEl.textContent = tt('dash.dyn.assets_loading', '자산 데이터 로딩 중...');
      try {
        const res = await fetch('/assets');
        if (!res.ok) { statusEl.textContent = tt('dash.dyn.assets_load_fail', '자산 데이터 로드 실패'); return; }
        const data = await res.json();
        // Cache raw data
        _assetCache.fleet = data.fleet?.hosts || [];
        _assetCache.zabbix = data.zabbix?.hosts || [];
        _assetCache.trivy = data.trivy?.rows || [];
        // Fleet summary
        document.getElementById('fleet_total').textContent = data.fleet?.total ?? '-';
        document.getElementById('fleet_online').textContent = data.fleet?.online ?? '-';
        document.getElementById('fleet_offline').textContent = data.fleet?.offline ?? '-';
        renderFleetTable(_assetCache.fleet, document.getElementById('fleet_table'));
        // Zabbix summary
        document.getElementById('zabbix_total').textContent = data.zabbix?.total ?? '-';
        document.getElementById('zabbix_online').textContent = data.zabbix?.online ?? '-';
        document.getElementById('zabbix_offline').textContent = data.zabbix?.offline ?? '-';
        renderZabbixTable(_assetCache.zabbix, document.getElementById('zabbix_table'));
        // Populate Zabbix category dropdown
        _populateZabbixCategories(_assetCache.zabbix);
        // Trivy summary
        document.getElementById('trivy_affected_hosts').textContent = data.trivy?.affected_hosts ?? '-';
        document.getElementById('trivy_total_vulns').textContent = data.trivy?.total_vulns ?? '-';
        document.getElementById('trivy_critical').textContent = data.trivy?.critical ?? '-';
        document.getElementById('trivy_high').textContent = data.trivy?.high ?? '-';
        _trivyFiltered = _assetCache.trivy;
        renderTrivyTable(_assetCache.trivy, document.getElementById('trivy_table'));
        loadRiskMatrix();
        // Reset search counts
        _updateSearchCount('fleet', _assetCache.fleet.length, _assetCache.fleet.length);
        _updateSearchCount('zabbix', _assetCache.zabbix.length, _assetCache.zabbix.length);
        _updateSearchCount('trivy', _assetCache.trivy.length, _assetCache.trivy.length);
        if (currentAssetTab === 'mine') renderMyServers();
        statusEl.textContent = `${tt('dash.dyn.assets_updated','자산 현황 업데이트: ')}${formatTime(data.generated_at)}`;
      } catch (err) { statusEl.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${err.message}`; }
    }

    function _populateZabbixCategories(hosts) {
      const sel = document.getElementById('zabbix_search_category');
      if (!sel) return;
      const cats = [...new Set(hosts.map(h => h.category).filter(Boolean))].sort();
      // keep first option (전체 분류), remove the rest
      while (sel.options.length > 1) sel.remove(1);
      cats.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; sel.appendChild(o); });
    }

    function _updateSearchCount(tab, shown, total) {
      const el = document.getElementById(`${tab}_search_count`);
      if (el) el.textContent = shown === total ? tt('dash.dyn.count_total','총 {total}건').replace('{total}',total) : tt('dash.dyn.count_partial','{shown} / {total}건').replace('{shown}',shown).replace('{total}',total);
    }

    function filterAssetTable(tab) {
      const hostnameVal = (document.getElementById(`${tab}_search_hostname`)?.value || '').trim().toLowerCase();
      if (tab === 'fleet') {
        const statusVal = document.getElementById('fleet_search_status')?.value || '';
        const filtered = _assetCache.fleet.filter(h => {
          if (hostnameVal && !h.hostname.toLowerCase().includes(hostnameVal)) return false;
          if (statusVal && h.status !== statusVal) return false;
          return true;
        });
        renderFleetTable(filtered, document.getElementById('fleet_table'));
        _updateSearchCount('fleet', filtered.length, _assetCache.fleet.length);
      } else if (tab === 'zabbix') {
        const statusVal = document.getElementById('zabbix_search_status')?.value || '';
        const catVal = document.getElementById('zabbix_search_category')?.value || '';
        const filtered = _assetCache.zabbix.filter(h => {
          if (hostnameVal && !h.hostname.toLowerCase().includes(hostnameVal)) return false;
          if (statusVal && h.status !== statusVal) return false;
          if (catVal && h.category !== catVal) return false;
          return true;
        });
        renderZabbixTable(filtered, document.getElementById('zabbix_table'));
        _updateSearchCount('zabbix', filtered.length, _assetCache.zabbix.length);
      } else if (tab === 'trivy') {
        const sevVal = document.getElementById('trivy_search_severity')?.value || '';
        const dateFrom = document.getElementById('trivy_search_date_from')?.value || '';
        const dateTo = document.getElementById('trivy_search_date_to')?.value || '';
        const filtered = _assetCache.trivy.filter(r => {
          if (hostnameVal && !r.hostname.toLowerCase().includes(hostnameVal)) return false;
          if (sevVal === 'critical' && !(r.critical > 0)) return false;
          if (sevVal === 'high' && !(r.high > 0)) return false;
          if (sevVal === 'medium' && !(r.medium > 0)) return false;
          if (dateFrom || dateTo) {
            const det = r.latest_detected_at ? r.latest_detected_at.substring(0, 10) : '';
            if (!det) return false;
            if (dateFrom && det < dateFrom) return false;
            if (dateTo && det > dateTo) return false;
          }
          return true;
        });
        _trivyFiltered = filtered;
        renderTrivyTable(filtered, document.getElementById('trivy_table'));
        _updateSearchCount('trivy', filtered.length, _assetCache.trivy.length);
      }
    }

    function downloadAssetsCSV(source) {
      if (source === 'trivy') {
        // 클라이언트에서 필터된 데이터 기반 CSV 생성
        const rows = _trivyFiltered.length ? _trivyFiltered : _assetCache.trivy;
        if (!rows.length) { alert(tt('dash.dyn.no_export_data','내보낼 데이터가 없습니다.')); return; }
        const header = [tt('dash.dyn.lbl.host','호스트'),'host_id',tt('dash.dyn.lbl.owner','담당자'),'Critical','High','Medium','Low',tt('dash.dyn.lbl.total','합계'),tt('dash.dyn.lbl.latest_cve','최근CVE'),tt('dash.dyn.lbl.detected_date','탐지일'),tt('dash.dyn.lbl.action_plan','조치계획'),tt('dash.dyn.csv.target_date','목표완료일'),tt('dash.dyn.author_label','작성자'),tt('dash.dyn.csv.exception_until','조치예외기한'),tt('dash.dyn.csv.exception_owner','예외담당자')];
        const csvRows = [header.join(',')];
        rows.forEach(r => {
          const owner = _ownerForHost(r.hostname);
          const ownerData = _getOwnerData(r.hostname);
          const exOwner = ownerData.owner || '';
          csvRows.push([r.hostname, r.host_id, '"'+owner.replace(/"/g,'""')+'"', r.critical, r.high, r.medium, r.low, r.total,
            r.latest_cve||'', r.latest_detected_at||'', '"'+(r.action_plan||'').replace(/"/g,'""')+'"',
            r.action_target_date||'', r.action_updated_by||'', r.exception_until||ownerData.exception_until||'', '"'+exOwner.replace(/"/g,'""')+'"'].join(','));
        });
        const blob = new Blob(['\\uFEFF' + csvRows.join('\\n')], {type:'text/csv;charset=utf-8'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `mori-trivy-filtered-${new Date().toISOString().slice(0,10)}.csv`;
        a.click(); URL.revokeObjectURL(url);
      } else {
        const a = document.createElement('a');
        a.href = `/assets?format=csv&source=${encodeURIComponent(source)}`;
        a.download = '';
        a.click();
      }
    }

    /* ── On-demand 수집 (새로고침 버튼) ──────────────────────────────── */
    async function onDemandRefresh(source) {
      const statusEl = document.getElementById('assets_status');
      statusEl.textContent = `🔄 ${source}${tt('dash.dyn.collecting',' 수집 중...')}`;
      statusEl.style.color = '#fde68a';
      try {
        const res = await fetch('/assets/refresh', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({source}),
        });
        const data = await res.json();
        if (data.status === 'success') {
          statusEl.style.color = '#86efac';
          statusEl.textContent = `✅ ${source}${tt('dash.dyn.collect_done',' 수집 완료')}`;
        } else if (data.status === 'skipped') {
          statusEl.style.color = '#fde68a';
          statusEl.textContent = `⏭️ ${data.message}`;
        } else {
          statusEl.style.color = '#fca5a5';
          statusEl.textContent = `❌ ${source}${tt('dash.dyn.collect_err',' 수집 오류: ')}${data.message}`;
        }
        // 수집 후 자산 목록 새로고침
        await loadAssets();
      } catch(e) {
        statusEl.style.color = '#fca5a5';
        statusEl.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${e.message}`;
      }
    }

    // ── Guide Tab ─────────────────────────────────────────────────────────
    // ── Compliance PDCA ──────────────────────────────────────────────────────
    async function loadCompliance() {
      const cardsEl = document.getElementById('pdca_cards');
      const statusEl = document.getElementById('pdca_status_chart');
      const categoryEl = document.getElementById('pdca_category_table');
      const cycleEl = document.getElementById('pdca_cycle_chart');
      const pendingEl = document.getElementById('pdca_pending_table');
      if (cardsEl) cardsEl.innerHTML = '<div class=\"empty\" style=\"padding:16px;color:#64748b\">⏳ ' + tt('dash.dyn.loading','로딩 중…') + '</div>';
      try {
        const res = await fetch('/compliance/pdca');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const sc = data.status_counts || {};
        const pdca = data.pdca || {};
        const ps = data.pending_sources || {};
        // Cache pending list so PDCA Do modal / CSV button can reuse the same dataset
        window.__pdcaPending = data.pending_remediations || [];
        window.__pdcaPendingSources = ps;
        // Summary cards — 상단은 control_checks만, 하단 2장은 통합(통제+Trivy+Alert)
        if (cardsEl) {
          // 바쁜 보안 담당자용: 행동 항목(미조치·기한초과) 우선 + 취약률 한 장(숫자 크게).
          // 피드백 반영: Pass Rate 대신 '취약률(Fail/Weakness Rate)' — 심사에서 봐야 할 건
          // '통과율'이 아니라 '얼마나 취약한가'라서 반전 표시. 상세는 아래 접기.
          const totalChecks = data.total_checks || 0;
          const weakCount = (sc.fail || 0) + (sc.warning || 0);
          const weakRateStr = totalChecks > 0 ? (Math.round(weakCount / totalChecks * 100) + '%') : '—';
          const weakColor = totalChecks > 0 && (weakCount / totalChecks) >= 0.3 ? '#f43f5e' : '#fb923c';
          const totalPending = data.pending_count || 0;
          const pendingSub = `${tt('dash.dyn.pdca.control','통제')} ${ps.control_check||0} · Trivy ${ps.trivy||0} · Alert ${ps.alert||0}`;
          const breakdownSub = totalChecks > 0
            ? `❌ ${sc.fail||0} · ⚠️ ${sc.warning||0} / ${totalChecks} (✅ ${sc.pass||0})`
            : tt('dash.dyn.pdca.no_control_data','통제 점검 데이터 없음');
          cardsEl.innerHTML = [
            _metricCard(tt('dash.dyn.pdca.pending_total_card','🔧 미조치 합계'), totalPending, '#fb923c', pendingSub, true),
            _metricCard(tt('dash.dyn.pdca.overdue_card','🔴 기한초과'), data.overdue_count || 0, '#f43f5e', tt('dash.dyn.pdca.combined_sources','통제+Trivy+Alert'), true),
            _metricCard(tt('dash.pdca.weakness_rate','⚠️ 취약률 (Fail/Weakness)'), weakRateStr, weakColor, breakdownSub, true),
          ].join('');
        }
        // Status bars
        if (statusEl) {
          const total = data.total_checks || 1;
          const bars = ['pass','fail','warning','not_applicable','not_checked'].map(s => {
            const cnt = sc[s] || 0;
            const pct = (cnt / total * 100).toFixed(1);
            const colors = {pass:'#22c55e',fail:'#ef4444',warning:'#f59e0b',not_applicable:'#64748b',not_checked:'#334155'};
            const labels = {pass:'Pass',fail:'Fail',warning:'Warning',not_applicable:'N/A',not_checked:tt('dash.dyn.pdca.not_checked','미점검')};
            return `<div style=\"flex:1;min-width:100px\">
              <div style=\"font-size:12px;color:#94a3b8;margin-bottom:4px\">${labels[s]}</div>
              <div style=\"background:#0f172a;border-radius:6px;height:24px;overflow:hidden;position:relative\">
                <div style=\"background:${colors[s]};width:${pct}%;height:100%;border-radius:6px;transition:width .5s\"></div>
                <span style=\"position:absolute;top:3px;left:8px;font-size:12px;font-weight:700;color:#fff\">${cnt} (${pct}%)</span>
              </div>
            </div>`;
          });
          statusEl.innerHTML = bars.join('');
        }
        // PDCA Cycle
        if (cycleEl) {
          const steps = [
            {key:'plan',  label:'Plan',  desc:tt('dash.dyn.pdca.plan_desc','미점검 항목'),  val: pdca.plan || 0,  color:'#38bdf8', icon:'📝'},
            {key:'do',    label:'Do',    desc:tt('dash.dyn.pdca.do_desc','조치 필요'),    val: pdca.do || 0,    color:'#f59e0b', icon:'🔧'},
            {key:'check', label:'Check', desc:tt('dash.dyn.pdca.check_desc','점검 완료'),    val: pdca.check || 0, color:'#a78bfa', icon:'🔍'},
            {key:'act',   label:'Act',   desc:tt('dash.dyn.pdca.act_desc','통과 (Pass)'),  val: pdca.act || 0,   color:'#22c55e', icon:'✅'},
          ];
          cycleEl.innerHTML = `<div style=\"display:grid;grid-template-columns:repeat(4,1fr);gap:12px;text-align:center\">`
            + steps.map(s => {
              const clickable = (s.key === 'do' && s.val > 0);
              const cursor = clickable ? 'cursor:pointer' : '';
              const handler = clickable ? ' onclick=\"openPdcaDoModal()\"' : '';
              const hint = clickable ? '<div style=\"font-size:10px;color:#fbbf24;margin-top:4px\">' + tt('dash.dyn.pdca.click_hint','▸ 클릭') + '</div>' : '';
              return `<div${handler} style=\"background:#0b1220;border:2px solid ${s.color};border-radius:12px;padding:16px 8px;${cursor}\">
                <div style=\"font-size:24px\">${s.icon}</div>
                <div style=\"font-size:18px;font-weight:800;color:${s.color};margin:4px 0\">${s.val}</div>
                <div style=\"font-size:13px;font-weight:700;color:#e2e8f0\">${s.label}</div>
                <div style=\"font-size:11px;color:#64748b\">${s.desc}</div>
                ${hint}
              </div>`;
            }).join('')
            + '</div>';
        }
        // Category table
        if (categoryEl) {
          const cats = data.categories || [];
          if (cats.length === 0) {
            categoryEl.innerHTML = '<div class=\"empty\" style=\"color:#64748b;padding:12px\">' + tt('dash.dyn.pdca.no_check_data','점검 데이터가 없습니다.') + '</div>';
          } else {
            categoryEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
              <thead><tr style=\"color:#94a3b8;border-bottom:1px solid #334155\">
                <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.category','카테고리')}</th>
                <th style=\"text-align:right;padding:6px 8px\">Pass</th>
                <th style=\"text-align:right;padding:6px 8px\">Fail</th>
                <th style=\"text-align:right;padding:6px 8px\">Warning</th>
                <th style=\"text-align:right;padding:6px 8px\">${tt('dash.dyn.pdca.not_checked','미점검')}</th>
                <th style=\"text-align:right;padding:6px 8px\">${tt('dash.dyn.lbl.total','합계')}</th>
              </tr></thead><tbody>`
              + cats.map(c => `<tr style=\"border-bottom:1px solid #1e293b\">
                <td style=\"padding:6px 8px;color:#e2e8f0;font-weight:600\">${escapeHtml(c.category)}</td>
                <td style=\"text-align:right;padding:6px 8px;color:#22c55e\">${c.pass}</td>
                <td style=\"text-align:right;padding:6px 8px;color:#ef4444\">${c.fail}</td>
                <td style=\"text-align:right;padding:6px 8px;color:#f59e0b\">${c.warning}</td>
                <td style=\"text-align:right;padding:6px 8px;color:#64748b\">${c.not_checked}</td>
                <td style=\"text-align:right;padding:6px 8px;color:#94a3b8\">${c.total}</td>
              </tr>`).join('')
              + '</tbody></table>';
          }
        }
        // Pending remediations (control_check + trivy + alert)
        if (pendingEl) {
          const items = data.pending_remediations || [];
          const ps = data.pending_sources || {};
          const breakdown = `<div style=\"margin-bottom:8px;font-size:12px;color:#94a3b8\">
            ${tt('dash.dyn.pdca.by_source','출처별: ')}<span style=\"color:#7dd3fc\">${tt('dash.dyn.pdca.control_checks','통제 점검')} ${ps.control_check||0}</span> ·
            <span style=\"color:#fdba74\">Trivy ${tt('dash.dyn.pdca.vulns','취약점')} ${ps.trivy||0}</span> ·
            <span style=\"color:#fca5a5\">Alert ${ps.alert||0}</span>
          </div>`;
          if (items.length === 0) {
            pendingEl.innerHTML = breakdown + '<div class=\"empty\" style=\"color:#64748b;padding:12px\">' + tt('dash.dyn.pdca.no_pending','미조치 항목이 없습니다. 🎉') + '</div>';
          } else {
            const sourceBadge = (s) => {
              if (s === 'trivy') return '<span style=\"background:#3b1f00;color:#fdba74;padding:2px 6px;border-radius:4px;font-size:10px\">🛡️ Trivy</span>';
              if (s === 'alert') return '<span style=\"background:#450a0a;color:#fca5a5;padding:2px 6px;border-radius:4px;font-size:10px\">🚨 Alert</span>';
              return '<span style=\"background:#0c2a4a;color:#7dd3fc;padding:2px 6px;border-radius:4px;font-size:10px\">' + tt('dash.dyn.pdca.control_badge','📋 통제') + '</span>';
            };
            pendingEl.innerHTML = breakdown + `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
              <thead><tr style=\"color:#94a3b8;border-bottom:1px solid #334155\">
                <th style=\"text-align:center;padding:6px 8px\">${tt('dash.dyn.pdca.source','출처')}</th>
                <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.control_id','통제 ID')}</th>
                <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.target','대상')}</th>
                <th style=\"text-align:center;padding:6px 8px\">${tt('dash.dyn.lbl.status','상태')}</th>
                <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.lbl.owner','담당자')}</th>
                <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.due','조치 기한')}</th>
                <th style=\"text-align:left;padding:6px 8px\">${tt('dash.dyn.pdca.note','비고')}</th>
              </tr></thead><tbody>`
              + items.map(i => {
                const statusBadge = i.status === 'fail'
                  ? '<span style=\"background:#450a0a;color:#fca5a5;padding:2px 8px;border-radius:999px;font-size:11px\">Fail</span>'
                  : '<span style=\"background:#451a03;color:#fbbf24;padding:2px 8px;border-radius:999px;font-size:11px\">Warning</span>';
                const due = i.remediation_due_at ? new Date(i.remediation_due_at).toLocaleDateString('ko-KR') : '-';
                const overdueFlag = i.overdue ? ' 🔴' : '';
                return `<tr style=\"border-bottom:1px solid #1e293b\">
                  <td style=\"text-align:center;padding:6px 8px\">${sourceBadge(i.source)}</td>
                  <td style=\"padding:6px 8px;color:#38bdf8;font-weight:600\">${escapeHtml(i.control_id)}</td>
                  <td style=\"padding:6px 8px;color:#e2e8f0\">${escapeHtml(i.entity_type)}:${escapeHtml(i.entity_id)}</td>
                  <td style=\"text-align:center;padding:6px 8px\">${statusBadge}</td>
                  <td style=\"padding:6px 8px;color:#94a3b8\">${escapeHtml(i.owner) || '-'}</td>
                  <td style=\"padding:6px 8px;color:#e2e8f0\">${due}${overdueFlag}</td>
                  <td style=\"padding:6px 8px;color:#64748b\">${escapeHtml(i.note) || ''}</td>
                </tr>`;
              }).join('')
              + '</tbody></table>';
          }
        }
      } catch(e) {
        if (cardsEl) cardsEl.innerHTML = '<div class=\"empty\" style=\"color:#f87171;padding:16px\">' + tt('dash.dyn.pdca.load_fail','❌ Compliance 데이터를 불러올 수 없습니다.') + '</div>';
      }
      // Load report download cards & crosscheck
      loadReportCards();
      loadCrosscheck();
    }

    async function loadReportCards() {
      const area = document.getElementById('report_download_area');
      if (!area) return;
      try {
        const res = await fetch('/compliance/reports');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const icons = {asset_inspection:'🖥️', account_privilege:'👤', log_collection_status:'📋', vulnerability_assessment:'🛡️', monthly_operations:'📊'};
        area.innerHTML = (data.report_types || []).map(rt => `
          <div style=\"background:#0b1220;border:1px solid #233046;border-radius:12px;padding:16px\">
            <div style=\"font-size:20px;margin-bottom:8px\">${icons[rt.id] || '📄'}</div>
            <div style=\"font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:4px\">${escapeHtml(rt.label)}</div>
            <div style=\"display:flex;gap:6px;margin-top:12px;flex-wrap:wrap\">
              <button onclick=\"openReportPreview('${rt.id}', '${escapeHtml(rt.label)}')\" style=\"flex:1;min-width:80px;padding:6px 10px;background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer\">${tt('dash.dyn.preview_btn','🔍 미리보기')}</button>
              <a href=\"${rt.url_csv}\" download style=\"flex:1;min-width:60px;text-align:center;padding:6px 10px;background:#164e63;color:#67e8f9;border-radius:8px;font-size:12px;font-weight:600;text-decoration:none\">📥 CSV</a>
              <a href=\"${rt.url_pdf || (rt.url_json + '?format=pdf')}\" download style=\"flex:1;min-width:60px;text-align:center;padding:6px 10px;background:#7c2d12;color:#fed7aa;border-radius:8px;font-size:12px;font-weight:600;text-decoration:none\">📄 PDF</a>
            </div>
          </div>
        `).join('');
      } catch(e) {
        area.innerHTML = '<div class=\"empty\" style=\"color:#f87171\">' + tt('dash.dyn.report_list_fail','리포트 목록을 불러올 수 없습니다.') + '</div>';
      }
    }

    /* ── 감사 증적 리포트 미리보기 ─────────────────────────────────────────── */
    function _parseSimpleCsv(text) {
      // BOM 제거
      if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
      const rows = [];
      let row = [], cur = '', inQ = false, i = 0;
      while (i < text.length) {
        const ch = text[i];
        if (inQ) {
          if (ch === '\"' && text[i+1] === '\"') { cur += '\"'; i += 2; continue; }
          if (ch === '\"') { inQ = false; i++; continue; }
          cur += ch; i++; continue;
        }
        if (ch === '\"') { inQ = true; i++; continue; }
        if (ch === ',') { row.push(cur); cur = ''; i++; continue; }
        if (ch === '\\r') { i++; continue; }
        if (ch === '\\n') { row.push(cur); rows.push(row); row = []; cur = ''; i++; continue; }
        cur += ch; i++;
      }
      if (cur.length > 0 || row.length > 0) { row.push(cur); rows.push(row); }
      return rows;
    }

    async function openReportPreview(reportType, label) {
      const modal = document.getElementById('report_preview_modal');
      const titleEl = document.getElementById('report_preview_title');
      const bodyEl = document.getElementById('report_preview_body');
      const dlEl = document.getElementById('report_preview_download');
      if (!modal || !bodyEl) return;
      titleEl.textContent = `📄 ${label}${tt('dash.dyn.preview_suffix',' — 미리보기')}`;
      dlEl.href = `/compliance/reports/${reportType}?format=csv`;
      const dlPdfEl = document.getElementById('report_preview_download_pdf');
      if (dlPdfEl) dlPdfEl.href = `/compliance/reports/${reportType}?format=pdf`;
      bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#64748b;padding:24px;text-align:center\">' + tt('dash.dyn.loading_fetch','⏳ 불러오는 중…') + '</div>';
      modal.style.display = 'flex';
      try {
        const res = await fetch(`/compliance/reports/${reportType}?format=csv`);
        if (!res.ok) throw new Error(res.status);
        const text = await res.text();
        const rows = _parseSimpleCsv(text);
        if (rows.length === 0) {
          bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#64748b;padding:24px;text-align:center\">' + tt('dash.dyn.no_data','데이터가 없습니다.') + '</div>';
          return;
        }
        const headers = rows[0] || [];
        const dataRows = rows.slice(1).filter(r => r.length > 0 && !(r.length === 1 && r[0] === ''));
        const limit = 50;
        const shown = dataRows.slice(0, limit);
        const overflowNote = dataRows.length > limit
          ? `<div style=\"color:#94a3b8;font-size:12px;margin-top:10px\">${tt('dash.dyn.report_overflow','… 총 {n}행 중 상위 {limit}행만 표시됩니다. 전체는 CSV 다운로드로 확인하세요.').replace('{n}','<strong style=\\\"color:#e2e8f0\\\">'+dataRows.length+'</strong>').replace('{limit}',limit)}</div>`
          : `<div style=\"color:#94a3b8;font-size:12px;margin-top:10px\">${tt('dash.dyn.report_total_rows','총 {n}행').replace('{n}','<strong style=\\\"color:#e2e8f0\\\">'+dataRows.length+'</strong>')}</div>`;
        const head = '<thead><tr style=\"color:#94a3b8;border-bottom:1px solid #334155;background:#0b1322;position:sticky;top:0\">'
          + headers.map(h => `<th style=\"text-align:left;padding:6px 10px;font-size:12px;white-space:nowrap\">${escapeHtml(h)}</th>`).join('')
          + '</tr></thead>';
        const body = shown.map(r => '<tr style=\"border-bottom:1px solid #1e293b\">'
          + headers.map((_, idx) => `<td style=\"padding:6px 10px;font-size:12px;color:#e2e8f0;white-space:nowrap;max-width:280px;overflow:hidden;text-overflow:ellipsis\" title=\"${escapeHtml(r[idx] || '')}\">${escapeHtml(r[idx] || '')}</td>`).join('')
          + '</tr>').join('');
        bodyEl.innerHTML = `<div style=\"max-height:60vh;overflow:auto;border:1px solid #1e293b;border-radius:6px\"><table style=\"width:100%;border-collapse:collapse\">${head}<tbody>${body}</tbody></table></div>${overflowNote}`;
      } catch (e) {
        bodyEl.innerHTML = `<div class=\"empty\" style=\"color:#f87171;padding:24px;text-align:center\">${tt('dash.dyn.report_load_fail','❌ 리포트를 불러올 수 없습니다: ')}${escapeHtml(String(e.message || e))}</div>`;
      }
    }
    function closeReportPreview() { document.getElementById('report_preview_modal').style.display = 'none'; }

    /* ── 인시던트 CSV 다운로드 안내 ────────────────────────────────────────── */
    function showIncidentCsvNotice(downloadFn) {
      const modal = document.getElementById('incident_csv_notice_modal');
      const btn = document.getElementById('incident_csv_confirm_btn');
      if (!modal || !btn) { downloadFn(); return; }
      btn.onclick = () => { closeIncidentCsvNotice(); downloadFn(); };
      modal.style.display = 'flex';
    }
    function closeIncidentCsvNotice() { document.getElementById('incident_csv_notice_modal').style.display = 'none'; }

    let _crosscheckData = null;

    function _renderCrosscheckHostTable(rows) {
      if (!rows || !rows.length) {
        return '<div class=\"empty\" style=\"padding:12px;color:#94a3b8\">' + tt('dash.dyn.cc.no_assets','해당 자산이 없습니다.') + '</div>';
      }
      const head = '<thead><tr><th style=\"text-align:left;padding:6px 8px;border-bottom:1px solid #233046;color:#94a3b8;font-size:12px\">' + tt('dash.dyn.lbl.hostname','호스트명') + '</th><th style=\"text-align:left;padding:6px 8px;border-bottom:1px solid #233046;color:#94a3b8;font-size:12px\">' + tt('dash.dyn.cc.host_id','호스트 ID') + '</th><th style=\"text-align:left;padding:6px 8px;border-bottom:1px solid #233046;color:#94a3b8;font-size:12px\">' + tt('dash.dyn.cc.source','소스') + '</th></tr></thead>';
      const body = rows.map(r => {
        const sources = (r.sources && r.sources.length) ? r.sources.join(', ') : '<span style=\"color:#fca5a5\">' + tt('dash.dyn.cc.none','없음') + '</span>';
        return `<tr><td style=\"padding:6px 8px;border-bottom:1px solid #1f2937;font-size:13px\">${escapeHtml(r.hostname || '-')}</td><td style=\"padding:6px 8px;border-bottom:1px solid #1f2937;font-size:12px;color:#94a3b8\">${escapeHtml(r.host_id || '-')}</td><td style=\"padding:6px 8px;border-bottom:1px solid #1f2937;font-size:12px\">${sources}</td></tr>`;
      }).join('');
      return `<table style=\"width:100%;border-collapse:collapse\">${head}<tbody>${body}</tbody></table>`;
    }

    function showCrosscheckHosts(kind) {
      if (!_crosscheckData) return;
      const chk = (_crosscheckData.checks || []).find(c => c.id === 'source_coverage');
      if (!chk) return;
      let title = '', desc = '', rows = [];
      if (kind === 'total') {
        title = tt('dash.dyn.cc.total_title','전체 자산') + ' (' + chk.total_hosts + tt('dash.dyn.cc.unit','대') + ')';
        desc = tt('dash.dyn.cc.total_desc','현재 hosts 테이블에 등록된 모든 자산입니다. 각 행의 \"소스\" 컬럼은 host_aliases 에 매핑된 수집 소스를 보여줍니다.');
        rows = chk.all_hosts || [];
      } else if (kind === 'covered') {
        title = tt('dash.dyn.cc.covered_title','소스 커버됨') + ' (' + chk.covered_hosts + tt('dash.dyn.cc.unit','대') + ')';
        desc = tt('dash.dyn.cc.covered_desc','Fleet / Zabbix / Trivy / Wazuh 중 최소 1개 소스에서 관측된 자산입니다.');
        rows = chk.covered || [];
      } else if (kind === 'uncovered') {
        title = tt('dash.dyn.cc.uncovered_title','미관측 자산') + ' (' + chk.uncovered_hosts + tt('dash.dyn.cc.unit','대') + ')';
        desc = tt('dash.dyn.cc.uncovered_desc','어떤 수집 소스에도 매핑되어 있지 않은 자산입니다. host_aliases 등록 또는 정리가 필요합니다.');
        rows = chk.uncovered || [];
      }
      openOverviewModal(title, desc, _renderCrosscheckHostTable(rows));
    }

    async function loadCrosscheck() {
      const area = document.getElementById('crosscheck_area');
      if (!area) return;
      try {
        const res = await fetch('/compliance/crosscheck');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        _crosscheckData = data;
        const checks = data.checks || [];
        area.innerHTML = checks.map(chk => {
          let detail = '';
          if (chk.id === 'zabbix_vs_fleet') {
            const bar1W = Math.max(5, Math.round(chk.zabbix_count / Math.max(chk.zabbix_count + chk.fleet_count, 1) * 100));
            detail = `
              <div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:12px 0\">
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#38bdf8\">${chk.zabbix_count}</div><div style=\"font-size:11px;color:#94a3b8\">Zabbix</div></div>
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#22c55e\">${chk.both_count}</div><div style=\"font-size:11px;color:#94a3b8\">${tt('dash.dyn.cc.both','양쪽 모두')}</div></div>
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#f59e0b\">${chk.fleet_count}</div><div style=\"font-size:11px;color:#94a3b8\">Fleet</div></div>
              </div>
              ${chk.zabbix_only_count > 0 ? '<div style=\"font-size:12px;color:#fca5a5;margin:4px 0\">' + tt('dash.dyn.cc.zabbix_only','⚠️ Zabbix에만 있는 자산: ') + chk.zabbix_only_count + tt('dash.dyn.cc.unit','대') + '</div>' : ''}
              ${chk.fleet_only_count > 0 ? '<div style=\"font-size:12px;color:#fbbf24;margin:4px 0\">' + tt('dash.dyn.cc.fleet_only','⚠️ Fleet에만 있는 자산: ') + chk.fleet_only_count + tt('dash.dyn.cc.unit','대') + '</div>' : ''}
            `;
          } else if (chk.id === 'source_coverage') {
            const covPct = chk.total_hosts > 0 ? (chk.covered_hosts / chk.total_hosts * 100).toFixed(1) : '0.0';
            // 클릭 가능한 숫자 카드 3개: 전체 / 커버됨 / 미관측
            detail = `
              <div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:12px 0\">
                <div role=\"button\" tabindex=\"0\" onclick=\"showCrosscheckHosts('total')\" style=\"text-align:center;cursor:pointer;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 6px;transition:border-color .15s\" onmouseover=\"this.style.borderColor='#38bdf8'\" onmouseout=\"this.style.borderColor='#334155'\">
                  <div style=\"font-size:22px;font-weight:800;color:#38bdf8\">${chk.total_hosts}</div>
                  <div style=\"font-size:11px;color:#94a3b8;text-decoration:underline;text-decoration-style:dotted\">${tt('dash.dyn.cc.total_title','전체 자산')}</div>
                </div>
                <div role=\"button\" tabindex=\"0\" onclick=\"showCrosscheckHosts('covered')\" style=\"text-align:center;cursor:pointer;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 6px;transition:border-color .15s\" onmouseover=\"this.style.borderColor='#22c55e'\" onmouseout=\"this.style.borderColor='#334155'\">
                  <div style=\"font-size:22px;font-weight:800;color:#22c55e\">${chk.covered_hosts}</div>
                  <div style=\"font-size:11px;color:#94a3b8;text-decoration:underline;text-decoration-style:dotted\">${tt('dash.dyn.cc.covered_title','소스 커버됨')}</div>
                </div>
                <div role=\"button\" tabindex=\"0\" onclick=\"showCrosscheckHosts('uncovered')\" style=\"text-align:center;cursor:pointer;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 6px;transition:border-color .15s\" onmouseover=\"this.style.borderColor='#fca5a5'\" onmouseout=\"this.style.borderColor='#334155'\">
                  <div style=\"font-size:22px;font-weight:800;color:${chk.uncovered_hosts > 0 ? '#fca5a5' : '#94a3b8'}\">${chk.uncovered_hosts}</div>
                  <div style=\"font-size:11px;color:#94a3b8;text-decoration:underline;text-decoration-style:dotted\">${tt('dash.dyn.cc.uncovered','미관측')}</div>
                </div>
              </div>
              <div style=\"margin:12px 0\">
                <div style=\"display:flex;justify-content:space-between;font-size:12px;color:#94a3b8;margin-bottom:4px\">
                  <span>${tt('dash.dyn.cc.coverage','커버리지')}</span><span>${covPct}% (${chk.covered_hosts}/${chk.total_hosts})</span>
                </div>
                <div style=\"background:#0f172a;border-radius:6px;height:14px;overflow:hidden\">
                  <div style=\"background:#22c55e;width:${covPct}%;height:100%;border-radius:6px;transition:width .5s\"></div>
                </div>
              </div>
              <div style=\"font-size:11px;color:#64748b;margin-top:8px\">${tt('dash.dyn.cc.click_hint','💡 숫자를 클릭하면 해당 자산 목록을 볼 수 있습니다.')}</div>
            `;
          } else if (chk.id === 'vuln_vs_observation') {
            detail = `
              <div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:12px 0\">
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#ef4444\">${chk.vuln_hosts}</div><div style=\"font-size:11px;color:#94a3b8\">${tt('dash.dyn.cc.vuln_hosts','취약점 자산')}</div></div>
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#22c55e\">${chk.recent_obs_hosts}</div><div style=\"font-size:11px;color:#94a3b8\">${tt('dash.dyn.cc.recent_obs','최근 관측')}</div></div>
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#f59e0b\">${chk.vuln_no_observation_count}</div><div style=\"font-size:11px;color:#94a3b8\">${tt('dash.dyn.cc.no_obs','관측 없음')}</div></div>
              </div>
              ${chk.vuln_no_observation_count > 0 ? '<div style=\"font-size:12px;color:#fca5a5\">' + tt('dash.dyn.cc.vuln_no_obs','⚠️ 취약점이 있으나 최근 30일간 관측 없는 자산: ') + chk.vuln_no_observation_count + tt('dash.dyn.cc.unit','대') + '</div>' : '<div style=\"font-size:12px;color:#22c55e\">' + tt('dash.dyn.cc.all_vuln_obs','✅ 모든 취약점 자산이 최근 관측됨') + '</div>'}
            `;
          } else if (chk.id === 'ldap_summary') {
            detail = `
              <div style=\"display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin:12px 0\">
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#a78bfa\">${chk.total_accounts}</div><div style=\"font-size:11px;color:#94a3b8\">${tt('dash.dyn.cc.total_accounts','전체 계정')}</div></div>
                <div style=\"text-align:center\"><div style=\"font-size:20px;font-weight:800;color:#f59e0b\">${chk.privileged_accounts}</div><div style=\"font-size:11px;color:#94a3b8\">${tt('dash.dyn.cc.privileged_accounts','특권 계정')}</div></div>
              </div>
              <div style=\"font-size:12px;color:#94a3b8\">${tt('dash.dyn.cc.ldap_summary','권한 바인딩: {b}건 · 그룹 멤버십: {g}건').replace('{b}',chk.total_privilege_bindings).replace('{g}',chk.total_group_memberships)}</div>
            `;
          }
          return `<div style=\"background:#0b1220;border:1px solid #233046;border-radius:12px;padding:16px;margin-bottom:12px\">
            <div style=\"font-size:15px;font-weight:700;color:#e2e8f0;margin-bottom:4px\">${escapeHtml(chk.title)}</div>
            <div style=\"font-size:12px;color:#64748b\">${escapeHtml(chk.description)}</div>
            ${detail}
          </div>`;
        }).join('');
      } catch(e) {
        area.innerHTML = `<div class=\"empty\" style=\"color:#f87171\">${tt('dash.dyn.crosscheck_fail','교차 검증 데이터를 불러올 수 없습니다.')}</div>`;
      }
    }

    function _metricCard(label, value, color, sub, big) {
      const subHtml = sub ? `<div class=\"metric-sub\" style=\"color:#64748b;font-size:11px;margin-top:2px\">${escapeHtml(sub)}</div>` : '';
      const valStyle = big ? `color:${color};font-size:44px;font-weight:800;line-height:1.1` : `color:${color}`;
      return `<div class=\"metric-card\" style=\"cursor:default\">
        <div class=\"metric-value\" style=\"${valStyle}\">${value}</div>
        <div class=\"metric-label\">${label}</div>
        ${subHtml}
      </div>`;
    }

    // ── Guides ───────────────────────────────────────────────────────────────
    let currentGuideId = null;
    const guideSubBtns = {};
    const guideSubTabsEl = document.getElementById('guide_sub_tabs');
    const guidePrefs = defaultPreferences.guides || {};

    function buildGuideSubTabs() {
      if (!guideSubTabsEl) return;
      guideSubTabsEl.innerHTML = '';
      Object.keys(guideLabels).forEach((id, idx) => {
        if (guidePrefs[id] === false) return; // hidden by admin
        const btn = document.createElement('button');
        btn.id = 'guide_tab_' + id;
        btn.textContent = tt('dash.dyn.guide.' + id, guideLabels[id]);
        btn.style.cssText = 'background:none;border:none;border-bottom:2px solid transparent;padding:8px 18px;color:#94a3b8;font-size:13px;font-weight:600;cursor:pointer;border-radius:0;margin-bottom:-1px;';
        btn.addEventListener('click', () => switchGuideTab(id));
        guideSubTabsEl.appendChild(btn);
        guideSubBtns[id] = btn;
        if (currentGuideId === null) currentGuideId = id; // first visible
      });
    }

    function switchGuideTab(guideId) {
      currentGuideId = guideId;
      Object.entries(guideSubBtns).forEach(([id, btn]) => {
        if (!btn) return;
        const active = id === guideId;
        btn.style.borderBottomColor = active ? '#38bdf8' : 'transparent';
        btn.style.color = active ? '#38bdf8' : '#94a3b8';
      });
      loadGuide(guideId);
    }

    function renderMarkdownLite(text) {
      // 매우 간단한 마크다운 렌더러: 헤더/볼드/코드블록/체크박스 지원
      return escapeHtml(text)
        .replace(/^### (.+)$/gm, '<h3 style="color:#a3e635;margin:16px 0 6px;font-size:14px">$1</h3>')
        .replace(/^## (.+)$/gm, '<h2 style="color:#38bdf8;margin:20px 0 8px;font-size:16px">$1</h2>')
        .replace(/^#### (.+)$/gm, '<h4 style="color:#94a3b8;margin:12px 0 4px;font-size:13px">$1</h4>')
        .replace(/\\*\\*(.+?)\\*\\*/g, '<strong style="color:#f1f5f9">$1</strong>')
        .replace(/`([^`]+)`/g, '<code style="background:#1e293b;padding:1px 6px;border-radius:4px;color:#a3e635;font-size:12px">$1</code>')
        .replace(/^```[\\s\\S]*?```/gm, m => `<pre style="background:#0f2035;border:1px solid #334155;border-radius:6px;padding:12px 14px;overflow-x:auto;font-size:12px;color:#86efac;margin:8px 0">${m.slice(m.indexOf('\\n')+1, m.lastIndexOf('\\n'))}</pre>`)
        .replace(/^- \\[ \\] (.+)$/gm, '<div style="display:flex;gap:8px;align-items:flex-start;padding:2px 0"><span style="color:#fde68a;margin-top:1px">☐</span><span>$1</span></div>')
        .replace(/^- \\[x\\] (.+)$/gm, '<div style="display:flex;gap:8px;align-items:flex-start;padding:2px 0"><span style="color:#86efac;margin-top:1px">☑</span><span style="color:#64748b;text-decoration:line-through">$1</span></div>')
        .replace(/^- (.+)$/gm, '<div style="padding:2px 0 2px 12px;color:#cbd5e1">• $1</div>')
        .replace(/^---$/gm, '<hr style="border:none;border-top:1px solid #334155;margin:16px 0">')
        .replace(/\\n/g, '\\n');
    }

    async function loadGuide(guideId) {
      const titleEl = document.getElementById('guide_content_title');
      const bodyEl = document.getElementById('guide_content_body');
      const updatedEl = document.getElementById('guide_updated_at');
      if (!titleEl || !bodyEl) return;
      bodyEl.innerHTML = '<span style="color:#64748b">' + tt('dash.dyn.loading','로딩 중…') + '</span>';
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`);
        if (!res.ok) throw new Error(res.status);
        const g = await res.json();
        titleEl.textContent = g.title || guideId;
        updatedEl.textContent = g.updated_at ? `${tt('dash.dyn.guide_updated_prefix','수정: ')}${g.updated_at.slice(0,10)}` : tt('dash.dyn.default_content','(기본 내용)');
        bodyEl.innerHTML = renderMarkdownLite(g.content || '');
      } catch(e) {
        bodyEl.innerHTML = `<span style="color:#fca5a5">${tt('dash.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
    }

    // ── Role-based tab visibility ─────────────────────────────────────────────
    const ROLE_LABELS = { admin: tt('admin.dyn.rolename.admin','어드민'), security: tt('admin.dyn.rolename.security','보안담당자'), monitor: tt('admin.dyn.rolename.monitor','서버모니터'), auditor: tt('admin.dyn.rolename.auditor','감사자'), helpdesk: tt('admin.dyn.rolename.helpdesk','헬프데스크'), user: tt('admin.dyn.rolename.user','사용자') };
    let _currentUserRole = 'user';
    let _currentProfile = { display_name: '', department: '', assigned_servers: [] };
    // Grafana 접근 등급: admin/monitor → full, security → limited, auditor/helpdesk/user → summary only
    const _GRAFANA_FULL_ROLES = ['admin', 'monitor'];
    const _GRAFANA_LIMITED_ROLES = ['security'];
    function _canViewGrafanaFull() { return _GRAFANA_FULL_ROLES.includes(_currentUserRole); }
    function _canViewGrafanaLimited() { return _GRAFANA_LIMITED_ROLES.includes(_currentUserRole); }
    function _canViewGrafana() { return _canViewGrafanaFull() || _canViewGrafanaLimited(); }
    /* 위험성 평가는 보안 판단이라 어드민/보안 담당자만. 인프라·헬프데스크는 취약점/조치 현황만 열람. */
    const _RISK_ROLES = ['admin', 'security'];
    function _canAssessRisk() { return _RISK_ROLES.includes(_currentUserRole); }
    window._canAssessRisk = _canAssessRisk;
    function _applyRiskGating() {
      const rc = document.getElementById('risk_matrix_card');
      if (rc) rc.style.display = _canAssessRisk() ? '' : 'none';
    }
    window._applyRiskGating = _applyRiskGating;
    /* 증적 층(증적 공백 + CSOP 증적)도 보안 판단이라 admin·security 만. /evidence·/dashboard/evidence-gaps 서버 정책과 동일. */
    const _EVIDENCE_ROLES = ['admin', 'security'];
    function _canViewEvidence() { return _EVIDENCE_ROLES.includes(_currentUserRole); }
    function _applyEvidenceGating() {
      const show = _canViewEvidence();
      ['evidence_gap_card', 'control_tree_card'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = show ? '' : 'none';
      });
      if (show) { loadEvidenceGaps(); loadControlTree(); }
    }
    const _CTL_SOURCE_COLOR = { zabbix:'#38bdf8', trivy:'#f59e0b', wazuh:'#a78bfa', fleet:'#34d399', loki:'#f472b6', mori:'#94a3b8' };
    async function loadControlTree() {
      const box = document.getElementById('control_tree_box');
      if (!box) return;
      try {
        const res = await fetch('/controls/tree');
        if (!res.ok) { box.innerHTML = `<div class=\"empty\">${tt('dash.ctl.err','통제 카탈로그를 불러오지 못했습니다.')}</div>`; return; }
        const data = await res.json();
        const lang = (window.lang === 'en') ? 'en' : 'ko';
        const cov = data.coverage || {};
        const covEl = document.getElementById('control_tree_coverage');
        if (covEl && cov.lite && cov.full) {
          covEl.textContent = `lite ${cov.lite.pct}% (${cov.lite.covered}/${cov.lite.total}) · full ${cov.full.pct}% (${cov.full.covered}/${cov.full.total})`;
        }
        const fwLabel = { 'isms-p': 'ISMS-P', 'iso27001': 'ISO 27001:2022' };
        const badge = (s) => { const c=_CTL_SOURCE_COLOR[s]||'#64748b'; return `<span style=\"background:${c}22;color:${c};border:1px solid ${c}55;padding:0 6px;border-radius:5px;font-size:10px;margin-left:3px\">${escapeHtml(s)}</span>`; };
        const ctrlRow = (c) => {
          const title = (lang==='en' ? c.title_en : c.title_ko) || c.title_ko || c.title_en || '';
          const dim = c.mapped ? '' : 'opacity:0.5;';
          const srcs = (c.evidence_sources||[]).map(badge).join('');
          const enc = encodeURIComponent(c.id);
          const clickable = c.mapped ? 'cursor:pointer' : '';
          const pdf = `<a href=\"/controls/detail/${enc}/evidence.pdf\" target=\"_blank\" title=\"${tt('dash.ctl.pdf','증적 팩 PDF')}\" style=\"margin-left:6px;text-decoration:none;font-size:11px\">📄</a>`;
          return `<div style=\"padding:3px 0;${dim}\"><span onclick=\"toggleControlDetail('${enc}', this)\" style=\"${clickable}\"><span style=\"color:#64748b;font-size:11px\">${escapeHtml(c.id)}</span> ${escapeHtml(title)}${srcs}</span>${pdf}<div class=\"ctl-detail\" style=\"display:none;margin:4px 0 8px 16px;padding:6px 10px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;font-size:12px\"></div></div>`;
        };
        let html = '';
        (data.tree || []).forEach(fw => {
          let covered = 0, total = 0;
          fw.domains.forEach(d => d.sections.forEach(s => s.controls.forEach(c => { total++; if (c.mapped) covered++; })));
          html += `<div style=\"margin-top:10px;font-weight:700;color:#e2e8f0\">${escapeHtml(fwLabel[fw.framework]||fw.framework)} <span style=\"color:#94a3b8;font-weight:400;font-size:12px\">(${covered}/${total})</span></div>`;
          fw.domains.forEach(d => {
            let dc=0, dt=0; d.sections.forEach(s => s.controls.forEach(c => { dt++; if (c.mapped) dc++; }));
            html += `<details style=\"margin:4px 0 0 4px\"><summary style=\"cursor:pointer;color:#cbd5e1;font-size:13px\">${escapeHtml(d.domain)} <span style=\"color:#64748b;font-size:11px\">(${dc}/${dt})</span></summary>`;
            d.sections.forEach(s => {
              html += `<div style=\"margin:4px 0 4px 10px\"><div style=\"color:#94a3b8;font-size:12px;margin:4px 0\">${escapeHtml(s.section||'')}</div>`;
              html += s.controls.map(ctrlRow).join('') + `</div>`;
            });
            html += `</details>`;
          });
        });
        box.innerHTML = html || `<div class=\"empty\">${tt('dash.ctl.none','카탈로그가 비어 있습니다.')}</div>`;
      } catch(e) { box.innerHTML = `<div class=\"empty\">${tt('dash.ctl.err','통제 카탈로그를 불러오지 못했습니다.')}</div>`; }
    }
    window.loadControlTree = loadControlTree;
    async function toggleControlDetail(enc, el) {
      const box = el.parentElement.querySelector('.ctl-detail');
      if (!box) return;
      if (box.style.display !== 'none') { box.style.display = 'none'; return; }
      box.style.display = 'block';
      box.innerHTML = `<span class=\"empty\">${tt('dash.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/controls/detail/' + enc);
        if (!res.ok) { box.innerHTML = `<span class=\"empty\">${tt('dash.ctl.err','통제 카탈로그를 불러오지 못했습니다.')}</span>`; return; }
        const d = await res.json();
        const lang = (window.lang === 'en') ? 'en' : 'ko';
        let h = '';
        if ((d.evidence_live||[]).length) {
          h += `<div style=\"font-weight:700;color:#5eead4;margin-bottom:2px\">${tt('dash.ctl.live','실증적 (현재)')}</div>`;
          h += d.evidence_live.map(e => {
            const lbl = (lang==='en'?e.label_en:e.label_ko) || e.source;
            const sm = (lang==='en'?e.summary_en:e.summary_ko) || '-';
            return `<div onclick=\"switchTab('${e.tab}')\" style=\"cursor:pointer;color:#cbd5e1;padding:1px 0\">• ${escapeHtml(lbl)}: <b>${escapeHtml(sm)}</b> ↗</div>`;
          }).join('');
        }
        if ((d.mapped_to||[]).length) {
          h += `<div style=\"font-weight:700;color:#93c5fd;margin:6px 0 2px\">${tt('dash.ctl.map','매핑')}</div>`;
          h += d.mapped_to.map(m => `<div style=\"color:#94a3b8\">↔ ${escapeHtml(m.id)} ${escapeHtml((lang==='en'?m.title_en:m.title_ko)||'')} <span style=\"font-size:10px\">(${escapeHtml(m.relation)})</span></div>`).join('');
        }
        if ((d.defects||[]).length) {
          h += `<div style=\"font-weight:700;color:#f59e0b;margin:6px 0 2px\">${tt('dash.ctl.def','관련 결함')}</div>`;
          h += d.defects.map(x => { const gc=(typeof x.gap_count==='number')?` · ${tt('dash.ctl.gap','현재 공백')} ${x.gap_count}`:''; return `<div style=\"color:#cbd5e1\">⚠ ${escapeHtml((lang==='en'?x.title_en:x.title_ko)||'')}${escapeHtml(gc)}</div>`; }).join('');
        }
        h += `<div style=\"margin-top:6px\"><a href=\"/controls/detail/${enc}/evidence.pdf\" target=\"_blank\" style=\"color:#38bdf8;text-decoration:none\">📄 ${tt('dash.ctl.pdf','증적 팩 PDF')}</a></div>`;
        box.innerHTML = h || `<span class=\"empty\">—</span>`;
      } catch(e) { box.innerHTML = `<span class=\"empty\">${tt('dash.ctl.err','통제 카탈로그를 불러오지 못했습니다.')}</span>`; }
    }
    window.toggleControlDetail = toggleControlDetail;
    window._applyEvidenceGating = _applyEvidenceGating;
    async function loadEvidenceGaps() {
      const box = document.getElementById('evidence_gap_box');
      if (!box) return;
      try {
        const res = await fetch('/dashboard/evidence-gaps');
        if (!res.ok) { box.innerHTML = `<div class=\"empty\">${tt('dash.gap.err','증적 공백을 불러오지 못했습니다.')}</div>`; return; }
        const data = await res.json();
        const g = data.gaps || {};
        const tsEl = document.getElementById('evidence_gap_ts');
        if (tsEl && data.generated_at) tsEl.textContent = tt('dash.gap.updated','기준 ') + String(data.generated_at).slice(0,16).replace('T',' ');
        const tiles = [
          { key:'vuln_pending', icon:'⚠️', label: tt('dash.gap.vuln','조치 안 된 Critical/High'), tab:'compliance', color:'#f87171' },
          { key:'exceptions_expiring', icon:'⏰', label: tt('dash.gap.exc','예외 만료 D-7 이내'), tab:'assets', color:'#fbbf24' },
          { key:'untriaged_alerts', icon:'🚨', label: tt('dash.gap.alert','미트리아지 alert'), tab:'triage', color:'#fb923c' },
          { key:'overdue', icon:'⌛', label: tt('dash.gap.overdue','조치 기한 초과'), tab:'compliance', color:'#f472b6' },
          { key:'unmapped_assets', icon:'🧭', label: tt('dash.gap.unmapped','미매핑 자산 (자산 대사)'), tab:'assets', color:'#5eead4' },
          { key:'control_pending', icon:'📋', label: tt('dash.gap.control','미조치 통제'), tab:'compliance', color:'#60a5fa' },
        ];
        box.innerHTML = `<div style=\"display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px\">` +
          tiles.map(t => {
            const n = Number(g[t.key] || 0);
            return `<div onclick=\"switchTab('${t.tab}')\" role=\"button\" tabindex=\"0\" style=\"cursor:pointer;background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:4px\">
              <div style=\"font-size:12px;color:#94a3b8\">${t.icon} ${escapeHtml(t.label)}</div>
              <div style=\"font-size:24px;font-weight:800;color:${n>0?t.color:'#334155'}\">${n}</div>
            </div>`;
          }).join('') + `</div>`;
      } catch(e) { box.innerHTML = `<div class=\"empty\">${tt('dash.gap.err','증적 공백을 불러오지 못했습니다.')}</div>`; }
    }
    window.loadEvidenceGaps = loadEvidenceGaps;
    async function applyRoleBasedTabs() {
      try {
        const res = await fetch('/auth/me');
        if (!res.ok) return;
        const me = await res.json();
        _currentUserRole = me.role || 'user';
        _currentProfile = {
          display_name: me.display_name || '',
          department: me.department || '',
          assigned_servers: Array.isArray(me.assigned_servers) ? me.assigned_servers : [],
        };
        const allowed = me.allowed_tabs || [];
        ['dashboard', 'triage', 'incidents', 'assets', 'compliance', 'guides'].forEach(tab => {
          const navBtn = document.querySelector(`.tabs-nav [data-tab="${tab}"]`);
          const bnBtn = document.querySelector(`.bottom-nav [data-tab="${tab}"]`);
          const visible = allowed.includes(tab);
          if (navBtn) navBtn.style.display = visible ? '' : 'none';
          if (bnBtn) bnBtn.style.display = visible ? '' : 'none';
        });
        // 현재 활성 탭이 허용되지 않으면 첫 번째 허용 탭으로 전환
        const activeNavBtn = document.querySelector('.tabs-nav button.active');
        const activeTab = activeNavBtn ? activeNavBtn.dataset.tab : 'dashboard';
        if (allowed.length > 0 && !allowed.includes(activeTab)) {
          switchTab(allowed[0]);
        }
        const roleLabel = ROLE_LABELS[me.role] || me.role;
        const heroP = document.querySelector('.hero p');
        if (heroP && me.username) {
          heroP.innerHTML = `${tt('dash.dyn.welcome_prefix','환영합니다, ')}<strong style="color:#38bdf8">${escapeHtml(me.username)}</strong> <span style="background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:6px;font-size:12px">${escapeHtml(roleLabel)}</span>`;
        }
        const badge = document.getElementById('ui_user_badge');
        if (badge && me.username) { badge.removeAttribute('data-i18n'); badge.textContent = me.username; }
        _applyRiskGating();
        _applyEvidenceGating();
        if (document.getElementById('security_hero_body')) renderSecurityHero();
      } catch(e) { /* 비로그인 상태에서도 대시보드는 동작 */ }
    }

    // ── 계정 메뉴 (언어 설정 등) ───────────────────────────────────────────────
    window.toggleAccountMenu = function() {
      const m = document.getElementById('account_menu');
      if (m) m.style.display = (!m.style.display || m.style.display === 'none') ? 'block' : 'none';
    };
    document.addEventListener('click', function(e) {
      const wrap = document.querySelector('.account-wrap');
      const menu = document.getElementById('account_menu');
      if (wrap && menu && !wrap.contains(e.target)) menu.style.display = 'none';
    });

    // ── 프로필 편집 모달 ───────────────────────────────────────────────────────
    window.openProfileModal = function() {
      const menu = document.getElementById('account_menu');
      if (menu) menu.style.display = 'none';
      document.getElementById('profile_display_name').value = _currentProfile.display_name || '';
      document.getElementById('profile_department').value = _currentProfile.department || '';
      document.getElementById('profile_assigned_servers').value = (_currentProfile.assigned_servers || []).join('\\n');
      const st = document.getElementById('profile_modal_status');
      st.textContent = ''; st.style.color = '#94a3b8';
      document.getElementById('profile_modal').style.display = 'flex';
    };
    window.closeProfileModal = function() { document.getElementById('profile_modal').style.display = 'none'; };
    window.saveProfile = async function() {
      const st = document.getElementById('profile_modal_status');
      const display_name = document.getElementById('profile_display_name').value.trim();
      const department = document.getElementById('profile_department').value.trim();
      const assigned_servers = document.getElementById('profile_assigned_servers').value;
      st.style.color = '#94a3b8';
      st.textContent = tt('dash.profile.saving', '저장 중...');
      try {
        const res = await fetch('/auth/profile', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ display_name, department, assigned_servers })
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        _currentProfile = {
          display_name: data.display_name || '',
          department: data.department || '',
          assigned_servers: Array.isArray(data.assigned_servers) ? data.assigned_servers : [],
        };
        st.style.color = '#34d399';
        st.textContent = tt('dash.profile.saved', '저장 완료 ✓');
        if (typeof renderMyServers === 'function') renderMyServers();
        setTimeout(closeProfileModal, 700);
      } catch(e) {
        st.style.color = '#f87171';
        st.textContent = tt('dash.profile.save_fail', '저장 실패: ') + e.message;
      }
    };

    // ── NLQ 핸들러 ─────────────────────────────────────────────────────────
    // nlq_textarea, nlq_interpret_btn 등 모든 NLQ 요소는 script 태그 이후의 dialog 안에 있음.
    // DOMContentLoaded 이후(전체 HTML 파싱 완료)에 요소를 얻고 핸들러를 등록한다.
    document.addEventListener('DOMContentLoaded', () => {
      nlqTextarea      = document.getElementById('nlq_textarea');
      nlqInterpretBtn  = document.getElementById('nlq_interpret_btn');
      nlqRunBtn        = document.getElementById('nlq_run_btn');
      nlqCsvBtn        = document.getElementById('nlq_csv_btn');
      nlqInterpretResult = document.getElementById('nlq_interpret_result');
      nlqResultArea    = document.getElementById('nlq_result_area');

      document.getElementById('nlq_guide_link')?.addEventListener('click', (e) => { e.preventDefault(); openNlqGuideModal(); });

      nlqInterpretBtn?.addEventListener('click', async () => {
        const text = nlqTextarea.value.trim();
        if (!text) { showInfoModal(tt('dash.dyn.nlq.need_input_title','입력 필요'), tt('dash.dyn.nlq.need_input_msg','질의할 내용을 입력해 주세요.')); return; }
        nlqInterpretResult.textContent = tt('dash.dyn.nlq.interpreting','해석 중...');
        try {
          const res = await fetch('/interpret', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text}) });
          const data = await res.json();
          if (!res.ok) { nlqInterpretResult.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${data.detail || res.status}`; return; }
          lastInterpretedPayload = { intent: data.intent, scope: data.scope || {time_range:'24h'}, filters: data.filters || {} };
          nlqInterpretResult.textContent = `${tt('dash.dyn.nlq.interpret_result','해석 결과')}: ${data.intent} (${data.recognized ? tt('dash.dyn.nlq.recognized','인식됨') : tt('dash.dyn.nlq.fuzzy','유사 매칭')})${data.warnings?.length ? ' ⚠ ' + data.warnings.join(', ') : ''}`;
          logUserAction('INTERPRET', text.substring(0, 200));
          if (!data.recognized) { openNlqGuideModal(); }
        } catch (err) { nlqInterpretResult.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${err.message}`; }
      });

      nlqRunBtn?.addEventListener('click', async () => {
        nlqResultArea.textContent = tt('dash.dyn.running','실행 중...');
        logUserAction('QUERY', (nlqTextarea?.value||'').substring(0, 200));
        const result = await runNlqQuery('json');
        if (!result) { nlqResultArea.textContent = ''; return; }
        renderNlqResult(result);
      });

      nlqCsvBtn?.addEventListener('click', async () => {
        await runNlqQuery('csv');
      });

      // NLQ FAB 열기/닫기
      const nlqFabDialog = document.getElementById('nlq_fab_dialog');
      document.getElementById('nlq_fab_btn')?.addEventListener('click', () => {
        if (nlqFabDialog && typeof nlqFabDialog.showModal === 'function') nlqFabDialog.showModal();
        else if (nlqFabDialog) nlqFabDialog.setAttribute('open', 'open');
      });
      document.getElementById('nlq_fab_close')?.addEventListener('click', () => {
        if (nlqFabDialog && nlqFabDialog.open) nlqFabDialog.close();
      });
    });

    async function initialize() {
      try { await loadPreferences(); } catch(e) { console.error('[MORI] loadPreferences error:', e); }
      try { await applyRoleBasedTabs(); } catch(e) { console.error('[MORI] applyRoleBasedTabs error:', e); }
      try { await loadDashboard(); } catch(e) {
        console.error('[MORI] loadDashboard error:', e);
        dashboardStatusEl.textContent = `${tt('dash.dyn.dash_load_fail', '❌ 대시보드 로드 실패')}: ${e.message}`;
        // 빈 데이터라도 placeholder 표시
        if (!sourceCoverageEl.children.length) sourceCoverageEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_source_connected','데이터 소스가 아직 연결되지 않았습니다.') + '</div>';
        if (!latestStatusEl.children.length || latestStatusEl.querySelector('.empty')) latestStatusEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_host_api','호스트 데이터 없음 — API 연결을 확인하세요.') + '</div>';
        if (!riskSummaryEl.children.length || riskSummaryEl.querySelector('.empty')) riskSummaryEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_risk_summary','위험 요약 데이터 없음') + '</div>';
        if (!recentActivityEl.children.length || recentActivityEl.querySelector('.empty')) recentActivityEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_recent_activity','최근 활동 데이터 없음') + '</div>';
        overviewCardsEl.innerHTML = '<div class=\"empty\" style=\"padding:16px;color:#fca5a5\">' + tt('dash.dyn.dash_load_fail_full','⚠️ 대시보드 데이터를 불러올 수 없습니다. 서버 상태를 확인하세요.') + '</div>';
      }
    }

    initialize();
  </script>

  <!-- ── NLQ Floating Action Button ───────────────────────────────────── -->
  <button class=\"nlq-fab\" id=\"nlq_fab_btn\" title=\"자연어 질의 (NLQ)\" data-i18n=\"dash.nlq.fab_btn\" data-i18n-title=\"dash.nlq.fab_title\">💬 NLQ 질의</button>

  <dialog id=\"nlq_fab_dialog\" class=\"nlq-dialog\">
    <div class=\"nlq-dialog-body\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px\">
        <h3 style=\"margin:0;font-size:18px\" data-i18n=\"dash.nlq.dialog_title\">💬 자연어 질의 (NLQ)</h3>
        <button id=\"nlq_fab_close\" class=\"secondary\" style=\"padding:4px 12px\" data-i18n=\"dash.f.close\">닫기</button>
      </div>
      <div style=\"color:#94a3b8;font-size:13px;margin-bottom:10px\"><span data-i18n=\"dash.nlq.dialog_desc\">자연스럽게 질문하거나 예시 형식으로 입력하면 해석합니다.</span> <a href=\"#\" id=\"nlq_guide_link\" style=\"color:#7dd3fc;\" data-i18n=\"dash.nlq.guide_link\">가이드 ↗</a></div>
      <textarea id=\"nlq_textarea\" rows=\"3\" style=\"width:100%;box-sizing:border-box;background:#0b1220;color:#e5e7eb;border:1px solid #334155;border-radius:8px;padding:10px;font-size:14px;resize:vertical;\" placeholder=\"예: 오프라인 호스트 보여줘 / 최근 24시간 wazuh high alert 요약\" data-i18n-placeholder=\"dash.nlq.textarea_ph\"></textarea>
      <div id=\"nlq_interpret_result\" style=\"margin:8px 0;color:#7dd3fc;font-size:13px;\"></div>
      <div style=\"display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;\">
        <button type=\"button\" id=\"nlq_interpret_btn\" class=\"secondary\">Interpret</button>
        <button type=\"button\" id=\"nlq_run_btn\">Run Query</button>
        <button type=\"button\" id=\"nlq_csv_btn\" class=\"secondary\" style=\"display:none;\">Download CSV</button>
      </div>
      <div id=\"nlq_result_area\" style=\"margin-top:12px;\"></div>
    </div>
  </dialog>
  __I18N_SCRIPT__
</body>
</html>"""
    return (
        html.replace("__DOCS_PORTAL_URL__", docs_url)
        .replace("__USER_DASHBOARD_PREFS_JSON__", default_preferences_json)
        .replace("__CARD_LABELS_JSON__", card_labels_json)
        .replace("__SECTION_LABELS_JSON__", section_labels_json)
        .replace("__NLQ_GUIDE_EXAMPLES__", nlq_guide_examples_json)
        .replace("__FLEET_UI_URL__", fleet_ui_url)
        .replace("__ZABBIX_UI_URL__", zabbix_ui_url)
        .replace("__WAZUH_UI_URL__", wazuh_ui_url)
        .replace("__GUIDE_LABELS_JSON__", guide_labels_json)
        .replace("__I18N_TOGGLE__", _i18n_toggle_html(fixed=False))
        .replace("__I18N_SCRIPT__", _i18n_script(_DASHBOARD_I18N))
    )


def render_login_html(error: str = "", next_url: str = "/ui") -> str:
    """로그인 페이지 HTML 반환 (KO/EN 토글 지원)."""
    error_html = f'<div class="login-error">{error}</div>' if error else ""
    i18n_runtime = _i18n_script(_LOGIN_I18N)
    toggle_widget = _i18n_toggle_html()
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title data-i18n-doctitle="login.doctitle">MORI SOC — 로그인</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a1628; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
    .login-card {{ background: #0f2035; border: 1px solid #1e3a5f; border-radius: 16px; padding: 40px 36px;
                   width: 100%; max-width: 400px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }}
    .login-logo {{ text-align: center; margin-bottom: 28px; }}
    .login-logo h1 {{ font-size: 28px; font-weight: 800; color: #7dd3fc; letter-spacing: -0.5px; }}
    .login-logo p {{ font-size: 13px; color: #64748b; margin-top: 6px; }}
    label {{ display: block; font-size: 12px; color: #94a3b8; margin-bottom: 5px; font-weight: 600; letter-spacing: .5px; }}
    input {{ width: 100%; background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px;
             color: #e2e8f0; padding: 10px 14px; font-size: 14px; outline: none; transition: border-color .2s; }}
    input:focus {{ border-color: #3b82f6; }}
    .field {{ margin-bottom: 16px; }}
    .btn {{ width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 15px; font-weight: 700;
            cursor: pointer; transition: all .2s; margin-top: 8px; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .login-error {{ background: #450a0a; border: 1px solid #991b1b; color: #fca5a5; border-radius: 8px;
                    padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; color: #64748b; }}
    .login-footer a {{ color: #7dd3fc; text-decoration: none; }}
    .status-line {{ font-size: 12px; color: #94a3b8; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  {toggle_widget}
  <div class="login-card">
    <div class="login-logo">
      <h1>🛡️ MORI SOC</h1>
      <p data-i18n="login.brand_sub">Audit-Ready Security Operations</p>
    </div>
    {error_html}
    <div class="field"><label data-i18n="login.label.username">아이디</label><input id="username" type="text" autocomplete="username" placeholder="admin" data-i18n-placeholder="login.placeholder.username" /></div>
    <div class="field"><label data-i18n="login.label.password">비밀번호</label><input id="password" type="password" autocomplete="current-password" placeholder="••••••" /></div>
    <button class="btn btn-primary" id="login_btn" data-i18n="login.button.login">로그인</button>
    <div class="status-line" id="status"></div>
    <div class="login-footer">
      <span data-i18n="login.footer.no_account">계정이 없으신가요?</span> <a href="/signup-request" data-i18n="login.footer.signup_link">가입 요청 →</a>
    </div>
  </div>
  {i18n_runtime}
  <script>
    const nextUrl = {json.dumps(next_url)};
    async function doLogin() {{
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;
      const statusEl = document.getElementById('status');
      if (!username || !password) {{ statusEl.textContent = window.t('login.error.empty'); return; }}
      statusEl.textContent = window.t('login.status.loading');
      try {{
        const res = await fetch('/auth/login', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{username, password}})
        }});
        if (res.ok) {{
          window.location.href = nextUrl || '/ui';
        }} else {{
          const d = await res.json().catch(() => ({{}}));
          statusEl.textContent = d.detail || window.t('login.error.invalid');
        }}
      }} catch(e) {{ statusEl.textContent = window.t('login.error.network') + e.message; }}
    }}
    document.getElementById('login_btn').addEventListener('click', doLogin);
    document.addEventListener('keydown', e => {{ if (e.key === 'Enter') doLogin(); }});
  </script>
</body>
</html>"""


def render_signup_request_html(success: bool = False) -> str:
    """가입 요청 페이지 HTML 반환 (KO/EN 토글 지원)."""
    body_html = """
    <p data-i18n="signup.intro" style="color:#94a3b8;font-size:14px;margin-bottom:20px;">계정 사용을 원하시면 아래 정보를 입력하고 운영자에게 가입을 요청하세요.</p>
    <div class="field"><label data-i18n="signup.label.name">이름 *</label><input id="req_name" placeholder="홍길동" data-i18n-placeholder="signup.placeholder.name" /></div>
    <div class="field"><label data-i18n="signup.label.email">이메일 *</label><input id="req_email" type="email" placeholder="hong@company.com" /></div>
    <div class="field"><label data-i18n="signup.label.dept">부서</label><input id="req_dept" placeholder="보안팀" data-i18n-placeholder="signup.placeholder.dept" /></div>
    <div class="field"><label data-i18n="signup.label.reason">요청 사유</label><textarea id="req_reason" style="width:100%;background:#0a1628;border:1px solid #1e3a5f;border-radius:8px;color:#e2e8f0;padding:10px 14px;font-size:14px;min-height:80px;outline:none;" placeholder="업무 목적 및 필요 권한을 간략히 작성해주세요." data-i18n-placeholder="signup.placeholder.reason"></textarea></div>
    <button class="btn btn-primary" id="submit_btn" data-i18n="signup.button.submit">가입 요청 제출</button>
    <div class="status-line" id="status"></div>
    <div class="login-footer"><a href="/login" data-i18n="signup.back">← 로그인으로 돌아가기</a></div>
    <script>
      document.getElementById('submit_btn').addEventListener('click', async () => {
        const name = document.getElementById('req_name').value.trim();
        const email = document.getElementById('req_email').value.trim();
        const department = document.getElementById('req_dept').value.trim();
        const reason = document.getElementById('req_reason').value.trim();
        const statusEl = document.getElementById('status');
        if (!name || !email) { statusEl.textContent = window.t('signup.error.required'); return; }
        statusEl.textContent = window.t('signup.status.submitting');
        try {
          const res = await fetch('/auth/signup-request', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, email, department, reason})
          });
          if (res.ok) {
            const title = window.t('signup.success.title');
            const bodyHtml = window.t('signup.success.body');
            const back = window.t('signup.back');
            document.querySelector('.login-card').innerHTML = '<div style="text-align:center;padding:40px 0"><div style="font-size:48px">✅</div><h2 style="color:#22c55e;margin:16px 0 8px">' + title + '</h2><p style="color:#94a3b8">' + bodyHtml + '</p><div style="margin-top:24px"><a href="/login" style="color:#7dd3fc">' + back + '</a></div></div>';
          } else {
            const d = await res.json().catch(() => ({}));
            statusEl.textContent = d.detail || window.t('signup.error.generic');
          }
        } catch(e) { statusEl.textContent = window.t('signup.error.network') + e.message; }
      });
    </script>""" if not success else '<div style="text-align:center;padding:40px 0"><div style="font-size:48px">✅</div><h2 data-i18n="signup.success.title" style="color:#22c55e">가입 요청 완료</h2><p data-i18n-html="signup.success.body" style="color:#94a3b8;margin-top:8px">운영자 승인 후 계정이 생성됩니다.<br>이메일로 안내드리겠습니다.</p><div style="margin-top:24px"><a href="/login" data-i18n="signup.back" style="color:#7dd3fc">← 로그인으로 돌아가기</a></div></div>'
    i18n_runtime = _i18n_script(_SIGNUP_I18N)
    toggle_widget = _i18n_toggle_html()
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title data-i18n-doctitle="signup.doctitle">MORI SOC — 가입 요청</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a1628; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
    .login-card {{ background: #0f2035; border: 1px solid #1e3a5f; border-radius: 16px; padding: 40px 36px;
                   width: 100%; max-width: 440px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }}
    .login-logo {{ text-align: center; margin-bottom: 24px; }}
    .login-logo h1 {{ font-size: 24px; font-weight: 800; color: #7dd3fc; }}
    label {{ display: block; font-size: 12px; color: #94a3b8; margin-bottom: 5px; font-weight: 600; letter-spacing: .5px; }}
    input {{ width: 100%; background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px;
             color: #e2e8f0; padding: 10px 14px; font-size: 14px; outline: none; transition: border-color .2s; }}
    input:focus {{ border-color: #3b82f6; }}
    .field {{ margin-bottom: 14px; }}
    .btn {{ width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 15px; font-weight: 700;
            cursor: pointer; transition: all .2s; margin-top: 4px; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; }}
    .login-footer a {{ color: #7dd3fc; text-decoration: none; }}
    .status-line {{ font-size: 12px; color: #ef4444; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  {toggle_widget}
  <div class="login-card">
    <div class="login-logo"><h1 data-i18n="signup.brand_title">🛡️ MORI SOC 가입 요청</h1></div>
    {body_html}
  </div>
  {i18n_runtime}
</body>
</html>"""
