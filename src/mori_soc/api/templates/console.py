"""어드민 콘솔 페이지 (render_query_console_html)."""
from mori_soc.api.templates._common import *  # noqa: F401,F403


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
  <title data-i18n-doctitle=\"admin.doctitle\">MORI 관리자 콘솔</title>
  <style>
    :root { color-scheme: light; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #ffffff; color: #111827; }
    .wrap { max-width: 1440px; margin: 0 auto; padding: 16px 20px 48px; }
    .hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 10px; }
    .hero h1 { margin: 0 0 3px; font-size: 22px; font-weight: 800; letter-spacing: -0.02em; }
    .hero p { margin: 0; color: #111827; max-width: 860px; line-height: 1.4; font-size: 13px; }
    .links { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
    .links a { color: #111827; text-decoration: none; border: 1px solid #e5e7eb; padding: 5px 11px; border-radius: 999px; background: #f9fafb; font-size: 12px; }
    .top-actions { display: flex; gap: 10px; flex-wrap: wrap; }
    .layout { display: grid; grid-template-columns: minmax(0, 2fr) minmax(340px, 420px); gap: 20px; align-items: start; }
    .stack { display: grid; gap: 20px; }
    .metrics { display: grid; gap: 12px; grid-template-columns: repeat(6, minmax(0, 1fr)); }
    .card { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 20px; padding: 24px; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2); }
    .metric-card { cursor: pointer; padding: 16px 18px; transition: transform 0.15s ease, border-color 0.15s ease; }
    .metric-card:hover { transform: translateY(-1px); border-color: #2563eb; }
    .metric-card:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; }
    .metric-label { color: #111827; font-size: 13px; margin-bottom: 8px; }
    .metric-value { font-size: 28px; font-weight: 800; }
    .metric-sub { margin-top: 6px; color: #2563eb; font-size: 13px; }
    .card h2 { margin: 0 0 14px; font-size: 17px; font-weight: 700; letter-spacing: -0.01em; }
    .subtext { color: #111827; font-size: 13px; margin-bottom: 14px; line-height: 1.55; }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
    th { color: #111827; font-weight: 600; }
    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .badge.online { background: rgba(34, 197, 94, 0.12); color: #16a34a; }
    .badge.offline { background: rgba(248, 113, 113, 0.12); color: #dc2626; }
    .badge.unknown { background: rgba(250, 204, 21, 0.12); color: #ea580c; }
    .coverage { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .coverage-item { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 14px; padding: 14px; }
    .coverage-item strong { display: block; font-size: 22px; margin-top: 8px; }
    .list { display: grid; gap: 10px; }
    .list-item { border: 1px solid #e5e7eb; border-radius: 12px; padding: 12px; background: #ffffff; }
    .list-item .top { display: flex; gap: 12px; justify-content: space-between; margin-bottom: 6px; }
    .list-item .meta { color: #111827; font-size: 12px; }
    .empty { color: #111827; font-size: 14px; padding: 6px 0; }
    .row { display: grid; gap: 8px; margin-bottom: 12px; }
    label { font-size: 13px; color: #111827; }
    input, select, textarea, button { width: 100%; box-sizing: border-box; border-radius: 12px; border: 1px solid #e5e7eb; background: #ffffff; color: #111827; padding: 10px 12px; }
    textarea { resize: vertical; min-height: 120px; font-family: ui-monospace, SFMono-Regular, monospace; }
    /* 컴팩트 인라인 입력(폼 한 줄에 여러 개) 베이스 팔레트와 통일 */
    .inp-sm { width: auto; border-radius: 10px; border: 1px solid #e5e7eb; background: #ffffff; color: #111827; padding: 7px 10px; font-size: 13px; }
    .inp-sm:focus { outline: none; border-color: #2563eb; }
    /* 버튼 계층: primary(저장/실행) / secondary(보조) / ghost(중립) / danger(삭제) */
    button { border: 1px solid #e5e7eb; background: #e5e7eb; color: #2563eb; font-weight: 600; cursor: pointer; font-size: 13px; }
    button:hover { background: #dbeafe; border-color: #2563eb; color: #2563eb; }
    button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
    button.primary:hover { background: #2563eb; }
    button.secondary { background: #e5e7eb; border: 1px solid #e5e7eb; color: #111827; }
    button.secondary:hover { background: #e5e7eb; color: #111827; }
    button.ghost { background: transparent; border: 1px solid #e5e7eb; color: #111827; }
    button.ghost:hover { background: #f9fafb; color: #111827; }
    button.danger { background: #fee2e2; border: 1px solid #fee2e2; color: #dc2626; }
    button.danger:hover { background: #fee2e2; }
    .actions { display: grid; gap: 10px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .actions a, .top-actions a { display: inline-flex; align-items: center; justify-content: center; border-radius: 12px; border: 1px solid #e5e7eb; background: #f9fafb; color: #111827; padding: 10px 12px; text-decoration: none; font-weight: 600; font-size: 13px; }
    .actions a:hover, .top-actions a:hover { background: #e5e7eb; color: #111827; }
    .quick-actions { display: grid; gap: 8px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .status-line { color: #111827; font-size: 13px; margin-top: 8px; }
    .mono { font-family: ui-monospace, SFMono-Regular, monospace; }
    .query-result-area { min-height: 80px; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 12px; overflow: auto; font-size: 13px; }
    .result-placeholder { color: #111827; font-style: italic; }
    .result-error { color: #dc2626; font-family: ui-monospace, SFMono-Regular, monospace; white-space: pre-wrap; font-size: 12px; }
    .result-summary { color: #2563eb; font-size: 13px; margin-bottom: 10px; padding: 8px 12px; background: #f9fafb; border-radius: 8px; border-left: 3px solid #2563eb; }
    .result-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 4px; }
    .result-table th { background: #f9fafb; color: #2563eb; font-weight: 600; text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; }
    .result-table td { padding: 7px 10px; border-bottom: 1px solid #dbeafe; color: #111827; vertical-align: top; word-break: break-all; }
    .result-table tr:last-child td { border-bottom: none; }
    .result-table tr:hover td { background: #f9fafb; }
    .result-badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: #e5e7eb; color: #2563eb; }
    .result-badge.wazuh { background: #dbeafe; color: #2563eb; }
    .result-badge.zabbix { background: #e5e7eb; color: #2563eb; }
    .result-badge.fleet { background: #dcfce7; color: #16a34a; }
    .result-badge.trivy { background: #fef9c3; color: #ea580c; }
    .result-badge.hosts { background: #f9fafb; color: #2563eb; }
    .top-actions button, .guide-chips button, .guide-list button { width: auto; }
    .guide-chips, .guide-list { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .chip { padding: 8px 12px; border-radius: 999px; }
    .toggle-grid { display: grid; gap: 8px; }
    .toggle-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; border: 1px solid #e5e7eb; border-radius: 12px; background: #ffffff; }
    .toggle-item input { width: auto; margin: 0; }
    .guide-banner { margin-top: 12px; border-radius: 12px; padding: 12px; border: 1px solid #e5e7eb; background: #ffffff; }
    .guide-banner strong { display: block; margin-bottom: 6px; }
    .guide-banner.need-guide { border-color: #ea580c; background: rgba(245, 158, 11, 0.12); }
    .guide-banner.warning { border-color: #2563eb; background: rgba(56, 189, 248, 0.1); }
    dialog { border: 1px solid #e5e7eb; border-radius: 18px; padding: 0; background: #f9fafb; color: #111827; width: min(760px, calc(100vw - 32px)); }
    dialog::backdrop { background: rgba(2, 6, 23, 0.74); }
    .guide-dialog { padding: 20px; }
    .guide-dialog-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    .guide-dialog-head h3 { margin: 0; font-size: 20px; }
    .guide-dialog-copy { color: #111827; font-size: 14px; line-height: 1.5; }
    .dialog-body { padding: 0 20px 20px; max-height: 60vh; overflow: auto; }
    /* Admin tabs */
    .atab-panel { display: none; margin-top: 16px; }
    .atab-panel.active { display: block; }
    #admin_tabs_nav { margin: 0; }
    /* Tab nav (dashboard와 동일) + 토스식 슬림 상단바 */
    .tabs-nav { display: flex; gap: 0; border-bottom: 1px solid #e5e7eb; margin-bottom: 12px; overflow-x: auto; }
    .tabs-nav button { width: auto; display: inline-flex; align-items: center; background: none; border: none; border-bottom: 2px solid transparent; padding: 8px 16px; color: #111827; font-size: 14px; font-weight: 600; cursor: pointer; margin-bottom: -1px; border-radius: 0; white-space: nowrap; }
    .tabs-nav button.active { color: #2563eb; border-bottom-color: #2563eb; }
    .topbar { display: flex; align-items: flex-end; gap: 18px; border-bottom: 1px solid #e5e7eb; margin-bottom: 16px; }
    .topbar .brand { font-size: 18px; font-weight: 800; letter-spacing: -0.03em; color: #111827; padding-bottom: 10px; white-space: nowrap; }
    .topbar .tabs-nav { flex: 1 1 auto; border-bottom: none; margin-bottom: 0; }
    .topbar .top-actions { padding-bottom: 8px; align-items: center; flex: 0 0 auto; }
    .topbar .portal-link { color: #111827; text-decoration: none; font-size: 12px; padding: 6px 11px; border: 1px solid #e5e7eb; border-radius: 999px; background: #f9fafb; white-space: nowrap; }
    .topbar .portal-link:hover { color: #111827; border-color: #2563eb; }
    @media (max-width: 1000px) {
      .topbar { flex-wrap: wrap; align-items: center; gap: 10px; }
      .topbar .tabs-nav { order: 3; flex-basis: 100%; }
    }
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
        background: #f9fafb;
        border-top: 1px solid #e5e7eb;
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
        color: #111827;
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
      .admin-bottom-nav button .bn-icon:empty { display: none; }
      .admin-bottom-nav button.active { color: #2563eb; border-top-color: #2563eb; }
    }
    @media (max-width: 480px) {
      .metrics { grid-template-columns: 1fr 1fr; }
      .metric-value { font-size: 22px; }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <header class=\"topbar\">
      <span class=\"brand\" data-i18n=\"admin.brand\">MORI 콘솔</span>
      <nav class=\"tabs-nav\" id=\"admin_tabs_nav\">
        <button class=\"active\" data-atab=\"overview\" onclick=\"switchAdminTab('overview')\" data-i18n=\"admin.tab.overview\">Overview</button>
        <button data-atab=\"remediation\" onclick=\"switchAdminTab('remediation')\" data-i18n=\"admin.tab.remediation\">Remediation</button>
        <button data-atab=\"assets\" onclick=\"switchAdminTab('assets')\" data-i18n=\"admin.tab.assets\">자산 / Owners</button>
        <button data-atab=\"access\" onclick=\"switchAdminTab('access')\" data-i18n=\"admin.tab.access\">Access Control</button>
        <button data-atab=\"logs\" onclick=\"switchAdminTab('logs')\" data-i18n=\"admin.tab.logs\">Audit &amp; Logs</button>
        <button data-atab=\"settings\" onclick=\"switchAdminTab('settings')\" data-i18n=\"admin.tab.settings\">Settings</button>
      </nav>
      <div class=\"top-actions\">
        <span id=\"admin_user_badge\" style=\"font-size:13px;color:#111827\"></span>
        <a class=\"portal-link\" href=\"/ui\" data-i18n=\"admin.actions.user_dashboard\">사용자 대시보드</a>
        <button id=\"refresh_dashboard\" class=\"secondary\" style=\"width:auto;padding:6px 12px;font-size:13px\" data-i18n=\"admin.actions.refresh\">Refresh Dashboard</button>
        <div class=\"account-wrap\" style=\"position:relative\">
          <button id=\"account_btn\" type=\"button\" onclick=\"toggleAccountMenu()\" class=\"ghost\" style=\"width:auto;padding:6px 12px;border-radius:999px\" data-i18n=\"admin.actions.account\">계정</button>
          <div id=\"account_menu\" style=\"display:none;position:absolute;right:0;top:calc(100% + 6px);background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:12px;min-width:230px;z-index:9998;box-shadow:0 8px 24px rgba(0,0,0,0.45)\">
            <button id=\"query_guide\" type=\"button\" style=\"display:block;width:100%;text-align:left;background:transparent;border:none;color:#111827;font-size:13px;font-weight:600;padding:6px 4px;cursor:pointer\" data-i18n=\"admin.actions.query_guide\">Query Guide</button>
            <div style=\"border-top:1px solid #e5e7eb;margin:8px 0\"></div>
            <a href=\"__DOCS_PORTAL_URL__\" target=\"_blank\" rel=\"noreferrer\" style=\"display:block;color:#111827;font-size:12px;padding:5px 4px;text-decoration:none\" data-i18n=\"admin.links.docs\">운영 문서 / 포털</a>
            <a href=\"/docs\" target=\"_blank\" rel=\"noreferrer\" style=\"display:block;color:#111827;font-size:12px;padding:5px 4px;text-decoration:none\" data-i18n=\"admin.links.api\">API 문서 (Swagger)</a>
            <a href=\"/health\" target=\"_blank\" rel=\"noreferrer\" style=\"display:block;color:#111827;font-size:12px;padding:5px 4px;text-decoration:none\">Health JSON</a>
            <a href=\"/dashboard/summary\" target=\"_blank\" rel=\"noreferrer\" style=\"display:block;color:#111827;font-size:12px;padding:5px 4px;text-decoration:none\">Dashboard JSON</a>
            <a href=\"/catalog\" target=\"_blank\" rel=\"noreferrer\" style=\"display:block;color:#111827;font-size:12px;padding:5px 4px;text-decoration:none\">Query Catalog JSON</a>
            <div style=\"border-top:1px solid #e5e7eb;margin:8px 0\"></div>
            <div style=\"font-size:12px;color:#111827;margin-bottom:6px\" data-i18n=\"admin.account.language\">언어 / Language</div>
            __I18N_TOGGLE__
            <div style=\"border-top:1px solid #e5e7eb;margin:10px 0\"></div>
            <a href=\"/auth/logout\" style=\"display:block;text-align:center;color:#dc2626;font-size:13px\" data-i18n=\"admin.actions.logout\">로그아웃</a>
          </div>
        </div>
      </div>
    </header>

    <!-- ── Tab: Overview ──────────────────────────────────────────────────── -->
    <div class=\"atab-panel active\" id=\"atab_overview\">
      <section class=\"metrics\" id=\"overview_cards\"></section>
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.phase2_health\">Phase 2 데이터 헬스</h2>
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
          <h2 data-i18n=\"admin.h.collector_health\">Collector Health · Source Freshness</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.collector_health\">수집기별 마지막 성공 시각과 SLA 임계 대비 지연(lag)을 표시합니다. SLA 초과 시 STALE, 마지막 sync가 error면 표시됩니다.</div>
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

    <!-- ── Tab: Remediation (vuln_actions + action_plans) ────────────────── -->
    <div class=\"atab-panel\" id=\"atab_remediation\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.trivy_remediation\">Trivy 취약점 조치 상태</h2>
          <div class=\"subtext\" data-i18n-html=\"admin.s.sub.trivy\">
            Critical / High 취약점과 등록된 조치 계획(plan) · 예외(exception) 입니다.
            편집은 <a href=\"/ui#assets\" style=\"color:#2563eb\">사용자 대시보드 Assets 탭의 취약점 카드</a>에서 가능합니다.
          </div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"admin_reload_vulns\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
            <a href=\"/trivy/vulnerabilities?format=csv&amp;severity=critical\" class=\"ghost\" style=\"display:inline-flex;align-items:center;justify-content:center;text-decoration:none\" data-i18n=\"admin.s.btn.critical_csv\">Critical CSV</a>
          </div>
          <div class=\"table-wrap\" id=\"admin_vuln_actions\"></div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.action_plans\">자산 조치 계획 (action_plans)</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.action_plans\">호스트별 등록된 조치 계획(target_date / text)을 표시합니다.</div>
          <div class=\"table-wrap\" id=\"admin_action_plans\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 자산 관리 ────────────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_assets\">
      <section class=\"card\">
        <h2 data-i18n=\"admin.h.asset_owners\">자산 담당자 관리</h2>
        <div class=\"subtext\" data-i18n=\"admin.s.sub.asset_owners\">서버·PC 자산의 담당자와 팀을 등록합니다. 호스트명과 정확히 일치해야 합니다.</div>
        <div id=\"owners_list\" class=\"list\" style=\"margin-bottom:16px;max-height:360px;overflow-y:auto\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
        <div id=\"owner_form_title\" style=\"font-size:14px;font-weight:700;color:#2563eb;margin-bottom:8px;\" data-i18n=\"admin.dyn.new_asset\">새 자산 등록</div>
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
          <h2 data-i18n=\"admin.h.dashboard_prefs\">사용자 대시보드 설정</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.dashboard_prefs\">`/ui` 에서 사용자에게 보이는 카드와 섹션을 제어합니다. 재시작 시 초기값으로 돌아갑니다.</div>
          <div class=\"row\"><label for=\"docs_portal_url\" data-i18n=\"admin.s.lbl.docs_url\">문서 / 포털 URL</label><input id=\"docs_portal_url\" value=\"__DOCS_PORTAL_URL__\" /></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.user_cards\">사용자 요약 카드</label><div class=\"toggle-grid\" id=\"user_dashboard_cards\"></div></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.user_sections\">사용자 섹션</label><div class=\"toggle-grid\" id=\"user_dashboard_sections\"></div></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.asset_columns\">자빅스 자산 테이블 컬럼 표시</label><div class=\"toggle-grid\" id=\"user_dashboard_asset_columns\"></div></div>
          <div class=\"row\"><label data-i18n=\"admin.s.lbl.guide_tabs\">가이드 탭 노출 설정</label><div class=\"toggle-grid\" id=\"user_dashboard_guides\"></div></div>
          <div class=\"actions\">
            <button id=\"save_dashboard_preferences\" class=\"primary\" data-i18n=\"admin.s.btn.save\">저장</button>
            <a href=\"/ui\" data-i18n=\"admin.s.btn.open_user_ui\">사용자 화면 열기</a>
          </div>
          <div class=\"status-line\" id=\"dashboard_preferences_status\">user dashboard settings loading...</div>
        </section>
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.slack\">Slack Webhook 관리</h2>
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
          <h2 data-i18n=\"admin.h.guides_editor\">가이드 &amp; 메뉴얼 편집</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.guides_editor\">사용자 UI에 표시되는 가이드 내용을 수정합니다. 마크다운 형식을 지원합니다.</div>
          <div class=\"row\"><label for=\"guide_edit_select\" data-i18n=\"admin.s.lbl.guide_select\">가이드 선택</label>
            <select id=\"guide_edit_select\">
              <option value=\"zabbix_setup\" data-i18n=\"admin.s.gopt.zabbix_setup\">Zabbix 에이전트 설정</option>
              <option value=\"fleet_install\" data-i18n=\"admin.s.gopt.fleet_install\">Fleet 에이전트 설치</option>
              <option value=\"isms_criteria\" data-i18n=\"admin.s.gopt.isms_criteria\">ISMS-P 심사 기준</option>
              <option value=\"iso27001_criteria\" data-i18n=\"admin.s.gopt.iso27001_criteria\">ISO 27001 심사 기준</option>
              <option value=\"ldap_setup\" data-i18n=\"admin.s.gopt.ldap_setup\">LDAP 통합 설정</option>
              <option value=\"incident_response\" data-i18n=\"admin.s.gopt.incident_response\">인시던트 대응 절차</option>
              <option value=\"security_policy\" data-i18n=\"admin.s.gopt.security_policy\">보안 정책 가이드</option>
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

        <!-- ── Dev Tools (자연어 / 구조화 질의 접기 기본) ───────────── -->
        <details class=\"card\" style=\"padding:0\">
          <summary style=\"cursor:pointer;padding:18px 22px;font-size:18px;font-weight:700;color:#111827;list-style:none\">
            Dev Tools <span style=\"color:#111827;font-weight:400;font-size:13px\" data-i18n=\"admin.s.devtools_tag\"> 자연어 / 구조화 질의 (개발자용)</span>
          </summary>
          <div style=\"padding:0 22px 22px 22px\">
            <div class=\"subtext\" style=\"margin-bottom:12px\" data-i18n-html=\"admin.s.sub.devtools\">관리자가 직접 백엔드 질의를 시험하기 위한 도구입니다. 일반 사용자 화면은 <a href=\"/ui\" style=\"color:#2563eb\">/ui</a> 를 참고하세요.</div>
            <section style=\"margin-bottom:18px\">
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#111827\" data-i18n=\"admin.h.quick_actions\">Quick Actions</h3>
              <div class=\"quick-actions\" id=\"quick_queries\"></div>
            </section>
            <section style=\"margin-bottom:18px\">
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#111827\" data-i18n=\"admin.h.nlq\">Natural Language Query</h3>
              <div class=\"subtext\"><span data-i18n=\"admin.s.sub.nlq\">자연스럽게 질문하면 의도를 해석해 실행합니다.</span> <a href=\"#\" id=\"query_guide_link\" style=\"color:#2563eb;\" data-i18n=\"admin.s.link.query_guide\">질의 가이드</a></div>
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
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#111827\" data-i18n=\"admin.h.query_builder\">Structured Query Builder</h3>
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
              <h3 style=\"margin:0 0 8px 0;font-size:15px;color:#111827\" data-i18n=\"admin.h.request_response\">Request / Response</h3>
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
          <h2 data-i18n=\"admin.h.signup_requests\">가입 요청 관리</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.signup_requests\">사용자가 제출한 가입 요청 목록입니다. 역할·초기 비밀번호를 정해 승인하면 계정이 자동 생성됩니다(LDAP 활성 시 디렉터리, 아니면 로컬). 초기 비밀번호는 1회 표시됩니다.</div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"reload_signup_requests\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div id=\"signup_requests_list\" class=\"list\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"signup_requests_status\"></div>
        </section>

        <!-- LDAP 사용자 관리 (admin 전용, LDAP 활성 시) -->
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
            <h2 style=\"margin:0\" data-i18n=\"admin.h.ldap\">LDAP 사용자 관리</h2>
            <span id=\"ldap_status_badge\" style=\"font-size:12px;color:#111827\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.ldap\">디렉터리에 사용자를 직접 추가·삭제하고 비밀번호·역할을 바꿉니다. 여기서 만든 계정은 같은 LDAP을 보는 Grafana/Zabbix/Fleet 에서도 로그인됩니다. (LDAP 비활성 시 .env의 MORI_LDAP_ENABLED=true 필요)</div>
          <div id=\"ldap_add_form\" style=\"display:none;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0\">
            <input id=\"ldap_new_uid\" class=\"inp-sm\" placeholder=\"uid (아이디)\" data-i18n-placeholder=\"admin.s.ph.ldap_uid\" style=\"width:130px\" />
            <input id=\"ldap_new_cn\" class=\"inp-sm\" placeholder=\"이름(cn)\" data-i18n-placeholder=\"admin.s.ph.ldap_cn\" style=\"width:120px\" />
            <input id=\"ldap_new_mail\" class=\"inp-sm\" placeholder=\"email\" style=\"width:160px\" />
            <input id=\"ldap_new_pw\" class=\"inp-sm\" placeholder=\"초기 비밀번호\" data-i18n-placeholder=\"admin.s.ph.ldap_pw\" style=\"width:140px\" />
            <select id=\"ldap_new_role\" class=\"inp-sm\"><option value=\"user\">user</option><option value=\"helpdesk\">helpdesk</option><option value=\"monitor\">monitor</option><option value=\"auditor\">auditor</option><option value=\"security\">security</option><option value=\"admin\">admin</option></select>
            <button class=\"secondary\" style=\"width:auto;padding:7px 14px;font-size:13px\" onclick=\"ldapAddUser()\" data-i18n=\"admin.s.btn.ldap_add\">+ 추가</button>
            <button id=\"reload_ldap_users\" class=\"secondary\" style=\"width:auto;padding:7px 12px;font-size:13px\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div id=\"ldap_users_list\" class=\"list\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"ldap_users_status\"></div>
        </section>

        <section class=\"card\">
          <h2 data-i18n=\"admin.h.role_perms\">역할별 탭 권한 관리</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.role_perms\">각 계정 역할에서 보이는 탭을 설정합니다. 저장 후 다음 로그인부터 적용됩니다.</div>
          <div id=\"roleperm_list\" style=\"display:grid;gap:16px;margin-bottom:16px\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"actions\">
            <button id=\"save_roleperm\" data-i18n=\"admin.s.btn.save\">저장</button>
            <button id=\"reload_roleperm\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div class=\"status-line\" id=\"roleperm_status\"></div>
        </section>

        <section class=\"card\">
          <h2 data-i18n=\"admin.h.acct_roles\">계정 거버넌스 열람 역할</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.acct_roles\">계정 탭·호스트 상세 계정 섹션·/accounts API를 볼 수 있는 역할을 지정합니다. admin은 항상 포함됩니다. 저장 후 다음 로그인부터 적용됩니다.</div>
          <div id=\"acctrole_list\" style=\"display:flex;flex-wrap:wrap;gap:14px;margin:14px 0\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"actions\">
            <button id=\"save_acctrole\" data-i18n=\"admin.s.btn.save\">저장</button>
            <button id=\"reload_acctrole\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div class=\"status-line\" id=\"acctrole_status\"></div>
        </section>

        <section class=\"card\">
          <h2 data-i18n=\"admin.h.user_tabs\">유저별 대시보드 탭 관리</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.user_tabs\">개별 유저에게 역할 기본값과 다른 탭을 지정합니다. 유저별 설정이 있으면 역할 기본값보다 우선 적용됩니다.</div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"reload_usertab\" class=\"secondary\" data-i18n=\"admin.s.btn.refresh_icon\">새로고침</button>
          </div>
          <div id=\"usertab_list\" style=\"display:grid;gap:14px;margin-bottom:16px\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"usertab_status\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: Audit·Logs (자산 변경 이력 + 사용자 행동 로그 통합) ─── -->
    <div class=\"atab-panel\" id=\"atab_logs\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2 data-i18n=\"admin.h.unified_log\">통합 이력 로그</h2>
          <div class=\"subtext\" data-i18n=\"admin.s.sub.unified_log\">로그인·자산·취약점·트리아지·인시던트·증적·계정·통제 등 모든 변경 이력을 한곳에서 검색합니다.</div>
          <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px\">
            <input id=\"ulog_q\" class=\"inp-sm\" placeholder=\"행위자·대상·내용 검색\" data-i18n-placeholder=\"admin.s.ph.ulog_q\" style=\"width:220px\" />
            <select id=\"ulog_category\" class=\"inp-sm\">
              <option value=\"\" data-i18n=\"admin.s.opt.all_cat\">전체 분류</option>
              <option value=\"login\" data-i18n=\"admin.s.opt.cat_login\">로그인</option>
              <option value=\"action\" data-i18n=\"admin.s.opt.cat_action\">사용자 행동</option>
              <option value=\"asset\" data-i18n=\"admin.s.opt.cat_asset\">자산 변경</option>
              <option value=\"vuln\" data-i18n=\"admin.s.opt.cat_vuln\">취약점 조치</option>
              <option value=\"triage\" data-i18n=\"admin.s.opt.cat_triage\">트리아지</option>
              <option value=\"incident\" data-i18n=\"admin.s.opt.cat_incident\">인시던트</option>
              <option value=\"evidence\" data-i18n=\"admin.s.opt.cat_evidence\">증적</option>
              <option value=\"account\" data-i18n=\"admin.s.opt.cat_account\">계정 승인</option>
              <option value=\"control_evidence\" data-i18n=\"admin.s.opt.cat_control_evidence\">통제 증적</option>
            </select>
            <input id=\"ulog_from\" class=\"inp-sm\" type=\"date\" title=\"시작일\" data-i18n-title=\"admin.s.ph.ulog_from\" style=\"width:150px\" />
            <input id=\"ulog_to\" class=\"inp-sm\" type=\"date\" title=\"종료일\" data-i18n-title=\"admin.s.ph.ulog_to\" style=\"width:150px\" />
            <button id=\"ulog_search_btn\" class=\"secondary\" style=\"padding:6px 14px\" data-i18n=\"admin.s.btn.search\">검색</button>
            <button id=\"ulog_reload\" class=\"secondary\" style=\"padding:6px 14px\" data-i18n=\"admin.s.btn.refresh\">새로고침</button>
          </div>
          <div id=\"ulog_list\" class=\"list\"><span class=\"empty\" data-i18n=\"admin.dyn.loading\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"ulog_status\"></div>
        </section>
      </div>
    </div>
  </div>

  <!-- ── 어드민 하단 탭 바 (모바일 전용) ────────────────────────────────── -->
  <nav class=\"admin-bottom-nav\" id=\"admin_bottom_nav\">
    <button class=\"active\" data-atab=\"overview\" onclick=\"switchAdminTab('overview')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"admin.s.bn.overview\">Overview</span>
    </button>
    <button data-atab=\"remediation\" onclick=\"switchAdminTab('remediation')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"admin.s.bn.remediation\">조치</span>
    </button>
    <button data-atab=\"assets\" onclick=\"switchAdminTab('assets')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"admin.s.bn.assets\">자산</span>
    </button>
    <button data-atab=\"access\" onclick=\"switchAdminTab('access')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"admin.s.bn.access\">권한</span>
    </button>
    <button data-atab=\"logs\" onclick=\"switchAdminTab('logs')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"admin.s.bn.logs\">로그</span>
    </button>
    <button data-atab=\"settings\" onclick=\"switchAdminTab('settings')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"admin.s.bn.settings\">설정</span>
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
    // i18n helper resolves via window.t() with a Korean fallback
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

    // ── 전역 함수 노출 (onclick 속성에서 직접 호출 함수 선언은 호이스팅됨) ──
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

    // ── 재사용 클라이언트 페이저 기본 10, 10단위 선택(최대 100), 이전/다음 ──────
    // container 안의 <table><tbody> 행을 페이지 단위로 표시/숨김 + 하단 컨트롤 바 추가.
    // 렌더 함수 끝에서 _pgApply(container) 만 호출하면 됨(행 빌더는 그대로).
    const _pg = {};  // key(container.id) -> {size, page, container}
    function _pgApply(container) {
      if (!container) return;
      let key = container.id || container.dataset.pgKey;
      if (!key) { key = 'pg' + Math.random().toString(36).slice(2); container.dataset.pgKey = key; }
      const bar = container.querySelector(':scope > .pgbar'); if (bar) bar.remove();
      const table = container.querySelector(':scope > table') || container.querySelector('table');
      const tbody = table && table.querySelector('tbody');
      // 테이블이면 tbody 행, 아니면 컨테이너 직속 자식(카드 목록)을 페이지 단위로.
      const rows = tbody ? Array.from(tbody.rows)
                         : Array.from(container.children).filter(c => !c.classList.contains('pgbar'));
      if (!rows.length) return;
      const total = rows.length;
      const st = _pg[key] || (_pg[key] = { size: 10, page: 1 });
      st.container = container;
      const pages = Math.max(1, Math.ceil(total / st.size));
      st.page = Math.min(Math.max(1, st.page), pages);
      const start = (st.page - 1) * st.size, end = start + st.size;
      rows.forEach((r, i) => { r.style.display = (i >= start && i < end) ? '' : 'none'; });
      if (total <= 10) return;  // 10개 이하는 전부 표시(바 숨김)
      const sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
      const el = document.createElement('div');
      el.className = 'pgbar';
      el.style.cssText = 'display:flex;align-items:center;gap:8px;justify-content:flex-end;margin-top:8px;font-size:12px;color:#111827;flex-wrap:wrap';
      el.innerHTML = `<span>${start + 1}–${Math.min(end, total)} / ${total}</span>` +
        `<select onchange=\"_pgSize('${key}',this.value)\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:3px 6px;font-size:12px\">${sizes.map(s => `<option value=\"${s}\"${s === st.size ? ' selected' : ''}>${s}</option>`).join('')}</select>` +
        `<button class=\"secondary\" style=\"width:auto;padding:2px 9px;font-size:12px\" onclick=\"_pgGo('${key}',-1)\" ${st.page <= 1 ? 'disabled' : ''}>이전</button>` +
        `<span>${st.page}/${pages}</span>` +
        `<button class=\"secondary\" style=\"width:auto;padding:2px 9px;font-size:12px\" onclick=\"_pgGo('${key}',1)\" ${st.page >= pages ? 'disabled' : ''}>다음</button>`;
      container.appendChild(el);
    }
    window._pgApply = _pgApply;
    window._pgSize = function(key, v) { const st = _pg[key]; if (!st) return; st.size = parseInt(v, 10) || 10; st.page = 1; _pgApply(st.container); };
    window._pgGo = function(key, d) { const st = _pg[key]; if (!st) return; st.page += d; _pgApply(st.container); };

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

    const UI_TRIAGE_COLORS = {new:'#ea580c', acknowledged:'#2563eb', investigating:'#2563eb', closed:'#16a34a', false_positive:'#111827'};
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
        { label: tt('admin.dyn.col.owner','담당자'), render: (item) => `<span style="color:#16a34a">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Severity', render: (item) => escapeHtml(item.severity) },
        { label: 'Message', render: (item) => escapeHtml(item.message) },
        {
          label: 'Triage',
          render: (item) => {
            const tr = uiTriageData[item.alert_id] || {status:'new'};
            const st = tr.status || 'new';
            const color = UI_TRIAGE_COLORS[st] || '#111827';
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
        { label: tt('admin.dyn.col.owner','담당자'), render: (item) => `<span style="color:#16a34a">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'CVE', render: (item) => escapeHtml(item.cve || '-') },
        { label: 'Package', render: (item) => escapeHtml(item.package_name || '-') },
        { label: tt('admin.dyn.col.action_plan','조치 계획'), render: (item) => {
          if (!item.plan_text) return `<span style="color:#111827;font-size:11px">${tt('admin.dyn.unset','미설정')}</span>`;
          const tgt = item.plan_target_date ? `<br /><span style="color:#111827;font-size:11px">~${escapeHtml(item.plan_target_date)}</span>` : '';
          const by = item.plan_updated_by ? ` <span style="color:#111827;font-size:11px">(${escapeHtml(item.plan_updated_by)})</span>` : '';
          return `<span style="color:#16a34a;font-size:12px" title="${escapeHtml(item.plan_text)}">${escapeHtml(item.plan_text.substring(0,30))}${item.plan_text.length>30?'…':''}</span>${by}${tgt}`;
        }},
        { label: tt('admin.dyn.col.exception','조치 예외'), render: (item) => {
          if (!item.exception_until) return `<span style="color:#111827;font-size:11px">${tt('admin.dyn.none_word','없음')}</span>`;
          const reason = item.exception_reason ? `<br /><span style="color:#111827;font-size:11px">${escapeHtml(item.exception_reason.substring(0,30))}${item.exception_reason.length>30?'…':''}</span>` : '';
          return `<span style="color:#ea580c;font-size:12px">~${escapeHtml(item.exception_until)}</span>${reason}`;
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
        const staleBadge = item.is_stale ? ' <span class=\"badge\" style=\"background:#ea580c;color:#000\">STALE</span>' : '';
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
                <td><span class=\"mono\" style=\"font-size:11px;color:#111827;\">${escapeHtml(ev.record_id || '-')}</span></td>
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
    const impColor = { '\uc0c1':'#dc2626', '\uc911':'#ea580c', '\ud558':'#16a34a' };

    async function loadOwners() {
      ownersListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/assets/owners');
        const data = await res.json();
        const list = data.owners || [];
        if (!list.length) { ownersListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.none_owners','등록된 담당자 없음')}</span>`; return; }
        ownersListEl.innerHTML = list.map(o => {
          const imp = o.importance || '';
          const impBadge = imp ? `<span style=\"background:#e5e7eb;color:${impColor[imp]||'#111827'};padding:1px 6px;border-radius:4px;font-size:11px;font-weight:700;margin-left:6px\">${escapeHtml(impLabel[imp]||imp)}</span>` : '';
          const catBadge = o.category ? `<span style=\"color:#2563eb;font-size:11px;margin-left:6px\">[${escapeHtml(o.category)}]</span>` : '';
          return `<div style=\"display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-bottom:1px solid #e5e7eb;font-size:13px;gap:8px\">
            <div style=\"flex:1;min-width:0\">
              <strong style=\"color:#111827\">${escapeHtml(o.hostname)}</strong>${catBadge}${impBadge}
              <br><span style=\"color:#16a34a;font-size:12px\">${escapeHtml(o.owner||'-')}</span>
              ${o.team ? `<span style=\"color:#111827;margin-left:6px;font-size:12px\">(${escapeHtml(o.team)})</span>` : ''}
              ${o.email ? `<span style=\"color:#111827;font-size:11px;margin-left:6px\">${escapeHtml(o.email)}</span>` : ''}
            </div>
            <div style=\"display:flex;gap:6px;flex-shrink:0\">
              <button onclick=\"editOwner('${escapeHtml(o.hostname)}')\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#2563eb;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px\">${tt('admin.dyn.edit','수정')}</button>
              <button onclick=\"deleteOwner('${escapeHtml(o.hostname)}')\" style=\"background:#fee2e2;border:none;color:#dc2626;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px\">${tt('admin.dyn.delete','삭제')}</button>
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
      ownerFormTitleEl.textContent = `${hostname} ${tt('admin.dyn.editing','수정 중')}`;
      ownerFormTitleEl.style.color = '#ea580c';
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
      ownerFormTitleEl.textContent = tt('admin.dyn.new_asset','새 자산 등록');
      ownerFormTitleEl.style.color = '#2563eb';
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
        ownerStatusEl.textContent = tt('admin.dyn.save_done','저장 완료 ');
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
              <button class=\"ghost\" style=\"width:auto;padding:4px 12px;font-size:12px;border-color:#dc2626;color:#dc2626\" onclick=\"deleteWebhook('${escapeHtml(w.id)}', this)\">${tt('admin.dyn.delete','삭제')}</button>
            </div>
          </div>
        `).join('');
      } catch(e) { webhooksListEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`; }
    }
    async function testWebhook(id, btn) {
      btn.textContent = tt('admin.dyn.sending','전송 중…'); btn.disabled = true;
      try {
        const res = await fetch(`/webhooks/${id}/test`, {method:'POST'});
        btn.textContent = res.ok ? tt('admin.dyn.success_check','성공') : tt('admin.dyn.fail_check','× 실패');
      } catch(e) { btn.textContent = tt('admin.dyn.error_check','× 오류'); }
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
        webhookStatusEl.textContent = tt('admin.dyn.add_done','추가 완료 ');
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
        guideEditStatusEl.textContent = tt('admin.dyn.save_done','저장 완료 ');
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
      if (tab === 'logs') { loadUnifiedLog(); }
      if (tab === 'remediation') { loadAdminVulnActions(); loadAdminActionPlans(); }
      if (tab === 'overview') { loadAdminPhase2Health(); loadAdminSourceFreshness(); }
      if (tab === 'access') { loadRolePermissions(); loadUserTabPermissions(); loadSignupRequests(); loadLdapUsers(); loadAccountViewRoles(); }
    }

    // i18n: refresh the active admin tab's dynamic content when the language changes
    window.onLangChange = function() {
      const activePanel = document.querySelector('.atab-panel.active');
      const tab = activePanel ? activePanel.id.replace('atab_', '') : 'overview';
      try {
        switchAdminTab(tab);
        // settings/access 탭은 init 시 1회 렌더되므로 언어 변경 시 직접 재렌더
        if (tab === 'settings') { renderDashboardPreferences(); renderGuideButtons(guideExamplesEl, guideExamples); }
        if (tab === 'access') { loadRolePermissions(); loadUserTabPermissions(); loadSignupRequests(); loadLdapUsers(); loadAccountViewRoles(); }
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
        // 처리 대기(pending)만 표시 — 승인 계정은 아래 LDAP 사용자 관리로, 이력은 통합 로그에서 확인
        const reqs = (data.requests || []).filter(r => r.status === 'pending');
        if (reqs.length === 0) {
          signupListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_signup_pending','처리할 가입 요청이 없습니다.')}</span>`;
          return;
        }
        const statusBadge = s => ({pending:tt('admin.dyn.signup.pending','대기중'), approved:tt('admin.dyn.signup.approved','승인됨'), rejected:tt('admin.dyn.signup.rejected','거절됨')}[s] || s);
        signupListEl.innerHTML = reqs.map(r => `
          <div class="owner-row" style="border:1px solid #e5e7eb;border-radius:10px;padding:12px;margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
              <div>
                <strong>${r.name}</strong> <span style="color:#111827;font-size:12px;">${r.email}</span>
                ${r.username ? `<span style="color:#2563eb;font-size:12px;margin-left:6px;font-family:monospace">@${r.username}</span>` : ''}
                ${r.department ? `<span style="color:#111827;font-size:12px;margin-left:6px;">[${r.department}]</span>` : ''}
                <div style="font-size:12px;color:#111827;margin-top:4px;">${r.reason || tt('admin.dyn.no_reason','(사유 없음)')}</div>
                <div style="font-size:11px;color:#111827;margin-top:4px;">${tt('admin.dyn.col.created','요청일')}: ${r.created_at || '-'}${r.reviewed_at ? ' / ' + tt('admin.dyn.col.reviewed','처리일') + ': ' + r.reviewed_at : ''}</div>
                ${r.status === 'approved' && r.username ? `<div style="font-size:11px;color:#16a34a;margin-top:3px">${tt('admin.dyn.signup.provisioned','계정 생성됨')}: ${r.username} (${r.role || 'user'}, ${r.backend || ''})</div>` : ''}
              </div>
              <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                <span>${statusBadge(r.status)}</span>
                ${r.status === 'pending' ? `
                  <select id="surole_${r.id}" class="inp-sm" style="font-size:12px;padding:4px 8px" title="${tt('admin.dyn.signup.role','부여 역할')}">
                    <option value="user">user</option><option value="helpdesk">helpdesk</option><option value="monitor">monitor</option><option value="auditor">auditor</option><option value="security">security</option><option value="admin">admin</option>
                  </select>
                  <input id="supw_${r.id}" class="inp-sm" placeholder="${tt('admin.dyn.signup.pw_ph','초기 PW(비우면 자동)')}" style="font-size:12px;padding:4px 8px;width:130px" />
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
      const body = { status };
      if (status === 'approved') {
        body.role = document.getElementById('surole_' + id)?.value || 'user';
        const pw = (document.getElementById('supw_' + id)?.value || '').trim();
        if (pw) body.password = pw;
      }
      try {
        const res = await fetch(`/auth/signup-requests/${id}`, {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || res.status);
        if (status === 'approved' && data.username) {
          signupStatusEl.innerHTML = `${tt('admin.dyn.approve_done','승인 완료')} <strong>${data.username}</strong> (${data.role}, ${data.backend}) · ${tt('admin.dyn.signup.initpw','초기 비밀번호')}: <code style="background:#ffffff;padding:1px 6px;border-radius:4px;color:#ea580c">${data.initial_password}</code> ${tt('admin.dyn.signup.copy_note','(사용자에게 전달, 1회 표시)')}`;
        } else {
          signupStatusEl.textContent = tt('admin.dyn.reject_done','거절 완료');
        }
        await loadSignupRequests();
      } catch(e) {
        signupStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
      }
    }

    if (document.getElementById('reload_signup_requests')) {
      document.getElementById('reload_signup_requests')?.addEventListener('click', loadSignupRequests);
    }

    // ── LDAP 사용자 관리 (admin 전용) ──────────────────────────────────────────
    const ldapListEl = document.getElementById('ldap_users_list');
    const ldapStatusMsgEl = document.getElementById('ldap_users_status');
    let _ldapRoles = ['user','helpdesk','monitor','auditor','security','admin'];
    async function loadLdapUsers() {
      if (!ldapListEl) return;
      const badge = document.getElementById('ldap_status_badge');
      const form = document.getElementById('ldap_add_form');
      ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const sres = await fetch('/admin/ldap/status');
        if (!sres.ok) { ldapListEl.innerHTML = `<span class="empty">${sres.status===401||sres.status===403 ? tt('admin.dyn.ldap.reauth','세션이 만료됐습니다. 새로고침 후 다시 로그인하세요.') : tt('admin.dyn.error_prefix','오류: ')+('HTTP '+sres.status)}</span>`; return; }
        const st = await sres.json();
        if (!st.enabled) {
          if (badge) { badge.textContent = tt('admin.dyn.ldap.disabled','● 비활성'); badge.style.color = '#111827'; }
          if (form) form.style.display = 'none';
          ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.ldap.off_note','LDAP이 꺼져 있습니다. .env 의 MORI_LDAP_ENABLED=true 로 켜면 여기서 관리할 수 있습니다.')}</span>`;
          return;
        }
        if (badge) { badge.textContent = `● ${tt('admin.dyn.ldap.enabled','활성')} · ${st.url} · ${st.base_dn}`; badge.style.color = '#16a34a'; }
        if (Array.isArray(st.roles) && st.roles.length) _ldapRoles = st.roles;
        if (form) form.style.display = 'flex';
        const res = await fetch('/admin/ldap/users');
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        const data = await res.json();
        const users = data.users || [];
        if (!users.length) { ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.ldap.none','디렉터리에 사용자가 없습니다.')}</span>`; return; }
        ldapListEl.innerHTML = users.map(u => {
          const roleOpts = _ldapRoles.map(r => `<option value="${r}"${u.role===r?' selected':''}>${r}</option>`).join('');
          return `<div class="owner-row" style="border:1px solid #e5e7eb;border-radius:10px;padding:10px 12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
            <div>
              <strong style="font-family:monospace;color:#2563eb">${escapeHtml(u.uid)}</strong>
              <span style="color:#111827;font-size:13px;margin-left:6px">${escapeHtml(u.cn||'')}</span>
              ${u.mail ? `<span style="color:#111827;font-size:12px;margin-left:6px">${escapeHtml(u.mail)}</span>` : ''}
            </div>
            <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
              <select onchange="ldapSetRole('${escapeHtml(u.uid)}', this.value)" class="inp-sm" style="font-size:12px;padding:4px 8px" title="${tt('admin.dyn.ldap.role','MORI 역할')}">${roleOpts}</select>
              <button class="secondary" style="font-size:12px;padding:3px 9px" onclick="ldapResetPw('${escapeHtml(u.uid)}')">${tt('admin.dyn.ldap.resetpw','비번 재설정')}</button>
              <button class="danger" style="font-size:12px;padding:3px 9px" onclick="ldapDeleteUser('${escapeHtml(u.uid)}')">${tt('admin.dyn.delete','삭제')}</button>
            </div>
          </div>`;
        }).join('');
      } catch(e) {
        ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
    }
    window.loadLdapUsers = loadLdapUsers;

    async function ldapAddUser() {
      const g = id => document.getElementById(id);
      const uid = g('ldap_new_uid').value.trim();
      const password = g('ldap_new_pw').value.trim();
      if (!uid || !password) { if (ldapStatusMsgEl) ldapStatusMsgEl.textContent = tt('admin.dyn.ldap.need_uid_pw','uid 와 초기 비밀번호는 필수입니다.'); return; }
      const body = { uid, cn: g('ldap_new_cn').value.trim(), mail: g('ldap_new_mail').value.trim(), password, role: g('ldap_new_role').value };
      try {
        const res = await fetch('/admin/ldap/users', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        const d = await res.json();
        if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.added','추가됨')}: ${d.uid} (${d.role})`; ldapStatusMsgEl.style.color = '#16a34a'; }
        ['ldap_new_uid','ldap_new_cn','ldap_new_mail','ldap_new_pw'].forEach(i => g(i).value = '');
        await loadLdapUsers();
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#dc2626'; } }
    }
    window.ldapAddUser = ldapAddUser;

    async function ldapDeleteUser(uid) {
      if (!confirm(tt('admin.dyn.ldap.confirm_del','LDAP 사용자를 삭제할까요? ') + uid)) return;
      try {
        const res = await fetch('/admin/ldap/users/' + encodeURIComponent(uid), { method:'DELETE' });
        const d = await res.json(); if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.deleted','삭제됨')}: ${uid}`; ldapStatusMsgEl.style.color = '#111827'; }
        await loadLdapUsers();
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#dc2626'; } }
    }
    window.ldapDeleteUser = ldapDeleteUser;

    async function ldapResetPw(uid) {
      const pw = prompt(tt('admin.dyn.ldap.newpw_prompt','새 비밀번호를 입력하세요:') + ' ' + uid);
      if (!pw) return;
      try {
        const res = await fetch('/admin/ldap/users/' + encodeURIComponent(uid) + '/password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password: pw}) });
        const d = await res.json(); if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.pw_done','비밀번호 재설정됨')}: ${uid}`; ldapStatusMsgEl.style.color = '#16a34a'; }
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#dc2626'; } }
    }
    window.ldapResetPw = ldapResetPw;

    async function ldapSetRole(uid, role) {
      try {
        const res = await fetch('/admin/ldap/users/' + encodeURIComponent(uid) + '/role', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({role}) });
        const d = await res.json(); if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.role_done','역할 변경됨')}: ${uid} → ${role}`; ldapStatusMsgEl.style.color = '#16a34a'; }
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#dc2626'; } }
    }
    window.ldapSetRole = ldapSetRole;

    document.getElementById('reload_ldap_users')?.addEventListener('click', loadLdapUsers);


    // ── 통합 이력 로그 (모든 이력 소스 병합 + 검색) ───────────────────────────
    const ulogListEl = document.getElementById('ulog_list');
    const ulogStatusEl = document.getElementById('ulog_status');
    // 분류 → [표시 라벨 i18n키·기본, 색상]
    const ULOG_CAT = {
      login: ['admin.dyn.cat.login', '로그인', '#2563eb'],
      action: ['admin.dyn.cat.action', '행동', '#2563eb'],
      asset: ['admin.dyn.cat.asset', '자산', '#ea580c'],
      vuln: ['admin.dyn.cat.vuln', '취약점', '#dc2626'],
      triage: ['admin.dyn.cat.triage', '트리아지', '#16a34a'],
      incident: ['admin.dyn.cat.incident', '인시던트', '#ea580c'],
      evidence: ['admin.dyn.cat.evidence', '증적', '#2563eb'],
      account: ['admin.dyn.cat.account', '계정', '#2563eb'],
      control_evidence: ['admin.dyn.cat.control_evidence', '통제증적', '#16a34a'],
    };
    async function loadUnifiedLog() {
      if (!ulogListEl) return;
      ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      const q = (document.getElementById('ulog_q')?.value || '').trim();
      const category = document.getElementById('ulog_category')?.value || '';
      const df = document.getElementById('ulog_from')?.value || '';
      const dt = document.getElementById('ulog_to')?.value || '';
      const params = new URLSearchParams();
      if (q) params.set('q', q);
      if (category) params.set('category', category);
      if (df) params.set('date_from', df);
      if (dt) params.set('date_to', dt);
      let url = '/admin/logs';
      if (params.toString()) url += '?' + params.toString();
      try {
        const res = await fetch(url);
        if (!res.ok) { ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.load_fail','로드 실패')}</span>`; return; }
        const data = await res.json();
        const logs = data.logs || [];
        if (!logs.length) { ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_log','이력 없음')}</span>`; return; }
        ulogListEl.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead><tr style="background:#f9fafb;">
            <th style="padding:8px;color:#2563eb;text-align:left">${tt('admin.dyn.col.time','시각')}</th>
            <th style="padding:8px;color:#2563eb;text-align:left">${tt('admin.dyn.col.category','분류')}</th>
            <th style="padding:8px;color:#2563eb;text-align:left">${tt('admin.dyn.col.actor','행위자')}</th>
            <th style="padding:8px;color:#2563eb;text-align:left">${tt('admin.dyn.col.action','액션')}</th>
            <th style="padding:8px;color:#2563eb;text-align:left">${tt('admin.dyn.col.target','대상')}</th>
            <th style="padding:8px;color:#2563eb;text-align:left">${tt('admin.dyn.col.detail','상세')}</th>
          </tr></thead>
          <tbody>
          ${logs.map(l => { const c = ULOG_CAT[l.category] || ['', l.category, '#111827']; return `<tr style="border-bottom:1px solid #e5e7eb;">
            <td style="padding:7px 8px;color:#111827;white-space:nowrap">${escapeHtml(formatTime(l.ts))}</td>
            <td style="padding:7px 8px;font-weight:600;color:${c[2]}">${escapeHtml(tt(c[0], c[1]))}</td>
            <td style="padding:7px 8px;color:#111827">${escapeHtml(l.actor || '-')}</td>
            <td style="padding:7px 8px;color:#ea580c">${escapeHtml(l.action || '-')}</td>
            <td style="padding:7px 8px;color:#111827">${escapeHtml(l.target || '-')}</td>
            <td style="padding:7px 8px;color:#111827">${escapeHtml(l.detail || '-')}</td>
          </tr>`; }).join('')}
          </tbody></table>`;
        _pgApply(ulogListEl);
        if (ulogStatusEl) ulogStatusEl.textContent = `${tt('admin.dyn.col.total','총')} ${data.total}${tt('admin.dyn.count_suffix','건')}`;
      } catch(e) {
        ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
    }
    document.getElementById('ulog_reload')?.addEventListener('click', loadUnifiedLog);
    document.getElementById('ulog_search_btn')?.addEventListener('click', loadUnifiedLog);
    document.getElementById('ulog_category')?.addEventListener('change', loadUnifiedLog);
    document.getElementById('ulog_q')?.addEventListener('keydown', e => { if (e.key === 'Enter') loadUnifiedLog(); });

    // ── Role Permissions ─────────────────────────────────────────────────────
    const ROLE_PERM_TABS = [
      { id: 'dashboard', label: '대시보드', labelKey: 'admin.dyn.tab.dashboard' },
      { id: 'triage', label: 'Alert Triage', labelKey: 'admin.dyn.tab.triage' },
      { id: 'incidents', label: '인시던트', labelKey: 'admin.dyn.tab.incidents' },
      { id: 'assets', label: '자산 현황', labelKey: 'admin.dyn.tab.assets' },
      { id: 'compliance', label: 'Compliance PDCA', labelKey: 'admin.dyn.tab.compliance' },
      { id: 'guides', label: '가이드', labelKey: 'admin.dyn.tab.guides' },
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
            return `<label style=\"display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid #e5e7eb;border-radius:8px;background:#ffffff;cursor:pointer\">
              <input type=\"checkbox\" data-role=\"${role.key}\" data-tab=\"${tab.id}\" ${checked} style=\"width:auto;margin:0\" />
              <span style=\"font-size:13px\">${tt(tab.labelKey, tab.label)}</span>
            </label>`;
          }).join('');
          return `<div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:14px\">
            <div style=\"font-weight:700;color:#2563eb;margin-bottom:10px\">${escapeHtml(tt(role.labelKey, role.label))}</div>
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
          statusEl.style.color = '#16a34a';
          statusEl.textContent = tt('admin.dyn.roleperm_saved','권한이 저장되었습니다. 해당 역할 사용자 재로그인 후 적용됩니다.');
        } catch(e) {
          statusEl.style.color = '#dc2626';
          statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
        }
      });
    }

    // ── 계정 거버넌스 열람 역할 (admin 조정) ───────────────────────────────
    async function loadAccountViewRoles() {
      const listEl = document.getElementById('acctrole_list');
      if (!listEl) return;
      listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/accounts/view-roles');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const roles = data.roles || ['admin','security'];
        const locked = data.locked || ['admin'];
        const all = data.all_roles || ['admin','security','monitor','auditor','helpdesk','user'];
        listEl.innerHTML = all.map(r => {
          const isLocked = locked.includes(r);
          const checked = roles.includes(r) ? 'checked' : '';
          const dis = isLocked ? 'disabled' : '';
          const meta = ROLE_PERM_ROLES.find(x => x.key === r);
          const lbl = r === 'admin' ? tt('admin.dyn.role.admin','관리자 (admin)') : (meta ? tt(meta.labelKey, meta.label) : r);
          return `<label style=\"display:flex;align-items:center;gap:8px;padding:8px 12px;border:1px solid #e5e7eb;border-radius:8px;background:#ffffff;cursor:${isLocked?'not-allowed':'pointer'};opacity:${isLocked?'0.65':'1'}\">
            <input type=\"checkbox\" data-acctrole=\"${r}\" ${checked} ${dis} style=\"width:auto;margin:0\" />
            <span style=\"font-size:13px\">${escapeHtml(lbl)}${isLocked?` <span style=\"color:#111827;font-size:11px\">${tt('admin.dyn.locked','(항상 포함)')}</span>`:''}</span>
          </label>`;
        }).join('');
      } catch(e) {
        listEl.innerHTML = `<span class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span>`;
      }
    }
    window.loadAccountViewRoles = loadAccountViewRoles;
    document.getElementById('reload_acctrole')?.addEventListener('click', loadAccountViewRoles);
    document.getElementById('save_acctrole')?.addEventListener('click', async () => {
      const statusEl = document.getElementById('acctrole_status');
      const roles = [...document.querySelectorAll('#acctrole_list input[type=checkbox]:checked')].map(cb => cb.dataset.acctrole);
      statusEl.textContent = tt('admin.dyn.saving','저장 중...');
      try {
        const res = await fetch('/accounts/view-roles', {
          method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({roles}),
        });
        if (!res.ok) throw new Error(await res.text());
        statusEl.style.color = '#16a34a';
        statusEl.textContent = tt('admin.dyn.acctrole_saved','저장되었습니다. 대상 사용자 재로그인 후 계정 탭이 보입니다.');
      } catch(e) {
        statusEl.style.color = '#dc2626';
        statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
      }
    });

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
            ? `<span style=\"background:#fef9c3;color:#ea580c;padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px\">${tt('admin.dyn.override_custom','개별 설정')}</span>`
            : `<span style=\"background:#e5e7eb;color:#2563eb;padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px\">${tt('admin.dyn.override_default','역할 기본값')}</span>`;
          const checks = ROLE_PERM_TABS.map(tab => {
            const checked = activeTabs.includes(tab.id) ? 'checked' : '';
            return `<label style=\"display:flex;align-items:center;gap:6px;padding:5px 8px;border:1px solid #e5e7eb;border-radius:6px;background:#ffffff;cursor:pointer;font-size:12px\">
              <input type=\"checkbox\" data-user=\"${escapeHtml(u.username)}\" data-utab=\"${tab.id}\" ${checked} style=\"width:auto;margin:0\" onchange=\"_onUserTabChange('${escapeHtml(u.username)}')\" />
              <span>${tt(tab.labelKey, tab.label)}</span>
            </label>`;
          }).join('');
          const resetBtn = u.has_override
            ? `<button onclick=\"_resetUserTabs('${escapeHtml(u.username)}')\" style=\"font-size:11px;padding:3px 10px;background:#fee2e2;color:#dc2626;border:1px solid #fee2e2;border-radius:6px;cursor:pointer;margin-left:8px\">${tt('admin.dyn.reset','초기화')}</button>`
            : '';
          return `<div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:14px\" id=\"usertab_row_${escapeHtml(u.username)}\">
            <div style=\"display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px\">
              <div>
                <strong style=\"color:#111827\">${escapeHtml(u.username)}</strong>
                <span style=\"color:#111827;font-size:12px;margin-left:6px\">(${escapeHtml(u.role)})</span>
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
      if (statusEl) { statusEl.style.color = '#111827'; statusEl.textContent = tt('admin.dyn.saving','저장 중…'); }
      try {
        const res = await fetch(`/admin/user-tab-permissions/${encodeURIComponent(username)}`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ tabs }),
        });
        if (!res.ok) throw new Error(await res.text());
        if (statusEl) { statusEl.style.color = '#16a34a'; statusEl.textContent = tt('admin.dyn.saved_relogin','저장됨 (재로그인 후 적용)'); }
        // 배지 업데이트
        setTimeout(() => loadUserTabPermissions(), 500);
      } catch(e) {
        if (statusEl) { statusEl.style.color = '#dc2626'; statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
      }
    }
    window._onUserTabChange = _onUserTabChange;

    async function _resetUserTabs(username) {
      if (!confirm(`${username}${tt('admin.dyn.confirm_reset_usertabs',' 유저의 개별 탭 설정을 초기화하시겠습니까?\\n역할 기본값으로 돌아갑니다.')}`)) return;
      const statusEl = document.getElementById('usertab_status_' + username);
      try {
        const res = await fetch(`/admin/user-tab-permissions/${encodeURIComponent(username)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await res.text());
        if (statusEl) { statusEl.style.color = '#16a34a'; statusEl.textContent = tt('admin.dyn.reset_done','초기화됨'); }
        setTimeout(() => loadUserTabPermissions(), 500);
      } catch(e) {
        if (statusEl) { statusEl.style.color = '#dc2626'; statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
      }
    }
    window._resetUserTabs = _resetUserTabs;

    if (document.getElementById('reload_usertab')) {
      document.getElementById('reload_usertab')?.addEventListener('click', loadUserTabPermissions);
    }


    // ── Phase 2: Overview · Compliance · Triage · Remediation 로더 ───────────
    const STATUS_BADGE = {
      pass:'<span style=\"background:rgba(34,197,94,.12);color:#16a34a;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">PASS</span>',
      fail:'<span style=\"background:rgba(248,113,113,.12);color:#dc2626;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">FAIL</span>',
      warning:'<span style=\"background:rgba(250,204,21,.12);color:#ea580c;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">WARN</span>',
      not_applicable:'<span style=\"background:rgba(148,163,184,.12);color:#111827;padding:2px 8px;border-radius:6px;font-size:12px\">N/A</span>',
      not_checked:`<span style=\"background:rgba(100,116,139,.12);color:#111827;padding:2px 8px;border-radius:6px;font-size:12px\">${tt('admin.dyn.metric.not_checked','미점검')}</span>`,
    };
    const _statusBadge = (s) => STATUS_BADGE[s] || `<span>${escapeHtml(s||'')}</span>`;
    const _sourceBadge = (src) => {
      const map = { control_check:'#2563eb', trivy:'#ea580c', alert:'#dc2626' };
      const color = map[src] || '#111827';
      return `<span style=\"background:rgba(56,189,248,.08);color:${color};padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700\">${escapeHtml(src||'-')}</span>`;
    };

    async function loadAdminPhase2Health() {
      const el = document.getElementById('phase2_health');
      if (!el) return;
      el.innerHTML = `<div class=\"coverage-item\"><span style=\"color:#111827\">${tt('admin.dyn.loading','로딩 중…')}</span></div>`;
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
            <div style=\"color:#111827;font-size:12px\">${escapeHtml(it.label)}</div>
            <strong style=\"color:${it.value>0?'#16a34a':'#dc2626'}\">${it.value}</strong>
            <div style=\"color:#111827;font-size:11px;margin-top:4px\">${escapeHtml(it.hint)}</div>
          </div>`).join('');
      } catch (e) {
        el.innerHTML = `<div class=\"coverage-item\"><span style=\"color:#dc2626\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span></div>`;
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
          let statusColor = '#16a34a', statusLabel = (rec.status||'unknown').toUpperCase();
          if (rec.status === 'error') { statusColor = '#dc2626'; }
          else if (rec.is_stale) { statusColor = '#ea580c'; statusLabel = 'STALE'; }
          else if (rec.status === 'running') { statusColor = '#2563eb'; }
          const lagColor = rec.is_stale ? '#ea580c' : (lagSec != null ? '#111827' : '#111827');
          const slaText = sla ? _humanizeLag(sla) : '-';
          const errBadge = lastErr ? `<div style=\"color:#dc2626;font-size:11px;margin-top:2px\">${tt('admin.dyn.recent_error_prefix','최근 에러: ')}${escapeHtml(formatTime(rec.last_error_at))}</div>` : '';
          return `<tr>
            <td><strong>${escapeHtml((rec.source||'-').toUpperCase())}</strong></td>
            <td><span style=\"background:rgba(56,189,248,.08);color:${statusColor};padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">${escapeHtml(statusLabel)}</span></td>
            <td style=\"text-align:right\">${rec.host_count||0}</td>
            <td style=\"color:${lagColor}\">${lagSec != null ? _humanizeLag(lagSec) + tt('admin.dyn.ago_suffix',' 전') : '-'}</td>
            <td style=\"color:#111827;font-size:12px\">${escapeHtml(slaText)}</td>
            <td style=\"text-align:right;color:#111827\">${rec.records_collected||0}<div style=\"color:#111827;font-size:11px\">env ${rec.envelopes_normalized||0} · save ${rec.entities_saved||0}</div></td>
            <td style=\"color:#111827;font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis\">${escapeHtml(rec.message||'-')}${errBadge}</td>
          </tr>`;
        };
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>Source</th><th>Status</th><th style=\"text-align:right\">${tt('admin.dyn.col.host','호스트')}</th><th>Lag</th><th>SLA</th><th style=\"text-align:right\">${tt('admin.dyn.col.collected','수집')}</th><th>${tt('admin.dyn.col.message','메시지')}</th></tr></thead>
          <tbody>${rows.map(fmt).join('')}</tbody></table>`;
          _pgApply(el);
      } catch (e) {
        el.innerHTML = `<div class=\"empty\">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_freshness')) {
      document.getElementById('admin_reload_freshness').addEventListener('click', loadAdminSourceFreshness);
    }

    async function loadAdminCompliance() {  // (deprecated Compliance는 /ui 에서만 편집)
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
          <div class=\"metric-card card\"><div class=\"metric-label\">${tt('admin.dyn.metric.total_checks','전체 점검')}</div><div class=\"metric-value\">${total}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">Pass</div><div class=\"metric-value\" style=\"color:#16a34a\">${s.pass||0}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">Fail</div><div class=\"metric-value\" style=\"color:#dc2626\">${s.fail||0}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">Warning</div><div class=\"metric-value\" style=\"color:#ea580c\">${s.warning||0}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">Pass Rate</div><div class=\"metric-value\" style=\"color:#2563eb\">${passRate===null?'':passRate+'%'}</div></div>
          <div class=\"metric-card card\"><div class=\"metric-label\">${tt('admin.dyn.metric.pending_icon','미조치')}</div><div class=\"metric-value\" style=\"color:#ea580c\">${data.pending_count||0}</div><div class=\"metric-sub\">${tt('admin.dyn.col.control','통제')} ${ps.control_check||0} · Trivy ${ps.trivy||0} · Alert ${ps.alert||0}</div></div>
        `;
        const cats = data.categories || [];
        if (!cats.length) {
          catEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_category','카테고리 데이터 없음 시드 누락 가능성')}</div>`;
        } else {
          catEl.innerHTML = `<table class=\"result-table\">
            <thead><tr><th>${tt('admin.dyn.col.category','카테고리')}</th><th>${tt('admin.dyn.col.total','총')}</th><th style=\"color:#16a34a\">Pass</th><th style=\"color:#dc2626\">Fail</th><th style=\"color:#ea580c\">Warning</th><th style=\"color:#111827\">N/A</th><th style=\"color:#111827\">${tt('admin.dyn.col.not_checked','미점검')}</th></tr></thead>
            <tbody>${cats.map(c => `<tr>
              <td><strong>${escapeHtml(c.category||'-')}</strong></td>
              <td>${c.total||0}</td>
              <td style=\"color:#16a34a\">${c.pass||0}</td>
              <td style=\"color:#dc2626\">${c.fail||0}</td>
              <td style=\"color:#ea580c\">${c.warning||0}</td>
              <td style=\"color:#111827\">${c.not_applicable||0}</td>
              <td style=\"color:#111827\">${c.not_checked||0}</td>
            </tr>`).join('')}</tbody></table>`;
            _pgApply(catEl);
        }
        const pending = data.pending_remediations || [];
        if (!pending.length) {
          pendingEl.innerHTML = `<div class=\"empty\">${tt('admin.dyn.none_pending','미조치 항목 없음 ')}</div>`;
        } else {
          pendingEl.innerHTML = `<table class=\"result-table\">
            <thead><tr><th>${tt('admin.dyn.col.source','출처')}</th><th>${tt('admin.dyn.col.control_id','통제 ID')}</th><th>${tt('admin.dyn.col.target','대상')}</th><th>${tt('admin.dyn.col.status','상태')}</th><th>${tt('admin.dyn.col.owner','담당자')}</th><th>${tt('admin.dyn.col.due','조치기한')}</th><th>${tt('admin.dyn.col.note','비고')}</th></tr></thead>
            <tbody>${pending.slice(0,100).map(p => `<tr>
              <td>${_sourceBadge(p.source)}</td>
              <td><strong>${escapeHtml(p.control_id||'-')}</strong></td>
              <td>${escapeHtml(p.entity_id||'-')}</td>
              <td>${_statusBadge(p.status)}</td>
              <td>${escapeHtml(p.owner||'-')}</td>
              <td style=\"${p.overdue?'color:#dc2626;font-weight:700':''}\">${p.overdue?'':''}${escapeHtml(p.remediation_due_at?formatTime(p.remediation_due_at):'-')}</td>
              <td style=\"color:#111827;font-size:12px\">${escapeHtml(p.note||'')}</td>
            </tr>`).join('')}${pending.length>100?`<tr><td colspan=\"7\" style=\"color:#111827;text-align:center;padding:8px\">… ${pending.length-100}${tt('admin.dyn.more_rows_suffix','건 더 (CSV 다운로드 권장)')}</td></tr>`:''}</tbody></table>`;
            _pgApply(pendingEl);
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
        const TRIAGE_LABEL = { pending:tt('admin.dyn.atriage.pending','대기'), reviewing:tt('admin.dyn.atriage.reviewing','검토중'), resolved:tt('admin.dyn.atriage.resolved','조치') };
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>${tt('admin.dyn.col.severity','심각도')}</th><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.message','메시지')}</th><th>Triage</th><th>${tt('admin.dyn.col.analyst','분석관')}</th><th>${tt('admin.dyn.col.observed','발생 시각')}</th></tr></thead>
          <tbody>${rows.map(a => {
            const sev = a.severity || '-';
            const sevColor = sev==='critical'?'#dc2626':sev==='high'?'#ea580c':'#111827';
            const t = a.triage || {};
            return `<tr>
              <td><strong style=\"color:${sevColor}\">${escapeHtml(sev.toUpperCase())}</strong></td>
              <td>${escapeHtml(a.hostname||a.host_id||'-')}</td>
              <td style=\"color:#111827;max-width:380px;overflow:hidden;text-overflow:ellipsis\">${escapeHtml(a.message||'')}</td>
              <td>${escapeHtml(TRIAGE_LABEL[t.status]||t.status||tt('admin.dyn.atriage.pending','대기'))}</td>
              <td style=\"color:#2563eb\">${escapeHtml(t.analyst||'-')}</td>
              <td style=\"color:#111827;font-size:12px\">${escapeHtml(formatTime(a.observed_at))}</td>
            </tr>`;
          }).join('')}</tbody></table>`;
          _pgApply(el);
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
        const STATUS_COLOR = { open:'#dc2626', investigating:'#ea580c', resolved:'#16a34a', closed:'#111827' };
        el.innerHTML = `<table class=\"result-table\">
          <thead><tr><th>${tt('admin.dyn.col.title','제목')}</th><th>${tt('admin.dyn.col.status','상태')}</th><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.handler','담당자')}</th><th>${tt('admin.dyn.col.analyst','분석관')}</th><th>${tt('admin.dyn.col.created','등록일')}</th><th>${tt('admin.dyn.col.updated','업데이트')}</th></tr></thead>
          <tbody>${list.slice(0,100).map(i => `<tr>
            <td><strong>${escapeHtml(i.title||'-')}</strong></td>
            <td><span style=\"background:rgba(56,189,248,.08);color:${STATUS_COLOR[i.status]||'#111827'};padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700\">${escapeHtml((i.status||'').toUpperCase())}</span></td>
            <td>${escapeHtml(i.hostname||'-')}</td>
            <td>${escapeHtml(i.handler||'-')}</td>
            <td style=\"color:#2563eb\">${escapeHtml(i.analyst||'-')}</td>
            <td style=\"color:#111827;font-size:12px\">${escapeHtml(formatTime(i.created_at))}</td>
            <td style=\"color:#111827;font-size:12px\">${escapeHtml(formatTime(i.status_updated_at))}</td>
          </tr>`).join('')}</tbody></table>`;
          _pgApply(el);
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
            const planTxt = act.plan_text ? `<div>${escapeHtml(act.plan_text.substring(0,80))}${act.plan_text.length>80?'…':''}</div><div style=\"color:#111827;font-size:11px\">${tt('admin.dyn.due_prefix','기한 ')}${escapeHtml(act.plan_target_date||'-')} · ${escapeHtml(act.plan_updated_by||'-')}</div>` : `<span style=\"color:#111827\">${tt('admin.dyn.unregistered','미등록')}</span>`;
            const excTxt = act.exception_until ? `<div style=\"color:#ea580c\">~${escapeHtml(act.exception_until)}</div><div style=\"color:#111827;font-size:11px\">${escapeHtml((act.exception_reason||'').substring(0,60))}</div>` : '<span style=\"color:#111827\">-</span>';
            return `<tr>
              <td><strong>${escapeHtml(v.hostname||'-')}</strong></td>
              <td style=\"font-family:ui-monospace\">${escapeHtml(v.cve||v.vuln_id||'-')}</td>
              <td style=\"color:#111827\">${escapeHtml(v.package_name||'-')}</td>
              <td><strong style=\"color:${v.severity==='critical'?'#dc2626':'#ea580c'}\">${escapeHtml((v.severity||'').toUpperCase())}</strong></td>
              <td style=\"color:#111827;font-size:12px\">${planTxt}</td>
              <td style=\"font-size:12px\">${excTxt}</td>
            </tr>`;
          }).join('')}${flatRows.length>150?`<tr><td colspan=\"6\" style=\"color:#111827;text-align:center;padding:8px\">… ${flatRows.length-150}${tt('admin.dyn.more_rows_short','건 더')}</td></tr>`:''}</tbody></table>`;
          _pgApply(el);
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
            <td style=\"color:#ea580c\">${escapeHtml(r.plan.target_date||'-')}</td>
            <td style=\"color:#111827\">${escapeHtml((r.plan.text||'').substring(0,200))}${(r.plan.text||'').length>200?'…':''}</td>
            <td style=\"color:#111827;font-size:12px\">${escapeHtml(formatTime(r.plan.updated_at)||'-')} · ${escapeHtml(r.plan.updated_by||'-')}</td>
          </tr>`).join('')}</tbody></table>`;
          _pgApply(el);
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
      security: ['overview','compliance','triage','remediation','assets','access','logs'],
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
          badge.innerHTML = '<strong style="color:#2563eb">' + me.username + '</strong> <span style="background:#e5e7eb;color:#2563eb;padding:2px 8px;border-radius:6px;font-size:12px">' + roleLabel + '</span>';
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


