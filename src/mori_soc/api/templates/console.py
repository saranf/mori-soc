"""어드민 콘솔 페이지 (render_query_console_html)."""
from mori_soc.api.templates._common import *  # noqa: F401,F403
from mori_soc.api.templates.console_tabs import ADMIN_TABS_HTML


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
  <link rel="stylesheet" href="/static/css/console.css" />
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

__ADMIN_TABS__  </div>

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
    window.__MORI_ADMIN__ = {
      defaultPayload: __DEFAULT_PAYLOAD_JSON__,
      guideExamples: __GUIDE_EXAMPLES__,
      defaultUserDashboardPreferences: __USER_DASHBOARD_PREFS_JSON__,
      userDashboardCardLabels: __CARD_LABELS_JSON__,
      userDashboardSectionLabels: __SECTION_LABELS_JSON__,
      userDashboardAssetColumnLabels: __ASSET_COLUMN_LABELS_JSON__,
      userDashboardGuideLabels: __GUIDE_LABELS_JSON__,
      docsUrl: "__DOCS_PORTAL_URL__"
    };
  </script>
  <script src="/static/js/console.js"></script>
  __I18N_SCRIPT__
</body>
</html>"""
    return (
        html.replace("__ADMIN_TABS__", ADMIN_TABS_HTML)
        .replace("__PAYLOAD_JSON__", payload_json)
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


