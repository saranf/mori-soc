"""사용자 대시보드 페이지 (render_user_dashboard_html)."""
from mori_soc.api.templates._common import *  # noqa: F401,F403
from mori_soc.api.templates.dashboard_tabs import (
    _TAB_ACCOUNTS_HTML,
    _TAB_ASSETS_HTML,
    _TAB_COMPLIANCE_HTML,
    _TAB_DASHBOARD_HTML,
    _TAB_GUIDES_HTML,
    _TAB_INCIDENTS_HTML,
    _TAB_TRIAGE_HTML,
)


def render_user_dashboard_html(
    docs_url: str = DOCS_PORTAL_URL,
    fleet_ui_url: str = FLEET_UI_URL,
    zabbix_ui_url: str = ZABBIX_UI_URL,
    wazuh_ui_url: str = WAZUH_UI_URL,
    grafana_ui_url: str = GRAFANA_UI_URL,
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
  <link rel="stylesheet" href="/static/css/dashboard.css" />
</head>
<body>
  <div class=\"wrap\">
    <header class=\"topbar\">
      <span class=\"brand\">MORI</span>
      <nav class=\"tabs-nav\" id=\"main_tabs_nav\">
        <button class=\"active\" data-tab=\"dashboard\" onclick=\"switchTab('dashboard')\" data-i18n=\"dash.tab.dashboard\">대시보드</button>
        <button data-tab=\"triage\" onclick=\"switchTab('triage')\" data-i18n=\"dash.tab.triage\">알림 분류</button>
        <button data-tab=\"incidents\" onclick=\"switchTab('incidents')\" data-i18n=\"dash.tab.incidents\">인시던트</button>
        <button data-tab=\"assets\" onclick=\"switchTab('assets')\" data-i18n=\"dash.tab.assets\">자산 현황</button>
        <button data-tab=\"compliance\" onclick=\"switchTab('compliance')\" data-i18n=\"dash.tab.compliance\">심사 준비</button>
        <button id=\"tab_btn_accounts\" data-tab=\"accounts\" onclick=\"switchTab('accounts')\" data-i18n=\"dash.tab.accounts\" style=\"display:none\">계정</button>
        <button data-tab=\"guides\" onclick=\"switchTab('guides')\" data-i18n=\"dash.tab.guides\">가이드 &amp; 기준</button>
      </nav>
      <div class=\"top-actions\">
        <a class=\"portal-link\" href=\"__DOCS_PORTAL_URL__\" target=\"_blank\" rel=\"noreferrer\" data-i18n=\"dash.links.docs\">운영 문서 / 포털</a>
        <button id=\"refresh_dashboard\" type=\"button\" class=\"secondary\" style=\"width:auto;padding:6px 12px;font-size:13px\" data-i18n=\"dash.actions.refresh\">새로고침</button>
        <div class=\"account-wrap\" style=\"position:relative\">
          <button id=\"account_btn\" type=\"button\" onclick=\"toggleAccountMenu()\" style=\"width:auto;background:#f9fafb;border:1px solid #e5e7eb;color:#111827;font-size:13px;font-weight:600;padding:6px 12px;border-radius:999px;cursor:pointer\"><span id=\"ui_user_badge\" data-i18n=\"dash.account.title\">계정</span></button>
          <div id=\"account_menu\" style=\"display:none;position:absolute;right:0;top:calc(100% + 6px);background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:12px;min-width:220px;z-index:9998;box-shadow:0 8px 24px rgba(0,0,0,0.45)\">
            <button type=\"button\" onclick=\"openProfileModal()\" style=\"display:block;width:100%;text-align:left;background:transparent;border:none;color:#111827;font-size:13px;font-weight:600;padding:6px 4px;cursor:pointer\" data-i18n=\"dash.account.edit_profile\">프로필 편집</button>
            <button type=\"button\" onclick=\"shortcutMyServers()\" style=\"display:block;width:100%;text-align:left;background:transparent;border:none;color:#111827;font-size:13px;font-weight:600;padding:6px 4px;cursor:pointer\" data-i18n=\"dash.account.my_servers\">내 서버</button>
            <a id=\"ui_admin_console_link\" href=\"/admin\" style=\"display:none;width:100%;text-align:left;color:#111827;font-size:13px;font-weight:600;padding:6px 4px;text-decoration:none\" data-i18n=\"dash.account.admin_console\">관리자 콘솔</a>
            <div style=\"border-top:1px solid #e5e7eb;margin:10px 0\"></div>
            <div style=\"font-size:12px;color:#111827;margin-bottom:6px\" data-i18n=\"dash.account.language\">언어 / Language</div>
            __I18N_TOGGLE__
            <div style=\"border-top:1px solid #e5e7eb;margin:10px 0\"></div>
            <a href=\"/auth/logout\" class=\"logout-btn\" style=\"display:block;text-align:center\" data-i18n=\"dash.actions.logout\">로그아웃</a>
          </div>
        </div>
      </div>
    </header>

__TAB_DASHBOARD____TAB_TRIAGE____TAB_INCIDENTS____TAB_ASSETS____TAB_COMPLIANCE____TAB_ACCOUNTS____TAB_GUIDES__  </div>

  <dialog id=\"overview_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"overview_modal_title\">Overview Details</h3>
        <form method=\"dialog\"><button type=\"submit\" style=\"padding:6px 16px;background:#f9fafb;color:#2563eb;border:1px solid #e5e7eb;border-radius:999px;cursor:pointer;\" data-i18n=\"dash.f.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"overview_modal_copy\" data-i18n=\"dash.modal.overview_copy\">선택한 카드의 상세 목록입니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"overview_modal_body\"></div>
  </dialog>

  <dialog id=\"info_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"info_modal_title\" data-i18n=\"dash.modal.info_title\">알림</h3>
        <form method=\"dialog\"><button type=\"submit\" style=\"padding:6px 16px;background:#f9fafb;color:#2563eb;border:1px solid #e5e7eb;border-radius:999px;cursor:pointer;\" data-i18n=\"dash.f.confirm\">확인</button></form>
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

  <dialog id=\"evidence_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"evidence_modal_title\" data-i18n=\"dash.ctl.ev_title\">수기 증적</h3>
        <form method=\"dialog\"><button class=\"secondary\" data-i18n=\"dash.f.close\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"evidence_modal_body\"></div>
    </div>
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
            <option value=\"pending\" data-i18n=\"dash.opt.triage_pending\">미확인 (Pending)</option>
            <option value=\"reviewing\" data-i18n=\"dash.opt.triage_reviewing\">검토중 (Reviewing)</option>
            <option value=\"resolved\" data-i18n=\"dash.opt.triage_resolved\">조치예정/완료 (Resolved)</option>
          </select>
        </div>
        <div class=\"row\"><label><span data-i18n=\"dash.f.analyst\">담당자</span> <span style=\"color:#111827;font-size:11px\" data-i18n=\"dash.modal.analyst_default_hint\">(서버 담당자 기본)</span></label><input id=\"triage_modal_analyst\" placeholder=\"예: alice\" data-i18n-placeholder=\"dash.ph.alice\" /></div>
        <div class=\"row\"><label data-i18n=\"dash.f.changed_by\">변경자(작성)</label><input id=\"triage_modal_actor\" placeholder=\"예: alice (미입력 시 로그인 사용자)\" data-i18n-placeholder=\"dash.ph.alice_login\" /></div>
        <div class=\"row\"><label data-i18n=\"dash.f.note\">메모</label><textarea id=\"triage_modal_note\" style=\"min-height:80px\"></textarea></div>
        <div class=\"actions\">
          <button id=\"triage_modal_save\" data-i18n=\"dash.f.save\">저장</button>
          <form method=\"dialog\"><button class=\"secondary\" data-i18n=\"dash.f.cancel\">취소</button></form>
        </div>
        <div class=\"status-line\" id=\"triage_modal_status_line\"></div>
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
        <div id=\"incident_modal_info\" style=\"margin-bottom:12px;font-size:13px;color:#111827\"></div>
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
        <hr style=\"border-color:#111827;margin:12px 0\" />
        <div style=\"margin-bottom:8px;font-size:13px;font-weight:600;color:#16a34a\" data-i18n=\"dash.modal.notes_title\">조사 노트</div>
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
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:28px 32px;width:500px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"plan_modal_title\" style=\"color:#16a34a;margin:0\" data-i18n=\"dash.modal.action_plan\">조치 계획</h3>
        <button onclick=\"closePlanModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.plan_content\">조치 계획 내용</label>
          <textarea id=\"plan_text\" rows=\"4\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 2024년 2분기 내 패키지 업그레이드 예정\" data-i18n-placeholder=\"dash.ph.plan_example\"></textarea>
        </div>
        <div style=\"display:flex;gap:12px\">
          <div style=\"flex:1\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.target_date\">목표 완료일</label>
            <input type=\"date\" id=\"plan_target_date\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
          </div>
          <div style=\"flex:1\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.author\">작성자</label>
            <input id=\"plan_updated_by\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 김보안\" data-i18n-placeholder=\"dash.ph.author_example\" />
          </div>
        </div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"plan_modal_save\" style=\"background:#16a34a;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
          <button onclick=\"closePlanModal()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 프로필 편집 모달 -->
  <div id=\"profile_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:28px 32px;width:440px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"profile_modal_title\" style=\"color:#2563eb;margin:0\" data-i18n=\"dash.profile.title\">내 프로필 편집</h3>
        <button onclick=\"closeProfileModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.profile.display_name\">이름</label>
          <input id=\"profile_display_name\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"dash.profile.display_name_ph\" />
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.profile.department\">부서</label>
          <input id=\"profile_department\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 인프라팀\" data-i18n-placeholder=\"dash.profile.department_ph\" />
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.profile.assigned_servers\">담당 서버 (호스트명)</label>
          <textarea id=\"profile_assigned_servers\" rows=\"4\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"한 줄에 하나씩 또는 쉼표로 구분\" data-i18n-placeholder=\"dash.profile.assigned_servers_ph\"></textarea>
          <span style=\"color:#111827;font-size:11px\" data-i18n=\"dash.profile.assigned_servers_hint\">내 서버 탭에서 이 호스트만 모아 볼 수 있습니다.</span>
        </div>
        <div id=\"profile_modal_status\" style=\"font-size:13px;color:#111827;\"></div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"profile_modal_save\" onclick=\"saveProfile()\" style=\"background:#2563eb;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.profile.save\">저장</button>
          <button onclick=\"closeProfileModal()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.profile.cancel\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 담당자 편집 모달 (사용자용) -->
  <div id=\"owner_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:28px 32px;width:440px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"owner_modal_title\" style=\"color:#16a34a;margin:0\" data-i18n=\"dash.modal.edit_owner_title\">담당자/카테고리 수정</h3>
        <button onclick=\"closeOwnerModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.hostname\">호스트명</label>
          <input id=\"owner_modal_hostname\" readonly style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.analyst\">담당자</label>
          <input id=\"owner_modal_owner\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"dash.ph.owner_example\" />
        </div>
        <div id=\"owner_modal_category_row\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.category\">카테고리 (서버 분류)</label>
          <input id=\"owner_modal_category\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 웹 서버\" data-i18n-placeholder=\"dash.ph.category_example\" />
        </div>
        <div id=\"owner_modal_importance_row\"><label style=\"color:#111827;font-size:13px\"><span data-i18n=\"dash.f.importance\">중요도</span> <span style=\"color:#111827;font-size:11px\" data-i18n=\"dash.modal.importance_hint\">(자동 분류 재정의)</span></label>
          <select id=\"owner_modal_importance\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\">
            <option value=\"\" data-i18n=\"dash.opt.auto\">자동 (기본)</option>
            <option value=\"상\" data-i18n=\"dash.opt.high\">상</option>
            <option value=\"중\" data-i18n=\"dash.opt.mid\">중</option>
            <option value=\"하\" data-i18n=\"dash.opt.low\">하</option>
          </select>
        </div>
        <div id=\"owner_modal_exception_row\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.exception_until\">처리 예외 기한</label>
          <input type=\"date\" id=\"owner_modal_exception_until\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
          <span style=\"color:#111827;font-size:11px\" data-i18n=\"dash.modal.exception_hint\">이 날짜까지 점검/알림 예외 처리됩니다</span>
          <label style=\"color:#111827;font-size:13px;margin-top:8px;display:block\" data-i18n=\"dash.f.exception_reason\">예외 사유</label>
          <textarea id=\"owner_modal_exception_reason\" rows=\"2\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 레거시 시스템으로 패치 불가, 2분기 교체 예정\" data-i18n-placeholder=\"dash.ph.exception_reason_example\"></textarea>
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.team\">팀</label>
          <input id=\"owner_modal_team\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 인프라팀\" data-i18n-placeholder=\"dash.ph.team_example\" />
        </div>

        <div id=\"owner_modal_status\" style=\"font-size:13px;color:#111827;\"></div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"owner_modal_save\" style=\"background:#2563eb;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
          <button onclick=\"closeOwnerModal()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Trivy 호스트별 취약점 리스트 모달 -->
  <div id=\"vuln_list_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:24px 28px;width:980px;max-width:96vw;max-height:88vh;overflow:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 id=\"vuln_list_modal_title\" style=\"color:#ca8a04;margin:0\" data-i18n=\"dash.modal.vuln_detail_title\">취약점 상세</h3>
        <button onclick=\"closeVulnListModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div id=\"vuln_list_modal_subtitle\" style=\"color:#111827;font-size:12px;margin-bottom:10px\"></div>
      <div id=\"vuln_list_modal_body\"></div>
    </div>
  </div>

  <!-- 호스트 단위 조치 계획 안내 모달 (CVE별 상세 계획 존재 시) -->
  <div id=\"vuln_plans_notice_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #fef9c3;border-radius:10px;padding:28px 32px;width:480px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 style=\"color:#ca8a04;margin:0\" data-i18n=\"dash.modal.plan_exists_title\">상세 계획이 정해져 있습니다</h3>
        <button onclick=\"closeVulnPlansNotice()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div id=\"vuln_plans_notice_body\" style=\"color:#111827;font-size:13px;line-height:1.6;margin-bottom:18px\"></div>
      <div style=\"display:flex;gap:10px;justify-content:flex-end\">
        <button onclick=\"closeVulnPlansNotice()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px\" data-i18n=\"dash.f.close\">닫기</button>
        <button id=\"vuln_plans_notice_open_list\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#2563eb;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600\" data-i18n=\"dash.modal.open_summary_tab\">합계 탭 열기</button>
      </div>
    </div>
  </div>

  <!-- PDCA Do(조치) 항목 상세 모달 -->
  <div id=\"pdca_do_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #ca8a04;border-radius:10px;padding:24px 28px;width:1080px;max-width:96vw;max-height:88vh;overflow:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 style=\"color:#ca8a04;margin:0\" data-i18n=\"dash.modal.pdca_do_title\">Do 조치가 필요한 항목</h3>
        <button onclick=\"closePdcaDoModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div id=\"pdca_do_modal_subtitle\" style=\"color:#111827;font-size:12px;margin-bottom:10px\"></div>
      <div id=\"pdca_do_modal_body\"></div>
    </div>
  </div>

  <!-- 감사 증적 리포트 미리보기 모달 (CSV 미리보기 + 다운로드) -->
  <div id=\"report_preview_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:24px 28px;width:1080px;max-width:96vw;max-height:88vh;overflow:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;gap:12px;flex-wrap:wrap\">
        <h3 id=\"report_preview_title\" style=\"color:#2563eb;margin:0\" data-i18n=\"dash.modal.report_preview_title\">리포트 미리보기</h3>
        <div style=\"display:flex;gap:8px;align-items:center\">
          <a id=\"report_preview_download\" href=\"#\" download style=\"background:#dbeafe;border:1px solid #dbeafe;color:#2563eb;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none\" data-i18n=\"dash.modal.csv_download\">CSV 다운로드</a>
          <a id=\"report_preview_download_pdf\" href=\"#\" download style=\"background:#ffedd5;border:1px solid #ca8a04;color:#ca8a04;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none\" data-i18n=\"dash.modal.pdf_download\">PDF 다운로드</a>
          <button onclick=\"closeReportPreview()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
        </div>
      </div>
      <div id=\"report_preview_subtitle\" style=\"color:#111827;font-size:12px;margin-bottom:10px\" data-i18n=\"dash.modal.report_preview_sub\">CSV 파일이 아래와 같은 형태로 생성됩니다. (상위 50행만 표시)</div>
      <div id=\"report_preview_body\"></div>
    </div>
  </div>

  <!-- 인시던트 CSV 다운로드 안내 모달 -->
  <div id=\"incident_csv_notice_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #fef9c3;border-radius:10px;padding:28px 32px;width:520px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 style=\"color:#ca8a04;margin:0\" data-i18n=\"dash.modal.incident_csv_title\">인시던트 CSV 다운로드</h3>
        <button onclick=\"closeIncidentCsvNotice()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div style=\"color:#111827;font-size:13px;line-height:1.7;margin-bottom:18px\">
        <div style=\"margin-bottom:10px\" data-i18n-html=\"dash.modal.incident_csv_warn_html\"><strong style=\"color:#ca8a04\">변경 내역(history)은 CSV 내역에 포함되지 않습니다.</strong></div>
        <div style=\"color:#111827\" data-i18n-html=\"dash.modal.incident_csv_desc_html\">각 인시던트는 <strong style=\"color:#2563eb\">변경 일자</strong>와 <strong style=\"color:#2563eb\">최신 내역</strong>(현재 상태 / 담당자 / 영향도 등)만 1행으로 표시됩니다.</div>
        <div style=\"color:#111827;margin-top:10px;font-size:12px\" data-i18n-html=\"dash.modal.incident_csv_hint_html\">전체 변경 이력은 어드민 <strong>통합 이력 로그</strong> 페이지 또는 <code style=\"background:#e5e7eb;padding:1px 6px;border-radius:3px\">/incidents/{id}/history</code> API를 이용해 주세요.</div>
      </div>
      <div style=\"display:flex;gap:10px;justify-content:flex-end\">
        <button onclick=\"closeIncidentCsvNotice()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px\" data-i18n=\"dash.f.cancel\">취소</button>
        <button id=\"incident_csv_confirm_btn\" style=\"background:#dbeafe;border:1px solid #dbeafe;color:#2563eb;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600\" data-i18n=\"dash.modal.download\">다운로드</button>
      </div>
    </div>
  </div>

  <!-- 취약점별 조치 계획 / 조치 예외 편집 모달 -->
  <div id=\"vuln_action_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:24px 28px;width:520px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 id=\"vuln_action_modal_title\" style=\"color:#16a34a;margin:0\" data-i18n=\"dash.modal.vuln_action_title\">취약점 조치</h3>
        <button onclick=\"closeVulnActionModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div id=\"vuln_action_modal_meta\" style=\"color:#111827;font-size:12px;margin-bottom:12px;border:1px solid #e5e7eb;border-radius:6px;padding:8px 10px;background:#ffffff\"></div>

      <!-- 조치 계획 영역 -->
      <div id=\"vuln_plan_section\" style=\"display:none;flex-direction:column;gap:10px\">
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.plan_content\">조치 계획 내용</label>
          <textarea id=\"vuln_plan_text\" rows=\"4\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 다음 정기 패치 일정에 openssh 9.3p2로 업그레이드\" data-i18n-placeholder=\"dash.ph.vuln_plan_example\"></textarea>
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.target_date\">목표 완료일</label>
          <input type=\"date\" id=\"vuln_plan_target_date\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.author\">작성자</label>
          <input id=\"vuln_plan_updated_by\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: security\" data-i18n-placeholder=\"dash.ph.security_example\" />
        </div>
      </div>

      <!-- 조치 예외 영역 -->
      <div id=\"vuln_exception_section\" style=\"display:none;flex-direction:column;gap:10px\">
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.modal.exception_period\">예외 처리 기한</label>
          <input type=\"date\" id=\"vuln_exception_until\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
          <span style=\"color:#111827;font-size:11px\" data-i18n=\"dash.modal.vuln_exception_hint\">이 날짜까지 해당 취약점 점검/알림에서 제외됩니다</span>
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.exception_reason\">예외 사유</label>
          <textarea id=\"vuln_exception_reason\" rows=\"3\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 종속 라이브러리 호환성 이슈로 차분기 교체 예정\" data-i18n-placeholder=\"dash.ph.vuln_exception_reason_example\"></textarea>
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.f.author\">작성자</label>
          <input id=\"vuln_exception_updated_by\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: security\" data-i18n-placeholder=\"dash.ph.security_example\" />
        </div>
      </div>

      <div id=\"vuln_action_modal_status\" style=\"font-size:13px;color:#111827;margin-top:10px\"></div>
      <div style=\"display:flex;gap:8px;justify-content:flex-end;margin-top:12px\">
        <button id=\"vuln_action_modal_clear\" style=\"display:none;background:#fee2e2;border:1px solid #fee2e2;color:#dc2626;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px\" data-i18n=\"dash.modal.clear_exception\">예외 해제</button>
        <button id=\"vuln_action_modal_save\" style=\"background:#16a34a;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
        <button onclick=\"closeVulnActionModal()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
      </div>
    </div>
  </div>

  <!-- 위험성 평가 모달 (R-4) -->
  <div id=\"risk_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:24px 28px;width:560px;max-width:95vw;max-height:88vh;overflow-y:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:14px\">
        <h3 id=\"risk_modal_title\" style=\"color:#2563eb;margin:0\" data-i18n=\"dash.risk.modal_title\">위험성 평가</h3>
        <button onclick=\"closeRiskModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div id=\"risk_modal_meta\" style=\"color:#111827;font-size:12px;margin-bottom:12px;border:1px solid #e5e7eb;border-radius:6px;padding:8px 10px;background:#ffffff\"></div>
      <!-- 현재 등급 배지 + 자동 제안 -->
      <div id=\"risk_modal_grade\" style=\"margin-bottom:6px\"></div>
      <div style=\"font-size:11px;color:#111827;margin-bottom:12px;line-height:1.5\" data-i18n=\"dash.risk.basis_note\">산정 기준: 영향도(자산 중요도 상/중/하) × 발생가능성(취약점 심각도·Trivy CVSS 기반). ISMS-P 위험관리 / ISO 27001 6.1.2·8.8 방법론. 조직 DoA(수용가능 위험수준)에 맞춰 등급 조정 가능.</div>
      <div style=\"display:flex;flex-direction:column;gap:10px\">
        <div style=\"display:flex;gap:10px;flex-wrap:wrap\">
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.impact\">영향도 (자산 중요도)</label>
            <select id=\"risk_impact\" onchange=\"_riskRecalc()\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px\">
              <option value=\"3\" data-i18n=\"dash.acc.impf.high\">상 (3)</option><option value=\"2\" data-i18n=\"dash.acc.impf.mid\">중 (2)</option><option value=\"1\" data-i18n=\"dash.acc.impf.low\">하 (1)</option>
            </select></div>
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.likelihood\">발생가능성 (심각도 기반)</label>
            <select id=\"risk_likelihood\" onchange=\"_riskRecalc()\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px\">
              <option value=\"3\" data-i18n=\"dash.acc.impf.high\">상 (3)</option><option value=\"2\" data-i18n=\"dash.acc.impf.mid\">중 (2)</option><option value=\"1\" data-i18n=\"dash.acc.impf.low\">하 (1)</option>
            </select></div>
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.treatment\">위험 처리 결정</label>
          <select id=\"risk_treatment\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px\">
            <option value=\"\" data-i18n=\"dash.risk.t.none\">미정</option>
            <option value=\"mitigate\" data-i18n=\"dash.risk.t.mitigate\">조치(경감)</option>
            <option value=\"accept\" data-i18n=\"dash.risk.t.accept\">수용</option>
            <option value=\"transfer\" data-i18n=\"dash.risk.t.transfer\">이관</option>
            <option value=\"avoid\" data-i18n=\"dash.risk.t.avoid\">회피</option>
          </select></div>
        <div style=\"display:flex;gap:10px;flex-wrap:wrap\">
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.accept_approver\">승인자</label>
            <input id=\"risk_accept_approver\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
          <div style=\"flex:1;min-width:180px\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.review_due\">재평가 예정일</label>
            <input type=\"date\" id=\"risk_review_due\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
        </div>
        <div><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.accept_reason\">수용 사유</label>
          <textarea id=\"risk_accept_reason\" rows=\"2\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\"></textarea></div>
        <div style=\"display:flex;gap:10px;flex-wrap:wrap\">
          <div style=\"flex:1;min-width:160px\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.residual\">잔여 위험</label>
            <input id=\"risk_residual\" data-i18n-placeholder=\"dash.risk.f.residual_ph\" placeholder=\"예: 중간 / 낮음\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
          <div style=\"flex:1;min-width:160px\"><label style=\"color:#111827;font-size:13px\" data-i18n=\"dash.risk.f.assessed_by\">평가자</label>
            <input id=\"risk_assessed_by\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
        </div>
      </div>
      <!-- 산정 근거 (관리자 전용) -->
      <div id=\"risk_provenance\" style=\"display:none;margin-top:14px;border:1px solid #dbeafe;border-radius:8px;padding:10px 12px;background:#f9fafb\"></div>
      <div id=\"risk_modal_status\" style=\"font-size:13px;color:#111827;margin-top:10px\"></div>
      <div style=\"display:flex;gap:8px;justify-content:flex-end;margin-top:12px\">
        <button id=\"risk_modal_save\" onclick=\"saveRiskAssessment()\" style=\"background:#2563eb;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.save\">저장</button>
        <button onclick=\"closeRiskModal()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\" data-i18n=\"dash.f.cancel\">취소</button>
      </div>
    </div>
  </div>

  <!-- 위험 버킷 드릴다운 모달 (매트릭스 셀/칩 클릭) -->
  <div id=\"risk_bucket_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:24px 28px;width:660px;max-width:95vw;max-height:82vh;overflow-y:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px\">
        <h3 id=\"risk_bucket_modal_title\" style=\"color:#2563eb;margin:0\" data-i18n=\"dash.risk.bucket_title\">위험 상세</h3>
        <button onclick=\"closeRiskBucketModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div id=\"risk_bucket_modal_body\"></div>
    </div>
  </div>

  <!-- 내 서버 호스트 상세 모달 (행 더블클릭) -->
  <div id=\"host_detail_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center;\">
    <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:24px 28px;width:640px;max-width:95vw;max-height:85vh;overflow-y:auto\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px\">
        <h3 id=\"host_detail_title\" style=\"color:#16a34a;margin:0\" data-i18n=\"dash.host.detail_title\">호스트 상세</h3>
        <button onclick=\"closeHostDetail()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
      </div>
      <div id=\"host_detail_body\" style=\"color:#111827;font-size:13px\"></div>
    </div>
  </div>

  <!-- ── 하단 탭 바 (모바일 전용) ────────────────────────────────────────── -->
  <nav class=\"bottom-nav\" id=\"bottom_nav\">
    <button class=\"active\" data-tab=\"dashboard\" onclick=\"switchTab('dashboard')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"dash.bn.dashboard\">대시보드</span>
    </button>
    <button data-tab=\"triage\" onclick=\"switchTab('triage')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"dash.bn.triage\">Triage</span>
    </button>
    <button data-tab=\"assets\" onclick=\"switchTab('assets')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"dash.bn.assets\">자산</span>
    </button>
    <button data-tab=\"incidents\" onclick=\"switchTab('incidents')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"dash.bn.incidents\">인시던트</span>
    </button>
    <button data-tab=\"compliance\" onclick=\"switchTab('compliance')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"dash.bn.compliance\">PDCA</span>
    </button>
    <button data-tab=\"guides\" onclick=\"switchTab('guides')\">
      <span class=\"bn-icon\"></span><span data-i18n=\"dash.bn.guides\">가이드</span>
    </button>
  </nav>

  <script>
    window.__MORI__ = {
      defaultPreferences: __USER_DASHBOARD_PREFS_JSON__,
      cardLabels: __CARD_LABELS_JSON__,
      sectionLabels: __SECTION_LABELS_JSON__,
      nlqGuideExamples: __NLQ_GUIDE_EXAMPLES__,
      guideLabels: __GUIDE_LABELS_JSON__,
      fleetUrl: "__FLEET_UI_URL__",
      zabbixUrl: "__ZABBIX_UI_URL__",
      wazuhUrl: "__WAZUH_UI_URL__",
      grafanaUrl: "__GRAFANA_UI_URL__"
    };
  </script>
  <script src="/static/js/dashboard.js"></script>

  <!-- ── NLQ Floating Action Button ───────────────────────────────────── -->
  <button class=\"nlq-fab\" id=\"nlq_fab_btn\" title=\"자연어 질의 (NLQ)\" data-i18n=\"dash.nlq.fab_btn\" data-i18n-title=\"dash.nlq.fab_title\">NLQ 질의</button>

  <dialog id=\"nlq_fab_dialog\" class=\"nlq-dialog\">
    <div class=\"nlq-dialog-body\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px\">
        <h3 style=\"margin:0;font-size:18px\" data-i18n=\"dash.nlq.dialog_title\">자연어 질의 (NLQ)</h3>
        <button id=\"nlq_fab_close\" class=\"secondary\" style=\"padding:4px 12px\" data-i18n=\"dash.f.close\">닫기</button>
      </div>
      <div style=\"color:#111827;font-size:13px;margin-bottom:10px\"><span data-i18n=\"dash.nlq.dialog_desc\">자연스럽게 질문하거나 예시 형식으로 입력하면 해석합니다.</span> <a href=\"#\" id=\"nlq_guide_link\" style=\"color:#2563eb;\" data-i18n=\"dash.nlq.guide_link\">가이드</a></div>
      <textarea id=\"nlq_textarea\" rows=\"3\" style=\"width:100%;box-sizing:border-box;background:#ffffff;color:#111827;border:1px solid #e5e7eb;border-radius:8px;padding:10px;font-size:14px;resize:vertical;\" placeholder=\"예: 오프라인 호스트 보여줘 / 최근 24시간 wazuh high alert 요약\" data-i18n-placeholder=\"dash.nlq.textarea_ph\"></textarea>
      <div id=\"nlq_interpret_result\" style=\"margin:8px 0;color:#2563eb;font-size:13px;\"></div>
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
        html.replace("__TAB_DASHBOARD__", _TAB_DASHBOARD_HTML)
        .replace("__TAB_TRIAGE__", _TAB_TRIAGE_HTML)
        .replace("__TAB_INCIDENTS__", _TAB_INCIDENTS_HTML)
        .replace("__TAB_ASSETS__", _TAB_ASSETS_HTML)
        .replace("__TAB_COMPLIANCE__", _TAB_COMPLIANCE_HTML)
        .replace("__TAB_ACCOUNTS__", _TAB_ACCOUNTS_HTML)
        .replace("__TAB_GUIDES__", _TAB_GUIDES_HTML)
        .replace("__DOCS_PORTAL_URL__", docs_url)
        .replace("__USER_DASHBOARD_PREFS_JSON__", default_preferences_json)
        .replace("__CARD_LABELS_JSON__", card_labels_json)
        .replace("__SECTION_LABELS_JSON__", section_labels_json)
        .replace("__NLQ_GUIDE_EXAMPLES__", nlq_guide_examples_json)
        .replace("__FLEET_UI_URL__", fleet_ui_url)
        .replace("__ZABBIX_UI_URL__", zabbix_ui_url)
        .replace("__WAZUH_UI_URL__", wazuh_ui_url)
        .replace("__GRAFANA_UI_URL__", grafana_ui_url)
        .replace("__GUIDE_LABELS_JSON__", guide_labels_json)
        .replace("__I18N_TOGGLE__", _i18n_toggle_html(fixed=False))
        .replace("__I18N_SCRIPT__", _i18n_script(_DASHBOARD_I18N))
    )


