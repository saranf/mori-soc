"""사용자 대시보드 페이지 (render_user_dashboard_html)."""
from mori_soc.api.templates._common import *  # noqa: F401,F403


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
        <button data-tab=\"triage\" onclick=\"switchTab('triage')\" data-i18n=\"dash.tab.triage\">Alert Triage</button>
        <button data-tab=\"incidents\" onclick=\"switchTab('incidents')\" data-i18n=\"dash.tab.incidents\">인시던트</button>
        <button data-tab=\"assets\" onclick=\"switchTab('assets')\" data-i18n=\"dash.tab.assets\">자산 현황</button>
        <button data-tab=\"compliance\" onclick=\"switchTab('compliance')\" data-i18n=\"dash.tab.compliance\">Compliance PDCA</button>
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

    <!-- ── Tab: Dashboard ──────────────────────────────────────────────── -->
    <div class=\"tab-panel active\" id=\"tab_dashboard\">
      <div style=\"display:flex;justify-content:flex-end;align-items:center;gap:8px;margin-bottom:10px;\">
        <span style=\"font-size:11px;color:#111827;margin-right:auto\" data-i18n=\"dash.panel.resize_hint\">패널 오른쪽-아래 모서리를 드래그해 크기를 조절할 수 있어요 (브라우저에 저장)</span>
        <button id=\"panel_layout_reset\" class=\"secondary\" onclick=\"resetPanelLayout()\" style=\"width:auto;padding:6px 12px;font-size:13px\" data-i18n=\"dash.panel.reset_layout\">크기 초기화</button>
        <button id=\"panel_edit_toggle\" class=\"secondary\" onclick=\"togglePanelEdit()\" data-i18n=\"dash.panel.edit\">패널 편집</button>
      </div>
      <div id=\"panel_edit_box\" class=\"card hidden\" style=\"margin-bottom:12px;\">
        <div style=\"font-weight:600;color:#2563eb;margin-bottom:4px\" data-i18n=\"dash.panel.edit_title\">표시할 패널 선택</div>
        <div class=\"subtext\" data-i18n=\"dash.panel.edit_sub\">보고 싶은 것만 켜세요. 자동 저장돼서 다음에도 그대로예요.</div>
        <div style=\"margin-top:10px;font-size:12px;color:#111827\" data-i18n=\"dash.panel.group.cards\">요약 카드</div>
        <div id=\"panel_edit_cards\" style=\"display:flex;flex-wrap:wrap;gap:12px;margin:6px 0 12px\"></div>
        <div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.panel.group.sections\">패널</div>
        <div id=\"panel_edit_sections\" style=\"display:flex;flex-wrap:wrap;gap:12px;margin-top:6px\"></div>
      </div>
      <!-- 보안 요약 히어로 (Toss형: 보안 KPI + 위험 TOP 랭킹) 보안 우선, 인프라는 아래 -->
      <section class=\"card\" id=\"security_hero_section\" style=\"background:linear-gradient(135deg,#ffffff,#f9fafb);border:1px solid #e5e7eb\">
        <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
          <h2 style=\"margin:0\" data-i18n=\"dash.hero.section\">지금 봐야 할 보안 현황</h2>
          <button onclick=\"switchTab('assets');switchAssetTab('trivy')\" class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" data-i18n=\"dash.hero.goto_risk\">위험 매트릭스 →</button>
        </div>
        <div id=\"security_hero_body\" style=\"margin-top:12px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
      </section>
      <section class=\"metrics\" id=\"overview_cards\"><div class=\"empty\" style=\"padding:16px;color:#111827\" data-i18n=\"dash.status.overview_loading\">요약 카드를 불러오는 중…</div></section>
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
          <!-- 인프라 현황 (24h/12h 전환 + Zabbix/Wazuh 딥링크) -->
          <section class=\"card\" id=\"infra_status_section\">
            <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
              <h2 style=\"margin:0\" data-i18n=\"dash.infra.title\">인프라 현황</h2>
              <div style=\"display:flex;gap:4px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:2px\">
                <button id=\"infra_win_24\" onclick=\"setInfraWindow('24h')\" style=\"padding:3px 10px;border:none;border-radius:6px;font-size:12px;cursor:pointer;background:#e5e7eb;color:#111827\">24h</button>
                <button id=\"infra_win_12\" onclick=\"setInfraWindow('12h')\" style=\"padding:3px 10px;border:none;border-radius:6px;font-size:12px;cursor:pointer;background:transparent;color:#111827\">12h</button>
              </div>
            </div>
            <div id=\"infra_status_body\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.status.loading\">로딩 중…</span></div>
          </section>
          <!-- PC 자산 현황 (Fleet: 전체/온라인/오프라인) — 자산 탭에서 이동 -->
          <!-- 증적 공백 / 오늘의 작업 큐 (admin·security 전용) -->
          <section class=\"card\" id=\"evidence_gap_card\">
            <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
              <h2 style=\"margin:0\" data-i18n=\"dash.gap.title\">오늘의 작업 큐 (증적 공백)</h2>
              <span id=\"evidence_gap_ts\" style=\"font-size:12px;color:#111827\"></span>
            </div>
            <div class=\"subtext\" data-i18n=\"dash.gap.sub\">아직 증적이 안 남은 미조치 항목이에요. 카드를 누르면 해당 탭으로 가요.</div>
            <div id=\"evidence_gap_box\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
          </section>
          <!-- 계정 거버넌스 요약 (admin·security 전용) — 계정 탭에서 이동 -->
          <section class=\"card\" id=\"acc_gov_dash_section\" style=\"display:none\">
            <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
              <h2 style=\"margin:0\" data-i18n=\"dash.acc.title\">계정 거버넌스 (접근권한 검토)</h2>
              <div style=\"display:flex;gap:8px;align-items:center;flex-wrap:wrap\">
                <span id=\"acc_summary\" style=\"font-size:12px;color:#111827\"></span>
                <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"openCsvPreview({title:tt('dash.acc.csv_preview_title','계정 거버넌스 CSV 미리보기'),filename:'mori-accounts-overview.csv',url:'/accounts/overview.csv'})\" data-i18n=\"dash.acc.csv\">CSV</button>
                <button onclick=\"switchTab('accounts')\" style=\"background:none;border:none;color:#2563eb;font-size:12px;cursor:pointer\" data-i18n=\"dash.acc.detail\">계정 탭에서 상세 →</button>
              </div>
            </div>
            <div class=\"subtext\" data-i18n=\"dash.acc.sub\">서버·PC의 로컬 계정을 LDAP·승인 대장과 대조해 이상 계정을 찾아요. ISMS-P 2.5.1·2.5.5·2.5.6 접근권한 검토 증적이에요.</div>
            <div class=\"metrics\" id=\"acc_finding_cards\" style=\"margin-top:12px\"></div>
          </section>
          <section class=\"card\" id=\"fleet_status_section\">
            <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
              <h2 style=\"margin:0\" data-i18n=\"dash.fleet.title\">PC 자산 현황</h2>
              <button onclick=\"switchTab('assets')\" style=\"background:none;border:none;color:#2563eb;font-size:12px;cursor:pointer\" data-i18n=\"dash.fleet.detail\">자산 현황에서 상세 →</button>
            </div>
            <div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-top:10px\">
              <div style=\"flex:1;min-width:100px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.fleet_total\">전체 PC</div><div style=\"font-size:24px;font-weight:800;margin-top:2px\" id=\"fleet_total\">-</div></div>
              <div style=\"flex:1;min-width:100px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.online\">온라인</div><div style=\"font-size:24px;font-weight:800;color:#16a34a;margin-top:2px\" id=\"fleet_online\">-</div></div>
              <div style=\"flex:1;min-width:100px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.offline\">오프라인</div><div style=\"font-size:24px;font-weight:800;color:#dc2626;margin-top:2px\" id=\"fleet_offline\">-</div></div>
            </div>
          </section>
          <!-- 서버 자산 현황 (Zabbix) — 자산 탭에서 이동 -->
          <section class=\"card\" id=\"zabbix_status_section\">
            <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
              <h2 style=\"margin:0\" data-i18n=\"dash.zabbix.title\">서버 자산 현황</h2>
              <button onclick=\"switchTab('assets');switchAssetTab('zabbix')\" style=\"background:none;border:none;color:#2563eb;font-size:12px;cursor:pointer\" data-i18n=\"dash.fleet.detail\">자산 현황에서 상세 →</button>
            </div>
            <div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-top:10px\">
              <div style=\"flex:1;min-width:90px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.zabbix_total\">전체 서버</div><div style=\"font-size:24px;font-weight:800;margin-top:2px\" id=\"zabbix_total\">-</div></div>
              <div style=\"flex:1;min-width:90px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.online\">온라인</div><div style=\"font-size:24px;font-weight:800;color:#16a34a;margin-top:2px\" id=\"zabbix_online\">-</div></div>
              <div style=\"flex:1;min-width:90px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.offline\">오프라인</div><div style=\"font-size:24px;font-weight:800;color:#dc2626;margin-top:2px\" id=\"zabbix_offline\">-</div></div>
            </div>
          </section>
          <!-- 취약점 현황 (Trivy) — 자산 탭에서 이동 -->
          <section class=\"card\" id=\"trivy_status_section\">
            <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
              <h2 style=\"margin:0\" data-i18n=\"dash.vuln.title\">취약점 현황</h2>
              <button onclick=\"switchTab('assets');switchAssetTab('trivy')\" style=\"background:none;border:none;color:#2563eb;font-size:12px;cursor:pointer\" data-i18n=\"dash.fleet.detail\">자산 현황에서 상세 →</button>
            </div>
            <div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-top:10px\">
              <div style=\"flex:1;min-width:90px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.trivy_affected\">영향받는 호스트</div><div style=\"font-size:24px;font-weight:800;margin-top:2px\" id=\"trivy_affected_hosts\">-</div></div>
              <div style=\"flex:1;min-width:90px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\" data-i18n=\"dash.assets.trivy_total\">전체 취약점</div><div style=\"font-size:24px;font-weight:800;margin-top:2px\" id=\"trivy_total_vulns\">-</div></div>
              <div style=\"flex:1;min-width:90px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\">Critical</div><div style=\"font-size:24px;font-weight:800;color:#dc2626;margin-top:2px\" id=\"trivy_critical\">-</div></div>
              <div style=\"flex:1;min-width:90px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\"><div style=\"font-size:12px;color:#111827\">High</div><div style=\"font-size:24px;font-weight:800;color:#ca8a04;margin-top:2px\" id=\"trivy_high\">-</div></div>
            </div>
          </section>
          <section class=\"card\" id=\"source_coverage_section\">
            <h2 data-i18n=\"dash.card.source_coverage\">Source Coverage</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.source_coverage.sub\">운영자가 노출을 허용한 경우에만 source 상태를 표시합니다.</div>
            <div class=\"coverage\" id=\"source_coverage\"><span class=\"empty\" data-i18n=\"dash.status.loading\">로딩 중…</span></div>
          </section>

          <section class=\"card\" id=\"latest_status_section\">
            <h2 data-i18n=\"dash.card.latest_status\">Latest Host Status</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.latest_status.sub\">조치가 필요한 offline / unknown 호스트를 우선 확인합니다.</div>
            <div class=\"table-wrap\" id=\"latest_status\"><span class=\"empty\" data-i18n=\"dash.status.loading\">로딩 중…</span></div>
          </section>

          <section class=\"card\" id=\"risk_summary_section\">
            <h2 data-i18n=\"dash.card.risk_summary\">Risk Summary</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.risk_summary.sub\">alert, 취약점, 상태를 기준으로 우선 대응 대상을 확인합니다.</div>
            <div class=\"table-wrap\" id=\"risk_summary\"><span class=\"empty\" data-i18n=\"dash.status.loading\">로딩 중…</span></div>
          </section>

          <section class=\"card\" id=\"recent_activity_section\">
            <h2 data-i18n=\"dash.card.recent_activity\">Recent Activity</h2>
            <div class=\"subtext\" data-i18n=\"dash.card.recent_activity.sub\">운영자가 허용한 범위에서 최근 이벤트와 관측값을 보여줍니다.</div>
            <div class=\"list\" id=\"recent_activity\"><span class=\"empty\" data-i18n=\"dash.status.loading\">로딩 중…</span></div>
          </section>

          <!-- NLQ section moved to floating button -->
      </div>
      <div class=\"status-line\" id=\"dashboard_status\" data-i18n=\"dash.status.initializing\">초기화 중…</div>
    </div>

    <!-- ── Tab: Alert Triage ───────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_triage\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.triage\">Alert Triage</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.triage.sub\">최근 24시간 경보예요. 상태를 눌러 처리하세요.</div>
        <div style=\"margin:0 0 12px;padding:8px 11px;background:#f9fafb;border:1px solid #e5e7eb;border-left:3px solid #2563eb;border-radius:8px;font-size:12px;color:#4b5563;line-height:1.65\" data-i18n=\"dash.card.triage.help\">이 탭을 열어두면 30초마다 자동으로 갱신돼요(처리 중일 땐 멈춤). 상태를 눌러 접수 → 조사중 → 완료로 처리하고, 소스 배지를 누르면 원본(Zabbix 등)으로 이동합니다.</div>
        <div class=\"table-wrap\" id=\"triage_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        <div style=\"margin-top:10px\"><button id=\"reload_triage\" class=\"secondary\" data-i18n=\"dash.btn.reload\">새로고침</button></div>
      </section>
    </div>

    <!-- ── Tab: Incidents ─────────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_incidents\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.incidents\">인시던트 관리</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.incidents.sub\">여러 경보를 하나의 인시던트로 묶고 조사 노트를 남깁니다.</div>
        <!-- 검색 + 날짜 필터 + CSV 다운로드 -->
        <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px;padding:10px 12px;background:#f9fafb;border-radius:8px;border:1px solid #e5e7eb\">
          <input type=\"text\" id=\"inc_search\" placeholder=\"제목 · 담당자 · 상태 검색\" data-i18n-placeholder=\"dash.inc.search_ph\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 10px;font-size:13px;min-width:180px;flex:1\" />
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#111827;font-size:13px;white-space:nowrap\" data-i18n=\"dash.inc.date_from\">시작일</label>
            <input type=\"date\" id=\"inc_date_from\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#111827;font-size:13px;white-space:nowrap\" data-i18n=\"dash.inc.date_to\">종료일</label>
            <input type=\"date\" id=\"inc_date_to\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <button id=\"inc_filter_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px\" data-i18n=\"dash.inc.filter_btn\">조회</button>
          <button id=\"inc_new_btn\" style=\"padding:5px 14px;font-size:13px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600\" data-i18n=\"dash.inc.new_btn\">+ 새 인시던트</button>
          <button id=\"inc_csv_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px;background:#dbeafe;color:#2563eb\" data-i18n=\"dash.inc.csv_btn\">CSV 다운로드</button>
        </div>
        <div id=\"incidents_list\" class=\"list\" style=\"margin-bottom:14px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
      </section>
    </div>

    <!-- 새 인시던트 생성 모달 (버튼 클릭 시 팝업) -->
    <div id=\"incident_create_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center\">
      <div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:24px 28px;width:560px;max-width:95vw;max-height:90vh;overflow:auto\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
          <h3 style=\"color:#2563eb;margin:0\" data-i18n=\"dash.inc.create_title\">새 인시던트 생성</h3>
          <button onclick=\"closeIncidentCreateModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
        </div>
        <div class=\"row\">
          <label for=\"inc_title\" data-i18n=\"dash.f.title\">제목</label>
          <input id=\"inc_title\" placeholder=\"예: 특정 서버 무단 접근 시도\" data-i18n-placeholder=\"dash.inc.title_ph\" />
        </div>
        <div class=\"row\" style=\"position:relative\">
          <label for=\"inc_hostname\"><span data-i18n=\"dash.inc.host\">관련 호스트</span> <span style=\"color:#111827;font-size:11px\" data-i18n=\"dash.inc.host_hint\">(검색)</span></label>
          <input id=\"inc_hostname\" placeholder=\"호스트명 입력…\" data-i18n-placeholder=\"dash.inc.host_ph\" autocomplete=\"off\" oninput=\"_incHostSearch(this.value)\" />
          <div id=\"inc_host_suggestions\" style=\"display:none;position:absolute;top:100%;left:0;right:0;background:#e5e7eb;border:1px solid #e5e7eb;border-radius:6px;max-height:160px;overflow-y:auto;z-index:100\"></div>
        </div>
        <div class=\"row\">
          <label for=\"inc_analyst\"><span data-i18n=\"dash.f.analyst\">담당자</span> <span style=\"color:#111827;font-size:11px\" data-i18n=\"dash.inc.analyst_hint\">(호스트 담당자 자동 입력)</span></label>
          <input id=\"inc_analyst\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"dash.ph.name_example\" />
        </div>
        <div style=\"margin:8px 0\">
          <label style=\"display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;color:#111827\">
            <input type=\"checkbox\" id=\"inc_diff_handler\" onchange=\"document.getElementById('inc_handler_row').style.display=this.checked?'':'none'\" />
            <span data-i18n=\"dash.inc.diff_handler\">담당자와 조치자가 다름</span>
          </label>
        </div>
        <div class=\"row\" id=\"inc_handler_row\" style=\"display:none\">
          <label for=\"inc_handler\" data-i18n=\"dash.f.handler\">조치자</label>
          <input id=\"inc_handler\" placeholder=\"예: 김보안\" data-i18n-placeholder=\"dash.ph.handler_example\" />
        </div>
        <div class=\"actions\" style=\"margin-top:14px;display:flex;gap:10px;justify-content:flex-end\">
          <button onclick=\"closeIncidentCreateModal()\" class=\"secondary\" style=\"width:auto;padding:8px 18px\" data-i18n=\"dash.f.cancel\">취소</button>
          <button id=\"create_incident\" style=\"width:auto;padding:8px 18px\" data-i18n=\"dash.inc.create_btn\">인시던트 생성</button>
        </div>
        <div class=\"status-line\" id=\"incident_status\"></div>
      </div>
    </div>

    <!-- ── Tab: 자산 현황 ─────────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_assets\">
      <!-- Sub-nav -->
      <nav class=\"asset-sub-nav\">
        <button class=\"active\" id=\"asset_tab_fleet\" onclick=\"switchAssetTab('fleet')\"><span data-i18n=\"dash.assets.tab.fleet\">PC 자산 (Fleet)</span></button>
        <button id=\"asset_tab_zabbix\" onclick=\"switchAssetTab('zabbix')\"><span data-i18n=\"dash.assets.tab.zabbix\">서버 자산 (Zabbix)</span></button>
        <button id=\"asset_tab_trivy\" onclick=\"switchAssetTab('trivy')\"><span data-i18n=\"dash.assets.tab.trivy\">취약점 (Trivy)</span></button>
        <button id=\"asset_tab_mine\" onclick=\"switchAssetTab('mine')\"><span data-i18n=\"dash.assets.tab.mine\">내 서버</span></button>
      </nav>

      <!-- Fleet PC Section (전체/온라인/오프라인 요약은 대시보드 'PC 자산 현황' 패널로 이동) -->
      <div id=\"assets_fleet_section\">
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;\">
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.fleet\">PC 자산 목록 (Fleet)</h2>
            <div style=\"display:flex;gap:6px;\">
              <button onclick=\"onDemandRefresh('fleet')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.assets.refresh\">새로고침</button>
              <button onclick=\"downloadAssetsCSV('fleet')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv\">CSV 내보내기</button>
            </div>
          </div>
          <div class=\"asset-search-bar\">
            <input type=\"text\" id=\"fleet_search_hostname\" placeholder=\"호스트명 검색…\" data-i18n-placeholder=\"dash.assets.host_search_ph\" oninput=\"filterAssetTable('fleet')\" />
            <select id=\"fleet_search_status\" onchange=\"filterAssetTable('fleet')\"><option value=\"\" data-i18n=\"dash.assets.all_status\">전체 상태</option><option value=\"online\" data-i18n=\"dash.assets.online\">온라인</option><option value=\"offline\" data-i18n=\"dash.assets.offline\">오프라인</option><option value=\"unknown\" data-i18n=\"dash.assets.unknown\">알 수 없음</option></select>
            <select id=\"fleet_search_team\" onchange=\"filterAssetTable('fleet')\"><option value=\"\" data-i18n=\"dash.assets.all_team\">전체 팀</option></select>
            <label style=\"display:inline-flex;align-items:center;gap:5px;color:#111827;font-size:12px;cursor:pointer;white-space:nowrap\"><input type=\"checkbox\" id=\"fleet_search_mine\" onchange=\"filterAssetTable('fleet')\" /> <span data-i18n=\"dash.assets.only_mine\">내 자산만</span></label>
            <span class=\"asset-search-count\" id=\"fleet_search_count\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.assets.fleet_sub\">Fleet이 관리하는 PC 현황이에요.</div>
          <div class=\"table-wrap\" id=\"fleet_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>

      <!-- Zabbix Server Section -->
      <div id=\"assets_zabbix_section\" class=\"hidden\">
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;\">
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.zabbix\">서버 자산 목록 (Zabbix)</h2>
            <div style=\"display:flex;gap:6px;\">
              <button onclick=\"onDemandRefresh('zabbix')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.assets.refresh\">새로고침</button>
              <button onclick=\"downloadAssetsCSV('zabbix')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv\">CSV 내보내기</button>
            </div>
          </div>
          <div class=\"asset-search-bar\">
            <input type=\"text\" id=\"zabbix_search_hostname\" placeholder=\"호스트명 검색…\" data-i18n-placeholder=\"dash.assets.host_search_ph\" oninput=\"filterAssetTable('zabbix')\" />
            <select id=\"zabbix_search_category\" onchange=\"filterAssetTable('zabbix')\"><option value=\"\" data-i18n=\"dash.assets.all_category\">전체 분류</option></select>
            <select id=\"zabbix_search_status\" onchange=\"filterAssetTable('zabbix')\"><option value=\"\" data-i18n=\"dash.assets.all_status\">전체 상태</option><option value=\"online\" data-i18n=\"dash.assets.online\">온라인</option><option value=\"offline\" data-i18n=\"dash.assets.offline\">오프라인</option><option value=\"unknown\" data-i18n=\"dash.assets.unknown\">알 수 없음</option></select>
            <select id=\"zabbix_search_team\" onchange=\"filterAssetTable('zabbix')\"><option value=\"\" data-i18n=\"dash.assets.all_team\">전체 팀</option></select>
            <label style=\"display:inline-flex;align-items:center;gap:5px;color:#111827;font-size:12px;cursor:pointer;white-space:nowrap\"><input type=\"checkbox\" id=\"zabbix_search_mine\" onchange=\"filterAssetTable('zabbix')\" /> <span data-i18n=\"dash.assets.only_mine\">내 자산만</span></label>
            <span class=\"asset-search-count\" id=\"zabbix_search_count\"></span>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.assets.zabbix_sub\">Zabbix가 모니터링 중인 서버 현황이에요.</div>
          <div class=\"table-wrap\" id=\"zabbix_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>

      <!-- Trivy Vulnerability Section -->
      <div id=\"assets_trivy_section\" class=\"hidden\">
        <!-- 위험성 평가 매트릭스 (R-4) — 더블클릭 시 팝업 (카드 요약은 여기, 매트릭스는 모달) -->
        <section class=\"card\" id=\"risk_matrix_card\" ondblclick=\"openRiskMatrixModal()\" style=\"cursor:pointer\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
            <h2 style=\"margin:0\" data-i18n=\"dash.risk.matrix_title\">위험성 평가 매트릭스</h2>
            <div style=\"display:flex;align-items:center;gap:10px\">
              <span id=\"risk_matrix_assessed\" style=\"font-size:12px;color:#111827\"></span>
              <button onclick=\"event.stopPropagation();openRiskMatrixModal()\" class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" data-i18n=\"dash.risk.open_modal\">매트릭스 열기</button>
            </div>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.risk.matrix_sub\">위험도는 영향도 × 발생가능성으로 계산해요. 아직 평가 안 한 건 자동 제안 등급으로 잡아요.</div>
          <div id=\"risk_doa_ctl\" style=\"margin-top:8px\" ondblclick=\"event.stopPropagation()\"></div>
          <div style=\"font-size:11px;color:#111827;margin-top:8px\" data-i18n=\"dash.risk.dblclick_hint\">카드를 더블클릭하거나 '매트릭스 열기'를 누르면 3×3 매트릭스가 팝업으로 열립니다.</div>
        </section>
        <!-- 위험성 평가 매트릭스 팝업 -->
        <div id=\"risk_matrix_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9998;align-items:center;justify-content:center\">
          <div style=\"background:#f1f5f9;border:1px solid #cbd5e1;border-radius:10px;padding:24px 28px;width:1080px;max-width:96vw;max-height:90vh;overflow:auto\">
            <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;gap:12px\">
              <h3 style=\"color:#2563eb;margin:0\" data-i18n=\"dash.risk.matrix_title\">위험성 평가 매트릭스</h3>
              <button onclick=\"closeRiskMatrixModal()\" style=\"background:none;border:none;color:#111827;font-size:20px;cursor:pointer\">×</button>
            </div>
            <div id=\"risk_matrix_box\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
          </div>
        </div>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;\">
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.trivy\">취약점 현황 (Trivy)</h2>
            <button onclick=\"downloadAssetsCSV('trivy')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv\">CSV 내보내기</button>
          </div>
          <div class=\"asset-search-bar\" style=\"flex-wrap:wrap;\">
            <input type=\"text\" id=\"trivy_search_hostname\" placeholder=\"호스트명 검색…\" data-i18n-placeholder=\"dash.assets.host_search_ph\" oninput=\"filterAssetTable('trivy')\" />
            <select id=\"trivy_search_severity\" onchange=\"filterAssetTable('trivy')\"><option value=\"\" data-i18n=\"dash.assets.all_severity\">전체 심각도</option><option value=\"critical\">Critical &gt; 0</option><option value=\"high\">High &gt; 0</option><option value=\"medium\">Medium &gt; 0</option></select>
            <span style=\"color:#111827;font-size:12px;margin-left:4px\" data-i18n=\"dash.assets.detected_date\">탐지일:</span>
            <input type=\"date\" id=\"trivy_search_date_from\" onchange=\"filterAssetTable('trivy')\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:4px;padding:4px 6px;font-size:12px\" title=\"시작일\" data-i18n-title=\"dash.inc.date_from\" />
            <span style=\"color:#111827;font-size:12px\">~</span>
            <input type=\"date\" id=\"trivy_search_date_to\" onchange=\"filterAssetTable('trivy')\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:4px;padding:4px 6px;font-size:12px\" title=\"종료일\" data-i18n-title=\"dash.inc.date_to\" />
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
            <h2 style=\"margin:0\" data-i18n=\"dash.card.assets.mine\">내 담당 서버</h2>
            <div style=\"display:flex;align-items:center;gap:8px\">
              <label style=\"color:#111827;font-size:13px;white-space:nowrap\" data-i18n=\"dash.assets.mine.groupby\">그룹 기준</label>
              <select id=\"mine_group_by\" onchange=\"renderMyServers()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:4px 8px;font-size:13px\">
                <option value=\"category\" data-i18n=\"dash.assets.mine.group.category\">카테고리</option>
                <option value=\"team\" data-i18n=\"dash.assets.mine.group.team\">팀</option>
                <option value=\"importance\" data-i18n=\"dash.assets.mine.group.importance\">중요도</option>
                <option value=\"status\" data-i18n=\"dash.assets.mine.group.status\">상태</option>
                <option value=\"none\" data-i18n=\"dash.assets.mine.group.flat\">없음(전체)</option>
              </select>
              <span class=\"asset-search-count\" id=\"mine_search_count\"></span>
            </div>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.assets.mine.sub\">내가 담당인 PC·서버만 모아서 보여줘요.</div>
          <div class=\"table-wrap\" id=\"mine_table\"><span class=\"empty\" data-i18n=\"dash.assets.mine.empty\">담당 자산이 없습니다. 계정 메뉴 → 프로필 편집에서 담당 서버를 등록하세요.</span></div>
        </section>
      </div>
      <div class=\"status-line\" id=\"assets_status\"></div>
    </div>

    <!-- ── Tab: Compliance PDCA ──────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_compliance\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.compliance\">Compliance PDCA 대시보드</h2>
        <div class=\"subtext\" data-i18n=\"dash.compliance.sub_short\">ISMS-P·ISO 27001 통제 점검 현황이에요. 미조치·기한초과부터 처리하면 돼요.</div>
        <details style=\"margin-top:8px\">
          <summary style=\"cursor:pointer;color:#2563eb;font-size:12px\" data-i18n=\"dash.pdca.criteria\">집계 기준 자세히</summary>
          <div class=\"subtext\" style=\"margin-top:6px\" data-i18n-html=\"dash.compliance.sub\">※ 상단 카드의 <strong>전체 점검 / Pass / Fail / Warning / Pass Rate</strong>는 <strong>통제 점검(control_checks)</strong> 결과만 집계합니다. <strong>미조치 합계</strong>와 <strong>기한초과</strong>는 통제 점검 + Trivy 취약점(critical/high) + Alert(critical/high, 7일) 미조치 항목을 통합 집계합니다.</div>
        </details>
      </section>

      <!-- PDCA Summary Cards -->
      <section class=\"metrics\" id=\"pdca_cards\">
        <div class=\"empty\" style=\"padding:16px;color:#111827\" data-i18n=\"dash.status.pdca_loading\">PDCA 데이터를 불러오는 중…</div>
      </section>

      <!-- 지금 할 일: 미조치 / 기한초과 (항상 표시, 최우선) -->
      <section class=\"card\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap\">
          <h2 style=\"margin:0\" data-i18n=\"dash.pdca.pending_title\">미조치 / 기한 초과 항목</h2>
          <button id=\"pdca_pending_csv_btn\" onclick=\"openCsvPreview({title:tt(\'dash.pdca.pending_csv_preview_title\',\'PDCA 미조치 CSV 미리보기\'),filename:\'mori-pdca-pending.csv\',url:\'/compliance/pdca/pending.csv\'})\" style=\"background:#f9fafb;border:1px solid #e5e7eb;color:#2563eb;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer\">CSV</button>
        </div>
        <div class=\"subtext\" data-i18n=\"dash.pdca.pending_sub\">점검에서 실패·경고가 뜬 통제예요. 기한이 지난 항목은 빨간색으로 보여요.</div>
        <div id=\"pdca_pending_table\" style=\"margin-top:8px;overflow-x:auto\"></div>
      </section>

      <!-- SoA (ISO 27001 적용선언서) 내보내기 -->
      <section class=\"card\" id=\"soa_card\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap\">
          <h2 style=\"margin:0\" data-i18n=\"dash.soa.title\">적용선언서 (SoA · ISO 27001)</h2>
          <div style=\"display:flex;gap:6px;align-items:center;flex-wrap:wrap\">
            <a href=\"/compliance/soa.csv\" download style=\"background:#f9fafb;border:1px solid #e5e7eb;color:#2563eb;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none\">CSV</a>
            <a href=\"/compliance/soa.pdf\" target=\"_blank\" style=\"background:#f9fafb;border:1px solid #e5e7eb;color:#2563eb;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none\">PDF</a>
          </div>
        </div>
        <div class=\"subtext\" data-i18n=\"dash.soa.sub\">ISO 27001 필수 산출물 — 통제별 적용여부·근거·이행상태를 카탈로그와 통제 상태에서 생성해요. 통제 상태를 채울수록 근거·이행상태가 실질화돼요.</div>
        <div id=\"soa_summary\" style=\"margin-top:8px;font-size:13px;color:#111827\"></div>
      </section>

      <!-- 상세 분석 (기본 접힘 처음 보는 담당자에겐 과부하라 뒤로) -->
      <details class=\"card\" style=\"padding:0\">
        <summary style=\"cursor:pointer;padding:16px 18px;font-weight:700;color:#111827;font-size:15px\" data-i18n=\"dash.pdca.detail_toggle\">상세 분석 통제 카탈로그 · 통제 상태 · 카테고리 · PDCA Cycle (펼치기)</summary>
        <!-- 통제 카탈로그 트리 (ISMS-P 101 × ISO, admin·security 전용) 이행 상태 편집 -->
        <section class=\"card\" id=\"control_tree_card\" style=\"margin:0 16px 12px\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
            <h2 style=\"margin:0\" data-i18n=\"dash.ctl.title\">통제 카탈로그 (ISMS-P × ISO 27001)</h2>
            <div style=\"display:flex;align-items:center;gap:10px;flex-wrap:wrap\">
              <span id=\"control_tree_coverage\" style=\"font-size:12px;color:#111827\"></span>
              <a href=\"/controls/evidence-bundle.zip\" download style=\"background:#f9fafb;border:1px solid #e5e7eb;color:#2563eb;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none\" data-i18n=\"dash.ctl.zip\">전체 증적 ZIP</a>
            </div>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.ctl.sub_compliance\">인증기준을 누르면 이행 상태·담당자·개선계획·기한을 바로 고칠 수 있어요. 저장한 내용은 계속 유지돼요.</div>
          <div id=\"ctl_admin_bar\" style=\"display:none;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0\">
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"openControlEditor()\" data-i18n=\"dash.ctl.add\">통제 추가</button>
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"openNlpImport()\" data-i18n=\"dash.ctl.nlp\">법령 텍스트 임포트(NLP)</button>
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"openCodeReviewScan()\" data-i18n=\"dash.ctl.scan\">GitHub 코드 보안 리뷰</button>
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"openPrivacyFlow()\" data-i18n=\"dash.pf.btn\">개인정보 흐름도</button>
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"openClaudeKey()\" data-i18n=\"dash.ctl.key_btn\">Claude 키</button>
            <span id=\"ctl_key_status\" style=\"font-size:11px;color:#111827\"></span>
            <span style=\"width:1px;height:20px;background:#e5e7eb\"></span>
            <span style=\"font-size:12px;color:#111827\" data-i18n=\"dash.ctl.snap_sched\">정기 증적 스냅샷</span>
            <select id=\"snap_schedule\" onchange=\"saveSnapshotConfig()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:12px\">
              <option value=\"off\" data-i18n=\"dash.ctl.snap_off\">끔</option>
              <option value=\"daily\" data-i18n=\"dash.ctl.snap_daily\">매일</option>
              <option value=\"weekly\" data-i18n=\"dash.ctl.snap_weekly\">매주</option>
              <option value=\"monthly\" data-i18n=\"dash.ctl.snap_monthly\">매월</option>
            </select>
            <select id=\"snap_scope\" onchange=\"saveSnapshotConfig()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:12px\">
              <option value=\"mapped\" data-i18n=\"dash.ctl.snap_mapped\">증적 있는 통제만</option>
              <option value=\"all\" data-i18n=\"dash.ctl.snap_all\">전 통제</option>
            </select>
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"runBulkSnapshot()\" data-i18n=\"dash.ctl.snap_now\">지금 일괄 스냅샷</button>
            <span id=\"snap_msg\" style=\"font-size:11px;color:#111827\"></span>
          </div>
          <div id=\"ctl_editor\" style=\"display:none;margin:8px 0;padding:12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px\"></div>
          <div id=\"ctl_nlp\" style=\"display:none;margin:8px 0;padding:12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px\"></div>
          <div id=\"control_tree_box\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
        <div class=\"layout\" style=\"padding:0 16px 16px\">
          <div class=\"stack\">
            <section class=\"card\">
              <h2 data-i18n=\"dash.pdca.status_title\">통제 항목 상태</h2>
              <div id=\"pdca_status_chart\" style=\"display:flex;flex-wrap:wrap;gap:12px;margin-top:12px\"></div>
            </section>
            <section class=\"card\">
              <h2 data-i18n=\"dash.pdca.category_title\">카테고리별 현황</h2>
              <div id=\"pdca_category_table\" style=\"margin-top:8px;overflow-x:auto\"></div>
            </section>
          </div>
          <div class=\"stack\">
            <section class=\"card\">
              <h2>PDCA Cycle</h2>
              <div id=\"pdca_cycle_chart\" style=\"margin-top:12px\"></div>
            </section>
          </div>
        </div>
      </details>

      <!-- ── 증적 리포트 다운로드 ────────────────────────────────────── -->
      <section class=\"card\" style=\"margin-top:20px\">
        <h2 data-i18n=\"dash.card.reports\">감사 증적 리포트 다운로드</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.reports.sub\">감사 증적으로 쓸 리포트를 CSV로 받을 수 있어요. 미리보기로 컬럼을 먼저 확인하세요.</div>
        <div id=\"report_download_area\" style=\"margin-top:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px\">
        </div>
      </section>

    </div>

    <!-- ── Tab: 계정 거버넌스 (admin·security 전용) ──────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_accounts\">

      <section class=\"card\">
        <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
          <h2 style=\"margin:0\" data-i18n=\"dash.acc.list_title\">계정 목록 (서버 · PC)</h2>
          <div style=\"display:flex;gap:6px;flex-wrap:wrap;align-items:center\">
            <input id=\"acc_search\" placeholder=\"계정/호스트 검색…\" data-i18n-placeholder=\"dash.acc.search_ph\" oninput=\"renderAccounts()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 10px;font-size:13px;width:180px\" />
            <select id=\"acc_filter_type\" onchange=\"renderAccounts()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.f.alltype\">전체 유형</option><option value=\"server\" data-i18n=\"dash.acc.f.server\">서버</option><option value=\"pc\" data-i18n=\"dash.acc.f.pc\">PC</option></select>
            <select id=\"acc_filter_finding\" onchange=\"renderAccounts()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.f.allfind\">전체</option><option value=\"flagged\" data-i18n=\"dash.acc.f.flagged\">이상만</option><option value=\"leaver\" data-i18n=\"dash.acc.find.leaver\">퇴사자 잔존</option><option value=\"orphan_priv\" data-i18n=\"dash.acc.find.orphan_priv\">미등록 특권</option><option value=\"unapproved_sudo\" data-i18n=\"dash.acc.find.unapproved_sudo\">미승인 sudo</option><option value=\"dormant\" data-i18n=\"dash.acc.find.dormant\">휴면</option><option value=\"privileged\" data-i18n=\"dash.acc.f.priv\">특권만</option></select>
          </div>
        </div>
        <div class=\"table-wrap\" id=\"acc_table\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
      </section>

      <!-- 접속 발자취 (Access Trail) — 실제 접속기록 미리보기, 전체는 Loki -->
      <section class=\"card\">
        <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
          <h2 style=\"margin:0\" data-i18n=\"dash.acc.trail_title\">접속 발자취 (누가 · 언제 · 어디서)</h2>
          <div style=\"display:flex;gap:10px;align-items:center\">
            <span id=\"acc_trail_meta\" style=\"font-size:12px;color:#111827\"></span>
            <a id=\"acc_trail_grafana\" href=\"#\" target=\"_blank\" style=\"display:none;color:#2563eb;font-size:12px;text-decoration:none\" data-i18n=\"dash.acc.trail_full\">전체는 Loki에서 →</a>
          </div>
        </div>
        <div class=\"subtext\" data-i18n=\"dash.acc.trail_sub\">최근 로그인·sudo 기록 미리보기예요. 계정 목록과 대조해 '등록된 계정이 실제로 언제 접속했나'를 봐요. 전체 로그는 Loki에서 보세요. (ISMS-P 2.9.4 접속기록)</div>
        <div class=\"table-wrap\" id=\"acc_trail\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
      </section>

      <div class=\"layout\">
        <section class=\"card\">
          <h2 data-i18n=\"dash.acc.approve_title\">승인 대장 (허용 계정 · sudo)</h2>
          <div class=\"subtext\" data-i18n=\"dash.acc.approve_sub\">여기 등록한 계정·sudo는 이상으로 안 잡아요. 승인 사유가 곧 증적이에요.</div>
          <div style=\"display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:10px 0\">
            <input id=\"acc_appr_user\" placeholder=\"username\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 10px;font-size:13px;width:120px\" />
            <select id=\"acc_appr_kind\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"account\">account</option><option value=\"sudo\">sudo</option></select>
            <input id=\"acc_appr_host\" placeholder=\"host(비우면 전역)\" data-i18n-placeholder=\"dash.acc.appr_host_ph\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 10px;font-size:13px;width:130px\" />
            <input id=\"acc_appr_reason\" placeholder=\"승인 사유\" data-i18n-placeholder=\"dash.acc.appr_reason_ph\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 10px;font-size:13px;flex:1;min-width:120px\" />
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:13px\" onclick=\"addAccApproval()\" data-i18n=\"dash.acc.appr_add\">+ 승인</button>
          </div>
          <div id=\"acc_approvals\" class=\"table-wrap\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
            <h2 style=\"margin:0\" data-i18n=\"dash.acc.ip_title\">IP 리스트</h2>
            <button class=\"secondary\" style=\"width:auto;padding:5px 12px;font-size:12px\" onclick=\"exportIpCsv()\" data-i18n=\"dash.acc.ip_csv\">선별 CSV</button>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.acc.ip_sub\">팀·용도로 IP를 골라서 CSV로 뽑을 수 있어요.</div>
          <div style=\"display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:10px 0\">
            <input id=\"ip_search\" placeholder=\"호스트/IP 검색…\" data-i18n-placeholder=\"dash.acc.ip_search_ph\" oninput=\"renderAccIpList()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 10px;font-size:13px;width:150px\" />
            <select id=\"ip_filter_team\" onchange=\"renderAccIpList()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.ip_allteam\">전체 팀</option></select>
            <select id=\"ip_filter_cat\" onchange=\"renderAccIpList()\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.ip_allcat\">전체 용도</option></select>
            <span id=\"ip_count\" style=\"font-size:12px;color:#111827\"></span>
          </div>
          <div class=\"table-wrap\" id=\"acc_ip_list\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 가이드·기준 ────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_guides\">
      <div id=\"guide_sub_tabs\" style=\"display:flex;gap:0;border-bottom:1px solid #e5e7eb;margin-bottom:20px;flex-wrap:wrap;\"></div>
      <section class=\"card\" style=\"padding:0\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;padding:16px 20px 0;\">
          <h2 id=\"guide_content_title\" style=\"margin:0;font-size:16px\"></h2>
          <span id=\"guide_updated_at\" style=\"font-size:12px;color:#111827\"></span>
        </div>
        <div id=\"guide_content_body\" style=\"padding:16px 20px 20px;color:#111827;line-height:1.8;white-space:pre-wrap;font-size:14px;font-family:inherit\"></div>
      </section>
    </div>
  </div>

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
            <input id=\"risk_residual\" placeholder=\"예: 중간 / 낮음\" style=\"width:100%;background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" /></div>
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
    const defaultPreferences = __USER_DASHBOARD_PREFS_JSON__;
    const cardLabels = __CARD_LABELS_JSON__;
    const sectionLabels = __SECTION_LABELS_JSON__;
    const guideLabels = __GUIDE_LABELS_JSON__;
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
      pending: '#dc2626', reviewing: '#ca8a04', resolved: '#16a34a',
      // legacy (backward compat)
      new: '#dc2626', acknowledged: '#ca8a04', investigating: '#ca8a04',
      closed: '#16a34a', false_positive: '#111827'
    };
    const tt = (k, f) => (window.t ? window.t(k, f) : f);
    const TRIAGE_STATUS_LABELS = { pending:tt('dash.dyn.triage.pending','미확인'), reviewing:tt('dash.dyn.triage.reviewing','검토중'), resolved:tt('dash.dyn.triage.resolved','조치예정/완료') };
    const triageLabel = (s) => tt('dash.dyn.triage.' + s, TRIAGE_STATUS_LABELS[s] || s);
    const INC_STATUS_COLORS = {open:'#ca8a04', investigating:'#2563eb', resolved:'#16a34a', closed:'#111827'};

    // ── 전역 함수 노출 (onclick 속성에서 직접 호출 함수 선언은 호이스팅됨) ──
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
      if (tabName === 'accounts') loadAccountsGov();
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
        if (tab === 'dashboard') {
          loadDashboard();
          // 대시보드 위젯은 별도 로더로 그려지므로 언어 전환 시 함께 재렌더
          try { renderSecurityHero(); } catch (e) {}
          try { renderInfraStatus(); } catch (e) {}
          if (typeof _canViewEvidence === 'function' && _canViewEvidence()) { try { loadEvidenceGaps(); } catch (e) {} }
          if (typeof _canViewAccounts === 'function' && _canViewAccounts()) { try { loadAccountsGov(); } catch (e) {} }
        }
        else if (tab === 'triage') loadTriage();
        else if (tab === 'incidents') loadIncidents();
        else if (tab === 'assets') loadAssets();
        else if (tab === 'compliance') loadCompliance();
        else if (tab === 'accounts') loadAccountsGov();
        else if (tab === 'guides') { buildGuideSubTabs(); if (currentGuideId) switchGuideTab(currentGuideId); }
        // 통제 카탈로그 트리는 언어 전환 시 재렌더해야 한/영이 반영됨 (admin·security)
        if (typeof _canViewEvidence === 'function' && _canViewEvidence()) loadControlTree();
      } catch (e) { /* re-render best-effort */ }
    };

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
        { label: tt('dash.dyn.col.owner', '담당자'), render: (item) => `<span style=\"color:#16a34a\">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Severity', render: (item) => escapeHtml(item.severity) },
        { label: 'Message', render: (item) => escapeHtml(item.message) },
      ], items, tt('dash.dyn.empty.alerts_24h', '최근 24시간 high / critical alert가 없습니다.'));
    }

    function renderVulnerabilityDetailTable(items) {
      return renderDetailTable([
        { label: 'Detected', render: (item) => escapeHtml(formatTime(item.detected_at)) },
        { label: 'Host', render: (item) => `<strong>${escapeHtml(item.hostname || item.host_id)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span>` },
        { label: tt('dash.dyn.col.owner', '담당자'), render: (item) => `<span style=\"color:#16a34a\">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'CVE', render: (item) => escapeHtml(item.cve || '-') },
        { label: 'Package', render: (item) => escapeHtml(item.package_name || '-') },
        { label: tt('dash.dyn.col.plan', '조치 계획'), render: (item) => {
          if (!item.plan_text) return `<span style=\"color:#111827;font-size:11px\">${tt('dash.dyn.plan.unset', '미설정')}</span>`;
          const tgt = item.plan_target_date ? `<br /><span style=\"color:#111827;font-size:11px\">~${escapeHtml(item.plan_target_date)}</span>` : '';
          const by = item.plan_updated_by ? ` <span style=\"color:#111827;font-size:11px\">(${escapeHtml(item.plan_updated_by)})</span>` : '';
          return `<span style=\"color:#16a34a;font-size:12px\" title=\"${escapeHtml(item.plan_text)}\">${escapeHtml(item.plan_text.substring(0,30))}${item.plan_text.length>30?'…':''}</span>${by}${tgt}`;
        }},
        { label: tt('dash.dyn.col.exception', '조치 예외'), render: (item) => {
          if (!item.exception_until) return `<span style=\"color:#111827;font-size:11px\">${tt('dash.dyn.exception.none', '없음')}</span>`;
          const reason = item.exception_reason ? `<br /><span style=\"color:#111827;font-size:11px\">${escapeHtml(item.exception_reason.substring(0,30))}${item.exception_reason.length>30?'…':''}</span>` : '';
          return `<span style=\"color:#ca8a04;font-size:12px\">~${escapeHtml(item.exception_until)}</span>${reason}`;
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

    /* 보안 요약 히어로 역할별로 다르게.
       보안/어드민: 위험 KPI(클릭→드릴다운) + 위험 TOP.
       인프라/헬프데스크: 내 담당 서버 취약점 + 조치율(읽기 전용). */
    const _heroKpi = (label, val, color, onclick) => `<div onclick=\"${onclick||''}\" style=\"flex:1;min-width:130px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px 14px;${onclick?'cursor:pointer':''}\">
        <div style=\"font-size:12px;color:#111827\">${label}</div>
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
      const barColor = s.pct >= 80 ? '#16a34a' : (s.pct >= 50 ? '#ca8a04' : '#dc2626');
      return `<div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;gap:14px;flex-wrap:wrap\">
        <span style=\"color:#111827;font-weight:600\">${tt('dash.mine.remediation_summary','내 서버 취약점 {n}건 · 조치 {m}건 ({p}%)').replace('{n}', s.total).replace('{m}', s.done).replace('{p}', s.pct)}</span>
        <span style=\"flex:1;min-width:120px;max-width:280px;height:8px;background:#e5e7eb;border-radius:4px;overflow:hidden\"><span style=\"display:block;height:100%;width:${s.pct}%;background:${barColor}\"></span></span>
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
          ${_heroKpi(tt('dash.hero.critical_risk','매우높음 위험'), (bl['매우높음']||0), '#dc2626', \"openRiskLevelModal('매우높음')\")}
          ${_heroKpi(tt('dash.hero.high_risk','높음 위험'), (bl['높음']||0), '#ca8a04', \"openRiskLevelModal('높음')\")}
          ${_heroKpi(tt('dash.hero.alerts','24h 경보'), (o.alerts_24h??0), '#dc2626', \"switchTab('triage')\")}
          ${_heroKpi(tt('dash.hero.crit_vulns','Critical 취약점'), (o.critical_vulns??0), '#dc2626', \"switchTab('assets');switchAssetTab('trivy')\")}
        </div>`;
        const top = (risk.items || []).slice(0, 6);
        const rankColor = (i) => i===0?'#dc2626':i===1?'#ca8a04':i===2?'#ca8a04':'#111827';
        const list = !top.length
          ? `<div class=\"empty\" style=\"color:#111827\">${tt('dash.hero.no_risk','평가 대상 취약점이 없습니다.')}</div>`
          : `<style>.hero-rank-row{border-bottom:1px solid #e5e7eb}.hero-rank-row:last-child{border-bottom:none}.hero-rank-row:hover{background:#f9fafb}</style>
             <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:4px\">
               <span style=\"font-size:13px;font-weight:700;color:#111827\">${tt('dash.hero.top_title','위험 TOP')} <span style=\"color:#111827;font-weight:400;font-size:11px\">· ${tt('dash.hero.by_score','위험점수순')}</span></span>
               <button onclick=\"switchTab('assets');switchAssetTab('trivy')\" style=\"background:none;border:none;color:#2563eb;font-size:12px;cursor:pointer\">${tt('dash.hero.view_all','전체 보기 →')}</button>
             </div>` + top.map((it, i) => `
              <div class=\"hero-rank-row\" onclick=\"openRiskModal('${escapeHtml(it.vuln_id)}')\" style=\"display:flex;align-items:center;gap:12px;padding:9px 6px;cursor:pointer\">
                <span style=\"width:20px;text-align:center;font-weight:800;font-size:15px;color:${rankColor(i)}\">${i+1}</span>
                <div style=\"min-width:0;flex:1\">
                  <div style=\"display:flex;align-items:center;gap:8px\">${_riskBadge(it.level, true)}<strong style=\"color:#111827;font-size:13px\">${escapeHtml(it.cve)}</strong></div>
                  <div style=\"color:#111827;font-size:11px;margin-top:2px\">${escapeHtml(it.hostname)} · <span style=\"text-transform:uppercase;color:${it.severity==='critical'?'#dc2626':'#ca8a04'}\">${escapeHtml(it.severity)}</span></div>
                </div>
                <div style=\"text-align:right;white-space:nowrap\">
                  <div style=\"font-weight:800;font-size:15px;color:${RISK_LEVEL_COLORS[it.level]||'#111827'}\">${it.score}</div>
                  <div style=\"font-size:10px;color:#111827\">${tt('dash.hero.score','위험점수')}</div>
                </div>
              </div>`).join('');
        el.innerHTML = kpis + list;
      } else {
        // 인프라/헬프데스크: 내 담당 서버 취약점 + 조치율(위험등급 없이)
        let rows = _assetCache.trivy;
        if (!rows || !rows.length) { try { const r = await fetch('/assets'); if (r.ok) { rows = (await r.json()).trivy?.rows || []; _assetCache.trivy = rows; } } catch (e) { rows = []; } }
        const s = _computeMyVulnSummary(rows);
        const kpis = `<div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px\">
          ${_heroKpi(tt('dash.hero.my_vulns','내 서버 취약점'), s.total, s.total?'#dc2626':'#16a34a', \"shortcutMyServers()\")}
          ${_heroKpi(tt('dash.hero.my_remediation','내 서버 조치율'), s.pct + '%', s.pct>=80?'#16a34a':(s.pct>=50?'#ca8a04':'#dc2626'), \"shortcutMyServers()\")}
          ${_heroKpi(tt('dash.hero.alerts','24h 경보'), (o.alerts_24h??0), '#dc2626', \"switchTab('triage')\")}
        </div>`;
        const list = !s.hosts.length
          ? `<div class=\"empty\" style=\"color:#111827\">${tt('dash.mine.no_vulns','취약점 없음')}</div>`
          : `<div style=\"font-size:12px;color:#111827;margin-bottom:6px\">${tt('dash.hero.my_servers_title','내 담당 서버 조치 현황')}</div>` + s.hosts.slice(0,6).map(h => {
              const pct = h.total ? Math.round(h.done/h.total*100) : 100;
              return `<div onclick=\"openVulnListModal('${escapeHtml(h.host_id)}')\" style=\"display:flex;align-items:center;gap:10px;padding:7px 10px;border:1px solid #e5e7eb;border-radius:8px;margin-bottom:6px;cursor:pointer;background:#ffffff\">
                <strong style=\"color:#111827;font-size:13px;min-width:120px\">${escapeHtml(h.hostname)}</strong>
                <span style=\"color:#dc2626;font-size:11px\">C ${h.critical}</span><span style=\"color:#ca8a04;font-size:11px\">H ${h.high}</span>
                <span style=\"margin-left:auto;display:flex;align-items:center;gap:6px\">
                  <span style=\"width:90px;height:7px;background:#e5e7eb;border-radius:4px;overflow:hidden\"><span style=\"display:block;height:100%;width:${pct}%;background:${pct>=80?'#16a34a':(pct>=50?'#ca8a04':'#dc2626')}\"></span></span>
                  <span style=\"font-size:11px;color:#111827;width:60px;text-align:right\">${h.done}/${h.total} (${pct}%)</span></span>
              </div>`;
            }).join('');
        el.innerHTML = kpis + list;
      }
    }
    window.renderSecurityHero = renderSecurityHero;

    /* 인프라 현황 위젯 24h/12h 전환 + Zabbix/Wazuh 딥링크 (대시보드=인프라 뷰) */
    let _infraWindow = '24h';
    function setInfraWindow(w) {
      _infraWindow = w;
      const b24 = document.getElementById('infra_win_24'), b12 = document.getElementById('infra_win_12');
      if (b24) { b24.style.background = w==='24h'?'#e5e7eb':'transparent'; b24.style.color = w==='24h'?'#e5e7eb':'#111827'; }
      if (b12) { b12.style.background = w==='12h'?'#e5e7eb':'transparent'; b12.style.color = w==='12h'?'#e5e7eb':'#111827'; }
      renderInfraStatus();
    }
    window.setInfraWindow = setInfraWindow;
    function renderInfraStatus() {
      const el = document.getElementById('infra_status_body');
      if (!el) return;
      const o = _lastOverviewData || {};
      const alertsWin = _infraWindow==='12h' ? (o.alerts_12h??0) : (o.alerts_24h??0);
      const zbx = ZABBIX_URL ? `<a href=\"${escapeHtml(ZABBIX_URL)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#2563eb;font-size:11px;text-decoration:none\">Zabbix</a>` : '';
      const wzh = WAZUH_URL ? `<a href=\"${escapeHtml(WAZUH_URL)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#2563eb;font-size:11px;text-decoration:none\">Wazuh</a>` : '';
      const tile = (label, val, color, extra) => `<div style=\"flex:1;min-width:110px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;padding:12px\">
        <div style=\"font-size:12px;color:#111827\">${label}</div>
        <div style=\"font-size:24px;font-weight:800;color:${color};margin-top:2px\">${val}</div>
        <div style=\"margin-top:4px\">${extra||''}</div></div>`;
      el.innerHTML = `<div style=\"display:flex;gap:10px;flex-wrap:wrap\">
        ${tile(tt('dash.infra.online','온라인'), (o.online_hosts??0), '#16a34a', zbx)}
        ${tile(tt('dash.infra.offline','오프라인'), (o.offline_hosts??0), '#dc2626', zbx)}
        ${tile(tt('dash.infra.unknown','미상'), (o.unknown_hosts??0), '#111827', '')}
        ${tile(_infraWindow==='12h'?tt('dash.infra.alerts_12','경보 12h'):tt('dash.infra.alerts_24','경보 24h'), alertsWin, '#dc2626', wzh)}
      </div>
      <div style=\"margin-top:8px;font-size:11px;color:#111827\">${tt('dash.infra.hint','카드의 Zabbix·Wazuh 링크로 원본 도구에서 상세를 보세요.')}</div>`;
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

    /* 패널 편집: 사용자가 직접 표시할 카드/패널을 선택 (개인별 자동 저장) */
    function togglePanelEdit() {
      _panelEditOpen = !_panelEditOpen;
      const box = document.getElementById('panel_edit_box');
      const btn = document.getElementById('panel_edit_toggle');
      if (box) box.classList.toggle('hidden', !_panelEditOpen);
      if (btn) btn.textContent = _panelEditOpen ? tt('dash.panel.done', '완료') : tt('dash.panel.edit', '패널 편집');
      if (_panelEditOpen) renderPanelEditor();
    }
    window.togglePanelEdit = togglePanelEdit;

    /* 패널 사이즈 자유조절 네이티브 드래그 리사이즈 + localStorage 영속(브라우저별) */
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
        dashboardStatusEl.textContent = tt('dash.panel.layout_reset', '패널 크기 초기화됨');
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
        <label style=\"display:flex;align-items:center;gap:6px;font-size:13px;color:#111827;cursor:pointer\">
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
            ? tt('dash.panel.saved', '패널 설정 저장됨')
            : `${tt('dash.panel.save_fail', '패널 설정 저장 실패')}: HTTP ${response.status}`;
        } catch (error) {
          dashboardStatusEl.textContent = `${tt('dash.panel.save_fail', '패널 설정 저장 실패')}: ${error.message}`;
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
        // 신선도 배지: STALE=노(#ca8a04)·FRESH=초(#16a34a) — 6색 팔레트 준수(주황 제거).
        const freshBadge = item.is_stale
          ? ' <span class=\"badge\" style=\"background:#ca8a04;color:#fff\">STALE</span>'
          : ' <span class=\"badge\" style=\"background:#16a34a;color:#fff\">FRESH</span>';
        const errLine = item.last_error_at
          ? `<div class=\"metric-sub\" style=\"color:#dc2626\">last error: ${escapeHtml(formatTime(item.last_error_at))}</div>`
          : '';
        const recLine = (item.records_collected > 0)
          ? `<div class=\"metric-sub\">records: ${escapeHtml(item.records_collected)}</div>`
          : '';
        return `
        <div class=\"coverage-item\">
          <div class=\"metric-label\">${escapeHtml(item.source.toUpperCase())}</div>
          <strong>${escapeHtml(item.host_count)}</strong>
          <div class=\"metric-sub\">${tt('dash.dyn.unit.hosts', '호스트')} · <span class=\"badge ${escapeHtml(statusToBadge[item.status] || 'unknown')}\">${escapeHtml(item.status)}</span>${freshBadge}</div>
          <div class=\"metric-sub\">last success: ${escapeHtml(formatTime(item.last_success_at))}</div>
          ${errLine}
          ${recLine}
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
        _pgApply(latestStatusEl);
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
        _pgApply(riskSummaryEl);
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
            grafanaLink = `<a href=\"${escapeHtml(item.grafana_url)}\" target=\"_blank\" rel=\"noreferrer\" style=\"color:#2563eb;font-size:12px;margin-left:8px;\">${tt('dash.dyn.grafana_full', 'Grafana 상세 로그')}</a>`;
          } else if (_canViewGrafanaLimited()) {
            grafanaLink = `<a href=\"${escapeHtml(item.grafana_url)}\" target=\"_blank\" rel=\"noreferrer\" style=\"color:#111827;font-size:12px;margin-left:8px;\">${tt('dash.dyn.grafana_limited', 'Grafana 제한 보기')}</a>`;
          } else {
            grafanaLink = `<span style=\"color:#111827;font-size:11px;margin-left:8px\" title=\"${tt('dash.dyn.grafana_no_access', '상세 로그 접근 권한 없음')}\">${tt('dash.dyn.grafana_summary', '요약')}</span>`;
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
        `<button type=\"button\" class=\"nlq-guide-chip\" data-idx=\"${idx}\" style=\"padding:8px 14px;background:#f9fafb;color:#2563eb;border:1px solid #e5e7eb;border-radius:999px;cursor:pointer;font-size:13px;\">${escapeHtml(tt('dash.dyn.nlq_ex.' + idx, ex))}</button>`
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
        return `<span style=\"display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;background:#e5e7eb;color:#2563eb;\" class=\"${cls}\">${escapeHtml(src||'-')}</span>`;
      };
      const rows = evidence.map((ev, i) => `
        <tr style=\"border-bottom:1px solid #dbeafe;\">
          <td style=\"padding:7px 10px;color:#111827\">${i+1}</td>
          <td style=\"padding:7px 10px\">${srcBadge(ev.source)}</td>
          <td style=\"padding:7px 10px;font-size:13px\">${escapeHtml(ev.summary || ev.raw_ref || '-')}</td>
          <td style=\"padding:7px 10px;font-size:11px;color:#111827;font-family:monospace\">${escapeHtml(ev.record_id || '-')}</td>
        </tr>`).join('');
      nlqResultArea.innerHTML = `
        ${summary ? `<div style=\"color:#2563eb;font-size:13px;margin-bottom:10px;padding:8px 12px;background:#f9fafb;border-radius:8px;border-left:3px solid #2563eb\">${escapeHtml(summary)}</div>` : ''}
        <div style=\"overflow:auto\">
          <table style=\"width:100%;border-collapse:collapse;font-size:13px\">
            <thead><tr style=\"background:#f9fafb\">
              <th style=\"padding:8px 10px;color:#2563eb;font-weight:600;text-align:left\">#</th>
              <th style=\"padding:8px 10px;color:#2563eb;font-weight:600;text-align:left\">Source</th>
              <th style=\"padding:8px 10px;color:#2563eb;font-weight:600;text-align:left\">Summary</th>
              <th style=\"padding:8px 10px;color:#2563eb;font-weight:600;text-align:left\">Record ID</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div style=\"color:#111827;font-size:13px;margin-top:8px\">${tt('dash.dyn.nlq.total_prefix', '총')} ${count}${tt('dash.dyn.nlq.total_suffix', '건 조회됨')}</div>`;
    }

    // nlqRunBtn / nlqCsvBtn 핸들러는 DOMContentLoaded 블록에서 등록 (아래 참조)

    async function loadPreferences() {
      try {
        const response = await fetch('/dashboard/preferences');
        const data = await response.json();
        if (response.ok && data.user_dashboard) {
          userPreferences = data.user_dashboard;
        }
      } catch (error) {
        dashboardStatusEl.textContent = `preferences load failed: ${error.message}`;
      }
      applyUserPreferences();
    }

    // 'PC 자산 현황' 패널용 경량 로더 — /assets 에서 Fleet 카운트만 채운다.
    async function loadFleetStatus() {
      try {
        const res = await fetch('/assets');
        if (!res.ok) return;
        const data = await res.json();
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v ?? '-'; };
        set('fleet_total', data.fleet?.total);
        set('fleet_online', data.fleet?.online);
        set('fleet_offline', data.fleet?.offline);
        set('zabbix_total', data.zabbix?.total);
        set('zabbix_online', data.zabbix?.online);
        set('zabbix_offline', data.zabbix?.offline);
        set('trivy_affected_hosts', data.trivy?.affected_hosts);
        set('trivy_total_vulns', data.trivy?.total_vulns);
        set('trivy_critical', data.trivy?.critical);
        set('trivy_high', data.trivy?.high);
      } catch (e) {}
    }

    async function loadDashboard() {
      dashboardStatusEl.textContent = tt('dash.dyn.dash_requesting', '대시보드 데이터 요청 중…');
      try {
        const response = await fetch('/dashboard/summary');
        if (!response.ok) {
          let detail = `HTTP ${response.status}`;
          try { const e = await response.json(); detail = e.detail || detail; } catch(_){}
          dashboardStatusEl.textContent = `${tt('dash.dyn.dash_load_fail', '대시보드 로드 실패')}: ${detail}`;
          overviewCardsEl.innerHTML = `<div class=\"empty\" style=\"padding:16px;color:#dc2626\">${tt('dash.dyn.dash_no_data', '서버가 데이터를 반환하지 못했습니다')} (${escapeHtml(detail)})</div>`;
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
        loadFleetStatus();  // PC 자산 현황 패널 채우기
        dashboardStatusEl.textContent = `dashboard updated at ${formatTime(data.generated_at)}`;
      } catch (error) {
        console.error('[MORI] loadDashboard fetch error:', error);
        dashboardStatusEl.textContent = `${tt('dash.dyn.dash_load_fail', '대시보드 로드 실패')}: ${error.message}`;
        overviewCardsEl.innerHTML = `<div class=\"empty\" style=\"padding:16px;color:#dc2626\">${tt('dash.dyn.network_err', '네트워크 오류 서버 연결을 확인하세요.')}</div>`;
      }
    }

    document.getElementById('refresh_dashboard')?.addEventListener('click', loadDashboard);

    // ── Triage ──────────────────────────────────────────────────────────────
    function _alertSourceUrl(a) {
      if (a.source === 'zabbix' && ZABBIX_URL) return a.source_event_id ? `${ZABBIX_URL}/tr_events.php?triggerid=${encodeURIComponent(a.rule_id||'')}&eventid=${encodeURIComponent(a.source_event_id)}` : ZABBIX_URL;
      if (a.source === 'wazuh' && WAZUH_URL) return WAZUH_URL;
      if (a.source === 'fleet' && FLEET_URL) return FLEET_URL;
      return '';
    }
    let _triageTimer = null;
    function _triageAutoRefresh() {
      if (_triageTimer) clearInterval(_triageTimer);
      _triageTimer = setInterval(() => {
        const p = document.getElementById('tab_triage');
        if (!p || !p.classList.contains('active')) { clearInterval(_triageTimer); _triageTimer = null; return; }
        if (typeof triageModalEl !== 'undefined' && triageModalEl && triageModalEl.open) return;
        loadTriage();
      }, 30000);
    }
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
        const _TRIAGE_LIMIT = 10;
        const shown = alerts.slice(0, _TRIAGE_LIMIT);
        const rows = shown.map(a => {
          const triage = a.triage || {};
          const rawStatus = triage.status || 'pending';
          const triageAnalyst = triage.analyst || '';
          const triageNote = triage.note || '';
          const triageChangedBy = triage.changed_by || '';
          const color = TRIAGE_STATUS_COLORS[rawStatus] || '#111827';
          const label = triageLabel(rawStatus);
          const alertOwner = _ownerForHost(a.hostname || '');
          return `<tr>
            <td>${escapeHtml(formatTime(a.observed_at))}</td>
            <td>${(() => { const u=_alertSourceUrl(a); const b=`<span style=\"background:#e5e7eb;color:#2563eb;padding:2px 8px;border-radius:4px;font-size:12px\">${escapeHtml(a.source)}</span>`; return u?`<a href=\"${escapeHtml(u)}\" target=\"_blank\" rel=\"noopener\" style=\"text-decoration:none\" title=\"${escapeHtml(a.source)} ${tt('dash.triage.open_source','원본 열기')}\">${b}</a>`:b; })()}</td>
            <td><strong>${escapeHtml(a.hostname || a.host_id || '-')}</strong></td>
            <td style=\"color:#16a34a;font-size:12px\">${escapeHtml(alertOwner)}</td>
            <td><span style=\"background:#ffffff;padding:2px 6px;border-radius:4px;font-size:12px\">${escapeHtml(a.severity)}</span>${a.resolved_at?`<br><span title=\"${escapeHtml(formatTime(a.resolved_at))}\" style=\"background:#dcfce7;color:#16a34a;border:1px solid #dcfce7;padding:1px 6px;border-radius:4px;font-size:10px\">${tt('dash.triage.source_resolved','소스 해소')}</span>`:''}</td>
            <td style=\"max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">${escapeHtml(a.message)}</td>
            <td style=\"color:#111827;font-size:12px\">${escapeHtml(triageAnalyst || '-')}</td>
            <td style=\"color:#ca8a04;font-size:12px\">${escapeHtml(triageChangedBy || '-')}</td>
            <td><button onclick=\"openTriageModal('${escapeHtml(a.alert_id)}','${escapeHtml(rawStatus)}','${escapeHtml(triageAnalyst)}','${escapeHtml(triageNote)}','${escapeHtml(a.message||'').replace(/'/g,\"&#39;\")}','${escapeHtml(alertOwner)}')\" style=\"background:${color};color:#fff;border:none;border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px;white-space:nowrap\">${label}</button></td>
          </tr>`;
        }).join('');
        triageTableEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
          <thead><tr style=\"background:#f9fafb\">
            <th style=\"padding:8px;color:#2563eb;text-align:left\">${tt('dash.dyn.lbl.time', '시각')}</th>
            <th style=\"padding:8px;color:#2563eb;text-align:left\">${tt('dash.dyn.lbl.source', '소스')}</th>
            <th style=\"padding:8px;color:#2563eb;text-align:left\">${tt('dash.dyn.lbl.host', '호스트')}</th>
            <th style=\"padding:8px;color:#16a34a;text-align:left\">${tt('dash.dyn.lbl.server_owner', '서버 담당자')}</th>
            <th style=\"padding:8px;color:#2563eb;text-align:left\">${tt('dash.dyn.lbl.severity', '심각도')}</th>
            <th style=\"padding:8px;color:#2563eb;text-align:left\">${tt('dash.dyn.lbl.message', '메시지')}</th>
            <th style=\"padding:8px;color:#111827;text-align:left\">${tt('dash.dyn.lbl.analyst', '분석관')}</th>
            <th style=\"padding:8px;color:#ca8a04;text-align:left\">${tt('dash.dyn.lbl.changed_by', '변경자')}</th>
            <th style=\"padding:8px;color:#2563eb;text-align:left\">${tt('dash.dyn.lbl.status', '상태')}</th>
          </tr></thead><tbody>${rows}</tbody></table>${alerts.length > _TRIAGE_LIMIT ? `<div class=\"empty\" style=\"padding:10px 2px\">${tt('dash.triage.more_note','최근 {n}건만 표시합니다. 나머지는 각 플랫폼(Zabbix·Wazuh)에서 확인하세요.').replace('{n}', _TRIAGE_LIMIT)}</div>` : ''}`;
        _triageAutoRefresh();
      } catch (err) { triageTableEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix', '오류: ')}${escapeHtml(err.message)}</span>`; }
    }

    function openTriageModal(alertId, status, analyst, note, message, serverOwner) {
      currentTriageAlertId = alertId;
      triageModalAlertInfoEl.innerHTML = `<strong>Alert ID:</strong> ${escapeHtml(alertId)}<br><span style=\"color:#111827\">${escapeHtml(message)}</span>`;
      triageModalStatusEl.value = status || 'pending';
      // 서버 담당자가 기본, 기존 analyst가 있으면 그 값 유지
      triageModalAnalystEl.value = analyst || serverOwner || '';
      triageModalNoteEl.value = note || '';
      const actorEl = document.getElementById('triage_modal_actor');
      if (actorEl) actorEl.value = '';
      triageModalStatusLineEl.textContent = '';
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
        triageModalStatusLineEl.style.color = '#16a34a';
        triageModalStatusLineEl.textContent = tt('dash.dyn.autosaved', '자동 저장됨');
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
        const STATUS_COLOR = { open: '#dc2626', investigating: '#ca8a04', resolved: '#16a34a', closed: '#111827' };
        incidentsListEl.innerHTML = list.map(inc => {
          const color = STATUS_COLOR[inc.status] || '#111827';
          const ownerLabel = (inc.related_owners || []).join(', ') || '-';
          const hostLabel = (inc.related_hosts || []).join(', ') || '';
          const incHost = inc.hostname || '';
          const incAnalyst = inc.analyst || '';
          const incHandler = inc.handler || '';
          const handlerInfo = (incHandler && incHandler !== incAnalyst) ? ` · ${tt('dash.dyn.lbl.handler', '조치자')}: <span style=\"color:#ca8a04\">${escapeHtml(incHandler)}</span>` : '';
          return `<div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center\">
            <div>
              <strong>${escapeHtml(inc.title)}</strong>
              <div style=\"color:#111827;font-size:12px;margin-top:4px\">${escapeHtml(formatTime(inc.created_at))} · ${tt('dash.dyn.notes_label', '노트')} ${(inc.notes||[]).length}${tt('dash.dyn.notes_unit', '개')}${incHost ? ' · ' + tt('dash.dyn.lbl.host', '호스트') + ': <span style=\"color:#2563eb\">' + escapeHtml(incHost) + '</span>' : ''}${hostLabel ? ' · <span style=\"color:#2563eb\">' + escapeHtml(hostLabel) + '</span>' : ''}</div>
              <div style=\"color:#16a34a;font-size:12px;margin-top:2px\">${tt('dash.dyn.col.owner', '담당자')}: ${escapeHtml(incAnalyst || ownerLabel)}${handlerInfo}</div>
            </div>
            <div style=\"display:flex;gap:8px;align-items:center\">
              <span style=\"background:${color};color:#fff;padding:3px 10px;border-radius:6px;font-size:12px\">${escapeHtml(inc.status)}</span>
              <button onclick=\"openIncidentModal('${escapeHtml(inc.incident_id)}')\" style=\"background:#e5e7eb;color:#2563eb;border:1px solid #e5e7eb;border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px\">${tt('dash.dyn.detail_btn', '상세')}</button>
            </div>
          </div>`;
        }).join('');
        _pgApply(incidentsListEl);
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
          ? `<br><strong style="color:#ca8a04">${tt('dash.dyn.status_changed_at', '상태 변경 시각')}:</strong> ${escapeHtml(formatTime(inc.status_updated_at))}`
          : '';
        const hostLine = inc.hostname ? `<br><strong style="color:#2563eb">${tt('dash.dyn.lbl.host', '호스트')}:</strong> ${escapeHtml(inc.hostname)}` : '';
        const analystLine = inc.analyst ? `<br><strong style="color:#16a34a">${tt('dash.dyn.col.owner', '담당자')}:</strong> ${escapeHtml(inc.analyst)}` : '';
        const handlerLine = (inc.handler && inc.handler !== inc.analyst) ? `<br><strong style="color:#ca8a04">${tt('dash.dyn.lbl.handler', '조치자')}:</strong> ${escapeHtml(inc.handler)}` : '';
        document.getElementById('incident_modal_info').innerHTML = `<span style="color:#111827">ID: ${escapeHtml(inc.incident_id)}</span><br>${tt('dash.dyn.created_label', '생성')}: ${escapeHtml(formatTime(inc.created_at))} &nbsp;|&nbsp; ${tt('dash.dyn.updated_label', '수정')}: ${escapeHtml(formatTime(inc.updated_at))}${statusUpdatedLine}${hostLine}${analystLine}${handlerLine}`;
        document.getElementById('incident_modal_status').value = inc.status;
        // 조사 노트
        const notes = inc.notes || [];
        document.getElementById('incident_modal_notes').innerHTML = notes.length
          ? notes.map(n => `<div style=\"background:#f9fafb;border-left:3px solid #e5e7eb;padding:8px 12px;margin-bottom:6px;border-radius:4px\"><div style=\"color:#111827;font-size:12px\">${escapeHtml(formatTime(n.created_at))} · ${escapeHtml(n.analyst||'-')}</div><div>${escapeHtml(n.text)}</div></div>`).join('')
          : `<div style=\"color:#111827;font-size:13px\">${tt('dash.dyn.no_notes', '조사 노트 없음')}</div>`;
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
          closeIncidentCreateModal();
          loadIncidents();
        }
        else { const d = await res.json(); incidentStatusEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${d.detail || res.status}`; }
      } catch (err) { incidentStatusEl.textContent = `${tt('dash.dyn.error_prefix', '오류: ')}${err.message}`; }
    });

    document.getElementById('reload_incidents')?.addEventListener('click', loadIncidents);

    // 새 인시던트 생성 모달 열기/닫기 (버튼 클릭 시 팝업)
    function openIncidentCreateModal() {
      incidentStatusEl.textContent = '';
      incTitleEl.value = '';
      const h = document.getElementById('inc_hostname'); if (h) h.value = '';
      const a = document.getElementById('inc_analyst'); if (a) a.value = '';
      const hd = document.getElementById('inc_handler'); if (hd) hd.value = '';
      const df = document.getElementById('inc_diff_handler'); if (df) df.checked = false;
      const hr = document.getElementById('inc_handler_row'); if (hr) hr.style.display = 'none';
      document.getElementById('incident_create_modal').style.display = 'flex';
      setTimeout(() => incTitleEl.focus(), 30);
    }
    function closeIncidentCreateModal() { document.getElementById('incident_create_modal').style.display = 'none'; }
    window.closeIncidentCreateModal = closeIncidentCreateModal;
    document.getElementById('inc_new_btn')?.addEventListener('click', openIncidentCreateModal);
    document.getElementById('incident_create_modal')?.addEventListener('click', e => {
      if (e.target.id === 'incident_create_modal') closeIncidentCreateModal();
    });

    // 검색 + 날짜 필터 조회 버튼
    document.getElementById('inc_filter_btn')?.addEventListener('click', loadIncidents);
    // 검색창 Enter 키
    document.getElementById('inc_search')?.addEventListener('keydown', e => { if (e.key === 'Enter') loadIncidents(); });

    // CSV 다운로드 — 미리보기 모달로 먼저 보여준 뒤 다운로드
    if (document.getElementById('inc_csv_btn')) {
      document.getElementById('inc_csv_btn')?.addEventListener('click', openIncidentCsvPreview);
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
        return `<div onclick=\"_incSelectHost('${escapeHtml(h.hostname)}','${escapeHtml(h.owner||'')}')\" style=\"padding:8px 12px;cursor:pointer;border-bottom:1px solid #e5e7eb;font-size:13px;color:#111827\" onmouseover=\"this.style.background='#e5e7eb'\" onmouseout=\"this.style.background=''\">
          <strong>${escapeHtml(h.hostname)}</strong> <span style=\"color:#111827;font-size:11px\">${tt('dash.dyn.lbl.owner_short', '담당')}: ${escapeHtml(ownerLabel)}</span>
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

    /* 내 서버: assigned_servers(호스트명) 또는 owner==display_name 인 자산만 모아 렌더 */
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
        return `<details open style=\"margin:8px 0;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden\">
          <summary style=\"cursor:pointer;padding:8px 12px;background:#f9fafb;font-weight:600;color:#111827\">${escapeHtml(name)} <span style=\"color:#111827;font-weight:400\">(${cnt})</span></summary>
          <div style=\"padding:8px 12px\">${_renderMineTables(g.fleet, g.zabbix)}</div>
        </details>`;
      }).join('');
    }
    window.renderMyServers = renderMyServers;

    /* D: 내 서버 간소화 테이블 호스트명·중요도·분류·상태·IP만. 행 더블클릭 → 상세 모달.
       통제/리스크/이력 등 상세는 상세 모달로 이동(대시보드 최소화). */
    const _MINE_IMP_COLOR = { '상':'#dc2626', '중':'#ca8a04', '하':'#16a34a' };
    function _mineRow(h, kind) {
      const statusCls = h.status === 'online' ? 'online' : h.status === 'offline' ? 'offline' : 'unknown';
      const typeBadge = kind === 'fleet'
        ? `<span style=\"background:#dbeafe;color:#16a34a;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700\">PC</span>`
        : `<span style=\"background:#dbeafe;color:#2563eb;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700\">${tt('dash.mine.server','서버')}</span>`;
      const imp = (h.importance || '').trim();
      const impCell = imp
        ? `<span style=\"color:${_MINE_IMP_COLOR[imp]||'#111827'};font-weight:700\">${escapeHtml(imp)}</span>`
        : '<span style=\"color:#111827\">-</span>';
      return `<tr ondblclick=\"openHostDetail('${escapeHtml(h.hostname)}')\" style=\"cursor:pointer\" title=\"${tt('dash.mine.dblclick','더블클릭하면 상세·조치현황')}\">
        <td style=\"padding:7px 8px;text-align:left\"><strong>${escapeHtml(h.hostname)}</strong> ${typeBadge}</td>
        <td style=\"padding:7px 8px;text-align:left\">${impCell}</td>
        <td style=\"padding:7px 8px;text-align:left\"><span class=\"badge ${statusCls}\">${escapeHtml(h.status || '-')}</span></td>
        <td style=\"padding:7px 8px;text-align:left;color:#111827;font-family:monospace;font-size:12px\">${escapeHtml(h.primary_ip || '-')}</td>
      </tr>`;
    }
    function _renderMineTables(fleetHosts, zabbixHosts) {
      const rows = [
        ...zabbixHosts.map(h => _mineRow(h, 'zabbix')),
        ...fleetHosts.map(h => _mineRow(h, 'fleet')),
      ].join('');
      if (!rows) return '';
      return `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
        <thead><tr style=\"background:#f9fafb\">
          <th style=\"padding:8px;text-align:left;color:#111827\">${tt('dash.dyn.lbl.hostname','호스트명')}</th>
          <th style=\"padding:8px;text-align:left;color:#2563eb\">${tt('dash.mine.importance','중요도')}</th>
          <th style=\"padding:8px;text-align:left;color:#2563eb\">${tt('dash.dyn.lbl.status','상태')}</th>
          <th style=\"padding:8px;text-align:left;color:#2563eb\">IP</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div style=\"font-size:11px;color:#111827;margin-top:4px\">${tt('dash.mine.hint','행을 더블클릭하면 상세와 조치현황을 볼 수 있어요.')}</div>`;
    }

    /* 호스트 상세 모달: 캐시의 전체 필드 + 미조치 3버킷(E, /dashboard/host-remediation) */
    function _hostFromCache(hostname) {
      const all = [...(_assetCache.zabbix || []), ...(_assetCache.fleet || [])];
      return all.find(h => h.hostname === hostname) || null;
    }
    function _kv(label, value) {
      return `<div style=\"display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid #e5e7eb\">
        <span style=\"color:#111827\">${label}</span><span style=\"color:#111827;text-align:right\">${value}</span></div>`;
    }
    /* 호스트 상세 모달용 외부 연동 딥링크. 자산 종류에 맞는 소스만: 서버→Zabbix, PC→Fleet, 공통→Grafana. */
    function _hostDeepLinks(h, kind) {
      const btn = (href, label, color) => `<a href=\"${escapeHtml(href)}\" target=\"_blank\" rel=\"noopener\" style=\"display:inline-flex;align-items:center;gap:4px;background:${color}18;border:1px solid ${color}66;color:${color};border-radius:6px;padding:5px 12px;font-size:12px;font-weight:600;text-decoration:none\">${label}</a>`;
      const links = [];
      if (kind === 'zabbix' && ZABBIX_URL) {
        links.push(btn(`${ZABBIX_URL}/zabbix.php?action=host.list&filter_set=1&filter_host=${encodeURIComponent(h.hostname)}`, 'Zabbix', '#2563eb'));
      }
      if (kind === 'fleet' && FLEET_URL) {
        links.push(btn(`${FLEET_URL}/hosts?query=${encodeURIComponent(h.hostname)}`, 'Fleet', '#16a34a'));
      }
      if (GRAFANA_URL) {
        const q = h.host_id ? `{host_id=\"${h.host_id}\"}` : `{hostname=\"${h.hostname}\"}`;
        const panes = encodeURIComponent(JSON.stringify({ pane: { queries: [{ refId: 'A', expr: q, queryType: 'range' }], range: { from: 'now-6h', to: 'now' } } }));
        links.push(btn(`${GRAFANA_URL}/explore?schemaVersion=1&panes=${panes}&orgId=1`, 'Grafana', '#ca8a04'));
      }
      if (!links.length) {
        return `<div style=\"font-size:11px;color:#111827;margin-bottom:12px\">${tt('dash.host.no_links','연동 URL 미설정 (.env: MORI_ZABBIX_UI_URL·MORI_GRAFANA_URL·MORI_FLEET_UI_URL)')}</div>`;
      }
      return `<div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px\">${links.join('')}</div>`;
    }
    async function openHostDetail(hostname) {
      const modal = document.getElementById('host_detail_modal');
      const titleEl = document.getElementById('host_detail_title');
      const bodyEl = document.getElementById('host_detail_body');
      if (!modal || !bodyEl) return;
      const h = _hostFromCache(hostname) || { hostname };
      const _isZ = (_assetCache.zabbix || []).some(x => x.hostname === hostname);
      const kind = _isZ ? 'zabbix' : 'fleet';  // 서버(Zabbix)면 Zabbix, 아니면 PC(Fleet)
      if (titleEl) titleEl.textContent = `${hostname}`;
      const imp = (h.importance || '').trim();
      const impStr = imp ? `<span style=\"color:${_MINE_IMP_COLOR[imp]||'#111827'};font-weight:700\">${escapeHtml(imp)}</span>` : '-';
      const ownerLabel = [h.owner, h.team].filter(Boolean).join(' / ') || '-';
      const _at = kind === 'zabbix' ? 'server' : 'pc';
      const excStr = h.exception_until
        ? `${escapeHtml(String(h.exception_until).slice(0,10))}${h.exception_reason ? ' · ' + escapeHtml(h.exception_reason) : ''}`
        : '-';
      const ownerCell = `${escapeHtml(ownerLabel)} <button onclick=\"openOwnerModal('${escapeHtml(hostname)}','${escapeHtml(h.owner||'')}','${escapeHtml(h.team||'')}','${escapeHtml(h.category||'')}','${_at}','','','${escapeHtml(h.importance||'')}')\" style=\"margin-left:8px;padding:2px 8px;font-size:11px;border-radius:4px;background:#e5e7eb;color:#2563eb;border:1px solid #d1d5db;cursor:pointer\">${tt('dash.dyn.edit_btn','수정')}</button>`;
      const meta = `<div style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:10px 14px;margin-bottom:14px\">
        ${_kv(tt('dash.dyn.lbl.type','유형'), _at==='server' ? tt('dash.host.kind_server','서버') : 'PC')}
        ${_kv(tt('dash.dyn.lbl.platform','플랫폼'), escapeHtml((h.platform||'').trim()||'-'))}
        ${_kv(tt('dash.mine.importance','중요도'), impStr)}
        ${_kv(tt('dash.mine.category','분류'), escapeHtml((h.category||'').trim()||'-'))}
        ${h.isms_control?_kv(tt('dash.dyn.lbl.isms_control','ISMS-P 통제'), `<span style=\\"color:#2563eb\\">${escapeHtml(h.isms_control)}</span>`):''}
        ${h.iso27001_control?_kv('ISO 27001', `<span style=\\"color:#2563eb\\">${escapeHtml(h.iso27001_control)}</span>`):''}
        ${h.latest_metric?_kv(tt('dash.dyn.lbl.latest_metric','최근 메트릭'), escapeHtml(h.latest_metric)+': '+escapeHtml(h.latest_value||'-')):''}
        ${_kv(tt('dash.dyn.lbl.status','상태'), `<span class=\\\"badge ${h.status==='online'?'online':h.status==='offline'?'offline':'unknown'}\\\">${escapeHtml(h.status||'-')}</span>`)}
        ${_kv('IP', `<span style=\\\"font-family:monospace\\\">${escapeHtml(h.primary_ip||'-')}</span>`)}
        ${_kv(tt('dash.dyn.lbl.owner_team','담당자 / 팀'), ownerCell)}
        ${h.risk_score!=null?_kv(tt('dash.dyn.lbl.risk','리스크'), escapeHtml(String(h.risk_score))):''}
        ${_kv(tt('dash.host.exception','예외'), excStr)}
        ${h.last_seen_at?_kv(tt('dash.dyn.lbl.last_seen','마지막 확인'), escapeHtml(formatTime(h.last_seen_at))):''}
      </div>`;
      const acctSlot = _canViewAccounts() ? `<div id=\"host_detail_acct\" style=\"margin-top:14px\"></div>` : '';
      const privreqSlot = (kind === 'zabbix') ? `<div id=\"host_detail_privreq\" style=\"margin-top:14px\"></div>` : '';
      bodyEl.innerHTML = _hostDeepLinks(h, kind) + meta + `<div id=\"host_detail_remed\"><span class=\"empty\">${tt('dash.dyn.loading','로딩 중…')}</span></div>` + privreqSlot + acctSlot;
      modal.style.display = 'flex';
      // E: 미조치 3버킷
      const remedEl = document.getElementById('host_detail_remed');
      try {
        const res = await fetch(`/dashboard/host-remediation/${encodeURIComponent(hostname)}`);
        if (!res.ok) { remedEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}HTTP ${res.status}</span>`; return; }
        const d = await res.json();
        remedEl.innerHTML = _renderRemediation(d);
      } catch (e) {
        remedEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
      // 호스트 계정 섹션 (계정 열람 역할 전용, admin 조정 가능)
      if (_canViewAccounts()) {
        const acctEl = document.getElementById('host_detail_acct');
        try {
          const ar = await fetch(`/accounts/host/${encodeURIComponent(hostname)}`);
          if (ar.ok) {
            const ad = await ar.json();
            if (!ad.count) {
              acctEl.innerHTML = `<div style=\"font-weight:700;color:#111827;margin-bottom:6px\">${tt('dash.acc.host_title','로컬 계정')}</div><div class=\"empty\" style=\"color:#111827\">${tt('dash.acc.host_none','수집된 계정 없음 (osquery push 필요)')}</div>`;
            } else {
              acctEl.innerHTML = `<div style=\"font-weight:700;color:#111827;margin-bottom:6px\">${tt('dash.acc.host_title','로컬 계정')} (${ad.count}${ad.flagged?` · ${ad.flagged}`:''})</div>` +
                `<div style=\"max-height:180px;overflow-y:auto\">${ad.accounts.map(a => `<div style=\"display:flex;justify-content:space-between;gap:8px;padding:3px 6px;border-bottom:1px solid #f9fafb;font-size:12px\"><span style=\"font-family:monospace\">${escapeHtml(a.username)}${a.is_privileged?` <span style=\"color:#dc2626\">●${a.is_sudo?'sudo':''}</span>`:''}</span><span>${a.findings.map(_accFindBadge).join('')||(a.in_directory?'':'')}</span></div>`).join('')}</div>`;
            }
          }
        } catch (e) { /* best-effort */ }
      }
      if (kind === 'zabbix') _loadHostPrivReq(hostname);  // 특권/sudo 승인요청 섹션
    }
    window.openHostDetail = openHostDetail;
    function closeHostDetail() { const m = document.getElementById('host_detail_modal'); if (m) m.style.display = 'none'; }
    window.closeHostDetail = closeHostDetail;

    function _remedBucket(title, color, emoji, bucket) {
      const b = bucket || { count: 0, items: [] };
      const items = (b.items || []).map(it => `<div style=\"display:flex;justify-content:space-between;gap:10px;padding:4px 8px;border-bottom:1px solid #f9fafb;font-size:12px\">
        <span style=\"color:#111827\">${escapeHtml(it.label||it.id)}</span>
        <span style=\"color:${it.severity==='critical'?'#dc2626':'#ca8a04'};text-transform:uppercase;font-size:10px\">${escapeHtml(it.severity||'')}${it.exception_until?` · ~${escapeHtml(String(it.exception_until).slice(0,10))}`:''}${it.plan_target_date?` · D:${escapeHtml(String(it.plan_target_date).slice(0,10))}`:''}</span>
      </div>`).join('');
      return `<div style=\"flex:1;min-width:170px;border:1px solid ${color}55;border-radius:8px;overflow:hidden\">
        <div style=\"background:${color}18;padding:6px 10px;display:flex;justify-content:space-between;align-items:center\">
          <span style=\"font-size:12px;font-weight:700;color:${color}\">${emoji} ${title}</span>
          <strong style=\"color:${color};font-size:15px\">${b.count||0}</strong></div>
        <div style=\"max-height:150px;overflow-y:auto\">${items || `<div style=\\\"padding:8px 10px;color:#111827;font-size:12px\\\">${tt('dash.host.remed_none','없음')}</div>`}</div>
      </div>`;
    }
    function _renderRemediation(d) {
      const bk = d.buckets || {};
      const head = `<div style=\"font-size:13px;font-weight:700;color:#111827;margin-bottom:8px\">${tt('dash.host.remed_title','조치현황 (미조치 {n}건)').replace('{n}', d.total||0)}</div>`;
      if (!d.total) return head + `<div class=\"empty\" style=\"padding:12px;color:#16a34a\">${tt('dash.host.remed_clear','미조치 항목이 없습니다.')}</div>`;
      return head + `<div style=\"display:flex;gap:10px;flex-wrap:wrap\">
        ${_remedBucket(tt('dash.host.bucket_exc','예외 만료'), '#dc2626', '', bk.exception_expired)}
        ${_remedBucket(tt('dash.host.bucket_overdue','조치기한 초과'), '#ca8a04', '', bk.overdue)}
        ${_remedBucket(tt('dash.host.bucket_other','기타 위험'), '#ca8a04', '', bk.other)}
      </div>`;
    }

    const FLEET_URL = '__FLEET_UI_URL__';
    const ZABBIX_URL = '__ZABBIX_UI_URL__';
    const WAZUH_URL = '__WAZUH_UI_URL__';
    const GRAFANA_URL = '__GRAFANA_UI_URL__';

    /* hostname → 담당자 조회 (Fleet + Zabbix 캐시에서) */
    function _ownerForHost(hostname) {
      const allHosts = [...(_assetCache.fleet || []), ...(_assetCache.zabbix || [])];
      const found = allHosts.find(h => h.hostname === hostname);
      if (!found) return '-';
      return [found.owner, found.team].filter(Boolean).join(' / ') || '-';
    }
    /* hostname → 자산 중요도(상/중/하) 조회 (Zabbix/Fleet 캐시에서) */
    function _importanceForHost(hostname) {
      const allHosts = [...(_assetCache.zabbix || []), ...(_assetCache.fleet || [])];
      const found = allHosts.find(h => h.hostname === hostname);
      return found ? (found.importance || '').trim() : '';
    }
    /* 호스트 위험점수(1~9) = 영향도(중요도) × 발생가능성(최고 심각도). 위험성 평가 매트릭스와 동일 로직. */
    function _hostRiskScore(r) {
      const imp = { '상':3, '중':2, '하':1 }[_importanceForHost(r.hostname)] || 2;
      const lk = (r.critical > 0 || r.high > 0) ? 3 : (r.medium > 0) ? 2 : (r.low > 0) ? 1 : 0;
      return imp * lk;
    }
    /* hostname → 담당자/팀/예외 전체 데이터 */
    function _getOwnerData(hostname) {
      const allHosts = [...(_assetCache.fleet || []), ...(_assetCache.zabbix || [])];
      const found = allHosts.find(h => h.hostname === hostname);
      return found ? { owner: found.owner || '', team: found.team || '', exception_until: found.exception_until || '', exception_reason: found.exception_reason || '' } : { owner: '', team: '', exception_until: '', exception_reason: '' };
    }

    /* PC(Fleet)·서버(Zabbix) 자산 표 kind별 차이 — 나머지 렌더는 renderAssetTable 로 공통화 */
    const _ASSET_TABLE_CFG = {
      fleet: {
        empty: () => tt('dash.dyn.empty.fleet', 'Fleet에서 수집된 PC 자산이 없습니다.'),
        headColor: '#16a34a',
        col2Head: () => tt('dash.dyn.lbl.platform','플랫폼'),
        col2: h => escapeHtml(h.platform),
        link: h => FLEET_URL ? `<a href=\"${escapeHtml(FLEET_URL)}/hosts?query=${encodeURIComponent(h.hostname)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#16a34a;font-size:12px;\">Fleet</a>` : '',
      },
      zabbix: {
        empty: () => tt('dash.dyn.empty.zabbix', 'Zabbix에서 수집된 서버 자산이 없습니다.'),
        headColor: '#2563eb',
        col2Head: () => tt('dash.dyn.lbl.category','분류'),
        col2: h => `<span style=\"font-size:12px\">${escapeHtml(h.category || '-')}</span>`,
        link: h => ZABBIX_URL ? `<a href=\"${escapeHtml(ZABBIX_URL)}/zabbix.php?action=host.list&filter_set=1&filter_host=${encodeURIComponent(h.hostname)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#2563eb;font-size:12px;\">Zabbix</a>` : '',
      },
    };
    /* PC/서버 자산 표 공통 렌더. kind='fleet'|'zabbix' */
    function renderAssetTable(kind, hosts, containerEl) {
      const cfg = _ASSET_TABLE_CFG[kind];
      if (!hosts.length) { containerEl.innerHTML = `<div class=\"empty\">${cfg.empty()}</div>`; return; }
      const rows = hosts.map(h => {
        const statusCls = h.status === 'online' ? 'online' : h.status === 'offline' ? 'offline' : 'unknown';
        const link = cfg.link(h);
        const ownerLabel = [h.owner, h.team].filter(Boolean).join(' / ') || '-';
        return `<tr ondblclick=\"openHostDetail('${escapeHtml(h.hostname)}')\" style=\"cursor:pointer\" title=\"${tt('dash.mine.dblclick','더블클릭하면 상세·조치현황')}\">
          <td><strong>${escapeHtml(h.hostname)}</strong>${link ? '<br>' + link : ''}</td>
          <td>${cfg.col2(h)}</td>
          <td>${escapeHtml(h.primary_ip)}</td>
          <td><span class=\"badge ${statusCls}\">${escapeHtml(h.status)}</span></td>
          <td><span style=\"color:#16a34a;font-size:12px\">${escapeHtml(ownerLabel)}</span></td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#f9fafb;\">
          <th style=\"padding:8px;color:${cfg.headColor}\">${tt('dash.dyn.lbl.hostname','호스트명')}</th>
          <th style=\"padding:8px;color:#2563eb\">${cfg.col2Head()}</th>
          <th style=\"padding:8px;color:#2563eb\">IP</th>
          <th style=\"padding:8px;color:#2563eb\">${tt('dash.dyn.lbl.status','상태')}</th>
          <th style=\"padding:8px;color:#16a34a\">${tt('dash.dyn.lbl.owner_team','담당자 / 팀')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
      _pgApply(containerEl);
    }

    function renderTrivyTable(rows, containerEl) {
      if (!rows.length) { containerEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.trivy_empty', 'Trivy 취약점 데이터가 없습니다.') + '</div>'; return; }
      const sevColor = { critical:'#dc2626', high:'#ca8a04', medium:'#ca8a04', low:'#16a34a', info:'#111827' };
      const tableRows = rows.map(r => {
        const planText = r.action_plan ? escapeHtml(r.action_plan).substring(0, 30) + (r.action_plan.length > 30 ? '…' : '') : '';
        let planCell;
        if (r.has_vuln_plans) {
          const cnt = (r.vuln_plans_count || 0) + (r.vuln_exceptions_count || 0);
          planCell = `<span style=\"color:#ca8a04;font-size:12px;font-weight:600\">${tt('dash.dyn.cve_plan_detail','CVE별 상세 계획')}</span>
            <br><span style=\"color:#111827;font-size:11px\">${tt('dash.dyn.plan_count','계획')} ${r.vuln_plans_count||0} · ${tt('dash.dyn.exception_count','예외')} ${r.vuln_exceptions_count||0}</span>
            <br><button onclick=\"showVulnPlansNotice('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}',${cnt})\" style=\"font-size:10px;padding:1px 6px;background:#fef9c3;border:1px solid #fef9c3;border-radius:3px;color:#ca8a04;cursor:pointer;margin-top:2px\">${tt('dash.dyn.notice_btn','안내')}</button>`;
        } else if (r.action_plan) {
          planCell = `<span style=\"color:#16a34a;font-size:12px\" title=\"${escapeHtml(r.action_plan)}\">${planText}</span>${r.action_target_date ? '<br><span style=\"color:#111827;font-size:11px\">~' + escapeHtml(r.action_target_date) + '</span>' : ''}<br><button onclick=\"openPlanModal('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}')\" style=\"font-size:10px;padding:1px 6px;background:#e5e7eb;border:1px solid #e5e7eb;border-radius:3px;color:#2563eb;cursor:pointer;margin-top:2px\">${tt('dash.dyn.edit_btn','수정')}</button>`;
        } else {
          planCell = `<button onclick=\"openPlanModal('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}')\" style=\"font-size:11px;padding:2px 7px;background:#e5e7eb;border:1px solid #e5e7eb;border-radius:4px;color:#2563eb;cursor:pointer\">${tt('dash.dyn.add_plan_btn','+ 계획 추가')}</button>`;
        }
        const ownerLabel = _ownerForHost(r.hostname);
        const ownerData = _getOwnerData(r.hostname);
        const exUntil = r.exception_until || ownerData.exception_until || '';
        const exReason = ownerData.exception_reason || '';
        let exCell;
        if (r.has_vuln_exceptions) {
          const cnt = (r.vuln_plans_count || 0) + (r.vuln_exceptions_count || 0);
          exCell = `<span style=\"color:#ca8a04;font-size:12px;font-weight:600\">${tt('dash.dyn.cve_exception_detail','CVE별 상세 예외')}</span>
            <br><span style=\"color:#111827;font-size:11px\">${tt('dash.dyn.exception_count','예외')} ${r.vuln_exceptions_count||0} · ${tt('dash.dyn.plan_count','계획')} ${r.vuln_plans_count||0}</span>
            <br><button onclick=\"showVulnExceptionsNotice('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}',${cnt})\" style=\"font-size:10px;padding:1px 6px;background:#fef9c3;border:1px solid #fef9c3;border-radius:3px;color:#ca8a04;cursor:pointer;margin-top:2px\">${tt('dash.dyn.notice_btn','안내')}</button>`;
        } else if (exUntil) {
          exCell = `<span style=\"color:#ca8a04;font-size:12px\">~${escapeHtml(exUntil)}</span>${exReason ? '<br><span style=\"color:#111827;font-size:11px\" title=\"'+escapeHtml(exReason)+'\">'+escapeHtml(exReason.substring(0,20))+(exReason.length>20?'…':'')+'</span>' : ''}<br><button onclick=\"openOwnerModal('${escapeHtml(r.hostname)}','${escapeHtml(ownerData.owner||'')}','${escapeHtml(ownerData.team||'')}','','trivy','${escapeHtml(exUntil)}','${escapeHtml(exReason).replace(/'/g,"\\\\'")}')\" style=\"font-size:10px;padding:1px 6px;background:#fef9c3;border:1px solid #fef9c3;border-radius:3px;color:#ca8a04;cursor:pointer;margin-top:2px\">${tt('dash.dyn.edit_btn','수정')}</button>`;
        } else {
          exCell = `<button onclick=\"openOwnerModal('${escapeHtml(r.hostname)}','${escapeHtml(ownerData.owner||'')}','${escapeHtml(ownerData.team||'')}','','trivy','','')\" style=\"font-size:11px;padding:2px 7px;background:#fef9c3;border:1px solid #fef9c3;border-radius:4px;color:#ca8a04;cursor:pointer\">${tt('dash.dyn.add_exception_btn','+ 예외 설정')}</button>`;
        }
        const totalCell = r.total > 0
          ? `<button onclick=\"openVulnListModal('${escapeHtml(r.host_id)}')\" title=\"${tt('dash.dyn.view_vuln_detail','취약점 상세 보기')}\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#2563eb;border-radius:6px;padding:3px 10px;cursor:pointer;font-size:13px;font-weight:700\">${r.total} ${tt('dash.dyn.cases_unit','건')}</button>`
          : `<span style=\"color:#111827\">${r.total}</span>`;
        const _rscore = _hostRiskScore(r);
        const riskCell = _rscore
          ? _riskBadge(_levelForScore(_rscore), true, _rscore)
          : '<span style=\"color:#111827\">-</span>';
        return `<tr ondblclick=\"openVulnListModal(\'${escapeHtml(r.host_id)}\')\" style=\"cursor:pointer\" title=\"${tt('dash.dyn.dblclick_vuln','더블클릭하면 취약점 상세')}\">
          <td><strong>${escapeHtml(r.hostname)}</strong><br><span style=\"color:#111827;font-size:11px\">${escapeHtml(r.host_id)}</span></td>
          <td>${riskCell}</td>
          <td>${totalCell}</td>
          <td style=\"color:#16a34a;font-size:12px\">${escapeHtml(ownerLabel)}</td>
          <td style=\"font-size:12px;color:#111827\">${escapeHtml(formatTime(r.latest_detected_at))}</td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#f9fafb;\">
          <th style=\"padding:8px;color:#ca8a04\">${tt('dash.dyn.lbl.host','호스트')}</th>
          <th style=\"padding:8px;color:#2563eb\">${tt('dash.dyn.lbl.risk_score','위험점수')}</th>
          <th style=\"padding:8px;color:#2563eb\">${tt('dash.dyn.lbl.total','합계')}</th>
          <th style=\"padding:8px;color:#16a34a\">${tt('dash.dyn.lbl.owner','담당자')}</th>
          <th style=\"padding:8px;color:#111827\">${tt('dash.dyn.lbl.detected_date','탐지일')}</th>
        </tr></thead>
        <tbody>${tableRows}</tbody>
      </table>`;
      _pgApply(containerEl);
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
    let _currentVulnListHostId = null, _vulnBulkIds = [];
    function _vulnBulkBarHtml() {
      return `<div style=\"display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;padding:8px 12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px\">
        <span style=\"font-size:12px;color:#111827\">${tt('dash.dyn.bulk_selected','선택')} <b id=\"vuln_bulk_count\" style=\"color:#2563eb\">0</b>${tt('dash.dyn.cases_unit','건')}</span>
        <button onclick=\"openVulnBulkAction(\'plan\')\" style=\"width:auto;padding:5px 12px;font-size:12px;background:#dcfce7;border:1px solid #dcfce7;color:#16a34a;border-radius:6px;cursor:pointer\">${tt('dash.dyn.bulk_plan','일괄 조치 계획')}</button>
        <button onclick=\"openVulnBulkAction(\'exception\')\" style=\"width:auto;padding:5px 12px;font-size:12px;background:#fef9c3;border:1px solid #fef9c3;color:#ca8a04;border-radius:6px;cursor:pointer\">${tt('dash.dyn.bulk_exception','일괄 조치 예외')}</button>
        <span style=\"font-size:11px;color:#111827\">${tt('dash.dyn.bulk_hint','체크한 CVE에 한 번에 적용')}</span>
      </div>`;
    }
    function _updateVulnBulkCount() {
      const n = document.querySelectorAll('.vuln_bulk_cb:checked').length;
      const el = document.getElementById('vuln_bulk_count'); if (el) el.textContent = n;
      const total = document.querySelectorAll('.vuln_bulk_cb').length;
      const all = document.getElementById('vuln_bulk_all'); if (all) { all.checked = n>0 && n===total; all.indeterminate = n>0 && n<total; }
    }
    window._updateVulnBulkCount = _updateVulnBulkCount;
    function _toggleVulnBulkAll(cb) {
      document.querySelectorAll('.vuln_bulk_cb').forEach(x => { x.checked = cb.checked; });
      _updateVulnBulkCount();
    }
    window._toggleVulnBulkAll = _toggleVulnBulkAll;
    function openVulnBulkAction(mode) {
      const ids = [...document.querySelectorAll('.vuln_bulk_cb:checked')].map(cb => cb.value);
      if (!ids.length) { alert(tt('dash.dyn.bulk_none','CVE를 하나 이상 선택하세요.')); return; }
      _vulnBulkIds = ids; _vulnActionId = null; _vulnActionMode = mode; _vulnActionHostId = _currentVulnListHostId;
      document.getElementById('vuln_action_modal_meta').innerHTML = `<div><strong style=\"color:#2563eb\">${tt('dash.dyn.bulk_title','일괄 설정')}</strong> · ${ids.length}${tt('dash.dyn.cases_unit','건')} CVE</div><div style=\"margin-top:3px;color:#111827\">${tt('dash.dyn.bulk_apply_note','선택한 모든 CVE에 동일하게 적용됩니다.')}</div>`;
      document.getElementById('vuln_action_modal_status').textContent = '';
      const planSec = document.getElementById('vuln_plan_section'), exSec = document.getElementById('vuln_exception_section'), clearBtn = document.getElementById('vuln_action_modal_clear');
      if (mode === 'exception') { document.getElementById('vuln_action_modal_title').textContent = tt('dash.dyn.bulk_exception','일괄 조치 예외'); planSec.style.display='none'; exSec.style.display='flex'; clearBtn.style.display='none'; }
      else { document.getElementById('vuln_action_modal_title').textContent = tt('dash.dyn.bulk_plan','일괄 조치 계획'); planSec.style.display='flex'; exSec.style.display='none'; clearBtn.style.display='none'; }
      ['vuln_plan_text','vuln_plan_target_date','vuln_plan_updated_by','vuln_exception_until','vuln_exception_reason','vuln_exception_updated_by'].forEach(id => { const e=document.getElementById(id); if(e) e.value=''; });
      document.getElementById('vuln_action_modal').style.display='flex';
    }
    window.openVulnBulkAction = openVulnBulkAction;
    function _renderVulnListBody(hostRow) {
      const sevColor = { critical:'#dc2626', high:'#ca8a04', medium:'#ca8a04', low:'#16a34a', info:'#111827' };
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
              <div style=\"color:#16a34a;font-size:11px;font-weight:600;margin-bottom:3px\">${tt('dash.dyn.host_plan_title','호스트 단위 조치 계획')}</div>
              <div style=\"color:#111827;font-size:13px\">${escapeHtml(hostPlan)}</div>
              <div style=\"color:#111827;font-size:11px;margin-top:2px\">${hostPlanDate?tt('dash.dyn.target_date_label','목표일')+' '+escapeHtml(hostPlanDate):''}${hostPlanBy?(hostPlanDate?' · ':'')+tt('dash.dyn.author_label','작성자')+' '+escapeHtml(hostPlanBy):''}</div>
            </div>`);
        }
        if (hasHostEx) {
          parts.push(`<div style=\"flex:1;min-width:200px\">
              <div style=\"color:#ca8a04;font-size:11px;font-weight:600;margin-bottom:3px\">${tt('dash.dyn.host_exception_title','호스트 단위 조치 예외')}</div>
              <div style=\"color:#111827;font-size:13px\">~${escapeHtml(hostEx)}${tt('dash.dyn.until_suffix',' 까지')}</div>
            </div>`);
        }
        hostBanner = `<div style=\"background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:10px 14px;margin-bottom:12px;display:flex;flex-wrap:wrap;gap:18px\">
          ${parts.join('')}
          <div style=\"width:100%;color:#111827;font-size:11px;margin-top:4px\">${tt('dash.dyn.cve_priority_note','※ 아래 CVE별 계획/예외가 설정된 경우 해당 CVE에 한해 우선 적용됩니다.')}</div>
        </div>`;
      }
      if (!vulns.length) {
        return hostBanner + '<div style=\"color:#111827;text-align:center;padding:20px\">' + tt('dash.dyn.empty.vulns','취약점이 없습니다.') + '</div>';
      }
      const rows = vulns.map(v => {
        const planLabel = v.plan_text
          ? `<span style=\"color:#16a34a;font-size:12px\" title=\"${escapeHtml(v.plan_text)}\">${escapeHtml(v.plan_text.substring(0,30))}${v.plan_text.length>30?'…':''}</span>${v.plan_target_date?'<br><span style=\"color:#111827;font-size:11px\">~'+escapeHtml(v.plan_target_date)+'</span>':''}`
          : (hasHostPlan
              ? `<span style=\"color:#16a34a;font-size:11px;font-style:italic\">${tt('dash.dyn.host_level_applied','호스트 단위 적용')}</span>${hostPlanDate?'<br><span style=\"color:#111827;font-size:11px\">~'+escapeHtml(hostPlanDate)+'</span>':''}`
              : '<span style=\"color:#111827;font-size:11px\">' + tt('dash.dyn.not_set','미설정') + '</span>');
        const exLabel = v.exception_until
          ? `<span style=\"color:#ca8a04;font-size:12px\">~${escapeHtml(v.exception_until)}</span>${v.exception_reason?'<br><span style=\"color:#111827;font-size:11px\" title=\"'+escapeHtml(v.exception_reason)+'\">'+escapeHtml(v.exception_reason.substring(0,24))+(v.exception_reason.length>24?'…':'')+'</span>':''}`
          : (hasHostEx
              ? `<span style=\"color:#ca8a04;font-size:11px;font-style:italic\">${tt('dash.dyn.host_level_applied','호스트 단위 적용')}</span><br><span style=\"color:#111827;font-size:11px\">~${escapeHtml(hostEx)}</span>`
              : '<span style=\"color:#111827;font-size:11px\">' + tt('dash.dyn.none','없음') + '</span>');
        const versionStr = v.installed_version
          ? `${escapeHtml(v.installed_version)}${v.fixed_version?' → <span style=\"color:#16a34a\">'+escapeHtml(v.fixed_version)+'</span>':''}`
          : '-';
        const rk = (_riskSummary.map || {})[v.vuln_id];
        const riskCell = rk
          ? `${_riskBadge(rk.level, true)}${rk.assessed?'':`<div style=\"color:#111827;font-size:9px;margin-top:2px\">${tt('dash.risk.badge_unassessed','미평가')}</div>`}`
          : `<span style=\"color:#111827;font-size:11px\">-</span>`;
        const riskTd = showRisk
          ? `<td style=\"padding:6px 8px;text-align:center;white-space:nowrap\">${riskCell}<br><button onclick=\"openRiskModal('${escapeHtml(v.vuln_id)}')\" style=\"font-size:10px;padding:1px 6px;background:#dbeafe;border:1px solid #dbeafe;border-radius:3px;color:#2563eb;cursor:pointer;margin-top:3px\">${tt('dash.risk.btn','평가')}</button></td>`
          : '';
        return `<tr>
          <td style=\"padding:6px 8px;text-align:center\"><input type=\"checkbox\" class=\"vuln_bulk_cb\" value=\"${escapeHtml(v.vuln_id)}\" onclick=\"_updateVulnBulkCount()\" style=\"cursor:pointer\"></td>
          <td style=\"padding:6px 8px\"><strong style=\"color:#2563eb\">${escapeHtml(v.cve||'-')}</strong></td>
          <td style=\"padding:6px 8px;text-align:center\"><span style=\"color:${sevColor[v.severity]||'#111827'};font-weight:700;text-transform:uppercase;font-size:11px\">${escapeHtml(v.severity)}</span></td>
          ${riskTd}
          <td style=\"padding:6px 8px;font-size:12px\">${escapeHtml(v.package_name||'-')}</td>
          <td style=\"padding:6px 8px;font-size:12px;color:#111827\">${versionStr}</td>
          <td style=\"padding:6px 8px;font-size:11px;color:#111827\">${escapeHtml(formatTime(v.detected_at))}</td>
          <td style=\"padding:6px 8px;min-width:140px\">${planLabel}<br><button onclick=\"openVulnActionModal('${escapeHtml(v.vuln_id)}','plan')\" style=\"font-size:10px;padding:1px 6px;background:#dcfce7;border:1px solid #dcfce7;border-radius:3px;color:#16a34a;cursor:pointer;margin-top:3px\">${tt('dash.dyn.edit_plan_btn','조치 계획')}</button></td>
          <td style=\"padding:6px 8px;min-width:140px\">${exLabel}<br><button onclick=\"openVulnActionModal('${escapeHtml(v.vuln_id)}','exception')\" style=\"font-size:10px;padding:1px 6px;background:#fef9c3;border:1px solid #fef9c3;border-radius:3px;color:#ca8a04;cursor:pointer;margin-top:3px\">${tt('dash.dyn.edit_exception_btn','조치 예외')}</button></td>
        </tr>`;
      }).join('');
      return hostBanner + _vulnBulkBarHtml() + `<table style=\"width:100%;border-collapse:collapse;font-size:12px\">
        <thead><tr style=\"background:#f9fafb\">
          <th style=\"padding:8px;width:30px;text-align:center\"><input type=\"checkbox\" id=\"vuln_bulk_all\" onclick=\"_toggleVulnBulkAll(this)\" style=\"cursor:pointer\"></th>
          <th style=\"padding:8px;color:#2563eb;text-align:left\">CVE</th>
          <th style=\"padding:8px;color:#ca8a04\">${tt('dash.dyn.lbl.severity','심각도')}</th>
          ${showRisk?`<th style=\"padding:8px;color:#2563eb\">${tt('dash.risk.col','위험등급')}</th>`:''}
          <th style=\"padding:8px;color:#111827;text-align:left\">${tt('dash.dyn.lbl.package','패키지')}</th>
          <th style=\"padding:8px;color:#111827;text-align:left\">${tt('dash.dyn.lbl.install_recommend','설치 → 권장')}</th>
          <th style=\"padding:8px;color:#111827\">${tt('dash.dyn.lbl.detected_date','탐지일')}</th>
          <th style=\"padding:8px;color:#16a34a;text-align:left\">${tt('dash.dyn.lbl.action_plan','조치 계획')}</th>
          <th style=\"padding:8px;color:#ca8a04;text-align:left\">${tt('dash.dyn.lbl.action_exception','조치 예외')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function openVulnListModal(hostId) {
      const row = (_assetCache.trivy || []).find(r => r.host_id === hostId);
      if (!row) { alert(tt('dash.dyn.host_not_found','호스트 데이터를 찾을 수 없습니다. 자산 새로고침 후 다시 시도해 주세요.')); return; }
      _currentVulnListHostId = hostId;
      document.getElementById('vuln_list_modal_title').textContent = `${row.hostname}${tt('dash.dyn.vuln_count_suffix',' 취약점 ')}${row.total}${tt('dash.dyn.unit_count','건')}`;
      document.getElementById('vuln_list_modal_subtitle').textContent =
        `Critical ${row.critical} · High ${row.high} · Medium ${row.medium} · Low ${row.low}`;
      document.getElementById('vuln_list_modal_body').innerHTML = _renderVulnListBody(row);
      _pgApply(document.getElementById('vuln_list_modal_body'));
      document.getElementById('vuln_list_modal').style.display = 'flex';
    }
    function closeVulnListModal() { document.getElementById('vuln_list_modal').style.display = 'none'; }

    /* ── 호스트 단위 조치 계획 안내 (CVE별 상세 계획 존재 시) ──────────── */
    function showVulnPlansNotice(hostId, hostname, count) {
      document.getElementById('vuln_plans_notice_body').innerHTML =
        `<div style=\"margin-bottom:10px\"><strong style=\"color:#ca8a04\">${escapeHtml(hostname)}</strong> 호스트에는 이미 <strong style=\"color:#16a34a\">CVE별 상세 조치 계획/예외</strong>가 ${count}건 설정되어 있습니다.</div>
         <div style=\"color:#111827\">호스트 단위 일괄 계획 대신 <strong style=\"color:#2563eb\">합계 탭</strong>(예: <span style=\"background:#e5e7eb;color:#2563eb;padding:1px 8px;border-radius:4px\">N 건</span> 버튼)에서 각 CVE별 계획을 확인·수정해 주세요.</div>`;
      const openBtn = document.getElementById('vuln_plans_notice_open_list');
      openBtn.onclick = () => { closeVulnPlansNotice(); openVulnListModal(hostId); };
      document.getElementById('vuln_plans_notice_modal').style.display = 'flex';
    }
    function closeVulnPlansNotice() { document.getElementById('vuln_plans_notice_modal').style.display = 'none'; }

    /* ── 호스트 단위 조치 예외 안내 (CVE별 상세 예외 존재 시) ──────────── */
    function showVulnExceptionsNotice(hostId, hostname, count) {
      document.getElementById('vuln_plans_notice_body').innerHTML =
        `<div style=\"margin-bottom:10px\"><strong style=\"color:#ca8a04\">${escapeHtml(hostname)}</strong> 호스트에는 이미 <strong style=\"color:#ca8a04\">CVE별 상세 조치 예외</strong>가 설정되어 있습니다. (총 ${count}건의 CVE별 계획/예외)</div>
         <div style=\"color:#111827\">호스트 단위 일괄 예외 대신 <strong style=\"color:#2563eb\">합계 탭</strong>(예: <span style=\"background:#e5e7eb;color:#2563eb;padding:1px 8px;border-radius:4px\">N 건</span> 버튼)에서 각 CVE별 예외를 확인·수정해 주세요.</div>`;
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
      subtitleEl.innerHTML = tt('dash.dyn.pdca.do_subtitle','총 {n}건 조치 필요 (기한 초과 {o}건) · ').replace('{n}','<strong style=\"color:#ca8a04\">'+items.length+'</strong>').replace('{o}','<strong style=\"color:#dc2626\">'+overdue+'</strong>')
        + `<span style=\"color:#2563eb\">${tt('dash.dyn.pdca.control','통제')} ${ps.control_check||0}</span> ·
        <span style=\"color:#ca8a04\">Trivy ${ps.trivy||0}</span> ·
        <span style=\"color:#dc2626\">Alert ${ps.alert||0}</span>
        <button onclick=\"openCsvPreview({title:tt(\'dash.pdca.pending_csv_preview_title\',\'PDCA 미조치 CSV 미리보기\'),filename:\'mori-pdca-pending.csv\',url:\'/compliance/pdca/pending.csv\'})\" style=\"margin-left:12px;background:#f9fafb;border:1px solid #e5e7eb;color:#2563eb;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer\">CSV</button>`;
      if (items.length === 0) {
        bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#111827;padding:24px;text-align:center\">' + tt('dash.dyn.pdca.do_no_items','조치가 필요한 항목이 없습니다. ') + '</div>';
      } else {
        const sourceBadge = (s) => {
          if (s === 'trivy') return '<span style=\"background:#fef9c3;color:#ca8a04;padding:2px 6px;border-radius:4px;font-size:10px\">Trivy</span>';
          if (s === 'alert') return '<span style=\"background:#fee2e2;color:#dc2626;padding:2px 6px;border-radius:4px;font-size:10px\">Alert</span>';
          return '<span style=\"background:#f9fafb;color:#2563eb;padding:2px 6px;border-radius:4px;font-size:10px\">' + tt('dash.dyn.pdca.control_badge','통제') + '</span>';
        };
        bodyEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
          <thead><tr style=\"color:#111827;border-bottom:1px solid #e5e7eb\">
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
              ? '<span style=\"background:#fee2e2;color:#dc2626;padding:2px 8px;border-radius:999px;font-size:11px\">Fail</span>'
              : '<span style=\"background:#fef9c3;color:#ca8a04;padding:2px 8px;border-radius:999px;font-size:11px\">Warning</span>';
            const due = i.remediation_due_at ? new Date(i.remediation_due_at).toLocaleDateString('ko-KR') : '-';
            const overdueFlag = i.overdue ? ' ' : '';
            return `<tr style=\"border-bottom:1px solid #e5e7eb\">
              <td style=\"text-align:center;padding:6px 8px\">${sourceBadge(i.source)}</td>
              <td style=\"padding:6px 8px;color:#2563eb;font-weight:600\">${escapeHtml(i.control_id)}</td>
              <td style=\"padding:6px 8px;color:#111827\">${escapeHtml(i.entity_type)}:${escapeHtml(i.entity_id)}</td>
              <td style=\"text-align:center;padding:6px 8px\">${statusBadge}</td>
              <td style=\"padding:6px 8px;color:#111827\">${escapeHtml(i.owner) || '-'}</td>
              <td style=\"padding:6px 8px;color:#111827\">${due}${overdueFlag}</td>
              <td style=\"padding:6px 8px;color:#111827\">${escapeHtml(i.note) || ''}</td>
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
      _vulnActionId = vulnId; _vulnActionMode = mode; _vulnBulkIds = [];
      // 현재 보고 있던 host row 찾기 (모달 닫혀도 list 갱신용)
      let foundVuln = null, foundHost = null;
      for (const row of (_assetCache.trivy || [])) {
        const v = (row.vulns || []).find(x => x.vuln_id === vulnId);
        if (v) { foundVuln = v; foundHost = row; break; }
      }
      _vulnActionHostId = foundHost ? foundHost.host_id : null;
      const meta = foundVuln
        ? `<div><strong style=\"color:#2563eb\">${escapeHtml(foundVuln.cve||vulnId)}</strong> · <span style=\"color:#ca8a04;text-transform:uppercase\">${escapeHtml(foundVuln.severity)}</span></div>
           <div style=\"margin-top:3px\">${escapeHtml(foundVuln.package_name||'-')} ${foundVuln.installed_version?'('+escapeHtml(foundVuln.installed_version)+')':''} ${foundVuln.fixed_version?'→ <span style=\"color:#16a34a\">'+escapeHtml(foundVuln.fixed_version)+'</span>':''}</div>
           <div style=\"margin-top:3px;color:#111827\">호스트: ${escapeHtml(foundHost?foundHost.hostname:'-')}</div>`
        : `<div>vuln_id: ${escapeHtml(vulnId)}</div>`;
      document.getElementById('vuln_action_modal_meta').innerHTML = meta;
      document.getElementById('vuln_action_modal_status').textContent = '';
      const planSec = document.getElementById('vuln_plan_section');
      const exSec = document.getElementById('vuln_exception_section');
      const clearBtn = document.getElementById('vuln_action_modal_clear');
      if (mode === 'exception') {
        document.getElementById('vuln_action_modal_title').textContent = tt('dash.dyn.vuln_action.exception_title','조치 예외 설정');
        planSec.style.display = 'none';
        exSec.style.display = 'flex';
        clearBtn.style.display = (foundVuln && foundVuln.exception_until) ? 'inline-block' : 'none';
      } else {
        document.getElementById('vuln_action_modal_title').textContent = tt('dash.dyn.vuln_action.plan_title','조치 계획 작성');
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

    /* ── 위험성 평가 (R-4) ─────────────────────────────────────────────── */
    const RISK_LEVEL_COLORS = { '매우높음':'#dc2626', '높음':'#ca8a04', '중간':'#ca8a04', '낮음':'#16a34a' };
    let _riskSummary = { items: [], map: {}, matrix: [[0,0,0],[0,0,0],[0,0,0]], by_level: {}, total: 0, assessed: 0 };
    let _riskModalVulnId = null;
    let _riskDoa = 4;  // 위험 수용 기준(DoA) 점수 1~9 /settings/risk 에서 로드

    // 점수 중심 배지: 큰 숫자로 'N점' + 등급 라벨(보조). score 생략 시 등급만.
    function _riskBadge(level, small, score) {
      const c = RISK_LEVEL_COLORS[level] || '#111827';
      const scorePart = (score != null && score !== '')
        ? `<strong style=\"font-size:${small?'12px':'14px'}\">${escapeHtml(String(score))}${tt('dash.risk.pt','점')}</strong> · `
        : '';
      return `<span style=\"display:inline-flex;align-items:center;gap:2px;background:${c}22;border:1px solid ${c};color:${c};font-weight:700;border-radius:6px;padding:${small?'1px 7px':'2px 10px'};font-size:${small?'11px':'12px'}\">${scorePart}${escapeHtml(level||'-')}</span>`;
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

    // ── B: DoA(수용가능 위험 기준) 로드/저장 ──────────────────────────────────
    async function loadRiskDoa() {
      try {
        const res = await fetch('/settings/risk');
        if (!res.ok) return;
        const d = await res.json();
        if (d.doa != null) _riskDoa = d.doa;
        _renderDoaCtl();
      } catch (e) { /* best-effort */ }
    }
    window.loadRiskDoa = loadRiskDoa;

    function _renderDoaCtl() {
      const el = document.getElementById('risk_doa_ctl');
      if (!el) return;
      const canEdit = (_currentUserRole === 'admin');
      const label = tt('dash.risk.doa_label','위험 수용 기준(DoA)');
      const help = tt('dash.risk.doa_help','이 점수(1~9) 이하 위험은 기본 수용가능으로 분류됩니다.');
      if (canEdit) {
        let opts = '';
        for (let i = 1; i <= 9; i++) opts += `<option value=\"${i}\"${i===_riskDoa?' selected':''}>${i}${tt('dash.risk.pt','점')}</option>`;
        el.innerHTML = `<div style=\"display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:8px 12px\">
          <span style=\"font-size:12px;color:#16a34a;font-weight:700\">${label}</span>
          <select id=\"doa_input\" style=\"background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:4px 8px;font-size:13px\">${opts}</select>
          <button onclick=\"saveRiskDoa()\" class=\"secondary\" style=\"width:auto;padding:4px 12px;font-size:12px\">${tt('dash.risk.doa_save','저장')}</button>
          <span id=\"doa_status\" style=\"font-size:11px;color:#111827\"></span>
          <span style=\"font-size:11px;color:#111827;flex-basis:100%\">${help}</span>
        </div>`;
      } else {
        el.innerHTML = `<div style=\"font-size:12px;color:#111827\">${label}: <strong style=\"color:#16a34a\">${_riskDoa}${tt('dash.risk.pt','점')}</strong> ${tt('dash.risk.doa_readonly','이하 기본 수용')}</div>`;
      }
    }

    async function saveRiskDoa() {
      const sel = document.getElementById('doa_input');
      const status = document.getElementById('doa_status');
      if (!sel) return;
      const val = parseInt(sel.value, 10);
      try {
        const res = await fetch('/settings/risk', {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ doa: val }),
        });
        if (!res.ok) { if (status) status.textContent = tt('dash.risk.doa_err','저장 실패'); return; }
        const d = await res.json();
        _riskDoa = d.doa;
        if (status) { status.textContent = tt('dash.risk.doa_ok','저장됨'); status.style.color = '#16a34a'; }
        loadRiskMatrix();  // 매트릭스 수용 셀 갱신
      } catch (e) { if (status) status.textContent = tt('dash.risk.doa_err','저장 실패'); }
    }
    window.saveRiskDoa = saveRiskDoa;

    // 위험성 매트릭스는 더블클릭 팝업 모달로 열림 (openRiskMatrixModal)
    function openRiskMatrixModal() {
      const modal = document.getElementById('risk_matrix_modal');
      if (!modal) return;
      modal.style.display = 'flex';
      loadRiskMatrix();  // 최신 데이터로 매트릭스 갱신
    }
    function closeRiskMatrixModal() {
      const modal = document.getElementById('risk_matrix_modal');
      if (modal) modal.style.display = 'none';
    }
    window.openRiskMatrixModal = openRiskMatrixModal;
    window.closeRiskMatrixModal = closeRiskMatrixModal;

    /* 매트릭스 셀/칩 클릭 → 해당 버킷의 실제 취약점·호스트 목록 모달 */
    function _riskBucketRows(items) {
      if (!items.length) return `<div class=\"empty\" style=\"color:#111827;padding:16px\">${tt('dash.dyn.empty.vulns','취약점이 없습니다.')}</div>`;
      const rows = items.map(it => `<tr>
        <td style=\"padding:6px 8px\">${_riskBadge(it.level, true, it.score)}</td>
        <td style=\"padding:6px 8px\"><strong style=\"color:#2563eb\">${escapeHtml(it.cve)}</strong></td>
        <td style=\"padding:6px 8px;color:#111827;font-size:12px\">${escapeHtml(it.hostname)}</td>
        <td style=\"padding:6px 8px;text-align:center\"><span style=\"color:${it.severity==='critical'?'#dc2626':'#ca8a04'};text-transform:uppercase;font-size:11px\">${escapeHtml(it.severity)}</span></td>
        <td style=\"padding:6px 8px;text-align:center;font-size:11px;color:#111827\">${it.doa_accept?`<span style=\"background:#16a34a22;border:1px solid #16a34a;color:#16a34a;border-radius:5px;padding:1px 6px;font-weight:700\">${tt('dash.risk.doa_accept','기본수용')}</span>`:(it.assessed?tt('dash.risk.assessed','평가됨'):tt('dash.risk.badge_unassessed','미평가'))}</td>
        <td style=\"padding:6px 8px;text-align:center\">${_canAssessRisk()?`<button onclick=\"closeRiskBucketModal();openRiskModal('${escapeHtml(it.vuln_id)}')\" style=\"font-size:10px;padding:2px 8px;background:#dbeafe;border:1px solid #dbeafe;border-radius:4px;color:#2563eb;cursor:pointer\">${tt('dash.risk.btn','평가')}</button>`:''}</td>
      </tr>`).join('');
      return `<table style=\"width:100%;border-collapse:collapse;font-size:12px\"><thead><tr style=\"background:#f9fafb\">
        <th style=\"padding:8px;color:#2563eb\">${tt('dash.risk.col','위험등급')}</th><th style=\"padding:8px;color:#2563eb;text-align:left\">CVE</th>
        <th style=\"padding:8px;color:#111827;text-align:left\">${tt('dash.risk.prov.host','자산')}</th><th style=\"padding:8px;color:#ca8a04\">${tt('dash.dyn.lbl.severity','심각도')}</th>
        <th style=\"padding:8px;color:#111827\">${tt('dash.risk.status','상태')}</th><th style=\"padding:8px\"></th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    function _openRiskBucket(pred, title) {
      const items = (_riskSummary.items || []).filter(pred);
      document.getElementById('risk_bucket_modal_title').textContent = `${title} (${items.length})`;
      document.getElementById('risk_bucket_modal_body').innerHTML = _riskBucketRows(items);
      document.getElementById('risk_bucket_modal').style.display = 'flex';
    }
    function openRiskLevelModal(level) { _openRiskBucket(it => it.level === level, `${tt('dash.risk.bucket_title','위험 상세')} · ${level}`); }
    function openRiskCellModal(impact, likelihood) { _openRiskBucket(it => it.impact === impact && it.likelihood === likelihood, `${tt('dash.risk.bucket_title','위험 상세')} · ${_levelForScore(impact*likelihood)}`); }
    function closeRiskBucketModal() { const m=document.getElementById('risk_bucket_modal'); if(m) m.style.display='none'; }
    window.openRiskLevelModal = openRiskLevelModal;
    window.openRiskCellModal = openRiskCellModal;
    window.closeRiskBucketModal = closeRiskBucketModal;

    function _levelForScore(s) { return s>=9?'매우높음':s>=5?'높음':s>=3?'중간':'낮음'; }

    function renderRiskMatrix(data) {
      const box = document.getElementById('risk_matrix_box');
      const assessedEl = document.getElementById('risk_matrix_assessed');
      if (data.doa != null) _riskDoa = data.doa;
      if (assessedEl) {
        const acc = (data.accepted != null)
          ? ` · ${tt('dash.risk.accepted','기본수용')} ${data.accepted}` : '';
        assessedEl.textContent = tt('dash.risk.assessed_of','{a}/{t} 평가 완료').replace('{a}', data.assessed||0).replace('{t}', data.total||0) + acc;
      }
      const m = data.matrix || [[0,0,0],[0,0,0],[0,0,0]];
      const impactByRow = [3,2,1], likeByCol = [1,2,3];
      const impLabel = {3:'상',2:'중',1:'하'}, likeLabel = {1:'하',2:'중',3:'상'};
      const header = `<tr><td></td>${likeByCol.map(l=>`<td style=\"text-align:center;color:#111827;font-size:12px;padding-bottom:2px\">${likeLabel[l]}</td>`).join('')}</tr>`;
      let cells = '';
      for (let r=0;r<3;r++){
        let rowCells = `<td style=\"padding:6px 8px;color:#111827;font-size:12px;text-align:right;white-space:nowrap\">${impLabel[impactByRow[r]]}</td>`;
        for (let c=0;c<3;c++){
          const imp = impactByRow[r], lk = likeByCol[c];
          const cellScore = imp*lk;
          const lvl = _levelForScore(cellScore);
          const col = RISK_LEVEL_COLORS[lvl];
          const n = (m[r] && m[r][c]) || 0;
          const accepted = cellScore <= _riskDoa;  // DoA 이하 = 기본 수용 셀
          const click = n ? `onclick=\"openRiskCellModal(${imp},${lk})\"` : '';
          const accRing = accepted ? 'box-shadow:inset 0 0 0 2px #16a34a99;' : '';
          rowCells += `<td style=\"padding:0\"><div ${click} title=\"${tt('dash.risk.score','위험점수')} ${cellScore}\" style=\"margin:3px;border-radius:6px;background:${col}${n?'33':'12'};border:1px solid ${col}${n?'':'44'};${accRing}width:60px;min-height:56px;display:flex;flex-direction:column;align-items:center;justify-content:center;${n?'cursor:pointer':''}\">
            <div style=\"font-size:9px;color:${col}cc;font-weight:700\">${cellScore}${tt('dash.risk.pt','점')}</div>
            <div style=\"font-size:18px;font-weight:800;color:${n?col:'#e5e7eb'}\">${n}</div>
            <div style=\"font-size:8px;color:${accepted?'#16a34a':col+'aa'}\">${accepted?tt('dash.risk.doa_accept','기본수용'):lvl}</div></div></td>`;
        }
        cells += `<tr>${rowCells}</tr>`;
      }
      const order = ['매우높음','높음','중간','낮음'];
      const chips = order.map(lv => { const n=(data.by_level&&data.by_level[lv])||0; return `<span onclick=\"${n?`openRiskLevelModal('${lv}')`:''}\" style=\"display:inline-flex;align-items:center;gap:5px;margin:0 8px 8px 0;font-size:12px;padding:4px 10px;border:1px solid ${RISK_LEVEL_COLORS[lv]}44;border-radius:8px;background:${RISK_LEVEL_COLORS[lv]}12;${n?'cursor:pointer':'opacity:.5'}\"><span style=\"width:10px;height:10px;border-radius:2px;background:${RISK_LEVEL_COLORS[lv]};display:inline-block\"></span>${lv} <strong style=\"color:${RISK_LEVEL_COLORS[lv]}\">${n}</strong></span>`; }).join('');
      const doaNote = `<div style=\"margin-top:8px;font-size:11px;color:#111827\">${tt('dash.risk.doa_note','DoA 기준: {n}점 이하는 기본 수용가능').replace('{n}', _riskDoa)}</div>`;
      box.innerHTML = `<div style=\"display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start\">
        <div>
          <table style=\"border-collapse:collapse\">${header}${cells}</table>
          <div style=\"text-align:center;color:#111827;font-size:11px;margin-top:4px\">${tt('dash.risk.likelihood','발생가능성')} →　　↑ ${tt('dash.risk.impact','영향도')}</div>
        </div>
        <div style=\"flex:1;min-width:220px\"><div>${chips}</div>${doaNote}</div>
      </div>`;
    }

    function _riskRecalc() {
      const imp = parseInt(document.getElementById('risk_impact').value,10)||2;
      const lk = parseInt(document.getElementById('risk_likelihood').value,10)||1;
      const s = imp*lk, level = _levelForScore(s);
      const gradeEl = document.getElementById('risk_modal_grade');
      if (!gradeEl) return;
      const note = gradeEl.dataset.suggested === '1' ? ` <span style=\"color:#2563eb;font-size:11px\">${tt('dash.risk.suggested_note','자동 제안 등급 (저장 전)')}</span>` : '';
      gradeEl.innerHTML = `${_riskBadge(level)} <span style=\"color:#111827;font-size:13px;margin-left:6px\">${tt('dash.risk.impact','영향도')} ${imp} × ${tt('dash.risk.likelihood','발생가능성')} ${lk} = <strong style=\"color:#111827\">${s}</strong></span>${note}`;
    }
    window._riskRecalc = _riskRecalc;

    async function openRiskModal(vulnId) {
      _riskModalVulnId = vulnId;
      document.getElementById('risk_modal_status').textContent = '';
      const it = _riskSummary.map[vulnId];
      document.getElementById('risk_modal_meta').innerHTML = it
        ? `<strong style=\"color:#2563eb\">${escapeHtml(it.cve)}</strong> · <span style=\"color:#ca8a04;text-transform:uppercase\">${escapeHtml(it.severity)}</span> · <span style=\"color:#111827\">${escapeHtml(it.hostname)}</span>`
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
          const row = (k,v) => `<div style=\"display:flex;justify-content:space-between;gap:10px;font-size:12px;padding:2px 0\"><span style=\"color:#111827\">${k}</span><span style=\"color:#111827;text-align:right\">${escapeHtml(String(v==null||v===''?'-':v))}</span></div>`;
          const impSrc = p.importance_source === 'owner' ? tt('dash.risk.prov.owner',' (담당자 지정)') : tt('dash.risk.prov.auto',' (자동분류)');
          document.getElementById('risk_provenance').innerHTML =
            `<div style=\"color:#2563eb;font-weight:700;font-size:12px;margin-bottom:6px\">${tt('dash.risk.provenance_title','산정 근거 (관리자 전용)')}</div>`
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
        if (!res.ok) { statusEl.textContent = `${tt('dash.risk.save_fail','위험성 평가 저장 실패')}: HTTP ${res.status}`; return; }
        statusEl.textContent = tt('dash.risk.saved','위험성 평가 저장됨');
        await loadRiskMatrix();
        const listModal = document.getElementById('vuln_list_modal');
        if (listModal && listModal.style.display === 'flex' && _vulnActionHostId != null) {
          const row = (_assetCache.trivy || []).find(r => r.host_id === _vulnActionHostId);
          if (row) document.getElementById('vuln_list_modal_body').innerHTML = _renderVulnListBody(row);
          _pgApply(document.getElementById('vuln_list_modal_body'));
        }
        setTimeout(closeRiskModal, 700);
      } catch(e) {
        statusEl.textContent = `${tt('dash.risk.save_fail','위험성 평가 저장 실패')}: ${e.message}`;
      }
    }
    window.saveRiskAssessment = saveRiskAssessment;

    /* 프로필 메뉴 → 내 서버 바로가기 */
    function shortcutMyServers() {
      const menu = document.getElementById('account_menu');
      if (menu) menu.style.display = 'none';
      switchTab('assets');
      switchAssetTab('mine');
    }
    window.shortcutMyServers = shortcutMyServers;

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
      document.getElementById('owner_modal_status').style.color = '#111827';
      // PC 자산은 카테고리 숨김, 서버만 표시
      const isServer = assetType === 'server';
      const isTrivy = assetType === 'trivy';
      document.getElementById('owner_modal_category_row').style.display = isServer ? '' : 'none';
      // 중요도 재정의는 서버 자산에서만 노출
      document.getElementById('owner_modal_importance_row').style.display = isServer ? '' : 'none';
      // 처리 예외 기한은 Trivy에서만 필요
      document.getElementById('owner_modal_exception_row').style.display = isTrivy ? '' : 'none';
      const titleMap = { server: tt('dash.dyn.asset_detail.server','서버 자산 상세페이지'), pc: tt('dash.dyn.asset_detail.pc','PC 자산 상세페이지'), trivy: tt('dash.dyn.asset_detail.trivy','취약점 상세페이지') };
      document.getElementById('owner_modal_title').textContent = `${titleMap[assetType] || tt('dash.dyn.asset_detail.default','자산 수정')} ${hostname}`;
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
          statusEl.style.color = '#16a34a';
          statusEl.textContent = tt('dash.dyn.saved','저장되었습니다.');
          setTimeout(() => { closeOwnerModal(); loadAssets(); }, 800);
        } catch(e) {
          statusEl.style.color = '#dc2626';
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
        const ids = (_vulnBulkIds && _vulnBulkIds.length && !_vulnActionId) ? _vulnBulkIds : (_vulnActionId ? [_vulnActionId] : []);
        if (!ids.length) return;
        const statusEl = document.getElementById('vuln_action_modal_status');
        statusEl.style.color = '#111827'; statusEl.textContent = tt('dash.dyn.saving','저장 중...');
        const _path = _vulnActionMode === 'exception' ? 'exception' : 'plan';
        const _body = _vulnActionMode === 'exception'
          ? { exception_until: document.getElementById('vuln_exception_until').value, exception_reason: document.getElementById('vuln_exception_reason').value, exception_updated_by: document.getElementById('vuln_exception_updated_by').value || tt('dash.dyn.operator','운영자') }
          : { plan_text: document.getElementById('vuln_plan_text').value, plan_target_date: document.getElementById('vuln_plan_target_date').value, plan_updated_by: document.getElementById('vuln_plan_updated_by').value || tt('dash.dyn.operator','운영자') };
        try {
          let okc = 0, failc = 0;
          for (const id of ids) {
            const res = await fetch(`/vulnerabilities/${encodeURIComponent(id)}/${_path}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(_body) });
            if (res.ok) okc++; else failc++;
          }
          if (failc) throw new Error(`${okc}${tt('dash.dyn.cases_unit','건')} ${tt('dash.dyn.bulk_ok','성공')}, ${failc}${tt('dash.dyn.cases_unit','건')} ${tt('dash.dyn.bulk_fail','실패')}`);
          const hostId = _vulnActionHostId; _vulnBulkIds = [];
          closeVulnActionModal();
          await loadAssets();
          if (hostId) openVulnListModal(hostId);
        } catch(err) {
          statusEl.style.color = '#dc2626';
          statusEl.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${err.message}`;
        }
      });

      const vulnClearBtn = document.getElementById('vuln_action_modal_clear');
      if (vulnClearBtn) vulnClearBtn.addEventListener('click', async () => {
        if (!_vulnActionId) return;
        if (!confirm(tt('dash.dyn.confirm_clear_exception','이 취약점의 예외 처리를 해제하시겠습니까?'))) return;
        const statusEl = document.getElementById('vuln_action_modal_status');
        statusEl.style.color = '#111827'; statusEl.textContent = tt('dash.dyn.clearing','해제 중...');
        try {
          const res = await fetch(`/vulnerabilities/${encodeURIComponent(_vulnActionId)}/exception`, { method: 'DELETE' });
          if (!res.ok) throw new Error(res.status);
          const hostId = _vulnActionHostId;
          closeVulnActionModal();
          await loadAssets();
          if (hostId) openVulnListModal(hostId);
        } catch(err) {
          statusEl.style.color = '#dc2626';
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
        renderAssetTable('fleet', _assetCache.fleet, document.getElementById('fleet_table'));
        // Zabbix summary
        document.getElementById('zabbix_total').textContent = data.zabbix?.total ?? '-';
        document.getElementById('zabbix_online').textContent = data.zabbix?.online ?? '-';
        document.getElementById('zabbix_offline').textContent = data.zabbix?.offline ?? '-';
        renderAssetTable('zabbix', _assetCache.zabbix, document.getElementById('zabbix_table'));
        // Populate Zabbix category dropdown
        _populateZabbixCategories(_assetCache.zabbix);
        // Populate team dropdowns (Fleet/Zabbix)
        _populateTeams('zabbix_search_team', _assetCache.zabbix);
        _populateTeams('fleet_search_team', _assetCache.fleet);
        // Trivy summary
        document.getElementById('trivy_affected_hosts').textContent = data.trivy?.affected_hosts ?? '-';
        document.getElementById('trivy_total_vulns').textContent = data.trivy?.total_vulns ?? '-';
        document.getElementById('trivy_critical').textContent = data.trivy?.critical ?? '-';
        document.getElementById('trivy_high').textContent = data.trivy?.high ?? '-';
        _trivyFiltered = _assetCache.trivy;
        renderTrivyTable(_assetCache.trivy, document.getElementById('trivy_table'));
        loadRiskDoa();
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
    /* 팀 드롭다운 채우기 (Fleet/Zabbix 공통) 자산의 team 값에서 유니크 추출 */
    function _populateTeams(selId, hosts) {
      const sel = document.getElementById(selId);
      if (!sel) return;
      const cur = sel.value;
      const teams = [...new Set(hosts.map(h => (h.team || '').trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'ko'));
      while (sel.options.length > 1) sel.remove(1);
      teams.forEach(t => { const o = document.createElement('option'); o.value = t; o.textContent = t; sel.appendChild(o); });
      if (cur && teams.includes(cur)) sel.value = cur;
    }

    function _updateSearchCount(tab, shown, total) {
      const el = document.getElementById(`${tab}_search_count`);
      if (el) el.textContent = shown === total ? tt('dash.dyn.count_total','총 {total}건').replace('{total}',total) : tt('dash.dyn.count_partial','{shown} / {total}건').replace('{shown}',shown).replace('{total}',total);
    }

    /* 프로필 담당 서버(assigned_servers) 또는 담당자(이름) 일치 = 내 자산 */
    function _isMyAsset(h) {
      const assigned = new Set((_currentProfile.assigned_servers || []).map(s => String(s).toLowerCase()));
      const myName = (_currentProfile.display_name || '').trim().toLowerCase();
      if (assigned.has(String(h.hostname || '').toLowerCase())) return true;
      if (myName && String(h.owner || '').trim().toLowerCase() === myName) return true;
      return false;
    }
    window._isMyAsset = _isMyAsset;
    function filterAssetTable(tab) {
      const hostnameVal = (document.getElementById(`${tab}_search_hostname`)?.value || '').trim().toLowerCase();
      if (tab === 'fleet' || tab === 'zabbix') {
        const statusVal = document.getElementById(`${tab}_search_status`)?.value || '';
        const teamVal = document.getElementById(`${tab}_search_team`)?.value || '';
        const mineOnly = document.getElementById(`${tab}_search_mine`)?.checked;
        const catVal = tab === 'zabbix' ? (document.getElementById('zabbix_search_category')?.value || '') : '';
        const filtered = _assetCache[tab].filter(h => {
          if (hostnameVal && !h.hostname.toLowerCase().includes(hostnameVal)) return false;
          if (statusVal && h.status !== statusVal) return false;
          if (teamVal && (h.team || '') !== teamVal) return false;
          if (catVal && h.category !== catVal) return false;
          if (mineOnly && !_isMyAsset(h)) return false;
          return true;
        });
        renderAssetTable(tab, filtered, document.getElementById(`${tab}_table`));
        _updateSearchCount(tab, filtered.length, _assetCache[tab].length);
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
        openCsvPreview({
          title: tt('dash.modal.assets_csv_preview_title','자산 CSV 미리보기'),
          filename: `mori-trivy-filtered-${new Date().toISOString().slice(0,10)}.csv`,
          text: csvRows.join('\\n'),
        });
      } else {
        openCsvPreview({
          title: tt('dash.modal.assets_csv_preview_title','자산 CSV 미리보기'),
          filename: `mori-${source}-${new Date().toISOString().slice(0,10)}.csv`,
          url: `/assets?format=csv&source=${encodeURIComponent(source)}`,
        });
      }
    }

    /* ── On-demand 수집 (새로고침 버튼) ──────────────────────────────── */
    async function onDemandRefresh(source) {
      const statusEl = document.getElementById('assets_status');
      statusEl.textContent = `${source}${tt('dash.dyn.collecting',' 수집 중...')}`;
      statusEl.style.color = '#ca8a04';
      try {
        const res = await fetch('/assets/refresh', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({source}),
        });
        const data = await res.json();
        if (data.status === 'success') {
          statusEl.style.color = '#16a34a';
          statusEl.textContent = `${source}${tt('dash.dyn.collect_done',' 수집 완료')}`;
        } else if (data.status === 'skipped') {
          statusEl.style.color = '#ca8a04';
          statusEl.textContent = `${data.message}`;
        } else {
          statusEl.style.color = '#dc2626';
          statusEl.textContent = `${source}${tt('dash.dyn.collect_err',' 수집 오류: ')}${data.message}`;
        }
        // 수집 후 자산 목록 새로고침
        await loadAssets();
      } catch(e) {
        statusEl.style.color = '#dc2626';
        statusEl.textContent = `${tt('dash.dyn.error_prefix','오류: ')}${e.message}`;
      }
    }

    // ── Guide Tab ─────────────────────────────────────────────────────────
    // ── Compliance PDCA ──────────────────────────────────────────────────────
    async function loadSoaSummary() {
      const el = document.getElementById('soa_summary'); if (!el) return;
      try {
        const res = await fetch('/compliance/soa');
        if (!res.ok) { el.textContent = tt('dash.dyn.error_prefix','오류: ') + 'HTTP ' + res.status; return; }
        const s = (await res.json()).summary || {};
        el.textContent = tt('dash.soa.total','통제') + ' ' + (s.total||0)
          + ' · ' + tt('dash.soa.applicable','적용') + ' ' + (s.applicable||0)
          + ' · ' + tt('dash.soa.excluded','제외') + ' ' + (s.excluded||0)
          + ' · ' + tt('dash.soa.implemented','이행') + ' ' + (s.implemented||0)
          + ' · ' + tt('dash.soa.evidence','증적연결') + ' ' + (s.evidence_wired||0);
      } catch(e) { el.textContent = tt('dash.dyn.error_prefix','오류: ') + e.message; }
    }
    window.loadSoaSummary = loadSoaSummary;

    async function loadCompliance() {
      const cardsEl = document.getElementById('pdca_cards');
      const statusEl = document.getElementById('pdca_status_chart');
      const categoryEl = document.getElementById('pdca_category_table');
      const cycleEl = document.getElementById('pdca_cycle_chart');
      const pendingEl = document.getElementById('pdca_pending_table');
      if (cardsEl) cardsEl.innerHTML = '<div class=\"empty\" style=\"padding:16px;color:#111827\">' + tt('dash.dyn.loading','로딩 중…') + '</div>';
      loadSoaSummary();
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
        // Summary cards 상단은 control_checks만, 하단 2장은 통합(통제+Trivy+Alert)
        if (cardsEl) {
          // 바쁜 보안 담당자용: 행동 항목(미조치·기한초과) 우선 + 취약률 한 장(숫자 크게).
          // 피드백 반영: Pass Rate 대신 '취약률(Fail/Weakness Rate)' 심사에서 봐야 할 건
          // '통과율'이 아니라 '얼마나 취약한가'라서 반전 표시. 상세는 아래 접기.
          const totalChecks = data.total_checks || 0;
          const weakCount = (sc.fail || 0) + (sc.warning || 0);
          const weakRateStr = totalChecks > 0 ? (Math.round(weakCount / totalChecks * 100) + '%') : '';
          const weakColor = totalChecks > 0 && (weakCount / totalChecks) >= 0.3 ? '#dc2626' : '#ca8a04';
          const totalPending = data.pending_count || 0;
          const pendingSub = `${tt('dash.dyn.pdca.control','통제')} ${ps.control_check||0} · Trivy ${ps.trivy||0} · Alert ${ps.alert||0}`;
          const breakdownSub = totalChecks > 0
            ? `${sc.fail||0} · ${sc.warning||0} / ${totalChecks} (${sc.pass||0})`
            : tt('dash.dyn.pdca.no_control_data','통제 점검 데이터 없음');
          cardsEl.innerHTML = [
            _metricCard(tt('dash.dyn.pdca.pending_total_card','미조치 합계'), totalPending, '#ca8a04', pendingSub, true),
            _metricCard(tt('dash.dyn.pdca.overdue_card','기한초과'), data.overdue_count || 0, '#dc2626', tt('dash.dyn.pdca.combined_sources','통제+Trivy+Alert'), true),
            _metricCard(tt('dash.pdca.weakness_rate','취약률 (Fail/Weakness)'), weakRateStr, weakColor, breakdownSub, true),
          ].join('');
        }
        // Status bars
        if (statusEl) {
          const total = data.total_checks || 1;
          const bars = ['pass','fail','warning','not_applicable','not_checked'].map(s => {
            const cnt = sc[s] || 0;
            const pct = (cnt / total * 100).toFixed(1);
            const colors = {pass:'#16a34a',fail:'#dc2626',warning:'#ca8a04',not_applicable:'#111827',not_checked:'#e5e7eb'};
            const labels = {pass:'Pass',fail:'Fail',warning:'Warning',not_applicable:'N/A',not_checked:tt('dash.dyn.pdca.not_checked','미점검')};
            return `<div style=\"flex:1;min-width:100px\">
              <div style=\"font-size:12px;color:#111827;margin-bottom:4px\">${labels[s]}</div>
              <div style=\"background:#f9fafb;border-radius:6px;height:24px;overflow:hidden;position:relative\">
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
            {key:'plan',  label:'Plan',  desc:tt('dash.dyn.pdca.plan_desc','미점검 항목'),  val: pdca.plan || 0,  color:'#2563eb', icon:''},
            {key:'do',    label:'Do',    desc:tt('dash.dyn.pdca.do_desc','조치 필요'),    val: pdca.do || 0,    color:'#ca8a04', icon:''},
            {key:'check', label:'Check', desc:tt('dash.dyn.pdca.check_desc','점검 완료'),    val: pdca.check || 0, color:'#2563eb', icon:''},
            {key:'act',   label:'Act',   desc:tt('dash.dyn.pdca.act_desc','통과 (Pass)'),  val: pdca.act || 0,   color:'#16a34a', icon:''},
          ];
          cycleEl.innerHTML = `<div style=\"display:grid;grid-template-columns:repeat(4,1fr);gap:12px;text-align:center\">`
            + steps.map(s => {
              const clickable = (s.key === 'do' && s.val > 0);
              const cursor = clickable ? 'cursor:pointer' : '';
              const handler = clickable ? ' onclick=\"openPdcaDoModal()\"' : '';
              const hint = clickable ? '<div style=\"font-size:10px;color:#ca8a04;margin-top:4px\">' + tt('dash.dyn.pdca.click_hint','▸ 클릭') + '</div>' : '';
              return `<div${handler} style=\"background:#ffffff;border:2px solid ${s.color};border-radius:12px;padding:16px 8px;${cursor}\">
                <div style=\"font-size:24px\">${s.icon}</div>
                <div style=\"font-size:18px;font-weight:800;color:${s.color};margin:4px 0\">${s.val}</div>
                <div style=\"font-size:13px;font-weight:700;color:#111827\">${s.label}</div>
                <div style=\"font-size:11px;color:#111827\">${s.desc}</div>
                ${hint}
              </div>`;
            }).join('')
            + '</div>';
        }
        // Category table
        if (categoryEl) {
          const cats = data.categories || [];
          if (cats.length === 0) {
            categoryEl.innerHTML = '<div class=\"empty\" style=\"color:#111827;padding:12px\">' + tt('dash.dyn.pdca.no_check_data','점검 데이터가 없습니다.') + '</div>';
          } else {
            // 통제 카탈로그 트리와 동일하게 프레임워크 → 도메인(접기) → 섹션 계층으로 매칭.
            // total = 카탈로그 통제 개수 → 트리 분모(예: 2.보호대책 64)와 정확히 일치.
            const _fwLabel = { 'isms-p': 'ISMS-P', 'iso27001': 'ISO 27001:2022', 'custom': 'Custom / 법령' };
            // cats 는 payload 에서 이미 트리 순서(ISMS-P 먼저 · 섹션번호 자연정렬)로 정렬됨.
            const groups = [];  // {fw, domain, rows:[], agg:{}}
            cats.forEach(c => {
              const fw = c.framework || '', dom = c.domain || c.category;
              let g = groups.length ? groups[groups.length-1] : null;
              if (!g || g.fw !== fw || g.domain !== dom) {
                g = { fw, domain: dom, rows: [], agg: {pass:0,fail:0,warning:0,not_checked:0,total:0} };
                groups.push(g);
              }
              g.rows.push(c);
              g.agg.pass += c.pass; g.agg.fail += c.fail; g.agg.warning += c.warning;
              g.agg.not_checked += c.not_checked; g.agg.total += c.total;
            });
            const secTable = rows => `<table style=\"width:100%;border-collapse:collapse;font-size:12px;margin:4px 0 2px 14px\">
              <tbody>${rows.map(c => `<tr style=\"border-bottom:1px solid #f1f5f9\">
                <td style=\"padding:4px 8px;color:#111827\">${escapeHtml(c.category)}</td>
                <td style=\"text-align:right;padding:4px 8px;color:#16a34a;width:42px\">${c.pass}</td>
                <td style=\"text-align:right;padding:4px 8px;color:#dc2626;width:42px\">${c.fail}</td>
                <td style=\"text-align:right;padding:4px 8px;color:#ca8a04;width:42px\">${c.warning}</td>
                <td style=\"text-align:right;padding:4px 8px;color:#111827;width:42px\">${c.not_checked}</td>
                <td style=\"text-align:right;padding:4px 8px;color:#111827;width:42px\">${c.total}</td></tr>`).join('')}</tbody></table>`;
            const legend = `<div style=\"display:flex;gap:12px;justify-content:flex-end;font-size:11px;color:#111827;margin-bottom:4px\">
              <span style=\"color:#16a34a\">Pass</span><span style=\"color:#dc2626\">Fail</span><span style=\"color:#ca8a04\">Warning</span><span>${tt('dash.dyn.pdca.not_checked','미점검')}</span><span>${tt('dash.dyn.lbl.total','합계')}</span></div>`;
            let lastFw = null, html = legend;
            groups.forEach(g => {
              if (g.fw !== lastFw) {
                lastFw = g.fw;
                html += `<div style=\"margin-top:10px;font-weight:700;color:#2563eb;font-size:13px\">${escapeHtml(_fwLabel[g.fw]||g.fw||'')}</div>`;
              }
              const a = g.agg;
              const nums = `<span style=\"color:#16a34a\">${a.pass}</span> / <span style=\"color:#dc2626\">${a.fail}</span> / <span style=\"color:#ca8a04\">${a.warning}</span> / ${a.not_checked} / ${a.total}`;
              const domSameAsSec = (g.rows.length === 1 && g.rows[0].category === g.domain);
              if (domSameAsSec) {
                html += `<div style=\"margin:4px 0 0 4px;color:#111827;font-size:13px;padding:2px 0\">${escapeHtml(g.domain)} <span style=\"font-size:11px\">(${nums})</span></div>`;
              } else {
                html += `<details style=\"margin:4px 0 0 4px\"><summary style=\"cursor:pointer;color:#111827;font-size:13px;padding:2px 0\">${escapeHtml(g.domain)} <span style=\"font-size:11px\">(${nums})</span></summary>`
                  + secTable(g.rows) + `</details>`;
              }
            });
            categoryEl.innerHTML = html;
          }
        }
        // Pending remediations (control_check + trivy + alert)
        if (pendingEl) {
          const items = data.pending_remediations || [];
          const ps = data.pending_sources || {};
          const breakdown = `<div style=\"margin-bottom:8px;font-size:12px;color:#111827\">
            ${tt('dash.dyn.pdca.by_source','출처별: ')}<span style=\"color:#2563eb\">${tt('dash.dyn.pdca.control_checks','통제 점검')} ${ps.control_check||0}</span> ·
            <span style=\"color:#ca8a04\">Trivy ${tt('dash.dyn.pdca.vulns','취약점')} ${ps.trivy||0}</span> ·
            <span style=\"color:#dc2626\">Alert ${ps.alert||0}</span>
          </div>`;
          if (items.length === 0) {
            pendingEl.innerHTML = breakdown + '<div class=\"empty\" style=\"color:#111827;padding:12px\">' + tt('dash.dyn.pdca.no_pending','미조치 항목이 없습니다. ') + '</div>';
          } else {
            const sourceBadge = (s) => {
              if (s === 'trivy') return '<span style=\"background:#fef9c3;color:#ca8a04;padding:2px 6px;border-radius:4px;font-size:10px\">Trivy</span>';
              if (s === 'alert') return '<span style=\"background:#fee2e2;color:#dc2626;padding:2px 6px;border-radius:4px;font-size:10px\">Alert</span>';
              return '<span style=\"background:#f9fafb;color:#2563eb;padding:2px 6px;border-radius:4px;font-size:10px\">' + tt('dash.dyn.pdca.control_badge','통제') + '</span>';
            };
            pendingEl.innerHTML = breakdown + `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
              <thead><tr style=\"color:#111827;border-bottom:1px solid #e5e7eb\">
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
                  ? '<span style=\"background:#fee2e2;color:#dc2626;padding:2px 8px;border-radius:999px;font-size:11px\">Fail</span>'
                  : '<span style=\"background:#fef9c3;color:#ca8a04;padding:2px 8px;border-radius:999px;font-size:11px\">Warning</span>';
                const due = i.remediation_due_at ? new Date(i.remediation_due_at).toLocaleDateString('ko-KR') : '-';
                const overdueFlag = i.overdue ? ' ' : '';
                return `<tr style=\"border-bottom:1px solid #e5e7eb\">
                  <td style=\"text-align:center;padding:6px 8px\">${sourceBadge(i.source)}</td>
                  <td style=\"padding:6px 8px;color:#2563eb;font-weight:600\">${escapeHtml(i.control_id)}</td>
                  <td style=\"padding:6px 8px;color:#111827\">${escapeHtml(i.entity_type)}:${escapeHtml(i.entity_id)}</td>
                  <td style=\"text-align:center;padding:6px 8px\">${statusBadge}</td>
                  <td style=\"padding:6px 8px;color:#111827\">${escapeHtml(i.owner) || '-'}</td>
                  <td style=\"padding:6px 8px;color:#111827\">${due}${overdueFlag}</td>
                  <td style=\"padding:6px 8px;color:#111827\">${escapeHtml(i.note) || ''}</td>
                </tr>`;
              }).join('')
              + '</tbody></table>';
            _pgApply(pendingEl);  // 미조치/기한초과 표 페이징(기본 10 · 최대 100)
          }
        }
      } catch(e) {
        if (cardsEl) cardsEl.innerHTML = '<div class=\"empty\" style=\"color:#dc2626;padding:16px\">' + tt('dash.dyn.pdca.load_fail','Compliance 데이터를 불러올 수 없습니다.') + '</div>';
      }
      // Load report download cards
      loadReportCards();
    }

    async function loadReportCards() {
      const area = document.getElementById('report_download_area');
      if (!area) return;
      try {
        const res = await fetch('/compliance/reports');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const icons = {asset_inspection:'', account_privilege:'', log_collection_status:'', vulnerability_assessment:'', monthly_operations:''};
        area.innerHTML = (data.report_types || []).map(rt => `
          <div style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:16px\">
            <div style=\"font-size:20px;margin-bottom:8px\">${icons[rt.id] || ''}</div>
            <div style=\"font-size:14px;font-weight:700;color:#111827;margin-bottom:4px\">${escapeHtml(rt.label)}</div>
            <div style=\"display:flex;gap:6px;margin-top:12px;flex-wrap:wrap\">
              <button onclick=\"openReportPreview('${rt.id}', '${escapeHtml(rt.label)}')\" style=\"flex:1;min-width:80px;padding:6px 10px;background:#e5e7eb;color:#111827;border:1px solid #e5e7eb;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer\">${tt('dash.dyn.preview_btn','미리보기')}</button>
              <a href=\"${rt.url_csv}\" download style=\"flex:1;min-width:60px;text-align:center;padding:6px 10px;background:#dbeafe;color:#2563eb;border-radius:8px;font-size:12px;font-weight:600;text-decoration:none\">CSV</a>
              <a href=\"${rt.url_pdf || (rt.url_json + '?format=pdf')}\" download style=\"flex:1;min-width:60px;text-align:center;padding:6px 10px;background:#ffedd5;color:#ca8a04;border-radius:8px;font-size:12px;font-weight:600;text-decoration:none\">PDF</a>
            </div>
          </div>
        `).join('');
      } catch(e) {
        area.innerHTML = '<div class=\"empty\" style=\"color:#dc2626\">' + tt('dash.dyn.report_list_fail','리포트 목록을 불러올 수 없습니다.') + '</div>';
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
      titleEl.textContent = `${label}${tt('dash.dyn.preview_suffix',' 미리보기')}`;
      dlEl.href = `/compliance/reports/${reportType}?format=csv`;
      const dlPdfEl = document.getElementById('report_preview_download_pdf');
      if (dlPdfEl) { dlPdfEl.href = `/compliance/reports/${reportType}?format=pdf`; dlPdfEl.style.display = ''; }
      dlEl.setAttribute('download', '');
      const subEl0 = document.getElementById('report_preview_subtitle');
      if (subEl0) subEl0.textContent = tt('dash.modal.report_preview_sub', 'CSV 파일이 아래와 같은 형태로 생성됩니다. (상위 50행만 표시)');
      bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#111827;padding:24px;text-align:center\">' + tt('dash.dyn.loading_fetch','불러오는 중…') + '</div>';
      modal.style.display = 'flex';
      try {
        const res = await fetch(`/compliance/reports/${reportType}?format=csv`);
        if (!res.ok) throw new Error(res.status);
        const text = await res.text();
        const rows = _parseSimpleCsv(text);
        if (rows.length === 0) {
          bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#111827;padding:24px;text-align:center\">' + tt('dash.dyn.no_data','데이터가 없습니다.') + '</div>';
          return;
        }
        const headers = rows[0] || [];
        const dataRows = rows.slice(1).filter(r => r.length > 0 && !(r.length === 1 && r[0] === ''));
        const limit = 50;
        const shown = dataRows.slice(0, limit);
        const overflowNote = dataRows.length > limit
          ? `<div style=\"color:#111827;font-size:12px;margin-top:10px\">${tt('dash.dyn.report_overflow','… 총 {n}행 중 상위 {limit}행만 표시됩니다. 전체는 CSV 다운로드로 확인하세요.').replace('{n}','<strong style=\\\"color:#111827\\\">'+dataRows.length+'</strong>').replace('{limit}',limit)}</div>`
          : `<div style=\"color:#111827;font-size:12px;margin-top:10px\">${tt('dash.dyn.report_total_rows','총 {n}행').replace('{n}','<strong style=\\\"color:#111827\\\">'+dataRows.length+'</strong>')}</div>`;
        const head = '<thead><tr style=\"color:#111827;border-bottom:1px solid #e5e7eb;background:#ffffff;position:sticky;top:0\">'
          + headers.map(h => `<th style=\"text-align:left;padding:6px 10px;font-size:12px;white-space:nowrap\">${escapeHtml(h)}</th>`).join('')
          + '</tr></thead>';
        const body = shown.map(r => '<tr style=\"border-bottom:1px solid #e5e7eb\">'
          + headers.map((_, idx) => `<td style=\"padding:6px 10px;font-size:12px;color:#111827;white-space:nowrap;max-width:280px;overflow:hidden;text-overflow:ellipsis\" title=\"${escapeHtml(r[idx] || '')}\">${escapeHtml(r[idx] || '')}</td>`).join('')
          + '</tr>').join('');
        bodyEl.innerHTML = `<div style=\"max-height:60vh;overflow:auto;border:1px solid #e5e7eb;border-radius:6px\"><table style=\"width:100%;border-collapse:collapse\">${head}<tbody>${body}</tbody></table></div>${overflowNote}`;
      } catch (e) {
        bodyEl.innerHTML = `<div class=\"empty\" style=\"color:#dc2626;padding:24px;text-align:center\">${tt('dash.dyn.report_load_fail','리포트를 불러올 수 없습니다: ')}${escapeHtml(String(e.message || e))}</div>`;
      }
    }
    function closeReportPreview() { document.getElementById('report_preview_modal').style.display = 'none'; }

    /* ── 인시던트 CSV 미리보기 후 다운로드 (리포트 미리보기 모달 재사용) ────────── */
    async function openIncidentCsvPreview() {
      const params = buildIncidentParams();
      params.set('format', 'csv');
      return openCsvPreview({
        title: tt('dash.modal.incident_csv_preview_title', '인시던트 CSV 미리보기'),
        subtitle: tt('dash.modal.incident_csv_preview_sub', '변경 이력(history)은 CSV에 포함되지 않습니다. 각 인시던트는 최신 상태 1행으로 표시됩니다. (상위 50행 미리보기)'),
        filename: 'incidents.csv',
        url: '/incidents?' + params.toString(),
      });
    }

    function _metricCard(label, value, color, sub, big) {
      const subHtml = sub ? `<div class=\"metric-sub\" style=\"color:#111827;font-size:11px;margin-top:2px\">${escapeHtml(sub)}</div>` : '';
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
        btn.style.cssText = 'background:none;border:none;border-bottom:2px solid transparent;padding:8px 18px;color:#111827;font-size:13px;font-weight:600;cursor:pointer;border-radius:0;margin-bottom:-1px;';
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
        btn.style.borderBottomColor = active ? '#2563eb' : 'transparent';
        btn.style.color = active ? '#2563eb' : '#111827';
      });
      loadGuide(guideId);
    }

    function renderMarkdownLite(text) {
      // 매우 간단한 마크다운 렌더러: 헤더/볼드/코드블록/체크박스 지원
      return escapeHtml(text)
        .replace(/^### (.+)$/gm, '<h3 style="color:#16a34a;margin:16px 0 6px;font-size:14px">$1</h3>')
        .replace(/^## (.+)$/gm, '<h2 style="color:#2563eb;margin:20px 0 8px;font-size:16px">$1</h2>')
        .replace(/^#### (.+)$/gm, '<h4 style="color:#111827;margin:12px 0 4px;font-size:13px">$1</h4>')
        .replace(/\\*\\*(.+?)\\*\\*/g, '<strong style="color:#111827">$1</strong>')
        .replace(/`([^`]+)`/g, '<code style="background:#e5e7eb;padding:1px 6px;border-radius:4px;color:#16a34a;font-size:12px">$1</code>')
        .replace(/^```[\\s\\S]*?```/gm, m => `<pre style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:12px 14px;overflow-x:auto;font-size:12px;color:#16a34a;margin:8px 0">${m.slice(m.indexOf('\\n')+1, m.lastIndexOf('\\n'))}</pre>`)
        .replace(/^- \\[ \\] (.+)$/gm, '<div style="display:flex;gap:8px;align-items:flex-start;padding:2px 0"><span style="color:#ca8a04;margin-top:1px"></span><span>$1</span></div>')
        .replace(/^- \\[x\\] (.+)$/gm, '<div style="display:flex;gap:8px;align-items:flex-start;padding:2px 0"><span style="color:#16a34a;margin-top:1px"></span><span style="color:#111827;text-decoration:line-through">$1</span></div>')
        .replace(/^- (.+)$/gm, '<div style="padding:2px 0 2px 12px;color:#111827">• $1</div>')
        .replace(/^---$/gm, '<hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0">')
        .replace(/\\n/g, '\\n');
    }

    async function loadGuide(guideId) {
      const titleEl = document.getElementById('guide_content_title');
      const bodyEl = document.getElementById('guide_content_body');
      const updatedEl = document.getElementById('guide_updated_at');
      if (!titleEl || !bodyEl) return;
      bodyEl.innerHTML = '<span style="color:#111827">' + tt('dash.dyn.loading','로딩 중…') + '</span>';
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}?lang=${encodeURIComponent(window.lang||'ko')}`);
        if (!res.ok) throw new Error(res.status);
        const g = await res.json();
        titleEl.textContent = g.title || guideId;
        updatedEl.textContent = g.updated_at ? `${tt('dash.dyn.guide_updated_prefix','수정: ')}${g.updated_at.slice(0,10)}` : tt('dash.dyn.default_content','(기본 내용)');
        bodyEl.innerHTML = renderMarkdownLite(g.content || '');
      } catch(e) {
        bodyEl.innerHTML = `<span style="color:#dc2626">${tt('dash.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
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
    // 계정 거버넌스 열람 역할 서버(account_view_roles)에서 주입, admin이 조정. 기본 admin·security.
    let _accountViewRoles = ['admin', 'security'];
    function _canViewAccounts() { return _accountViewRoles.includes(_currentUserRole); }
    window._canViewAccounts = _canViewAccounts;
    function _applyAccountGating() {
      const show = _canViewAccounts();
      document.querySelectorAll('[data-tab="accounts"]').forEach(btn => btn.style.display = show ? '' : 'none');
      const dash = document.getElementById('acc_gov_dash_section');
      if (dash) dash.style.display = show ? '' : 'none';
      if (show) loadAccountsGov();  // 대시보드 요약 + 계정 탭 데이터 로딩
    }
    window._applyAccountGating = _applyAccountGating;
    const _CTL_SOURCE_COLOR = { zabbix:'#2563eb', trivy:'#ca8a04', wazuh:'#2563eb', fleet:'#16a34a', loki:'#dc2626', mori:'#111827' };
    // M2-7: 통제 이행 상태 색상/배지
    const _CTL_STATUS_COLOR = { '이행':'#16a34a', '부분이행':'#ca8a04', '미이행':'#dc2626', '해당없음':'#111827', '미정':'#111827' };
    const _CTL_STATUSES = ['미정','이행','부분이행','미이행','해당없음'];
    function _ctlStatusBadge(s) {
      const c = _CTL_STATUS_COLOR[s] || '#111827';
      return `<span style=\"background:${c}22;color:${c};border:1px solid ${c};padding:0 6px;border-radius:5px;font-size:10px;margin-left:5px;font-weight:700\">${escapeHtml(s)}</span>`;
    }
    let _ctlCanEdit = false;
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
          let t = `lite ${cov.lite.pct}% (${cov.lite.covered}/${cov.lite.total}) · full ${cov.full.pct}% (${cov.full.covered}/${cov.full.total})`;
          covEl.innerHTML = escapeHtml(t)
            + (cov.review ? ` · <span style=\"color:#a16207\" title=\"${tt('dash.ctl.review_tip','커버리지 %는 검토완료(reviewed)+증적 연결 통제만 집계합니다. 나머지는 초안(draft)이며 공식 고시 대비 검토 전입니다.')}\">${tt('dash.ctl.reviewed','검토완료')} ${cov.review.reviewed}/${cov.review.total} (${cov.review.pct}%)</span>` : '');
        }
        const fwLabel = { 'isms-p': 'ISMS-P', 'iso27001': 'ISO 27001:2022', 'custom': 'Custom / 법령' };
        const smap = data.status_map || {};
        _ctlCanEdit = !!data.can_edit;
        const abar = document.getElementById('ctl_admin_bar');
        if (abar) abar.style.display = _ctlCanEdit ? 'flex' : 'none';
        if (_ctlCanEdit) { loadSnapshotConfig(); loadClaudeKeyStatus(); }
        const badge = (s) => { const c=_CTL_SOURCE_COLOR[s]||'#111827'; return `<span style=\"background:${c}22;color:${c};border:1px solid ${c}55;padding:0 6px;border-radius:5px;font-size:10px;margin-left:3px\">${escapeHtml(s)}</span>`; };
        const ctrlRow = (c) => {
          const title = (lang==='en' ? c.title_en : c.title_ko) || c.title_ko || c.title_en || '';
          const dim = c.mapped ? '' : 'opacity:0.5;';
          const srcs = (c.evidence_sources||[]).map(badge).join('');
          const enc = encodeURIComponent(c.id);
          const clickable = 'cursor:pointer';  // M2-7: 상태 편집 위해 전 항목 클릭 가능
          const st = smap[c.id];
          const stBadge = (st && st.status && st.status !== '미정') ? _ctlStatusBadge(st.status) : '';
          const draftBadge = (c.status && c.status !== 'reviewed') ? `<span title=\"${tt('dash.ctl.draft_tip','초안 — 공식 고시 대비 검토 전')}\" style=\"background:#fef9c3;color:#a16207;border:1px solid #a1620733;padding:0 5px;border-radius:5px;font-size:9px;margin-left:4px;vertical-align:middle\">${tt('dash.ctl.draft','draft')}</span>` : '';
          const pdf = c.mapped ? `<a href=\"/controls/detail/${enc}/evidence.pdf\" target=\"_blank\" title=\"${tt('dash.ctl.pdf','증적 팩 PDF')}\" style=\"margin-left:6px;text-decoration:none;font-size:11px\"></a>` : '';
          const editBtns = _ctlCanEdit ? `<span onclick=\"openControlEditor('${enc}')\" title=\"${tt('dash.ctl.edit','수정')}\" style=\"cursor:pointer;margin-left:6px;font-size:11px\"></span><span onclick=\"deleteControl('${enc}')\" title=\"${tt('dash.ctl.del','삭제')}\" style=\"cursor:pointer;margin-left:3px;font-size:11px\"></span>` : '';
          return `<div style=\"padding:3px 0;${dim}\"><span onclick=\"toggleControlDetail('${enc}', this)\" style=\"${clickable}\"><span style=\"color:#111827;font-size:11px\">${escapeHtml(c.id)}</span> ${escapeHtml(title)}${draftBadge}${stBadge}${srcs}</span>${pdf}${editBtns}<div class=\"ctl-detail\" style=\"display:none;margin:4px 0 8px 16px;padding:6px 10px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;font-size:12px\"></div></div>`;
        };
        let html = '';
        (data.tree || []).forEach(fw => {
          let covered = 0, total = 0;
          fw.domains.forEach(d => d.sections.forEach(s => s.controls.forEach(c => { total++; if (c.mapped) covered++; })));
          html += `<div style=\"margin-top:10px;font-weight:700;color:#111827\">${escapeHtml(fwLabel[fw.framework]||fw.framework)} <span style=\"color:#111827;font-weight:400;font-size:12px\">(${covered}/${total})</span></div>`;
          fw.domains.forEach(d => {
            let dc=0, dt=0; d.sections.forEach(s => s.controls.forEach(c => { dt++; if (c.mapped) dc++; }));
            html += `<details style=\"margin:4px 0 0 4px\"><summary style=\"cursor:pointer;color:#111827;font-size:13px\">${escapeHtml(d.domain)} <span style=\"color:#111827;font-size:11px\">(${dc}/${dt})</span></summary>`;
            d.sections.forEach(s => {
              html += `<div style=\"margin:4px 0 4px 10px\"><div style=\"color:#111827;font-size:12px;margin:4px 0\">${escapeHtml(s.section||'')}</div>`;
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
          h += `<div style=\"font-weight:700;color:#2563eb;margin-bottom:2px\">${tt('dash.ctl.live','실증적 (현재)')}</div>`;
          h += d.evidence_live.map(e => {
            const lbl = (lang==='en'?e.label_en:e.label_ko) || e.source;
            const sm = (lang==='en'?e.summary_en:e.summary_ko) || '-';
            let row = `<div onclick=\"switchTab('${e.tab}')\" style=\"cursor:pointer;color:#111827;padding:1px 0\">• ${escapeHtml(lbl)}: <b>${escapeHtml(sm)}</b></div>`;
            const bd = e.breakdown || [];
            if (bd.length) {
              row += `<div style=\"margin:1px 0 3px 14px;color:#111827;font-size:11px\">` +
                bd.map(r => `<div>– ${escapeHtml(r.label)}: ${escapeHtml(r.value)}</div>`).join('') +
                (e.more ? `<div style=\"color:#111827\">… +${e.more}</div>` : '') + `</div>`;
            }
            return row;
          }).join('');
        }
        if ((d.mapped_to||[]).length) {
          h += `<div style=\"font-weight:700;color:#2563eb;margin:6px 0 2px\">${tt('dash.ctl.map','매핑')}</div>`;
          h += d.mapped_to.map(m => `<div style=\"color:#111827\">${escapeHtml(m.id)} ${escapeHtml((lang==='en'?m.title_en:m.title_ko)||'')} <span style=\"font-size:10px\">(${escapeHtml(m.relation)})</span></div>`).join('');
        }
        if ((d.defects||[]).length) {
          h += `<div style=\"font-weight:700;color:#ca8a04;margin:6px 0 2px\">${tt('dash.ctl.def','관련 결함')}</div>`;
          h += d.defects.map(x => { const gc=(typeof x.gap_count==='number')?` · ${tt('dash.ctl.gap','현재 공백')} ${x.gap_count}`:''; return `<div style=\"color:#111827\">${escapeHtml((lang==='en'?x.title_en:x.title_ko)||'')}${escapeHtml(gc)}</div>`; }).join('');
        }
        // 수기 증적: 인라인 누적 목록 대신 별도 팝업으로 (데이터는 그대로 보유)
        const _evN = (d.evidence_records || []).length;
        h += `<div style=\"margin-top:8px;padding-top:6px;border-top:1px solid #e5e7eb;display:flex;align-items:center;gap:10px;flex-wrap:wrap\">
          <span style=\"font-weight:700;color:#ca8a04\">${tt('dash.ctl.ev_title','수기 증적')}</span>
          <button onclick=\"openEvidenceModal('${enc}')\" class=\"secondary\" style=\"width:auto;padding:4px 12px;font-size:12px\">${tt('dash.ctl.ev_open','증적 누적 보기·기록')} (${_evN})</button>
        </div>`;
        // M2-7: 이행 상태 편집 폼 (admin·security) 저장 시 영속 + audit-log
        h += _ctlStatusForm(enc, d.runtime_status || {});
        // M2-8: 증적 팩 다운로드 CSV / PDF 선택
        h += `<div style=\"margin-top:8px;padding-top:6px;border-top:1px solid #e5e7eb;display:flex;gap:12px;align-items:center;flex-wrap:wrap\">
          <span style=\"color:#111827\">${tt('dash.ctl.download','증적 팩 다운로드')}:</span>
          <a href=\"/controls/detail/${enc}/evidence.csv\" style=\"color:#2563eb;text-decoration:none\">CSV</a>
          <a href=\"/controls/detail/${enc}/evidence.pdf\" target=\"_blank\" style=\"color:#2563eb;text-decoration:none\">PDF</a>
        </div>`;
        box.innerHTML = h || `<span class=\"empty\"></span>`;
      } catch(e) { box.innerHTML = `<span class=\"empty\">${tt('dash.ctl.err','통제 카탈로그를 불러오지 못했습니다.')}</span>`; }
    }
    window.toggleControlDetail = toggleControlDetail;

    /* M2-7: 통제 이행 상태 편집 폼 (admin·security 전용). id=enc(URI-encoded control id) */
    function _ctlStatusForm(enc, rs) {
      if (!_canViewEvidence()) {
        const badge = rs.status ? _ctlStatusBadge(rs.status) : '';
        return `<div style=\"margin-top:8px;padding-top:6px;border-top:1px solid #e5e7eb;color:#111827\">${tt('dash.ctl.status','이행 상태')}: ${badge || tt('dash.ctl.status_undecided','미정')}</div>`;
      }
      const inp = 'background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:5px;padding:4px 7px;font-size:12px';
      const opts = _CTL_STATUSES.map(s => `<option value=\"${s}\"${(rs.status||'미정')===s?' selected':''}>${s}</option>`).join('');
      const upd = rs.updated_at ? `<span style=\"color:#111827;font-size:11px;margin-left:8px\">${tt('dash.ctl.updated','수정')}: ${escapeHtml(String(rs.updated_at).slice(0,10))} · ${escapeHtml(rs.updated_by||'')}</span>` : '';
      return `<div style=\"margin-top:8px;padding-top:8px;border-top:1px solid #e5e7eb\">
        <div style=\"font-weight:700;color:#16a34a;margin-bottom:6px\">${tt('dash.ctl.status_edit','이행 상태 편집')}${upd}</div>
        <div style=\"display:flex;gap:8px;flex-wrap:wrap;align-items:center\">
          <select id=\"cst_status_${enc}\" style=\"${inp}\">${opts}</select>
          <input id=\"cst_owner_${enc}\" placeholder=\"${tt('dash.ctl.owner','담당자')}\" value=\"${escapeHtml(rs.owner||'')}\" style=\"${inp};width:110px\" />
          <input type=\"date\" id=\"cst_due_${enc}\" value=\"${escapeHtml(rs.due_date||'')}\" title=\"${tt('dash.ctl.due','조치 기한')}\" style=\"${inp}\" />
        </div>
        <input id=\"cst_plan_${enc}\" placeholder=\"${tt('dash.ctl.plan','개선계획')}\" value=\"${escapeHtml(rs.improvement_plan||'')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:6px\" />
        <input id=\"cst_exc_${enc}\" placeholder=\"${tt('dash.ctl.exc','예외 사유')}\" value=\"${escapeHtml(rs.exception_reason||'')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:6px\" />
        <div style=\"margin-top:6px;display:flex;align-items:center;gap:8px\">
          <button onclick=\"saveControlStatus('${enc}', this)\" class=\"secondary\" style=\"width:auto;padding:4px 14px;font-size:12px\">${tt('dash.ctl.save','저장')}</button>
          <span id=\"cst_msg_${enc}\" style=\"font-size:11px;color:#111827\"></span>
        </div>
      </div>`;
    }

    async function saveControlStatus(enc, btn) {
      const g = (p) => document.getElementById('cst_' + p + '_' + enc);
      const msg = g('msg');
      const body = {
        status: g('status').value,
        owner: g('owner').value.trim(),
        improvement_plan: g('plan').value.trim(),
        exception_reason: g('exc').value.trim(),
        due_date: g('due').value,
      };
      try {
        const res = await fetch('/controls/status/' + enc, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!res.ok) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color = '#dc2626'; } return; }
        if (msg) { msg.textContent = tt('dash.ctl.saved','저장됨 (재시작 후에도 유지)'); msg.style.color = '#16a34a'; }
        loadControlTree();  // 트리 상태 배지 갱신
      } catch (e) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color = '#dc2626'; } }
    }
    window.saveControlStatus = saveControlStatus;
    window._applyEvidenceGating = _applyEvidenceGating;

    // ── M2-8: 수기 증적 레코드 (문서화) ────────────────────────────────────────
    function _evRecordsHtml(enc, records) {
      const canEdit = _canViewEvidence();
      let h = `<div style=\"margin-top:8px;padding-top:6px;border-top:1px solid #e5e7eb\"><div style=\"font-weight:700;color:#ca8a04;margin-bottom:4px\">${tt('dash.ctl.ev_title','수기 증적')}</div>`;
      if (records.length) {
        const SHOW = 3;
        const rowHtml = (r, idx) => {
          const isAuto = r.source === 'auto';
          const autoBadge = isAuto ? ` <span style=\"background:#dbeafe;color:#2563eb;padding:0 5px;border-radius:4px;font-size:10px\">${tt('dash.ctl.ev_auto','자동')}</span>` : '';
          const meta = [r.collected_at, r.collected_by].filter(Boolean).map(escapeHtml).join(' · ');
          const ref = (r.reference && !isAuto) ? ` <a href=\"${escapeHtml(r.reference)}\" target=\"_blank\" style=\"color:#2563eb\"></a>` : '';
          const del = canEdit ? `<span onclick=\"deleteEvidenceRecord('${enc}','${escapeHtml(r.id)}')\" style=\"cursor:pointer;color:#dc2626;margin-left:6px\">×</span>` : '';
          // 자동 스냅샷: 한 줄 요약(집계) 인라인 + 전체 본문은상세로 접힘 / 수기 증적: 짧으니 그대로
          let bodyToggle = '', body = '';
          if (r.body) {
            const bid = 'evbody_' + enc + '_' + idx;
            if (isAuto) {
              const summ = _evSummary(r.body);
              bodyToggle = ` <span onclick=\"_toggleBody('${bid}',this)\" data-lbl=\"${tt('dash.ctl.ev_detail','상세')}\" style=\"cursor:pointer;color:#2563eb;font-size:11px;white-space:nowrap\">${tt('dash.ctl.ev_detail','상세')}</span>`;
              body = (summ ? `<div style=\"color:#2563eb;font-size:11px;margin-left:12px;margin-top:1px\">${summ}</div>` : '')
                   + `<div id=\"${bid}\" style=\"display:none;color:#111827;font-size:11px;margin:4px 0 2px 12px;white-space:pre-wrap;padding:7px 9px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px\">${escapeHtml(r.body)}</div>`;
            } else {
              body = `<div style=\"color:#111827;font-size:11px;margin-left:12px;white-space:pre-wrap\">${escapeHtml(r.body)}</div>`;
            }
          }
          return `<div style=\"color:#111827;padding:3px 0;border-top:${idx?'1px solid #f9fafb':'none'}\">• <b>${escapeHtml(r.title)}</b>${autoBadge}${meta?` <span style=\"color:#111827;font-size:11px\">(${meta})</span>`:''}${ref}${bodyToggle}${del}${body}</div>`;
        };
        h += records.slice(0, SHOW).map((r, i) => rowHtml(r, i)).join('');
        const rest = records.slice(SHOW);
        if (rest.length) {
          h += `<div id=\"evmore_${enc}\" style=\"display:none\">${rest.map((r, i) => rowHtml(r, i + SHOW)).join('')}</div>`;
          h += `<div id=\"evmoretog_${enc}\" onclick=\"_toggleEvMore('${enc}')\" style=\"cursor:pointer;color:#2563eb;font-size:12px;margin-top:3px\">${tt('dash.ctl.ev_more','더보기')} (${rest.length})</div>`;
        }
      } else {
        h += `<div style=\"color:#111827\">${tt('dash.ctl.ev_none','문서화된 수기 증적이 없습니다.')}</div>`;
      }
      if (canEdit) {
        const inp = 'background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:5px;padding:4px 7px;font-size:12px';
        h += `<div style=\"margin-top:6px\"><button onclick=\"autoEvidence('${enc}')\" class=\"secondary\" style=\"width:auto;padding:4px 12px;font-size:12px\" title=\"${tt('dash.ctl.ev_auto_tip','현재 실증적(라이브 집계)을 날짜 찍힌 증적으로 자동 생성')}\">${tt('dash.ctl.ev_auto_btn','실증적 자동 기록')}</button> <span id=\"evr_auto_msg_${enc}\" style=\"font-size:11px;color:#111827\"></span></div>
        <div style=\"margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;align-items:center\">
          <input id=\"evr_title_${enc}\" placeholder=\"${tt('dash.ctl.ev_ttl_ph','증적 제목(예: 접근권한 검토 회의록)')}\" style=\"${inp};width:220px\" />
          <input type=\"date\" id=\"evr_date_${enc}\" style=\"${inp}\" />
          <input id=\"evr_ref_${enc}\" placeholder=\"${tt('dash.ctl.ev_ref_ph','참조 링크/위치')}\" style=\"${inp};width:160px\" />
          <button onclick=\"addEvidenceRecord('${enc}')\" class=\"secondary\" style=\"width:auto;padding:4px 12px;font-size:12px\">+ ${tt('dash.ctl.ev_add','기록')}</button>
        </div>
        <input id=\"evr_body_${enc}\" placeholder=\"${tt('dash.ctl.ev_body_ph','증적 내용/설명')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:6px\" />
        <span id=\"evr_msg_${enc}\" style=\"font-size:11px;color:#111827\"></span>`;
      }
      return h + `</div>`;
    }
    async function addEvidenceRecord(enc) {
      const g = (p) => document.getElementById('evr_' + p + '_' + enc);
      const title = g('title').value.trim();
      const msg = g('msg');
      if (!title) { if (msg) { msg.textContent = tt('dash.ctl.ev_need_ttl','제목을 입력하세요'); msg.style.color='#dc2626'; } return; }
      const body = { title, body: g('body').value.trim(), collected_at: g('date').value, reference: g('ref').value.trim() };
      try {
        const res = await fetch('/controls/detail/' + enc + '/evidence-records', {
          method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        if (!res.ok) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; } return; }
        _refreshControlDetail(enc);
      } catch(e) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; } }
    }
    window.addEvidenceRecord = addEvidenceRecord;
    async function autoEvidence(enc) {
      const msg = document.getElementById('evr_auto_msg_' + enc);
      if (msg) { msg.textContent = tt('dash.ctl.ev_auto_run','스냅샷 생성 중…'); msg.style.color='#111827'; }
      try {
        const res = await fetch('/controls/detail/' + enc + '/evidence-records/auto', { method:'POST' });
        if (!res.ok) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; } return; }
        _refreshControlDetail(enc);
      } catch(e) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; } }
    }
    window.autoEvidence = autoEvidence;
    // 수기 증적 누적을 별도 팝업으로 표시(+기록/자동/삭제도 여기서). 데이터는 서버 보유.
    async function openEvidenceModal(enc) {
      const modal = document.getElementById('evidence_modal');
      if (!modal) return;
      modal.dataset.enc = enc;
      const titleEl = document.getElementById('evidence_modal_title');
      const bodyEl = document.getElementById('evidence_modal_body');
      if (titleEl) titleEl.textContent = decodeURIComponent(enc) + ' · ' + tt('dash.ctl.ev_title','수기 증적');
      if (bodyEl) bodyEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.loading','로딩 중…')}</span>`;
      if (!modal.open) modal.showModal();
      try {
        const res = await fetch('/controls/detail/' + enc);
        const recs = res.ok ? ((await res.json()).evidence_records || []) : [];
        if (bodyEl) bodyEl.innerHTML = _evRecordsHtml(enc, recs);
      } catch(e) { if (bodyEl) bodyEl.innerHTML = `<span class=\"empty\">${tt('dash.ctl.err','불러오지 못했습니다.')}</span>`; }
    }
    window.openEvidenceModal = openEvidenceModal;
    function _toggleEvMore(enc) {
      const box = document.getElementById('evmore_' + enc);
      const tog = document.getElementById('evmoretog_' + enc);
      if (!box) return;
      const open = box.style.display === 'none';
      box.style.display = open ? 'block' : 'none';
      if (tog) tog.innerHTML = open ? ('' + tt('dash.ctl.ev_less','접기'))
                                    : ('' + tt('dash.ctl.ev_more','더보기') + ' (' + box.children.length + ')');
    }
    window._toggleEvMore = _toggleEvMore;
    // 자동 스냅샷 본문에서 '[라벨] 요약' 집계줄만 뽑아 한 줄 요약으로 (호스트 목록 등 상세는 접힘)
    function _evSummary(body) {
      const parts = String(body || '').split('\\n')
        .filter(l => /^\\s*\[.+?\]/.test(l)).map(l => l.trim());
      return parts.length ? escapeHtml(parts.join('   ·   ')) : '';
    }
    function _toggleBody(id, el) {
      const b = document.getElementById(id);
      if (!b) return;
      const open = b.style.display === 'none';
      b.style.display = open ? 'block' : 'none';
      if (el) el.innerHTML = (open ? '' : '') + (el.dataset.lbl || '상세');
    }
    window._toggleBody = _toggleBody;
    // ── 정기 증적 스냅샷 설정 (admin) ──────────────────────────────────────────
    async function loadSnapshotConfig() {
      try {
        const res = await fetch('/controls/evidence-snapshot/config');
        if (!res.ok) return;
        const d = await res.json();
        const sch = document.getElementById('snap_schedule'); if (sch) sch.value = d.schedule || 'off';
        const sc = document.getElementById('snap_scope'); if (sc) sc.value = d.scope || 'mapped';
        const msg = document.getElementById('snap_msg');
        if (msg && d.last_run) msg.textContent = `${tt('dash.ctl.snap_last','최근')}: ${escapeHtml(String(d.last_run).slice(0,10))}`;
      } catch(e) {}
    }
    window.loadSnapshotConfig = loadSnapshotConfig;
    async function saveSnapshotConfig() {
      const msg = document.getElementById('snap_msg');
      const schedule = document.getElementById('snap_schedule').value;
      const scope = document.getElementById('snap_scope').value;
      try {
        const res = await fetch('/controls/evidence-snapshot/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({schedule, scope}) });
        if (msg) { msg.textContent = res.ok ? tt('dash.ctl.saved','저장됨') : tt('dash.ctl.save_fail','저장 실패'); msg.style.color = res.ok ? '#16a34a' : '#dc2626'; }
      } catch(e) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; } }
    }
    window.saveSnapshotConfig = saveSnapshotConfig;
    async function runBulkSnapshot() {
      const msg = document.getElementById('snap_msg');
      if (!confirm(tt('dash.ctl.snap_confirm','설정된 범위의 전 통제를 지금 일괄 스냅샷할까요?'))) return;
      if (msg) { msg.textContent = tt('dash.ctl.snap_running','일괄 스냅샷 중…'); msg.style.color='#111827'; }
      try {
        const res = await fetch('/controls/evidence-snapshot/run', { method:'POST' });
        if (!res.ok) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; } return; }
        const d = await res.json();
        if (msg) { msg.textContent = `${d.count}${tt('dash.ctl.snap_done','건 스냅샷됨')}`; msg.style.color='#16a34a'; }
      } catch(e) { if (msg) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; } }
    }
    window.runBulkSnapshot = runBulkSnapshot;
    async function deleteEvidenceRecord(enc, id) {
      if (!confirm(tt('dash.ctl.ev_del_confirm','이 수기 증적을 삭제할까요?'))) return;
      try {
        const res = await fetch('/controls/detail/' + enc + '/evidence-records/' + encodeURIComponent(id), { method:'DELETE' });
        if (res.ok) _refreshControlDetail(enc);
      } catch(e) {}
    }
    window.deleteEvidenceRecord = deleteEvidenceRecord;
    // 상세 패널 재렌더(열린 상태에서 갱신) 해당 통제의 detail div를 다시 로드
    function _refreshControlDetail(enc) {
      // 증적 팝업이 열려 있으면 그걸 갱신
      const modal = document.getElementById('evidence_modal');
      if (modal && modal.open && modal.dataset.enc === enc) { openEvidenceModal(enc); }
      // 인라인 상세가 열려 있으면 버튼 카운트 갱신 위해 재렌더
      const anchor = document.querySelector(`[onclick*=\"toggleControlDetail('${enc}'\"]`);
      if (!anchor) { return; }
      const box = anchor.parentElement.querySelector('.ctl-detail');
      if (box && box.style.display !== 'none') { box.style.display='none'; toggleControlDetail(enc, anchor); }
    }

    // ── M2-8: 카탈로그 통제 편집/추가 (admin) ──────────────────────────────────
    async function openControlEditor(enc) {
      const box = document.getElementById('ctl_editor');
      document.getElementById('ctl_nlp').style.display = 'none';
      let c = { id:'', framework:'custom', domain:'', section:'', title_ko:'', title_en:'', intent_ko:'', evidence_hint_ko:'', evidence_sources:[], status:'draft' };
      const isEdit = !!enc;
      if (isEdit) {
        try {
          const res = await fetch('/controls/detail/' + enc);
          if (res.ok) { const d = await res.json(); const ctl = d.control||{}; c = { ...c, ...ctl, id: ctl.id||decodeURIComponent(enc), evidence_sources: ctl.evidence_sources||[] }; }
        } catch(e) {}
      }
      const inp = 'background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:6px 9px;font-size:13px';
      box.innerHTML = `<div style=\"font-weight:700;color:#16a34a;margin-bottom:8px\">${isEdit?tt('dash.ctl.edit_ttl','통제 수정'):tt('dash.ctl.add_ttl','통제 추가')}</div>
        <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:8px\">
          <input id=\"ce_id\" placeholder=\"ID (예: PIPA-5)\" value=\"${escapeHtml(c.id)}\" ${isEdit?'readonly':''} style=\"${inp}\" />
          <input id=\"ce_framework\" placeholder=\"framework\" value=\"${escapeHtml(c.framework||'custom')}\" style=\"${inp}\" />
          <input id=\"ce_domain\" placeholder=\"${tt('dash.ctl.f_domain','도메인/영역')}\" value=\"${escapeHtml(c.domain||'')}\" style=\"${inp}\" />
          <input id=\"ce_section\" placeholder=\"${tt('dash.ctl.f_section','섹션')}\" value=\"${escapeHtml(c.section||'')}\" style=\"${inp}\" />
        </div>
        <input id=\"ce_title_ko\" placeholder=\"${tt('dash.ctl.f_title_ko','제목(한글)')}\" value=\"${escapeHtml(c.title_ko||'')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:8px\" />
        <input id=\"ce_title_en\" placeholder=\"${tt('dash.ctl.f_title_en','제목(영문)')}\" value=\"${escapeHtml(c.title_en||'')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:8px\" />
        <textarea id=\"ce_intent_ko\" placeholder=\"${tt('dash.ctl.f_intent','취지/설명')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:8px;min-height:54px\">${escapeHtml(c.intent_ko||'')}</textarea>
        <input id=\"ce_hint\" placeholder=\"${tt('dash.ctl.f_hint','증적 힌트')}\" value=\"${escapeHtml(c.evidence_hint_ko||'')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:8px\" />
        <input id=\"ce_sources\" placeholder=\"${tt('dash.ctl.f_sources','증적 소스(콤마: zabbix,trivy,fleet…)')}\" value=\"${escapeHtml((c.evidence_sources||[]).join(','))}\" style=\"${inp};width:100%;box-sizing:border-box;margin-top:8px\" />
        <div style=\"margin-top:10px;display:flex;gap:8px;align-items:center\">
          <button onclick=\"saveControlEdit()\" style=\"width:auto;padding:6px 16px\">${tt('dash.ctl.save','저장')}</button>
          <button onclick=\"document.getElementById('ctl_editor').style.display='none'\" class=\"secondary\" style=\"width:auto;padding:6px 16px\">${tt('dash.ctl.cancel','취소')}</button>
          <span id=\"ce_msg\" style=\"font-size:12px;color:#111827\"></span>
        </div>`;
      box.style.display = 'block';
    }
    window.openControlEditor = openControlEditor;
    async function saveControlEdit() {
      const v = (id) => (document.getElementById(id)?.value || '').trim();
      const msg = document.getElementById('ce_msg');
      const body = { id: v('ce_id'), framework: v('ce_framework')||'custom', domain: v('ce_domain'),
        section: v('ce_section'), title_ko: v('ce_title_ko'), title_en: v('ce_title_en'),
        intent_ko: v('ce_intent_ko'), evidence_hint_ko: v('ce_hint'), evidence_sources: v('ce_sources') };
      if (!body.id || (!body.title_ko && !body.title_en)) { msg.textContent = tt('dash.ctl.need_id_ttl','ID와 제목은 필수'); msg.style.color='#dc2626'; return; }
      try {
        const res = await fetch('/controls', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        if (!res.ok) { msg.textContent = tt('dash.ctl.save_fail','저장 실패') + ' (' + res.status + ')'; msg.style.color='#dc2626'; return; }
        document.getElementById('ctl_editor').style.display='none';
        loadControlTree();
      } catch(e) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; }
    }
    window.saveControlEdit = saveControlEdit;
    async function deleteControl(enc) {
      if (!confirm(tt('dash.ctl.del_confirm','이 통제를 삭제(또는 숨김)할까요?'))) return;
      try {
        const res = await fetch('/controls/' + enc, { method:'DELETE' });
        if (res.ok) loadControlTree();
      } catch(e) {}
    }
    window.deleteControl = deleteControl;

    // ── M2-8: 법령 텍스트 NLP 임포트 (admin) ───────────────────────────────────
    function openNlpImport() {
      const box = document.getElementById('ctl_nlp');
      document.getElementById('ctl_editor').style.display = 'none';
      const inp = 'background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:6px 9px;font-size:13px';
      box.innerHTML = `<div style=\"font-weight:700;color:#2563eb;margin-bottom:6px\">${tt('dash.ctl.nlp_ttl','법령/고시 텍스트 → 통제 초안')}</div>
        <div class=\"subtext\" style=\"margin-bottom:8px\">${tt('dash.ctl.nlp_help','법령 원문을 붙여넣으면 통제 초안으로 바꿔서 저장해요. Claude 키가 있으면 더 정확하게, 없으면 조항 단위로 나눠요.')}</div>
        <div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px\">
          <input id=\"nlp_framework\" placeholder=\"${tt('dash.ctl.nlp_fw','프레임워크(예: 개인정보보호법)')}\" style=\"${inp};width:220px\" />
          <input id=\"nlp_prefix\" placeholder=\"ID 접두어(예: PIPA)\" value=\"REG\" style=\"${inp};width:150px\" />
        </div>
        <textarea id=\"nlp_text\" placeholder=\"${tt('dash.ctl.nlp_ph','법령/고시 전문을 붙여넣으세요…')}\" style=\"${inp};width:100%;box-sizing:border-box;min-height:120px\"></textarea>
        <div style=\"margin-top:8px;display:flex;gap:8px;align-items:center\">
          <button onclick=\"runNlpImport()\" style=\"width:auto;padding:6px 16px\">${tt('dash.ctl.nlp_run','변환·저장')}</button>
          <button onclick=\"document.getElementById('ctl_nlp').style.display='none'\" class=\"secondary\" style=\"width:auto;padding:6px 16px\">${tt('dash.ctl.cancel','취소')}</button>
          <span id=\"nlp_msg\" style=\"font-size:12px;color:#111827\"></span>
        </div>`;
      box.style.display = 'block';
    }
    window.openNlpImport = openNlpImport;
    async function runNlpImport() {
      const msg = document.getElementById('nlp_msg');
      const text = document.getElementById('nlp_text').value.trim();
      if (!text) { msg.textContent = tt('dash.ctl.nlp_need','텍스트를 붙여넣으세요'); msg.style.color='#dc2626'; return; }
      msg.textContent = tt('dash.ctl.nlp_running','변환 중…'); msg.style.color='#111827';
      try {
        const res = await fetch('/controls/import-nlp', { method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ text, framework: document.getElementById('nlp_framework').value.trim()||'custom', id_prefix: document.getElementById('nlp_prefix').value.trim()||'REG' }) });
        if (!res.ok) { msg.textContent = tt('dash.ctl.save_fail','저장 실패') + ' (' + res.status + ')'; msg.style.color='#dc2626'; return; }
        const d = await res.json();
        const via = d.method === 'claude' ? 'Claude API' : (d.method === 'heuristic' ? tt('dash.ctl.nlp_heur','휴리스틱') : d.method);
        msg.textContent = `${d.count}${tt('dash.ctl.nlp_done','건 저장됨')} (${via})`; msg.style.color='#16a34a';
        loadControlTree();
      } catch(e) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; }
    }
    window.runNlpImport = runNlpImport;

    // ── 코드 보안 리뷰 원격 트리거 (Option A — GitHub workflow_dispatch) ──────────
    function openCodeReviewScan() {
      const box = document.getElementById('ctl_nlp');
      document.getElementById('ctl_editor').style.display = 'none';
      const inp = 'background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:6px 9px;font-size:13px';
      box.innerHTML = `<div style=\"font-weight:700;color:#2563eb;margin-bottom:6px\">${tt('dash.ctl.scan_ttl','GitHub 레포 코드 보안 리뷰 요청')}</div>
        <div class=\"subtext\" style=\"margin-bottom:8px\">${tt('dash.ctl.scan_help','레포 URL과 GitHub 토큰(actions:write)을 넣으면 그 레포의 CI에서 무료 보안 스캔(Semgrep)이 돌고 결과가 MORI로 자동 회수돼요. MORI는 코드를 가져오지 않고 토큰도 저장하지 않아요. 대상 레포에 code-review-semgrep.yml 1개만 있으면 돼요.')}</div>
        <div style=\"margin-bottom:8px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px;font-size:12px;color:#111827;line-height:1.6\">${tt('dash.ctl.scan_warn_pr','온디맨드 스캔 = 무료 Semgrep(SAST)로 기존 코드 전체를 스캔해요. 대상 레포에 code-review-semgrep.yml 1개만 두면 이 버튼으로 바로 스캔돼요. (더 깊은 유료 Claude 리뷰는 code-review-fullscan.yml 참고.)')}</div>
        <details style=\"margin-bottom:8px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px\">
          <summary style=\"cursor:pointer;font-size:12px;color:#2563eb;font-weight:600\">${tt('dash.ctl.scan_guide_t','처음이신가요? code-review-semgrep(무료) 셋업 방법 보기')}</summary>
          <div style=\"font-size:12px;color:#111827;margin-top:6px;line-height:1.6\">
            <div style=\"margin-bottom:4px\">${tt('dash.ctl.scan_guide_what','code-review-semgrep = 대상 GitHub 레포의 .github/workflows/ 에 넣는 무료 자동화 파일이에요. 실행하면 Semgrep(무료 SAST)이 기존 코드 전체를 스캔해 결과를 MORI로 보내요. (MORI는 코드를 가져오지 않아요)')}</div>
            <div style=\"font-weight:600;margin:6px 0 2px\">${tt('dash.ctl.scan_guide_steps','대상 레포에 한 번만 준비하면 돼요:')}</div>
            <ol style=\"margin:0;padding-left:18px\">
              <li>${tt('dash.ctl.scan_guide_s1','레포 .github/workflows/ 에 code-review-semgrep.yml 1개 복사 (MORI 저장소의 같은 파일)')}</li>
              <li>${tt('dash.ctl.scan_guide_s2','레포 Settings → Secrets 에 1개만 등록: MORI_INGEST_URL (무료 — ANTHROPIC 키 불필요, 등록 방법 아래 ↓)')}</li>
              <li>${tt('dash.ctl.scan_guide_s3','아래에 GitHub 토큰(그 레포 actions:write) 입력 — 저장하지 않고 이번 실행에만 써요')}</li>
            </ol>
            <details style=\"margin-top:6px;background:#fff;border:1px dashed #e5e7eb;border-radius:6px;padding:6px 8px\">
              <summary style=\"cursor:pointer;font-size:11px;color:#111827\">${tt('dash.ctl.scan_sec_t','시크릿 등록 방법 (GitHub에서 처음이면)')}</summary>
              <ol style=\"margin:6px 0 0;padding-left:18px;font-size:11px;color:#111827;line-height:1.7\">
                <li>${tt('dash.ctl.scan_sec_1','대상 레포 페이지 상단 Settings 탭')}</li>
                <li>${tt('dash.ctl.scan_sec_2','좌측 메뉴 Secrets and variables → Actions')}</li>
                <li>${tt('dash.ctl.scan_sec_3','New repository secret 버튼 클릭')}</li>
                <li>${tt('dash.ctl.scan_sec_4','Name=MORI_INGEST_URL, Secret=이 MORI 주소(예: https://mori.example.com) → Add secret')}</li>
                <li>${tt('dash.ctl.scan_sec_5','(선택) 유료 Claude 심층 스캔을 쓸 때만 ANTHROPIC_API_KEY 도 추가')}</li>
              </ol>
              <div style=\"font-size:11px;color:#16a34a;margin-top:4px\">${tt('dash.ctl.scan_sec_note','※ OIDC로 인증하므로 별도 ingest 토큰 시크릿은 필요 없어요.')}</div>
            </details>
            <div style=\"margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;align-items:center\">
              <button onclick=\"showCodeReviewTemplate()\" class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\">${tt('dash.ctl.scan_tpl_btn','워크플로(.yml) 보기·복사')}</button>
              <span id=\"scan_tpl_msg\" style=\"font-size:11px;color:#16a34a\"></span>
            </div>
            <div style=\"margin-top:6px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:6px 8px\">
              <div style=\"font-size:11px;font-weight:600;color:#111827;margin-bottom:2px\">${tt('dash.ctl.scan_files_t','파일 위치')}</div>
              <div style=\"font-family:monospace;font-size:11px;color:#111827;line-height:1.5\">
                <div>${tt('dash.ctl.scan_files_root','레포 루트')}/</div>
                <div>└─ .github/workflows/code-review-semgrep.yml</div>
              </div>
              <div style=\"font-size:11px;color:#111827;margin-top:3px\">${tt('dash.ctl.scan_files_warn','파일 1개면 끝이에요(무료 Semgrep). 더 깊은 유료 Claude 리뷰는 아래 고급 참고.')}</div>
            </div>
            <pre id=\"scan_tpl\" style=\"display:none;margin-top:6px;max-height:240px;overflow:auto;background:#111827;color:#e5e7eb;padding:10px;border-radius:8px;font-size:11px;line-height:1.45;white-space:pre\"></pre>
          </div>
        </details>
        <details style=\"margin-bottom:8px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px\">
          <summary style=\"cursor:pointer;font-size:12px;color:#ca8a04;font-weight:600\">${tt('dash.ctl.fs_t','고급: 유료 Claude 심층 리뷰 (선택)')}</summary>
          <div style=\"font-size:12px;color:#111827;margin-top:6px;line-height:1.6\">
            <div style=\"margin-bottom:4px\">${tt('dash.ctl.fs_what','Semgrep(무료)보다 깊은 로직 리뷰가 필요하면 Claude fullscan을 쓰세요. Anthropic 크레딧이 듭니다. 한 번의 Claude 호출로 보안 findings(2.8)와 개인정보 흐름(3.x)이 함께 나와요. 파일 1개 + 시크릿 2개.')}</div>
            <div style=\"font-family:monospace;font-size:11px;color:#111827;line-height:1.5\">
              <div>${tt('dash.ctl.scan_files_root','레포 루트')}/</div>
              <div>└─ .github/workflows/code-review-fullscan.yml&nbsp;&nbsp;← ${tt('dash.ctl.fs_only','이 파일 하나만')}</div>
            </div>
            <div style=\"margin:4px 0;font-size:11px;color:#111827\">${tt('dash.ctl.fs_noscript','스캐너(.py)는 MORI가 서빙 — 워크플로가 실행 때 최신본을 자동으로 받아요(재복사 불필요).')}</div>
            <div style=\"margin:4px 0\">${tt('dash.ctl.fs_secrets','레포 Secrets 2개: ANTHROPIC_API_KEY(console.anthropic.com 발급) · MORI_INGEST_URL')}</div>
            <div style=\"display:flex;gap:6px;flex-wrap:wrap;align-items:center\">
              <button onclick=\"showFullscanWorkflow()\" class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\">${tt('dash.ctl.fs_yml','워크플로(.yml) 복사')}</button>
              <span id=\"scan_fs_msg\" style=\"font-size:11px;color:#16a34a\"></span>
            </div>
            <pre id=\"scan_fs\" style=\"display:none;margin-top:6px;max-height:240px;overflow:auto;background:#111827;color:#e5e7eb;padding:10px;border-radius:8px;font-size:11px;line-height:1.45;white-space:pre\"></pre>
            <div style=\"font-size:11px;color:#111827;margin-top:3px\">${tt('dash.ctl.fs_run','실행: 대상 레포 Actions → code-review-fullscan → Run workflow. → 스캔 이력에 Claude(유료) 배지 + 개인정보 흐름도가 함께 갱신돼요.')}</div>
          </div>
        </details>
        <div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px\">
          <input id=\"scan_url\" placeholder=\"${tt('dash.ctl.scan_url_ph','https://github.com/owner/repo')}\" style=\"${inp};flex:1;min-width:260px\" />
          <input id=\"scan_ref\" placeholder=\"${tt('dash.ctl.scan_ref_ph','브랜치(기본 main)')}\" value=\"main\" style=\"${inp};width:150px\" />
        </div>
        <div style=\"display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;font-size:12px;color:#111827;align-items:center\">
          <span style=\"font-weight:600\">${tt('dash.ctl.scan_mode','스캔 방식')}:</span>
          <label style=\"display:inline-flex;align-items:center;gap:4px\"><input type=\"radio\" name=\"scan_mode\" value=\"code-review-semgrep.yml\" checked> ${tt('dash.ctl.scan_mode_free','무료 Semgrep(SAST·PII)')}</label>
          <label style=\"display:inline-flex;align-items:center;gap:4px\"><input type=\"radio\" name=\"scan_mode\" value=\"code-review-fullscan.yml\"> ${tt('dash.ctl.scan_mode_ai','유료 Claude 심층(라이프사이클 완벽)')}</label>
          <span style=\"font-size:11px;color:#111827\">${tt('dash.ctl.scan_mode_note','유료는 레포에 code-review-fullscan.yml + ANTHROPIC_API_KEY 필요(고급 팝업 참고)')}</span>
        </div>
        <input id=\"scan_token\" type=\"password\" placeholder=\"${tt('dash.ctl.scan_token_ph','GitHub 토큰 (actions:write · 저장 안 함)')}\" style=\"${inp};width:100%;box-sizing:border-box;margin-bottom:4px\" />
        <details style=\"margin-bottom:8px;background:#fff;border:1px dashed #e5e7eb;border-radius:6px;padding:6px 8px\">
          <summary style=\"cursor:pointer;font-size:11px;color:#111827\">${tt('dash.ctl.scan_tok_t','GitHub 토큰이 뭔가요? 어떻게 발급하나요?')}</summary>
          <div style=\"font-size:11px;color:#111827;margin-top:6px;line-height:1.7\">
            <div style=\"margin-bottom:4px\">${tt('dash.ctl.scan_tok_what','MORI가 그 레포의 리뷰 워크플로를 원격 실행하려면 GitHub 권한이 필요해요. 개인 액세스 토큰(PAT)을 발급해 아래에 넣으면 이번 실행에만 쓰고 저장하지 않아요. (스캔은 GitHub에서 돌고 MORI는 코드를 안 가져와요)')}</div>
            <div style=\"font-weight:600;margin:4px 0 2px\">${tt('dash.ctl.scan_tok_how','발급 방법 (fine-grained 권장):')}</div>
            <ol style=\"margin:0;padding-left:18px\">
              <li>${tt('dash.ctl.scan_tok_1','GitHub 우측 상단 프로필 → Settings')}</li>
              <li>${tt('dash.ctl.scan_tok_2','좌측 맨 아래 Developer settings → Personal access tokens → Fine-grained tokens')}</li>
              <li>${tt('dash.ctl.scan_tok_3','Generate new token → Repository access = 대상 레포만 선택')}</li>
              <li>${tt('dash.ctl.scan_tok_4','Permissions → Actions = Read and write 부여')}</li>
              <li>${tt('dash.ctl.scan_tok_5','Generate token → 나온 값(ghp_… 또는 github_pat_…)을 복사해 아래에 붙여넣기')}</li>
            </ol>
            <div style=\"color:#16a34a;margin-top:4px\">${tt('dash.ctl.scan_tok_note','※ 최소 권한(그 레포·Actions write)만 주세요. 토큰은 서버에 저장되지 않아요.')}</div>
          </div>
        </details>
        <div style=\"display:flex;gap:8px;align-items:center\">
          <button onclick=\"runCodeReviewScan()\" style=\"width:auto;padding:6px 16px\">${tt('dash.ctl.scan_run','스캔 요청')}</button>
          <button onclick=\"document.getElementById('ctl_nlp').style.display='none'\" class=\"secondary\" style=\"width:auto;padding:6px 16px\">${tt('dash.ctl.cancel','취소')}</button>
          <span id=\"scan_msg\" style=\"font-size:12px;color:#111827\"></span>
        </div>
        <details style=\"margin-top:8px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px\">
          <summary style=\"cursor:pointer;font-size:12px;color:#16a34a;font-weight:600\">${tt('dash.ctl.scan_res_t','스캔 후 결과는 어디서 확인하나요?')}</summary>
          <div style=\"font-size:12px;color:#111827;margin-top:6px;line-height:1.7\">
            <div style=\"font-weight:600;margin-bottom:2px\">${tt('dash.ctl.scan_res_step1','1) 먼저 GitHub에서 실행 확인')}</div>
            <div style=\"margin-bottom:6px\">${tt('dash.ctl.scan_res_gh','대상 레포 → Actions 탭 → \"code-review-semgrep\" 실행(초록 체크)이 떠야 해요. 안 뜨면 그 레포에 code-review-semgrep.yml·시크릿이 없는 거예요.')}</div>
            <div style=\"font-weight:600;margin-bottom:2px\">${tt('dash.ctl.scan_res_step2','2) MORI에서 결과 확인 (잠시 후 새로고침)')}</div>
            <ul style=\"margin:0;padding-left:18px\">
              <li>${tt('dash.ctl.scan_res_triage','Alert Triage 탭 — findings가 보라색 code_review 배지로 떠요. 상태(접수→조사중→완료)를 눌러 처리.')}</li>
              <li>${tt('dash.ctl.scan_res_gap','대시보드 \"미조치 코드 보안 리뷰\" 타일 — 미처리 건수(누르면 트리아지로).')}</li>
              <li>${tt('dash.ctl.scan_res_ctl','Compliance → 통제 카탈로그 2.8.1·2.8.5 / A.8.25·A.8.28 — 이 통제에 증적으로 연결(통제별 증적 PDF/CSV).')}</li>
            </ul>
            <div style=\"color:#111827;margin-top:4px\">${tt('dash.ctl.scan_res_note','※ 반영에 1~3분 걸릴 수 있어요. 바로 안 보이면 페이지 새로고침(또는 워커 주기 후) 하세요. 안 보이면: 레포 MORI_INGEST_URL 시크릿이 이 MORI 주소인지·MORI가 외부에서 접근 가능한지 확인.')}</div>
          </div>
        </details>
        <div style=\"margin-top:10px\">
          <div style=\"font-size:12px;font-weight:600;color:#111827;display:flex;align-items:center;gap:6px\">${tt('dash.ctl.scan_hist_t','최근 코드 리뷰 스캔 이력')} <button onclick=\"loadRecentCodeReviewScans()\" class=\"secondary\" style=\"width:auto;padding:2px 8px;font-size:11px\">${tt('dash.btn.reload','새로고침')}</button> <button onclick=\"backfillCodeReviewEvidence()\" class=\"secondary\" style=\"width:auto;padding:2px 8px;font-size:11px\" title=\"${tt('dash.ctl.scan_backfill_hint','자동 승격 도입 전 과거 스캔을 2.8 통제 증적으로 소급 반영')}\">${tt('dash.ctl.scan_backfill','과거 스캔 증적 반영')}</button></div>
          <div id=\"scan_recent\" style=\"margin-top:6px;font-size:12px;color:#111827\"><span class=\"empty\">${tt('dash.dyn.loading','로딩 중…')}</span></div>
          <details style=\"margin-top:8px;border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px\">
            <summary style=\"cursor:pointer;font-size:12px;color:#111827;font-weight:600\">${tt('dash.ctl.scan_legend_t','결과 읽는 법 — 배지·용어 설명')}</summary>
            <ul style=\"margin:6px 0 0;padding-left:16px;font-size:12px;color:#111827;line-height:1.7\">
              <li>${tt('dash.ctl.scan_legend_verified','‘검증됨(OIDC)’: GitHub이 서명한 레포·커밋·실행ID를 MORI가 검증한 결과예요 — 출처 위조 불가. ‘미검증’은 서명 없이(정적 토큰/무인증) 받은 결과라 출처를 그대로 신뢰하기 어려워요.')}</li>
              <li>${tt('dash.ctl.scan_legend_findings','‘findings N건’: 스캔이 찾은 보안 이슈 수. 각 건은 Alert Triage 탭에 code_review 배지로 떠서 접수→조사중→완료로 처리해요.')}</li>
              <li>${tt('dash.ctl.scan_legend_pii','개인정보(PII)도 함께 탐지돼요 — 주민등록번호·휴대전화·카드번호·하드코딩 비밀키. 발견되면 ‘개인정보 흐름도’ 화면의 [PII 스캔으로 시드]로 흐름표 후보 행이 자동 생성돼요(3.x 개인정보 통제 증적으로 연결).')}</li>
              <li>${tt('dash.ctl.scan_legend_csv','‘결과 CSV’: 그 스캔의 findings 목록(파일·라인·심각도·룰)을 파일로 받아 확인해요.')}</li>
              <li>${tt('dash.ctl.scan_legend_backfill','‘과거 스캔 증적 반영’: 이력의 스캔을 2.8 개발보안 통제(2.8.1·2.8.5·A.8.25·A.8.28) 증적으로 소급 등록해요.')}</li>
              <li>${tt('dash.ctl.scan_legend_ctl','반영 확인: Compliance → 통제 카탈로그의 해당 통제 상세에 날짜 찍힌 증적 레코드로 연결돼요(통제별 증적 PDF/CSV로도 확인).')}</li>
            </ul>
          </details>
        </div>`;
      box.style.display = 'block';
      loadRecentCodeReviewScans();
    }
    window.openCodeReviewScan = openCodeReviewScan;

    // ── 개인정보 처리흐름도 (ISMS-P 3.x) — 읽기 전용 증적 ──────────────────────────
    function openPrivacyFlow() {
      const box = document.getElementById('ctl_nlp');
      document.getElementById('ctl_editor').style.display = 'none';
      box.innerHTML = `<div style=\"font-weight:700;color:#2563eb;margin-bottom:4px\">${tt('dash.pf.title','개인정보 처리흐름도 (ISMS-P 3.x)')}</div>
        <div class=\"subtext\" style=\"margin-bottom:8px\">${tt('dash.pf.help','개인정보 항목이 수집→저장→이용→파기로 흐르는 경로와 저장위치(DB/테이블)를 기록해요. 코드 스캔에서 발견된 개인정보/비밀정보로 자동 생성돼요. MORI는 코드를 읽지 않아요.')}</div>
        <div style=\"display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;align-items:center\">
          <button class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" onclick=\"seedPrivacyFlow()\">${tt('dash.pf.seed','PII 스캔으로 시드')}</button>
          <button class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" onclick=\"openCsvPreview({title:tt('dash.pf.title','개인정보 처리흐름도 (ISMS-P 3.x)'),filename:'mori-personal-data-flow.csv',url:'/privacy/data-flow.csv'})\">${tt('dash.pf.csv','CSV')}</button>
          <a href=\"/privacy/data-flow.pdf\" target=\"_blank\" class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px;text-decoration:none;color:#2563eb;border:1px solid #e5e7eb;border-radius:6px\">${tt('dash.pf.pdf','PDF')}</a>
          <button class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" onclick=\"promotePrivacyFlow()\">${tt('dash.pf.promote','3.x 통제 증적 승격')}</button>
          <button class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" onclick=\"togglePiiCriteria()\">${tt('dash.pf.criteria','PII 기준 편집')}</button>
          <button class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" onclick=\"loadPrivacyFlow()\">${tt('dash.pf.reload','새로고침')}</button>
          <button class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px;color:#dc2626\" onclick=\"resetPrivacyFlow()\">${tt('dash.pf.reset','리셋')}</button>
          <span id=\"pf_msg\" style=\"font-size:11px;color:#16a34a\"></span>
        </div>
        <div id=\"pf_criteria\" style=\"display:none;border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px;margin-bottom:8px;font-size:12px\"></div>
        <div style=\"font-size:12px;font-weight:600;color:#111827;margin:6px 0 4px\">${tt('dash.pf.diagram','처리 흐름도 (수집→저장→이용→파기)')}</div>
        <div id=\"pf_diagram\" style=\"overflow-x:auto;border:1px solid #e5e7eb;border-radius:8px;padding:6px;background:#fff\"></div>
        <div style=\"margin-top:4px;font-size:11px;color:#111827;line-height:1.6\">${tt('dash.pf.legend','읽는 법: ‘PII 시드’ 배지 = 코드 스캔에서 자동 발견된 개인정보 처리 지점이에요(저장위치·테이블에 코드 파일:라인). 단계는 수집→저장→이용→파기 순이고, 오른쪽 ‘제3자/국외’는 그 항목에 해당 처리가 있다는 뜻이에요. 이 표는 읽기 전용 증적이며, ‘3.x 통제 증적 승격’으로 3.1.1·3.2.1·3.4.1 통제에 연결돼요.')}</div>
        <div style=\"font-size:12px;font-weight:600;color:#111827;margin:10px 0 4px\">${tt('dash.pf.detail','처리흐름 상세')}</div>
        <div id=\"pf_rows\" style=\"margin-top:2px;font-size:12px\"></div>`;
      box.style.display = 'block';
      loadPrivacyFlow();
    }
    window.openPrivacyFlow = openPrivacyFlow;

    async function loadPrivacyFlow() {
      const rowsBox = document.getElementById('pf_rows');
      const dia = document.getElementById('pf_diagram');
      if (!rowsBox) return;
      try {
        const res = await fetch('/privacy/data-flow');
        if (!res.ok) { rowsBox.innerHTML = `<span class=\"empty\">${tt('dash.pf.denied','권한이 없어요 (admin·security)')}</span>`; return; }
        const d = await res.json();
        const rows = d.rows || [];
        const meta = d.meta || {};
        try { const sv = await fetch('/privacy/data-flow.svg'); if (dia) dia.innerHTML = sv.ok ? await sv.text() : ''; } catch(e){ if (dia) dia.innerHTML=''; }
        if (!rows.length) { rowsBox.innerHTML = `<span class=\"empty\">${tt('dash.pf.empty','흐름표가 비어 있어요.')}</span>`; return; }
        // 요약 카드(AI 심층 결과일 때)
        const s = meta.summary || {}; const gaps = meta.gaps || [];
        const card = (v,l) => `<div style=\"border:1px solid #e5e7eb;border-radius:8px;padding:8px 12px;min-width:88px\"><div style=\"font-size:18px;font-weight:700;color:#111827\">${escapeHtml(String(v))}</div><div style=\"font-size:10px;color:#111827\">${escapeHtml(l)}</div></div>`;
        const cardsArr = [];
        if (s.items!=null) cardsArr.push(card(s.items, tt('dash.pf.f_item','개인정보 항목')));
        if (s.tables!=null) cardsArr.push(card(s.tables, tt('dash.pf.sum_tables','저장 테이블')));
        if (s.encryption) cardsArr.push(card(s.encryption, tt('dash.pf.sum_enc','저장 암호화')));
        if (gaps.length) cardsArr.push(card(gaps.length, tt('dash.pf.sum_gaps','파기 흐름 개선 지점')));
        const cards = cardsArr.length ? `<div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px\">${cardsArr.join('')}</div>` : '';
        // 단계별 표(항목 × 수집·저장·이용·파기)
        const catColor = {'일반':'#2563eb','고유식별':'#dc2626','비밀':'#111827','금융':'#ca8a04'};
        const cols = [['collection_source', tt('dash.pf.st_collect','수집')],['store', tt('dash.pf.st_store','저장')],['purpose', tt('dash.pf.st_use','이용')],['destruction', tt('dash.pf.st_dispose','파기')]];
        const th = `<th style=\"padding:4px 6px;text-align:left;color:#111827;font-size:10px;border-bottom:1px solid #e5e7eb\">${tt('dash.pf.f_item','개인정보 항목')}</th>` + cols.map(c => `<th style=\"padding:4px 6px;text-align:left;color:#111827;font-size:10px;border-bottom:1px solid #e5e7eb\">${c[1]}</th>`).join('') + `<th style=\"padding:4px 6px;text-align:left;color:#111827;font-size:10px;border-bottom:1px solid #e5e7eb\">${tt('dash.pf.f_third_party','제3자·국외')}</th>`;
        const cell = v => `<td style=\"padding:5px 6px;border-bottom:1px solid #f3f4f6;vertical-align:top;white-space:pre-line;font-size:11px\">${escapeHtml(v||'—')}</td>`;
        const trs = rows.map(r => {
          const cat = r.category ? ` <span style=\"color:${catColor[r.category]||'#111827'};border:1px solid ${catColor[r.category]||'#111827'};border-radius:5px;padding:0 5px;font-size:10px\">${escapeHtml(r.category)}</span>` : '';
          const seed = r.source==='pii_scan' ? ` <span style=\"color:#2563eb;border:1px solid #2563eb;border-radius:5px;padding:0 5px;font-size:10px\">PII 시드</span>` : '';
          const store = [r.storage_location? (r.storage_location) : '', r.storage_table||''].filter(Boolean).join('\\n');
          const third = [r.third_party?('제3자: '+r.third_party):'', r.overseas?('국외: '+r.overseas):''].filter(Boolean).join('\\n');
          return `<tr><td style=\"padding:5px 6px;border-bottom:1px solid #f3f4f6;vertical-align:top\"><b>${escapeHtml(r.item||'(미기재)')}</b>${cat}${seed}</td>${cell(r.collection_source)}${cell(store)}${cell(r.purpose)}${cell(r.destruction)}${cell(third)}</tr>`;
        }).join('');
        const gapsHtml = gaps.length ? `<div style=\"margin-top:10px\"><div style=\"font-size:12px;font-weight:600;color:#dc2626;margin-bottom:4px\">${tt('dash.pf.gaps_title','파기 흐름 개선 필요 지점')}</div><ul style=\"margin:0;padding-left:16px;font-size:11px;color:#111827;line-height:1.6\">${gaps.map(g=>`<li>${escapeHtml(String(g))}</li>`).join('')}</ul></div>` : '';
        rowsBox.innerHTML = cards + `<div style=\"overflow-x:auto\"><table style=\"width:100%;border-collapse:collapse\"><thead><tr>${th}</tr></thead><tbody>${trs}</tbody></table></div>` + gapsHtml;
      } catch(e) { rowsBox.innerHTML = `<span class=\"empty\">${tt('dash.pf.denied','권한이 없어요 (admin·security)')}</span>`; }
    }
    window.loadPrivacyFlow = loadPrivacyFlow;

    async function seedPrivacyFlow() {
      const res = await fetch('/privacy/data-flow/seed-from-scan', {method:'POST'});
      const msg = document.getElementById('pf_msg');
      if (!res.ok) { if (msg){ msg.style.color='#dc2626'; msg.textContent = tt('dash.pf.denied','권한이 없어요 (admin·security)'); } return; }
      const d = await res.json();
      if (msg){ msg.style.color='#16a34a'; msg.textContent = tt('dash.pf.seeded','시드됨: ')+(d.seeded||0); }
      loadPrivacyFlow();
    }
    window.seedPrivacyFlow = seedPrivacyFlow;

    async function promotePrivacyFlow() {
      const res = await fetch('/privacy/data-flow/promote-evidence', {method:'POST'});
      const msg = document.getElementById('pf_msg');
      if (!res.ok) { if (msg){ msg.style.color='#dc2626'; msg.textContent = tt('dash.pf.promote_fail','승격 실패(흐름표가 비었거나 권한 없음)'); } return; }
      const d = await res.json();
      if (msg){ msg.style.color='#16a34a'; msg.textContent = tt('dash.pf.promoted','통제 증적 승격됨: ')+(d.evidence_promoted||0); }
    }
    window.promotePrivacyFlow = promotePrivacyFlow;

    async function resetPrivacyFlow() {
      if (!confirm(tt('dash.pf.reset_confirm','흐름표를 모두 비웁니다. 재스캔하면 다시 채워져요. 계속할까요?'))) return;
      const res = await fetch('/privacy/data-flow/reset', {method:'POST'});
      const msg = document.getElementById('pf_msg');
      if (!res.ok) { if (msg){ msg.style.color='#dc2626'; msg.textContent = tt('dash.pf.denied','권한이 없어요 (admin·security)'); } return; }
      const d = await res.json();
      if (msg){ msg.style.color='#16a34a'; msg.textContent = tt('dash.pf.reset_done','리셋됨: ')+(d.cleared||0); }
      loadPrivacyFlow();
    }
    window.resetPrivacyFlow = resetPrivacyFlow;

    async function togglePiiCriteria() {
      const el = document.getElementById('pf_criteria');
      if (!el) return;
      if (el.style.display !== 'none') { el.style.display='none'; return; }
      el.style.display='block';
      const res = await fetch('/privacy/pii-criteria');
      if (!res.ok) { el.innerHTML = `<span class=\"empty\">${tt('dash.pf.denied','권한이 없어요 (admin·security)')}</span>`; return; }
      const d = await res.json();
      const defs = (d.defaults||[]).map(x => escapeHtml(x.item)).filter((v,i,a)=>a.indexOf(v)===i).join(', ');
      const custom = (d.custom||[]).map(t => `${t.term}=${t.item}`).join('\\n');
      let opts = {route_match:false, orm_extra:false};
      try { const o = await fetch('/privacy/flow-opts'); if (o.ok) opts = await o.json(); } catch(e){}
      const ck = (id,on,label) => `<label style=\"display:inline-flex;align-items:center;gap:4px;font-size:11px;color:#111827;margin-right:12px\"><input type=\"checkbox\" id=\"${id}\" ${on?'checked':''}> ${label}</label>`;
      el.innerHTML = `<div style=\"color:#111827;margin-bottom:4px\">${tt('dash.pf.criteria_help','스캔은 기본셋 + 아래 커스텀 기준을 함께 써요. 한 줄에 하나씩 <b>정규식=항목라벨</b> (예: 배송지|shippingAddr=주소).')}</div>
        <div style=\"color:#111827;font-size:11px;margin-bottom:4px\">${tt('dash.pf.criteria_default','기본 탐지 항목')}: ${defs}</div>
        <textarea id=\"pf_criteria_txt\" style=\"width:100%;box-sizing:border-box;min-height:80px;font-family:monospace;font-size:12px;border:1px solid #e5e7eb;border-radius:6px;padding:6px\">${escapeHtml(custom)}</textarea>
        <div style=\"margin-top:6px\"><button class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" onclick=\"savePiiCriteria()\">${tt('dash.pf.criteria_save','기준 저장')}</button> <span id=\"pf_criteria_msg\" style=\"font-size:11px;color:#16a34a\"></span></div>
        <div style=\"margin-top:8px;padding-top:8px;border-top:1px solid #e5e7eb\">
          <div style=\"font-size:11px;font-weight:600;color:#111827;margin-bottom:4px\">${tt('dash.pf.opts_title','무료 파서 고급 옵션(옵트인)')}</div>
          ${ck('pf_opt_route', opts.route_match, tt('dash.pf.opt_route','항목별 라우트 매칭(수집·이용·파기 경로 연결)'))}
          ${ck('pf_opt_orm', opts.orm_extra, tt('dash.pf.opt_orm','추가 ORM 파싱(TypeORM·Sequelize·JPA)'))}
          <button class=\"secondary\" style=\"width:auto;padding:3px 10px;font-size:11px;margin-left:6px\" onclick=\"saveFlowOpts()\">${tt('dash.pf.opts_save','옵션 저장')}</button>
          <span id=\"pf_opts_msg\" style=\"font-size:11px;color:#16a34a\"></span>
        </div>`;
    }
    async function saveFlowOpts() {
      const body = {route_match:(document.getElementById('pf_opt_route')||{}).checked||false, orm_extra:(document.getElementById('pf_opt_orm')||{}).checked||false};
      const res = await fetch('/privacy/flow-opts', {method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
      const msg = document.getElementById('pf_opts_msg');
      if (msg){ if(res.ok){ msg.style.color='#16a34a'; msg.textContent = tt('dash.pf.criteria_saved','저장됨 — 다음 스캔부터 반영'); } else { msg.style.color='#dc2626'; msg.textContent = tt('dash.pf.denied','권한이 없어요 (admin·security)'); } }
    }
    window.saveFlowOpts = saveFlowOpts;
    window.togglePiiCriteria = togglePiiCriteria;

    async function savePiiCriteria() {
      const txt = (document.getElementById('pf_criteria_txt')||{}).value || '';
      const custom = txt.split('\\n').map(l => l.trim()).filter(Boolean).map(l => {
        const i = l.lastIndexOf('='); return i<0 ? {term:l, item:'개인정보'} : {term:l.slice(0,i).trim(), item:l.slice(i+1).trim()||'개인정보'};
      });
      const res = await fetch('/privacy/pii-criteria', {method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({custom})});
      const msg = document.getElementById('pf_criteria_msg');
      if (msg){ if(res.ok){ msg.style.color='#16a34a'; msg.textContent = tt('dash.pf.criteria_saved','저장됨 — 다음 스캔부터 반영'); } else { msg.style.color='#dc2626'; msg.textContent = tt('dash.pf.denied','권한이 없어요 (admin·security)'); } }
    }
    window.savePiiCriteria = savePiiCriteria;

    async function runCodeReviewScan() {
      const msg = document.getElementById('scan_msg');
      const repo_url = document.getElementById('scan_url').value.trim();
      const github_token = document.getElementById('scan_token').value.trim();
      const ref = document.getElementById('scan_ref').value.trim() || 'main';
      const modeEl = document.querySelector('input[name=\"scan_mode\"]:checked');
      const workflow = modeEl ? modeEl.value : 'code-review-semgrep.yml';
      if (!repo_url) { msg.textContent = tt('dash.ctl.scan_need_url','레포 URL을 넣으세요'); msg.style.color='#dc2626'; return; }
      if (!github_token) { msg.textContent = tt('dash.ctl.scan_need_tok','GitHub 토큰을 넣으세요'); msg.style.color='#dc2626'; return; }
      msg.textContent = tt('dash.ctl.scan_running','요청 중…'); msg.style.color='#111827';
      try {
        const res = await fetch('/controls/code-review/scan', { method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ repo_url, github_token, ref, workflow }) });
        const d = await res.json().catch(()=>({}));
        if (!res.ok) { msg.textContent = (d.detail || tt('dash.ctl.scan_fail','요청 실패')) + ' (' + res.status + ')'; msg.style.color='#dc2626'; return; }
        document.getElementById('scan_token').value = '';  // 토큰 화면에서 즉시 비움
        msg.textContent = `${d.owner}/${d.repo} ${tt('dash.ctl.scan_done','스캔 요청됨 — 완료되면 트리아지·증적에 반영돼요')}`; msg.style.color='#16a34a';
      } catch(e) { msg.textContent = tt('dash.ctl.scan_fail','요청 실패'); msg.style.color='#dc2626'; }
    }
    window.runCodeReviewScan = runCodeReviewScan;
    async function showCodeReviewTemplate() {
      const pre = document.getElementById('scan_tpl');
      const msg = document.getElementById('scan_tpl_msg');
      try {
        const res = await fetch('/controls/code-review/workflow-template');
        const d = await res.json();
        pre.textContent = d.content || '(empty)';
        pre.style.display = 'block';
        if (navigator.clipboard) {
          try { await navigator.clipboard.writeText(d.content); if (msg) msg.textContent = tt('dash.ctl.scan_tpl_copied','클립보드에 복사됨 — 레포 .github/workflows/code-review-semgrep.yml 에 붙여넣기'); } catch(e) {}
        }
      } catch(e) { pre.textContent = '(불러오기 실패)'; pre.style.display='block'; }
    }
    window.showCodeReviewTemplate = showCodeReviewTemplate;
    async function showFullscanWorkflow() {
      const pre = document.getElementById('scan_fs');
      const msg = document.getElementById('scan_fs_msg');
      try {
        const res = await fetch('/controls/code-review/workflow-template');
        const d = await res.json();
        const c = d.fullscan_content || '';
        pre.textContent = c || '(불러오기 실패)';
        pre.style.display = 'block';
        if (c && navigator.clipboard) {
          try { await navigator.clipboard.writeText(c); if (msg) msg.textContent = tt('dash.ctl.fs_yml_copied','복사됨 — 레포 .github/workflows/code-review-fullscan.yml 로 저장'); } catch(e) {}
        }
      } catch(e) { pre.textContent = '(불러오기 실패)'; pre.style.display='block'; }
    }
    window.showFullscanWorkflow = showFullscanWorkflow;
    async function loadRecentCodeReviewScans() {
      const box = document.getElementById('scan_recent');
      if (!box) return;
      try {
        const res = await fetch('/evidence?delta=code_review_scan&limit=10');
        if (!res.ok) { box.innerHTML = `<span class=\"empty\">${tt('dash.ctl.scan_hist_denied','목록을 볼 수 없어요 (admin·security 권한 필요)')}</span>`; return; }
        const d = await res.json();
        const evs = d.events || [];
        if (!evs.length) { box.innerHTML = `<span class=\"empty\">${tt('dash.ctl.scan_hist_empty','아직 스캔 이력이 없어요. 스캔을 요청하면 여기에 떠요 (0건 클린 스캔도 기록돼요).')}</span>`; return; }
        box.innerHTML = evs.map(e => {
          const env = e.envelope || {};
          const repo = env.repo || e.host_id || '?';
          const commit = (env.commit || '').slice(0,8);
          const when = String(e.received_at || env.scan_time || '').slice(0,16).replace('T',' ');
          const verified = env.verified ? `<span style=\"background:#ffffff22;color:#16a34a;border:1px solid #16a34a55;padding:0 5px;border-radius:5px;font-size:10px\">OIDC ${tt('dash.ctl.scan_hist_verified','검증됨')}</span>` : `<span style=\"background:#ffffff22;color:#111827;border:1px solid #11182755;padding:0 5px;border-radius:5px;font-size:10px\">${tt('dash.ctl.scan_hist_unverified','미검증')}</span>`;
          const toolBadge = env.tool ? ` <span style=\"color:#2563eb;border:1px solid #2563eb;border-radius:5px;padding:0 5px;font-size:10px\">${escapeHtml(env.tool)}</span>` : '';
          const link = env.run_url ? ` · <a href=\"${escapeHtml(env.run_url)}\" target=\"_blank\" style=\"color:#2563eb;text-decoration:none\">GitHub</a>` : '';
          const q = new URLSearchParams(); if (env.repo) q.set('repo', env.repo); if (env.commit) q.set('commit', env.commit);
          const csvUrl = '/controls/code-review/findings.csv' + (q.toString() ? ('?'+q.toString()) : '');
          const dl = ` · <a href=\"#\" onclick=\"event.preventDefault();openCsvPreview({title:tt('dash.ctl.scan_csv_title','코드 리뷰 findings CSV 미리보기'),filename:'mori-code-review-findings.csv',url:'${csvUrl}'})\" style=\"color:#2563eb;text-decoration:none\">${tt('dash.ctl.scan_csv_dl','결과 CSV')}</a>`;
          const del = e.id ? ` <a href=\"#\" title=\"${tt('dash.ctl.scan_del','이력 삭제')}\" onclick=\"event.preventDefault();deleteCodeReviewScan('${escapeHtml(e.id)}')\" style=\"color:#dc2626;text-decoration:none;font-weight:700\">×</a>` : '';
          return `<div style=\"padding:5px 0;border-bottom:1px solid #f3f4f6\">✓ <b>${escapeHtml(repo)}</b>${commit?('@'+escapeHtml(commit)):''} — ${escapeHtml(e.summary||'')} <span style=\"color:#111827\">${escapeHtml(when)}</span> ${verified}${toolBadge}${link}${dl}${del}</div>`;
        }).join('');
      } catch(e) { box.innerHTML = `<span class=\"empty\">${tt('dash.ctl.scan_hist_err','이력을 불러오지 못했어요')}</span>`; }
    }
    window.loadRecentCodeReviewScans = loadRecentCodeReviewScans;

    async function deleteCodeReviewScan(id) {
      if (!confirm(tt('dash.ctl.scan_del_confirm','이 스캔 이력을 삭제할까요?'))) return;
      const res = await fetch('/controls/code-review/scan/' + encodeURIComponent(id), {method:'DELETE'});
      if (res.ok) loadRecentCodeReviewScans();
      else alert(tt('dash.ctl.scan_hist_denied','목록을 볼 수 없어요 (admin·security 권한 필요)'));
    }
    window.deleteCodeReviewScan = deleteCodeReviewScan;

    async function backfillCodeReviewEvidence() {
      try {
        const res = await fetch('/controls/code-review/backfill-evidence', {method:'POST'});
        if (!res.ok) { alert(tt('dash.ctl.scan_backfill_denied','권한이 없거나 실패했어요 (admin·security 필요)')); return; }
        const d = await res.json();
        alert(tt('dash.ctl.scan_backfill_done','과거 스캔 ')+(d.scans||0)+tt('dash.ctl.scan_backfill_done2','건 → 통제 증적 ')+(d.evidence_promoted||0)+tt('dash.ctl.scan_backfill_done3','건 반영됨. 통제 상세에서 확인하세요.'));
        loadRecentCodeReviewScans();
      } catch(e) { alert(tt('dash.ctl.scan_backfill_err','반영 중 오류가 났어요')); }
    }
    window.backfillCodeReviewEvidence = backfillCodeReviewEvidence;

    // ── M2-8: Claude API 키 관리 (admin, env 우선 → DB 폴백) ────────────────────
    async function loadClaudeKeyStatus() {
      const el = document.getElementById('ctl_key_status'); if (!el) return;
      try {
        const r = await fetch('/controls/claude-key');
        if (!r.ok) { el.textContent = ''; return; }
        const d = await r.json();
        if (!d.configured) {
          el.innerHTML = `<span style=\"color:#ca8a04\">${tt('dash.ctl.key_none','키 없음 · 휴리스틱')}</span>`;
        } else {
          const src = d.source === 'env' ? tt('dash.ctl.key_env','환경변수') : tt('dash.ctl.key_db','저장됨');
          el.innerHTML = `<span style=\"color:#16a34a\">Claude ${tt('dash.ctl.key_on','연결됨')} · ${src} ${escapeHtml(d.masked||'')}</span>`;
        }
      } catch(e) { el.textContent = ''; }
    }
    window.loadClaudeKeyStatus = loadClaudeKeyStatus;
    async function openClaudeKey() {
      const box = document.getElementById('ctl_nlp');
      document.getElementById('ctl_editor').style.display = 'none';
      const inp = 'background:#e5e7eb;border:1px solid #e5e7eb;color:#111827;border-radius:6px;padding:6px 9px;font-size:13px';
      let st = { configured:false, source:'none', masked:'', env_locked:false };
      try { const r = await fetch('/controls/claude-key'); if (r.ok) st = await r.json(); } catch(e) {}
      const statusLine = st.configured
        ? `<span style=\"color:#16a34a\">${tt('dash.ctl.key_on','연결됨')} · ${st.source==='env'?tt('dash.ctl.key_env','환경변수'):tt('dash.ctl.key_db','저장됨')} ${escapeHtml(st.masked||'')}</span>`
        : `<span style=\"color:#ca8a04\">${tt('dash.ctl.key_none','키 없음 · 휴리스틱')}</span>`;
      const envNote = st.env_locked ? `<div class=\"subtext\" style=\"color:#ca8a04;margin-top:6px\">${tt('dash.ctl.key_envlock','환경변수 키가 설정돼 있어 UI 저장값보다 우선합니다.')}</div>` : '';
      box.innerHTML = `<div style=\"font-weight:700;color:#2563eb;margin-bottom:6px\">${tt('dash.ctl.key_ttl','Claude API 키 설정')}</div>
        <div class=\"subtext\" style=\"margin-bottom:8px\">${tt('dash.ctl.key_help','키를 저장하면 법령 변환이 Claude로 더 정확해져요. 키는 서버에만 저장되고 화면엔 마스킹돼 보여요.')}</div>
        <div style=\"margin-bottom:8px;font-size:12px\">${tt('dash.ctl.key_cur','현재 상태')}: ${statusLine}</div>
        <input id=\"claude_key_input\" type=\"password\" autocomplete=\"off\" placeholder=\"sk-ant-...\" style=\"${inp};width:100%;box-sizing:border-box\" ${st.env_locked?'disabled':''} />
        ${envNote}
        <div style=\"margin-top:8px;display:flex;gap:8px;align-items:center\">
          <button onclick=\"saveClaudeKey()\" style=\"width:auto;padding:6px 16px\" ${st.env_locked?'disabled':''}>${tt('dash.ctl.key_save','저장')}</button>
          <button onclick=\"saveClaudeKey(true)\" class=\"secondary\" style=\"width:auto;padding:6px 16px\" ${(!st.configured||st.env_locked)?'disabled':''}>${tt('dash.ctl.key_clear','삭제')}</button>
          <button onclick=\"document.getElementById('ctl_nlp').style.display='none'\" class=\"secondary\" style=\"width:auto;padding:6px 16px\">${tt('dash.ctl.cancel','취소')}</button>
          <span id=\"claude_key_msg\" style=\"font-size:12px;color:#111827\"></span>
        </div>`;
      box.style.display = 'block';
    }
    window.openClaudeKey = openClaudeKey;
    async function saveClaudeKey(clear) {
      const msg = document.getElementById('claude_key_msg');
      const val = clear ? '' : (document.getElementById('claude_key_input').value || '').trim();
      if (!clear && !val) { msg.textContent = tt('dash.ctl.key_need','키를 입력하세요'); msg.style.color='#dc2626'; return; }
      msg.textContent = tt('dash.dyn.saving','저장 중…'); msg.style.color='#111827';
      try {
        const r = await fetch('/controls/claude-key', { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ api_key: val }) });
        if (!r.ok) { msg.textContent = tt('dash.ctl.save_fail','저장 실패') + ' (' + r.status + ')'; msg.style.color='#dc2626'; return; }
        msg.textContent = clear ? tt('dash.ctl.key_cleared','삭제됨') : tt('dash.ctl.key_saved','저장됨'); msg.style.color='#16a34a';
        loadClaudeKeyStatus();
        setTimeout(() => { const b=document.getElementById('ctl_nlp'); if (b) b.style.display='none'; }, 800);
      } catch(e) { msg.textContent = tt('dash.ctl.save_fail','저장 실패'); msg.style.color='#dc2626'; }
    }
    window.saveClaudeKey = saveClaudeKey;

    // ── 계정 거버넌스 (admin·security) ─────────────────────────────────────────
    let _accData = { accounts: [], counts: {}, summary: {}, ip_list: [], dormant_days: 90 };
    let _accApprovals = [];
    const _ACC_FIND = { leaver:['퇴사자 잔존','#dc2626',''], orphan_priv:['미등록 특권','#ca8a04',''], unapproved_sudo:['미승인 sudo','#ca8a04',''], dormant:['휴면','#2563eb',''] };
    async function loadAccountsGov() {
      const tableEl = document.getElementById('acc_table');
      if (!tableEl) return;
      tableEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.loading','로딩 중…')}</span>`;
      try {
        const [ovRes, apRes] = await Promise.all([fetch('/accounts/overview'), fetch('/accounts/approvals')]);
        if (!ovRes.ok) { tableEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}HTTP ${ovRes.status}</span>`; return; }
        _accData = await ovRes.json();
        _accApprovals = apRes.ok ? ((await apRes.json()).approvals || []) : [];
        const s = _accData.summary || {};
        const sumEl = document.getElementById('acc_summary');
        if (sumEl) sumEl.textContent = `${tt('dash.acc.hosts','호스트')} ${s.hosts||0} · ${tt('dash.acc.accounts','계정')} ${s.accounts||0} · ${tt('dash.acc.priv','특권')} ${s.privileged||0} · ${tt('dash.acc.dir','디렉터리')} ${s.directory||0}`;
        const c = _accData.counts || {};
        const cardsEl = document.getElementById('acc_finding_cards');
        cardsEl.innerHTML = Object.keys(_ACC_FIND).map(k => { const [lbl,col,em] = _ACC_FIND[k]; const v = c[k]||0; return `<section class=\"card metric-card\" onclick=\"document.getElementById('acc_filter_finding').value='${k}';renderAccounts()\" style=\"padding:14px;cursor:pointer\"><div class=\"metric-label\">${em} ${tt('dash.acc.find.'+k, lbl)}</div><div class=\"metric-value\" style=\"color:${v?col:'#111827'}\">${v}</div></section>`; }).join('');
        renderAccounts(); renderAccApprovals(); renderAccIpList(); loadAccessTrail();
      } catch(e) { tableEl.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`; }
    }
    window.loadAccountsGov = loadAccountsGov;

    // 접속 발자취 — 최근 접속기록 미리보기(전체는 Loki). Loki 미설정 시 안내 + Grafana 링크.
    const _TRAIL_EV = { login:['로그인','login'], sudo:['sudo','sudo'], session_opened:['세션시작','session'], session_closed:['세션종료','session end'] };
    async function loadAccessTrail() {
      const el = document.getElementById('acc_trail'); if (!el) return;
      const meta = document.getElementById('acc_trail_meta');
      const gl = document.getElementById('acc_trail_grafana');
      el.innerHTML = `<span class=\"empty\">${tt('dash.dyn.loading','로딩 중…')}</span>`;
      try {
        const r = await fetch('/accounts/access-trail?limit=30');
        if (!r.ok) { el.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}HTTP ${r.status}</span>`; return; }
        const d = await r.json();
        if (gl && d.grafana_url) { gl.href = d.grafana_url; gl.style.display = ''; }
        if (!d.available) {
          el.innerHTML = `<span class=\"empty\">${tt('dash.acc.trail_off','Loki 접속기록 미연결 — MORI_LOKI_URL 설정 시 최근 접속이 여기 떠요. 전체 로그는 Loki에서 확인하세요.')}</span>`;
          if (meta) meta.textContent = '';
          return;
        }
        const rows = d.entries || [];
        if (meta) meta.textContent = tt('dash.acc.trail_recent','최근') + ' ' + (d.shown||rows.length) + tt('dash.acc.trail_count','건 미리보기');
        if (!rows.length) { el.innerHTML = `<span class=\"empty\">${tt('dash.acc.trail_empty','최근 접속기록 없음')}</span>`; return; }
        const rBadge = (res) => { const c = res==='success'?'#16a34a':(res==='fail'?'#dc2626':'#111827'); const t = res==='success'?tt('dash.acc.trail_ok','성공'):(res==='fail'?tt('dash.acc.trail_fail','실패'):'-'); return `<span style=\"background:${c}22;border:1px solid ${c};color:${c};border-radius:5px;padding:1px 6px;font-size:10px\">${t}</span>`; };
        el.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:12px\"><thead><tr style=\"text-align:left;color:#111827\">`
          + `<th style=\"padding:4px 6px\">${tt('dash.acc.trail_time','시각')}</th><th style=\"padding:4px 6px\">${tt('dash.acc.trail_user','계정')}</th><th style=\"padding:4px 6px\">${tt('dash.acc.trail_event','유형')}</th><th style=\"padding:4px 6px\">${tt('dash.acc.trail_host','호스트')}</th><th style=\"padding:4px 6px\">${tt('dash.acc.trail_ip','출발 IP')}</th><th style=\"padding:4px 6px\">${tt('dash.acc.trail_result','결과')}</th></tr></thead><tbody>`
          + rows.map(e => { const ev = (_TRAIL_EV[e.event]||[e.event])[lang==='en'?1:0] || e.event; return `<tr style=\"border-top:1px solid #f3f4f6\"><td style=\"padding:4px 6px;white-space:nowrap\">${escapeHtml(e.time||'')}</td><td style=\"padding:4px 6px;font-family:monospace\">${escapeHtml(e.user||'')}</td><td style=\"padding:4px 6px\">${escapeHtml(ev)}${e.detail?` <span style=\"color:#111827\">${escapeHtml(e.detail)}</span>`:''}</td><td style=\"padding:4px 6px\">${escapeHtml(e.host||'-')}</td><td style=\"padding:4px 6px;font-family:monospace\">${escapeHtml(e.source_ip||'-')}</td><td style=\"padding:4px 6px\">${rBadge(e.result)}</td></tr>`; }).join('')
          + `</tbody></table>`;
      } catch(e) { el.innerHTML = `<span class=\"empty\">${tt('dash.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`; }
    }
    window.loadAccessTrail = loadAccessTrail;

    function _accFindBadge(f) { const c = (_ACC_FIND[f]||['',''])[1] || '#111827'; return `<span style=\"background:${c}22;border:1px solid ${c};color:${c};border-radius:5px;padding:1px 6px;font-size:10px;margin-right:3px\">${tt('dash.acc.find.'+f, (_ACC_FIND[f]||[f])[0])}</span>`; }
    function renderAccounts() {
      const tableEl = document.getElementById('acc_table'); if (!tableEl) return;
      const q = (document.getElementById('acc_search')?.value||'').trim().toLowerCase();
      const ft = document.getElementById('acc_filter_type')?.value||'';
      const ff = document.getElementById('acc_filter_finding')?.value||'';
      const rows = (_accData.accounts||[]).filter(a => {
        if (q && !(a.username.toLowerCase().includes(q) || a.host_key.toLowerCase().includes(q))) return false;
        if (ft && a.host_type !== ft) return false;
        if (ff === 'flagged' && !a.findings.length) return false;
        if (ff === 'privileged' && !a.is_privileged) return false;
        if (ff && !['flagged','privileged'].includes(ff) && !a.findings.includes(ff)) return false;
        return true;
      });
      if (!rows.length) { tableEl.innerHTML = `<div class=\"empty\">${tt('dash.acc.none','해당 계정이 없습니다. (osquery push 전이거나 필터)')}</div>`; return; }
      const dd = _accData.dormant_days||90;
      tableEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\"><thead><tr style=\"background:#f9fafb\">
        <th style=\"padding:8px;text-align:left\">${tt('dash.acc.col.host','호스트')}</th><th style=\"padding:8px;text-align:left\">${tt('dash.acc.col.user','계정')}</th><th style=\"padding:8px\">${tt('dash.acc.col.priv','특권')}</th><th style=\"padding:8px\">${tt('dash.acc.col.login','최근 로그인')}</th><th style=\"padding:8px;text-align:left\">${tt('dash.acc.col.find','이상')}</th></tr></thead><tbody>
        ${rows.map(a => `<tr>
          <td style=\"padding:6px 8px\"><strong>${escapeHtml(a.host_key)}</strong> <span style=\"color:#111827;font-size:11px\">${a.host_type==='pc'?'PC':''+tt('dash.mine.server','서버')}</span></td>
          <td style=\"padding:6px 8px;font-family:monospace\">${escapeHtml(a.username)}${a.disabled?' <span style=\"color:#111827\">(disabled)</span>':''}</td>
          <td style=\"padding:6px 8px;text-align:center\">${a.is_privileged?`<span style=\"color:#dc2626\">●${a.is_sudo?' sudo':''}</span>`:'-'}</td>
          <td style=\"padding:6px 8px;text-align:center;color:${(a.login_age_days!=null&&a.login_age_days>dd)?'#2563eb':'#111827'};font-size:12px\">${a.login_age_days!=null?a.login_age_days+'d':(a.last_login?'-':'never')}</td>
          <td style=\"padding:6px 8px\">${a.findings.map(_accFindBadge).join('')||'<span style=\"color:#16a34a\"></span>'}</td>
        </tr>`).join('')}</tbody></table>`;
      _pgApply(tableEl);
    }
    window.renderAccounts = renderAccounts;

    function renderAccApprovals() {
      const el = document.getElementById('acc_approvals'); if (!el) return;
      const pending = _accApprovals.filter(a => a.status === 'pending');
      const approved = _accApprovals.filter(a => a.status !== 'pending');
      let html = '';
      if (pending.length) {
        html += `<div style=\"font-weight:700;color:#ca8a04;margin-bottom:6px\">${tt('dash.acc.req.pending_title','승인 대기 요청')} (${pending.length})</div>`;
        html += `<table style=\"width:100%;border-collapse:collapse;font-size:12px;margin-bottom:14px\"><tbody>${pending.map(a => `<tr style=\"border-bottom:1px solid #e5e7eb\">
          <td style=\"padding:5px 6px;font-family:monospace;color:#2563eb\">${escapeHtml(a.username)}</td>
          <td style=\"padding:5px 6px\"><span style=\"background:#ca8a0422;color:#ca8a04;padding:1px 6px;border-radius:4px\">${escapeHtml(a.kind)}</span></td>
          <td style=\"padding:5px 6px;color:#111827\">${a.scope==='host'?escapeHtml(a.host_key):tt('dash.acc.global','전역')}</td>
          <td style=\"padding:5px 6px;color:#111827\">${escapeHtml(a.reason||'')}<div style=\"font-size:10px;color:#111827\">${tt('dash.acc.req.by','요청')}: ${escapeHtml(a.requested_by||'-')}</div></td>
          <td style=\"padding:5px 6px;text-align:right;white-space:nowrap\">
            <button class=\"secondary\" style=\"width:auto;padding:2px 8px;font-size:11px\" onclick=\"approveAccRequest('${escapeHtml(a.id)}')\">${tt('dash.acc.req.approve','승인')}</button>
            <button class=\"danger\" style=\"width:auto;padding:2px 8px;font-size:11px\" onclick=\"rejectAccRequest('${escapeHtml(a.id)}')\">${tt('dash.acc.req.reject','거절')}</button>
          </td></tr>`).join('')}</tbody></table>`;
      }
      if (!approved.length) {
        html += `<span class=\"empty\">${tt('dash.acc.appr_none','등록된 승인이 없습니다.')}</span>`;
      } else {
        html += `<table style=\"width:100%;border-collapse:collapse;font-size:12px\"><tbody>${approved.map(a => `<tr style=\"border-bottom:1px solid #e5e7eb\">
          <td style=\"padding:5px 6px;font-family:monospace;color:#2563eb\">${escapeHtml(a.username)}</td>
          <td style=\"padding:5px 6px\"><span style=\"background:${a.kind==='sudo'?'#ca8a0422':'#e5e7eb'};color:${a.kind==='sudo'?'#ca8a04':'#2563eb'};padding:1px 6px;border-radius:4px\">${escapeHtml(a.kind)}</span></td>
          <td style=\"padding:5px 6px;color:#111827\">${a.scope==='host'?escapeHtml(a.host_key):tt('dash.acc.global','전역')}</td>
          <td style=\"padding:5px 6px;color:#111827\">${escapeHtml(a.reason||'')}</td>
          <td style=\"padding:5px 6px;text-align:right\"><button class=\"danger\" style=\"width:auto;padding:2px 8px;font-size:11px\" onclick=\"deleteAccApproval('${escapeHtml(a.id)}')\">${tt('dash.acc.appr_del','삭제')}</button></td>
        </tr>`).join('')}</tbody></table>`;
      }
      el.innerHTML = html;
    }
    async function _loadHostPrivReq(hostname) {
      const el = document.getElementById('host_detail_privreq'); if (!el) return;
      try {
        const r = await fetch(`/accounts/host/${encodeURIComponent(hostname)}/privileged`);
        if (!r.ok) { el.innerHTML = ''; return; }
        const d = await r.json();
        if (!d.count) { el.innerHTML = ''; return; }
        const badge = st => st==='approved' ? `<span style=\"color:#16a34a;font-size:11px\">${tt('dash.acc.req.approved','승인됨')}</span>`
          : st==='pending' ? `<span style=\"color:#ca8a04;font-size:11px\">${tt('dash.acc.req.pending','승인 대기중')}</span>` : '';
        const rows = d.privileged.map(a => {
          const action = (a.approval_status === 'none')
            ? `<button onclick=\"requestAccApproval('${escapeHtml(hostname)}','${escapeHtml(a.username)}','${a.is_sudo?'sudo':'account'}')\" style=\"padding:2px 10px;font-size:11px;border-radius:4px;background:#2563eb;color:#fff;border:none;cursor:pointer\">${tt('dash.acc.req.btn','승인 요청')}</button>`
            : badge(a.approval_status);
          return `<div style=\"display:flex;justify-content:space-between;align-items:center;gap:8px;padding:5px 6px;border-bottom:1px solid #f9fafb;font-size:12px\">
            <span style=\"font-family:monospace\">${escapeHtml(a.username)} <span style=\"color:#dc2626\">●${a.is_sudo?'sudo':''}</span></span>${action}</div>`;
        }).join('');
        el.innerHTML = `<div style=\"font-weight:700;color:#111827;margin-bottom:6px\">${tt('dash.acc.req.title','특권/sudo 계정 승인 요청')}</div>
          <div style=\"font-size:11px;color:#111827;margin-bottom:6px\">${tt('dash.acc.req.sub','미승인 특권 계정은 승인 요청하면 admin·보안이 검토합니다.')}</div>${rows}`;
      } catch (e) { el.innerHTML = ''; }
    }
    window._loadHostPrivReq = _loadHostPrivReq;
    async function requestAccApproval(hostKey, username, kind) {
      const reason = prompt(tt('dash.acc.req.reason_prompt','승인 요청 사유를 입력하세요 (예: 배포 자동화 계정)'));
      if (reason === null) return;
      try {
        const res = await fetch('/accounts/approval-requests', { method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ host_key: hostKey, username, kind, reason: reason||'' }) });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        _loadHostPrivReq(hostKey);
        if (typeof loadAccountsGov === 'function' && _canViewAccounts()) loadAccountsGov();
        alert(tt('dash.acc.req.done','승인 요청을 보냈습니다. admin·보안 검토 후 반영됩니다.'));
      } catch (e) { alert(tt('dash.dyn.error_prefix','오류: ') + (e.message || e)); }
    }
    window.requestAccApproval = requestAccApproval;
    async function approveAccRequest(id) {
      try {
        const r = await fetch('/accounts/approvals/' + encodeURIComponent(id) + '/approve', { method:'POST' });
        if (!r.ok) throw new Error((await r.json()).detail || r.status);
        await loadAccountsGov();
      } catch (e) { alert(tt('dash.dyn.error_prefix','오류: ') + (e.message || e)); }
    }
    window.approveAccRequest = approveAccRequest;
    async function rejectAccRequest(id) {
      if (!confirm(tt('dash.acc.req.reject_confirm','이 승인 요청을 거절할까요?'))) return;
      try {
        const r = await fetch('/accounts/approvals/' + encodeURIComponent(id) + '/reject', { method:'POST' });
        if (!r.ok) throw new Error((await r.json()).detail || r.status);
        await loadAccountsGov();
      } catch (e) { alert(tt('dash.dyn.error_prefix','오류: ') + (e.message || e)); }
    }
    window.rejectAccRequest = rejectAccRequest;
    async function addAccApproval() {
      const g = id => document.getElementById(id);
      const username = g('acc_appr_user').value.trim();
      if (!username) return;
      const host = g('acc_appr_host').value.trim();
      const body = { username, kind: g('acc_appr_kind').value, reason: g('acc_appr_reason').value.trim() };
      if (host) { body.scope = 'host'; body.host_key = host; }
      try {
        const res = await fetch('/accounts/approvals', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        ['acc_appr_user','acc_appr_host','acc_appr_reason'].forEach(i => g(i).value='');
        await loadAccountsGov();
      } catch(e) { alert(tt('dash.dyn.error_prefix','오류: ') + e.message); }
    }
    window.addAccApproval = addAccApproval;
    async function deleteAccApproval(id) {
      try {
        const res = await fetch('/accounts/approvals/' + encodeURIComponent(id), { method:'DELETE' });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        await loadAccountsGov();
      } catch(e) { alert(tt('dash.dyn.error_prefix','오류: ') + e.message); }
    }
    window.deleteAccApproval = deleteAccApproval;

    function _ipFiltered() {
      const q = (document.getElementById('ip_search')?.value||'').trim().toLowerCase();
      const tm = document.getElementById('ip_filter_team')?.value||'';
      const cat = document.getElementById('ip_filter_cat')?.value||'';
      return (_accData.ip_list||[]).filter(h => {
        if (q && !((h.hostname||'').toLowerCase().includes(q) || (h.primary_ip||'').toLowerCase().includes(q))) return false;
        if (tm && (h.team||'') !== tm) return false;
        if (cat && (h.category||'') !== cat) return false;
        return true;
      });
    }
    function renderAccIpList() {
      const el = document.getElementById('acc_ip_list'); if (!el) return;
      const all = _accData.ip_list || [];
      // 팀/용도 옵션 채우기(최초 1회 유지)
      const fillSel = (id, vals) => { const s=document.getElementById(id); if(!s) return; const cur=s.value; while(s.options.length>1) s.remove(1); [...new Set(vals.filter(Boolean))].sort((a,b)=>a.localeCompare(b,'ko')).forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;s.appendChild(o);}); if(cur) s.value=cur; };
      fillSel('ip_filter_team', all.map(h=>h.team));
      fillSel('ip_filter_cat', all.map(h=>h.category));
      const rows = _ipFiltered();
      const cnt = document.getElementById('ip_count'); if (cnt) cnt.textContent = `${rows.length}/${all.length}`;
      if (!rows.length) { el.innerHTML = `<span class=\"empty\">${tt('dash.acc.ip_none','호스트 없음')}</span>`; return; }
      el.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:12px\"><thead><tr style=\"background:#f9fafb\">
        <th style=\"padding:6px;text-align:left\">${tt('dash.dyn.lbl.hostname','호스트명')}</th>
        <th style=\"padding:6px;text-align:left\">IP</th>
        <th style=\"padding:6px;text-align:left\">${tt('dash.acc.ip_col_team','팀')}</th>
        <th style=\"padding:6px;text-align:left\">${tt('dash.acc.ip_col_cat','용도')}</th>
        <th style=\"padding:6px;text-align:left\">${tt('dash.dyn.lbl.status','상태')}</th></tr></thead><tbody>${rows.map(h => `<tr>
          <td style=\"padding:5px 6px;text-align:left\"><strong>${escapeHtml(h.hostname)}</strong></td>
          <td style=\"padding:5px 6px;text-align:left;font-family:monospace;color:#111827\">${escapeHtml(h.primary_ip||'-')}</td>
          <td style=\"padding:5px 6px;text-align:left;color:#111827\">${escapeHtml(h.team||'-')}</td>
          <td style=\"padding:5px 6px;text-align:left;color:#111827\">${escapeHtml(h.category||'-')}</td>
          <td style=\"padding:5px 6px;text-align:left\"><span class=\"badge ${h.status==='online'?'online':h.status==='offline'?'offline':'unknown'}\">${escapeHtml(h.status||'-')}</span></td>
        </tr>`).join('')}</tbody></table>`;
      _pgApply(el);
    }
    function _renderCsvPreviewBody(bodyEl, text) {
      const rows = _parseSimpleCsv((text || '').replace(/^\\uFEFF/, ''));
      if (rows.length === 0) {
        bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#111827;padding:24px;text-align:center\">' + tt('dash.dyn.no_data', '데이터가 없습니다.') + '</div>';
        return;
      }
      const headers = rows[0] || [];
      const dataRows = rows.slice(1).filter(r => r.length > 0 && !(r.length === 1 && r[0] === ''));
      const limit = 50;
      const shown = dataRows.slice(0, limit);
      const overflowNote = dataRows.length > limit
        ? `<div style=\"color:#111827;font-size:12px;margin-top:10px\">${tt('dash.dyn.report_overflow','… 총 {n}행 중 상위 {limit}행만 표시됩니다. 전체는 CSV 다운로드로 확인하세요.').replace('{n}','<strong style=\\\"color:#111827\\\">'+dataRows.length+'</strong>').replace('{limit}',limit)}</div>`
        : `<div style=\"color:#111827;font-size:12px;margin-top:10px\">${tt('dash.dyn.report_total_rows','총 {n}행').replace('{n}','<strong style=\\\"color:#111827\\\">'+dataRows.length+'</strong>')}</div>`;
      const head = '<thead><tr style=\"color:#111827;border-bottom:1px solid #111827;background:#ffffff;position:sticky;top:0\">'
        + headers.map(h => `<th style=\"text-align:left;padding:6px 10px;font-size:12px;white-space:nowrap\">${escapeHtml(h)}</th>`).join('')
        + '</tr></thead>';
      const body = shown.map(r => '<tr style=\"border-bottom:1px solid #e2e8f0\">'
        + headers.map((_, idx) => `<td style=\"padding:6px 10px;font-size:12px;color:#111827;white-space:nowrap;max-width:280px;overflow:hidden;text-overflow:ellipsis\" title=\"${escapeHtml(r[idx] || '')}\">${escapeHtml(r[idx] || '')}</td>`).join('')
        + '</tr>').join('');
      bodyEl.innerHTML = `<div style=\"max-height:60vh;overflow:auto;border:1px solid #e2e8f0;border-radius:6px\"><table style=\"width:100%;border-collapse:collapse\">${head}<tbody>${body}</tbody></table></div>${overflowNote}`;
    }

    /* 범용 CSV 미리보기+다운로드 (report_preview_modal 재사용). opts:{title,subtitle,filename,url|text} */
    async function openCsvPreview(opts) {
      opts = opts || {};
      const modal = document.getElementById('report_preview_modal');
      const titleEl = document.getElementById('report_preview_title');
      const bodyEl = document.getElementById('report_preview_body');
      const dlEl = document.getElementById('report_preview_download');
      const dlPdfEl = document.getElementById('report_preview_download_pdf');
      const subEl = document.getElementById('report_preview_subtitle');
      if (!modal || !bodyEl) return;
      titleEl.textContent = opts.title || tt('dash.modal.csv_preview_title', 'CSV 미리보기');
      if (dlPdfEl) dlPdfEl.style.display = 'none';   // CSV 전용(PDF 없음)
      if (subEl) subEl.textContent = opts.subtitle || tt('dash.modal.csv_preview_sub', 'CSV 파일이 아래와 같은 형태로 생성됩니다. (상위 50행 미리보기)');
      dlEl.setAttribute('download', opts.filename || 'export.csv');
      bodyEl.innerHTML = '<div class=\"empty\" style=\"color:#111827;padding:24px;text-align:center\">' + tt('dash.dyn.loading_fetch', '불러오는 중…') + '</div>';
      modal.style.display = 'flex';
      try {
        let text = opts.text;
        if (opts.url) {
          const res = await fetch(opts.url);
          if (!res.ok) throw new Error(res.status);
          text = await res.text();
          dlEl.href = opts.url;
        } else {
          const blob = new Blob(['\\uFEFF' + (text || '')], { type: 'text/csv;charset=utf-8' });
          dlEl.href = URL.createObjectURL(blob);
        }
        _renderCsvPreviewBody(bodyEl, text || '');
      } catch (e) {
        bodyEl.innerHTML = `<div class=\"empty\" style=\"color:#dc2626;padding:24px;text-align:center\">${tt('dash.dyn.report_load_fail','불러올 수 없습니다: ')}${escapeHtml(String(e.message || e))}</div>`;
      }
    }
    window.openCsvPreview = openCsvPreview;

    function exportIpCsv() {
      const rows = _ipFiltered();
      const head = ['hostname','ip','team','category','status'];
      const csv = [head.join(',')].concat(rows.map(h => [h.hostname, h.primary_ip||'', h.team||'', h.category||'', h.status||''].map(v => `\"${String(v).replaceAll('\"','\"\"')}\"`).join(','))).join('\\n');
      openCsvPreview({
          title: tt('dash.modal.ip_csv_preview_title','IP 리스트 CSV 미리보기'),
          filename: `mori-ip-list-${new Date().toISOString().slice(0,10)}.csv`,
          text: csv,
        });
    }
    window.exportIpCsv = exportIpCsv;
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
          { key:'vuln_pending', icon:'', label: tt('dash.gap.vuln','조치 안 된 Critical/High'), tab:'compliance', color:'#dc2626' },
          { key:'exceptions_expiring', icon:'', label: tt('dash.gap.exc','예외 만료 D-7 이내'), tab:'assets', color:'#ca8a04' },
          { key:'untriaged_alerts', icon:'', label: tt('dash.gap.alert','미트리아지 alert'), tab:'triage', color:'#ca8a04' },
          { key:'code_review_pending', icon:'', label: tt('dash.gap.code_review','미조치 코드 보안 리뷰'), tab:'triage', color:'#ca8a04' },
          { key:'overdue', icon:'', label: tt('dash.gap.overdue','조치 기한 초과'), tab:'compliance', color:'#dc2626' },
          { key:'unmapped_assets', icon:'', label: tt('dash.gap.unmapped','미매핑 자산 (자산 대사)'), tab:'assets', color:'#2563eb' },
          { key:'access_uncovered', icon:'', label: tt('dash.gap.access','접속기록 미수집 서버'), tab:'accounts', color:'#dc2626' },
          { key:'control_pending', icon:'', label: tt('dash.gap.control','미조치 통제'), tab:'compliance', color:'#2563eb' },
        ];
        box.innerHTML = `<div style=\"display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px\">` +
          tiles.map(t => {
            const n = Number(g[t.key] || 0);
            return `<div onclick=\"switchTab('${t.tab}')\" role=\"button\" tabindex=\"0\" style=\"cursor:pointer;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:4px\">
              <div style=\"font-size:12px;color:#111827\">${t.icon} ${escapeHtml(t.label)}</div>
              <div style=\"font-size:24px;font-weight:800;color:${n>0?t.color:'#e5e7eb'}\">${n}</div>
            </div>`;
          }).join('') + `</div>`;
      } catch(e) { box.innerHTML = `<div class=\"empty\">${tt('dash.gap.err','증적 공백을 불러오지 못했습니다.')}</div>`; }
    }
    window.loadEvidenceGaps = loadEvidenceGaps;
    function _tabOrderKey() { return 'mori_tab_order_' + (((document.getElementById('ui_user_badge')||{}).textContent || 'anon').trim() || 'anon'); }
    function _saveTabOrder() {
      const nav = document.getElementById('main_tabs_nav');
      if (!nav) return;
      const order = [...nav.querySelectorAll('button[data-tab]')].map(b => b.dataset.tab);
      try { localStorage.setItem(_tabOrderKey(), JSON.stringify(order)); } catch (e) {}
    }
    function _applyTabOrder() {
      const nav = document.getElementById('main_tabs_nav');
      if (!nav) return;
      let order = null;
      try { order = JSON.parse(localStorage.getItem(_tabOrderKey()) || 'null'); } catch (e) {}
      if (!Array.isArray(order)) return;
      // 저장된 순서대로 재배치. 목록에 없는(새로 추가된) 탭은 뒤에 그대로 남음.
      order.forEach(tab => {
        const btn = nav.querySelector(`button[data-tab=\"${tab}\"]`);
        if (btn) nav.appendChild(btn);
      });
    }
    function _initTabReorder() {
      const nav = document.getElementById('main_tabs_nav');
      if (!nav || nav._reorderInit) return;
      nav._reorderInit = true;
      let dragEl = null;
      nav.querySelectorAll('button[data-tab]').forEach(btn => {
        btn.setAttribute('draggable', 'true');
        btn.style.cursor = 'grab';
      });
      nav.addEventListener('dragstart', e => {
        const b = e.target.closest('button[data-tab]');
        if (!b) return;
        dragEl = b; b.style.opacity = '0.4';
        if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
      });
      nav.addEventListener('dragend', () => {
        if (dragEl) dragEl.style.opacity = '';
        dragEl = null;
        _saveTabOrder();
      });
      nav.addEventListener('dragover', e => {
        if (!dragEl) return;
        e.preventDefault();
        const target = e.target.closest('button[data-tab]');
        if (!target || target === dragEl) return;
        const rect = target.getBoundingClientRect();
        const before = (e.clientX - rect.left) < rect.width / 2;
        nav.insertBefore(dragEl, before ? target : target.nextSibling);
      });
    }
    window._initTabReorder = _initTabReorder;

    async function applyRoleBasedTabs() {
      try {
        const res = await fetch('/auth/me');
        if (!res.ok) return;
        const me = await res.json();
        _currentUserRole = me.role || 'user';
        if (Array.isArray(me.account_view_roles) && me.account_view_roles.length) _accountViewRoles = me.account_view_roles;
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
          heroP.innerHTML = `${tt('dash.dyn.welcome_prefix','환영합니다, ')}<strong style="color:#2563eb">${escapeHtml(me.username)}</strong> <span style="background:#e5e7eb;color:#2563eb;padding:2px 8px;border-radius:6px;font-size:12px">${escapeHtml(roleLabel)}</span>`;
        }
        const badge = document.getElementById('ui_user_badge');
        if (badge && me.username) { badge.removeAttribute('data-i18n'); badge.textContent = me.username; }
        const adminLink = document.getElementById('ui_admin_console_link');
        if (adminLink) adminLink.style.display = (_currentUserRole === 'admin') ? 'block' : 'none';
        _applyRiskGating();
        _applyEvidenceGating();
        _applyAccountGating();
        _initTabReorder();   // 상단 메뉴 드래그 정렬 활성화
        _applyTabOrder();    // 사용자별 저장된 순서 복원
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
      st.textContent = ''; st.style.color = '#111827';
      document.getElementById('profile_modal').style.display = 'flex';
    };
    window.closeProfileModal = function() { document.getElementById('profile_modal').style.display = 'none'; };
    window.saveProfile = async function() {
      const st = document.getElementById('profile_modal_status');
      const display_name = document.getElementById('profile_display_name').value.trim();
      const department = document.getElementById('profile_department').value.trim();
      const assigned_servers = document.getElementById('profile_assigned_servers').value;
      st.style.color = '#111827';
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
        st.style.color = '#16a34a';
        st.textContent = tt('dash.profile.saved', '저장 완료 ');
        if (typeof renderMyServers === 'function') renderMyServers();
        setTimeout(closeProfileModal, 700);
      } catch(e) {
        st.style.color = '#dc2626';
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
          nlqInterpretResult.textContent = `${tt('dash.dyn.nlq.interpret_result','해석 결과')}: ${data.intent} (${data.recognized ? tt('dash.dyn.nlq.recognized','인식됨') : tt('dash.dyn.nlq.fuzzy','유사 매칭')})${data.warnings?.length ? ' ' + data.warnings.join(', ') : ''}`;
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
        dashboardStatusEl.textContent = `${tt('dash.dyn.dash_load_fail', '대시보드 로드 실패')}: ${e.message}`;
        // 빈 데이터라도 placeholder 표시
        if (!sourceCoverageEl.children.length) sourceCoverageEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_source_connected','데이터 소스가 아직 연결되지 않았습니다.') + '</div>';
        if (!latestStatusEl.children.length || latestStatusEl.querySelector('.empty')) latestStatusEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_host_api','호스트 데이터 없음 API 연결을 확인하세요.') + '</div>';
        if (!riskSummaryEl.children.length || riskSummaryEl.querySelector('.empty')) riskSummaryEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_risk_summary','위험 요약 데이터 없음') + '</div>';
        if (!recentActivityEl.children.length || recentActivityEl.querySelector('.empty')) recentActivityEl.innerHTML = '<div class=\"empty\">' + tt('dash.dyn.empty.no_recent_activity','최근 활동 데이터 없음') + '</div>';
        overviewCardsEl.innerHTML = '<div class=\"empty\" style=\"padding:16px;color:#dc2626\">' + tt('dash.dyn.dash_load_fail_full','대시보드 데이터를 불러올 수 없습니다. 서버 상태를 확인하세요.') + '</div>';
      }
    }

    initialize();
  </script>

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
        html.replace("__DOCS_PORTAL_URL__", docs_url)
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


