"""대시보드 탭 HTML 조각 (P3: dashboard.py 거대 리터럴에서 분리).

render_user_dashboard_html 이 __TAB_*__ placeholder 치환으로 조립한다. 순수 문자열 상수.
"""

_TAB_GUIDES_HTML = """    <!-- ── Tab: 가이드·기준 ────────────────────────────────────────── -->
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
"""

_TAB_DASHBOARD_HTML = """    <!-- ── Tab: Dashboard ──────────────────────────────────────────────── -->
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
      <!-- P1: #dash_grid 레이아웃 CSS는 static/css/dashboard.css 로 이관됨 -->
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

"""

_TAB_TRIAGE_HTML = """    <!-- ── Tab: Alert Triage ───────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_triage\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.triage\">Alert Triage</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.triage.sub\">최근 24시간 경보예요. 상태를 눌러 처리하세요.</div>
        <div style=\"margin:0 0 12px;padding:8px 11px;background:#f9fafb;border:1px solid #e5e7eb;border-left:3px solid #2563eb;border-radius:8px;font-size:12px;color:#4b5563;line-height:1.65\" data-i18n=\"dash.card.triage.help\">이 탭을 열어두면 30초마다 자동으로 갱신돼요(처리 중일 땐 멈춤). 상태를 눌러 접수 → 조사중 → 완료로 처리하고, 소스 배지를 누르면 원본(Zabbix 등)으로 이동합니다.</div>
        <div class=\"table-wrap\" id=\"triage_table\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        <div style=\"margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap\">
          <button id=\"reload_triage\" class=\"secondary\" data-i18n=\"dash.btn.reload\">새로고침</button>
          <label for=\"triage_refresh_sec\" style=\"font-size:12px;color:#111827\" data-i18n=\"dash.autorefresh.label\">자동 갱신</label>
          <select id=\"triage_refresh_sec\" class=\"inp-sm\" style=\"width:auto;padding:5px 8px;font-size:12px\">
            <option value=\"30\" data-i18n=\"dash.autorefresh.30s\">30초마다</option>
            <option value=\"60\" data-i18n=\"dash.autorefresh.1m\">1분마다</option>
            <option value=\"180\" data-i18n=\"dash.autorefresh.3m\">3분마다</option>
            <option value=\"0\" data-i18n=\"dash.autorefresh.off\">끄기</option>
          </select>
        </div>
      </section>
    </div>

"""

_TAB_INCIDENTS_HTML = """    <!-- ── Tab: Incidents ─────────────────────────────────────────────── -->
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

"""

_TAB_ASSETS_HTML = """    <!-- ── Tab: 자산 현황 ─────────────────────────────────────────────── -->
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
              <button onclick=\"importAssetOwnersCsv()\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv_import\">CSV 가져오기</button>
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
              <button onclick=\"importAssetOwnersCsv()\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\" data-i18n=\"dash.btn.csv_import\">CSV 가져오기</button>
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

"""

_TAB_COMPLIANCE_HTML = """    <!-- ── Tab: Compliance PDCA ──────────────────────────────────────── -->
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
              <button class=\"secondary\" style=\"width:auto;padding:6px 12px;font-size:12px\" onclick=\"loadEvidenceFreshness()\" data-i18n=\"dash.fresh.btn\">증적 신선도</button>
              <a href=\"/controls/evidence-bundle.zip\" download style=\"background:#f9fafb;border:1px solid #e5e7eb;color:#2563eb;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none\" data-i18n=\"dash.ctl.zip\">전체 증적 ZIP</a>
            </div>
          </div>
          <div id=\"evidence_freshness_box\" style=\"display:none;margin-top:8px;padding:10px 12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px\"></div>
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

"""

_TAB_ACCOUNTS_HTML = """    <!-- ── Tab: 계정 거버넌스 (admin·security 전용) ──────────────────────── -->
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

"""
