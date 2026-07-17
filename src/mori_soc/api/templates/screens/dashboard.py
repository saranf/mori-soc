"""대시보드 화면 탭 HTML 조각.

dashboard_tabs.py 에서 화면 단위로 분리. 순수 문자열 상수 하나만 보유.
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
