"""자산 현황 화면 탭 HTML 조각.

dashboard_tabs.py 에서 화면 단위로 분리. 순수 문자열 상수 하나만 보유.
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
            <label style=\"display:inline-flex;align-items:center;gap:5px;color:#191f28;font-size:12px;cursor:pointer;white-space:nowrap\"><input type=\"checkbox\" id=\"fleet_search_mine\" onchange=\"filterAssetTable('fleet')\" /> <span data-i18n=\"dash.assets.only_mine\">내 자산만</span></label>
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
            <label style=\"display:inline-flex;align-items:center;gap:5px;color:#191f28;font-size:12px;cursor:pointer;white-space:nowrap\"><input type=\"checkbox\" id=\"zabbix_search_mine\" onchange=\"filterAssetTable('zabbix')\" /> <span data-i18n=\"dash.assets.only_mine\">내 자산만</span></label>
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
              <span id=\"risk_matrix_assessed\" style=\"font-size:12px;color:#191f28\"></span>
              <button onclick=\"event.stopPropagation();openRiskMatrixModal()\" class=\"secondary\" style=\"width:auto;padding:4px 10px;font-size:12px\" data-i18n=\"dash.risk.open_modal\">매트릭스 열기</button>
            </div>
          </div>
          <div class=\"subtext\" data-i18n=\"dash.risk.matrix_sub\">위험도는 영향도 × 발생가능성으로 계산해요. 아직 평가 안 한 건 자동 제안 등급으로 잡아요.</div>
          <div id=\"risk_doa_ctl\" style=\"margin-top:8px\" ondblclick=\"event.stopPropagation()\"></div>
          <div style=\"font-size:11px;color:#191f28;margin-top:8px\" data-i18n=\"dash.risk.dblclick_hint\">카드를 더블클릭하거나 '매트릭스 열기'를 누르면 3×3 매트릭스가 팝업으로 열립니다.</div>
        </section>
        <!-- 위험성 평가 매트릭스 팝업 -->
        <div id=\"risk_matrix_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9998;align-items:center;justify-content:center\">
          <div style=\"background:#f7f8fa;border:1px solid #e5e8eb;border-radius:10px;padding:24px 28px;width:1080px;max-width:96vw;max-height:90vh;overflow:auto\">
            <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;gap:12px\">
              <h3 style=\"color:#3182f6;margin:0\" data-i18n=\"dash.risk.matrix_title\">위험성 평가 매트릭스</h3>
              <button onclick=\"closeRiskMatrixModal()\" style=\"background:none;border:none;color:#191f28;font-size:20px;cursor:pointer\">×</button>
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
            <span style=\"color:#191f28;font-size:12px;margin-left:4px\" data-i18n=\"dash.assets.detected_date\">탐지일:</span>
            <input type=\"date\" id=\"trivy_search_date_from\" onchange=\"filterAssetTable('trivy')\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:4px;padding:4px 6px;font-size:12px\" title=\"시작일\" data-i18n-title=\"dash.inc.date_from\" />
            <span style=\"color:#191f28;font-size:12px\">~</span>
            <input type=\"date\" id=\"trivy_search_date_to\" onchange=\"filterAssetTable('trivy')\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:4px;padding:4px 6px;font-size:12px\" title=\"종료일\" data-i18n-title=\"dash.inc.date_to\" />
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
              <label style=\"color:#191f28;font-size:13px;white-space:nowrap\" data-i18n=\"dash.assets.mine.groupby\">그룹 기준</label>
              <select id=\"mine_group_by\" onchange=\"renderMyServers()\" style=\"background:#f7f8fa;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:4px 8px;font-size:13px\">
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
