"""인시던트 화면 탭 HTML 조각.

dashboard_tabs.py 에서 화면 단위로 분리. 순수 문자열 상수 하나만 보유.
"""

_TAB_INCIDENTS_HTML = """    <!-- ── Tab: Incidents ─────────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_incidents\">
      <section class=\"card\">
        <h2 data-i18n=\"dash.card.incidents\">인시던트 관리</h2>
        <div class=\"subtext\" data-i18n=\"dash.card.incidents.sub\">여러 경보를 하나의 인시던트로 묶고 조사 노트를 남깁니다.</div>
        <!-- 검색 + 날짜 필터 + CSV 다운로드 -->
        <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px;padding:10px 12px;background:#f7f8fa;border-radius:8px;border:1px solid #e5e8eb\">
          <input type=\"text\" id=\"inc_search\" placeholder=\"제목 · 담당자 · 상태 검색\" data-i18n-placeholder=\"dash.inc.search_ph\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 10px;font-size:13px;min-width:180px;flex:1\" />
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#191f28;font-size:13px;white-space:nowrap\" data-i18n=\"dash.inc.date_from\">시작일</label>
            <input type=\"date\" id=\"inc_date_from\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#191f28;font-size:13px;white-space:nowrap\" data-i18n=\"dash.inc.date_to\">종료일</label>
            <input type=\"date\" id=\"inc_date_to\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <button id=\"inc_filter_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px\" data-i18n=\"dash.inc.filter_btn\">조회</button>
          <button id=\"inc_new_btn\" style=\"padding:5px 14px;font-size:13px;background:#3182f6;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600\" data-i18n=\"dash.inc.new_btn\">+ 새 인시던트</button>
          <button id=\"inc_csv_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px;background:#eaf1fe;color:#3182f6\" data-i18n=\"dash.inc.csv_btn\">CSV 다운로드</button>
        </div>
        <!-- 요약 스트립: 인시던트 상태별 집계 (loadIncidents 가 실데이터로 채움) -->
        <div class=\"mori-strip\" id=\"incident_summary\" style=\"display:none;margin-bottom:14px;padding:14px 16px;background:#f7f8fa;border:1px solid #e5e8eb;border-radius:12px\"></div>
        <div id=\"incidents_list\" class=\"list\" style=\"margin-bottom:14px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
      </section>
    </div>

    <!-- 새 인시던트 생성 모달 (버튼 클릭 시 팝업) -->
    <div id=\"incident_create_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9998;align-items:center;justify-content:center\">
      <div style=\"background:#f7f8fa;border:1px solid #e5e8eb;border-radius:10px;padding:24px 28px;width:560px;max-width:95vw;max-height:90vh;overflow:auto\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
          <h3 style=\"color:#3182f6;margin:0\" data-i18n=\"dash.inc.create_title\">새 인시던트 생성</h3>
          <button onclick=\"closeIncidentCreateModal()\" style=\"background:none;border:none;color:#191f28;font-size:20px;cursor:pointer\">×</button>
        </div>
        <div class=\"row\">
          <label for=\"inc_title\" data-i18n=\"dash.f.title\">제목</label>
          <input id=\"inc_title\" placeholder=\"예: 특정 서버 무단 접근 시도\" data-i18n-placeholder=\"dash.inc.title_ph\" />
        </div>
        <div class=\"row\" style=\"position:relative\">
          <label for=\"inc_hostname\"><span data-i18n=\"dash.inc.host\">관련 호스트</span> <span style=\"color:#191f28;font-size:11px\" data-i18n=\"dash.inc.host_hint\">(검색)</span></label>
          <input id=\"inc_hostname\" placeholder=\"호스트명 입력…\" data-i18n-placeholder=\"dash.inc.host_ph\" autocomplete=\"off\" oninput=\"_incHostSearch(this.value)\" />
          <div id=\"inc_host_suggestions\" style=\"display:none;position:absolute;top:100%;left:0;right:0;background:#e5e8eb;border:1px solid #e5e8eb;border-radius:6px;max-height:160px;overflow-y:auto;z-index:100\"></div>
        </div>
        <div class=\"row\">
          <label for=\"inc_analyst\"><span data-i18n=\"dash.f.analyst\">담당자</span> <span style=\"color:#191f28;font-size:11px\" data-i18n=\"dash.inc.analyst_hint\">(호스트 담당자 자동 입력)</span></label>
          <input id=\"inc_analyst\" placeholder=\"예: 홍길동\" data-i18n-placeholder=\"dash.ph.name_example\" />
        </div>
        <div style=\"margin:8px 0\">
          <label style=\"display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;color:#191f28\">
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
