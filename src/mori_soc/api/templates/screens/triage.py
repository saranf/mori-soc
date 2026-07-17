"""알림 분류 화면 탭 HTML 조각.

dashboard_tabs.py 에서 화면 단위로 분리. 순수 문자열 상수 하나만 보유.
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
