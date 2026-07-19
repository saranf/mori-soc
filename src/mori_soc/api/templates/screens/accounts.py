"""계정 거버넌스 화면 탭 HTML 조각.

dashboard_tabs.py 에서 화면 단위로 분리. 순수 문자열 상수 하나만 보유.
"""

_TAB_ACCOUNTS_HTML = """    <!-- ── Tab: 계정 거버넌스 (admin·security 전용) ──────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_accounts\">

      <section class=\"card\">
        <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
          <h2 style=\"margin:0\" data-i18n=\"dash.acc.list_title\">계정 목록 (서버 · PC)</h2>
          <div style=\"display:flex;gap:6px;flex-wrap:wrap;align-items:center\">
            <input id=\"acc_search\" placeholder=\"계정/호스트 검색…\" data-i18n-placeholder=\"dash.acc.search_ph\" oninput=\"renderAccounts()\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 10px;font-size:13px;width:180px\" />
            <select id=\"acc_filter_type\" onchange=\"renderAccounts()\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.f.alltype\">전체 유형</option><option value=\"server\" data-i18n=\"dash.acc.f.server\">서버</option><option value=\"pc\" data-i18n=\"dash.acc.f.pc\">PC</option></select>
            <select id=\"acc_filter_finding\" onchange=\"renderAccounts()\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.f.allfind\">전체</option><option value=\"flagged\" data-i18n=\"dash.acc.f.flagged\">이상만</option><option value=\"leaver\" data-i18n=\"dash.acc.find.leaver\">퇴사자 잔존</option><option value=\"orphan_priv\" data-i18n=\"dash.acc.find.orphan_priv\">미등록 특권</option><option value=\"unapproved_sudo\" data-i18n=\"dash.acc.find.unapproved_sudo\">미승인 sudo</option><option value=\"dormant\" data-i18n=\"dash.acc.find.dormant\">휴면</option><option value=\"privileged\" data-i18n=\"dash.acc.f.priv\">특권만</option></select>
          </div>
        </div>
        <div class=\"table-wrap\" id=\"acc_table\" style=\"margin-top:10px\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
      </section>

      <!-- 접속 발자취 (Access Trail) — 실제 접속기록 미리보기, 전체는 Loki -->
      <section class=\"card\">
        <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px\">
          <h2 style=\"margin:0\" data-i18n=\"dash.acc.trail_title\">접속 발자취 (누가 · 언제 · 어디서)</h2>
          <div style=\"display:flex;gap:10px;align-items:center\">
            <span id=\"acc_trail_meta\" style=\"font-size:12px;color:#191f28\"></span>
            <a id=\"acc_trail_grafana\" href=\"#\" target=\"_blank\" style=\"display:none;color:#3182f6;font-size:12px;text-decoration:none\" data-i18n=\"dash.acc.trail_full\">전체는 Loki에서 →</a>
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
            <input id=\"acc_appr_user\" placeholder=\"username\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 10px;font-size:13px;width:120px\" />
            <select id=\"acc_appr_kind\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"account\">account</option><option value=\"sudo\">sudo</option></select>
            <input id=\"acc_appr_host\" placeholder=\"host(비우면 전역)\" data-i18n-placeholder=\"dash.acc.appr_host_ph\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 10px;font-size:13px;width:130px\" />
            <input id=\"acc_appr_reason\" placeholder=\"승인 사유\" data-i18n-placeholder=\"dash.acc.appr_reason_ph\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 10px;font-size:13px;flex:1;min-width:120px\" />
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
            <input id=\"ip_search\" placeholder=\"호스트/IP 검색…\" data-i18n-placeholder=\"dash.acc.ip_search_ph\" oninput=\"renderAccIpList()\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 10px;font-size:13px;width:150px\" />
            <select id=\"ip_filter_team\" onchange=\"renderAccIpList()\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.ip_allteam\">전체 팀</option></select>
            <select id=\"ip_filter_cat\" onchange=\"renderAccIpList()\" style=\"background:#e5e8eb;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:5px 8px;font-size:13px\"><option value=\"\" data-i18n=\"dash.acc.ip_allcat\">전체 용도</option></select>
            <span id=\"ip_count\" style=\"font-size:12px;color:#191f28\"></span>
          </div>
          <div class=\"table-wrap\" id=\"acc_ip_list\"><span class=\"empty\" data-i18n=\"dash.dyn.loading\">로딩 중…</span></div>
        </section>
      </div>
    </div>

"""
