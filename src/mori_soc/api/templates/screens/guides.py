"""가이드·기준 화면 탭 HTML 조각.

dashboard_tabs.py 에서 화면 단위로 분리. 순수 문자열 상수 하나만 보유.
"""

_TAB_GUIDES_HTML = """    <!-- ── Tab: 가이드·기준 ────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_guides\">
      <div id=\"guide_sub_tabs\" style=\"display:flex;gap:0;border-bottom:1px solid #e5e8eb;margin-bottom:20px;flex-wrap:wrap;\"></div>
      <section class=\"card\" style=\"padding:0\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;padding:16px 20px 0;\">
          <h2 id=\"guide_content_title\" style=\"margin:0;font-size:16px\"></h2>
          <span id=\"guide_updated_at\" style=\"font-size:12px;color:#191f28\"></span>
        </div>
        <div id=\"guide_content_body\" style=\"padding:16px 20px 20px;color:#191f28;line-height:1.8;white-space:pre-wrap;font-size:14px;font-family:inherit\"></div>
      </section>
    </div>
"""
