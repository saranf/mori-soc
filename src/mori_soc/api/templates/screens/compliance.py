"""심사 준비 (Compliance) 화면 탭 HTML 조각.

dashboard_tabs.py 에서 화면 단위로 분리. 순수 문자열 상수 하나만 보유.
"""

_TAB_COMPLIANCE_HTML = """    <!-- ── Tab: 심사 준비 (Compliance PDCA) ──────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_compliance\">
      <section class=\"card\">
        <div style=\"display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap\">
          <div style=\"flex:1;min-width:240px\">
            <h2 data-i18n=\"dash.card.compliance\">심사 준비</h2>
            <div class=\"subtext\" data-i18n=\"dash.compliance.sub_short\">ISMS-P·ISO 27001 통제 점검 현황이에요. 미조치·기한초과부터 처리하면 돼요.</div>
            <details style=\"margin-top:8px\">
              <summary style=\"cursor:pointer;color:#2563eb;font-size:12px\" data-i18n=\"dash.pdca.criteria\">집계 기준 자세히</summary>
              <div class=\"subtext\" style=\"margin-top:6px\" data-i18n-html=\"dash.compliance.sub\">※ 상단 카드의 <strong>전체 점검 / Pass / Fail / Warning / Pass Rate</strong>는 <strong>통제 점검(control_checks)</strong> 결과만 집계합니다. <strong>미조치 합계</strong>와 <strong>기한초과</strong>는 통제 점검 + Trivy 취약점(critical/high) + Alert(critical/high, 7일) 미조치 항목을 통합 집계합니다.</div>
            </details>
          </div>
          <!-- 준비율 링: 통제 pass/total 기반 실데이터 (renderPdca 가 채움) -->
          <div class=\"mori-ring\" id=\"pdca_readiness_ring\" style=\"display:none\" title=\"통제 점검 Pass / 전체 비율\">
            <div class=\"inner\"><b id=\"pdca_readiness_pct\">–</b><span data-i18n=\"dash.pdca.ready_label\">준비됨</span></div>
          </div>
        </div>
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
              <button class=\"secondary\" style=\"width:auto;padding:6px 12px;font-size:12px\" onclick=\"loadAuditSample()\" data-i18n=\"dash.sample.btn\">감사 표본</button>
              <button class=\"secondary\" style=\"width:auto;padding:6px 12px;font-size:12px\" onclick=\"loadGapDeadlines()\" data-i18n=\"dash.gapdl.btn\">Gap 기한·예외</button>
              <button class=\"secondary\" style=\"width:auto;padding:6px 12px;font-size:12px\" onclick=\"loadChangeReport()\" data-i18n=\"dash.chg.btn\">월별 변경</button>
              <a href=\"/controls/evidence-bundle.zip\" download style=\"background:#f9fafb;border:1px solid #e5e7eb;color:#2563eb;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none\" data-i18n=\"dash.ctl.zip\">전체 증적 ZIP</a>
            </div>
          </div>
          <div id=\"evidence_freshness_box\" style=\"display:none;margin-top:8px;padding:10px 12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px\"></div>
          <div id=\"audit_sample_box\" style=\"display:none;margin-top:8px;padding:10px 12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px\"></div>
          <div id=\"gap_deadlines_box\" style=\"display:none;margin-top:8px;padding:10px 12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px\"></div>
          <div id=\"change_report_box\" style=\"display:none;margin-top:8px;padding:10px 12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px\"></div>
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
