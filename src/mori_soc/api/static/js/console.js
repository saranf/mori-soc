    const defaultPayload = window.__MORI_ADMIN__.defaultPayload;
    const guideExamples = window.__MORI_ADMIN__.guideExamples;
    // i18n helper resolves via window.t() with a Korean fallback
    const tt = (k, f) => (window.t ? window.t(k, f) : f);
    const overviewCardsEl = document.getElementById('overview_cards');
    const sourceCoverageEl = document.getElementById('source_coverage');
    const latestStatusEl = document.getElementById('latest_status');
    const riskSummaryEl = document.getElementById('risk_summary');
    const recentActivityEl = document.getElementById('recent_activity');
    const quickQueriesEl = document.getElementById('quick_queries');
    const dashboardStatusEl = document.getElementById('dashboard_status');
    const queryStatusEl = document.getElementById('query_status');
    const intentEl = document.getElementById('intent');
    const nlpTextEl = document.getElementById('nlp_text');
    const timeRangeEl = document.getElementById('time_range');
    const hostIdEl = document.getElementById('host_id');
    const hostnameEl = document.getElementById('hostname');
    const severityEl = document.getElementById('severity');
    const sourceEl = document.getElementById('source');
    const filtersEl = document.getElementById('filters');
    const payloadEl = document.getElementById('payload');
    const resultEl = document.getElementById('result');
    const interpretationHintEl = document.getElementById('interpretation_hint');
    const guideExamplesEl = document.getElementById('guide_examples');
    const guideModalEl = document.getElementById('query_guide_modal');
    const guideMessageEl = document.getElementById('query_guide_message');
    const guideListEl = document.getElementById('query_guide_list');
    const overviewModalEl = document.getElementById('overview_modal');
    const overviewModalTitleEl = document.getElementById('overview_modal_title');
    const overviewModalCopyEl = document.getElementById('overview_modal_copy');
    const overviewModalBodyEl = document.getElementById('overview_modal_body');
    const docsPortalUrlEl = document.getElementById('docs_portal_url');
    const userDashboardCardsEl = document.getElementById('user_dashboard_cards');
    const userDashboardSectionsEl = document.getElementById('user_dashboard_sections');
    const userDashboardAssetColumnsEl = document.getElementById('user_dashboard_asset_columns');
    const userDashboardGuidesEl = document.getElementById('user_dashboard_guides');
    const dashboardPreferencesStatusEl = document.getElementById('dashboard_preferences_status');

    // Webhooks
    const webhooksListEl = document.getElementById('webhooks_list');
    const whNameEl = document.getElementById('wh_name');
    const whUrlEl = document.getElementById('wh_url');
    const webhookStatusEl = document.getElementById('webhook_status');


    const defaultUserDashboardPreferences = window.__MORI_ADMIN__.defaultUserDashboardPreferences;
    const userDashboardCardLabels = window.__MORI_ADMIN__.userDashboardCardLabels;
    const userDashboardSectionLabels = window.__MORI_ADMIN__.userDashboardSectionLabels;
    const userDashboardAssetColumnLabels = window.__MORI_ADMIN__.userDashboardAssetColumnLabels;
    const userDashboardGuideLabels = window.__MORI_ADMIN__.userDashboardGuideLabels;
    let dashboardDetails = {};
    let userDashboardPreferences = JSON.parse(JSON.stringify(defaultUserDashboardPreferences));
    let queryMode = 'natural';

    // ── 전역 함수 노출 (onclick 속성에서 직접 호출 함수 선언은 호이스팅됨) ──
    window.switchAdminTab       = switchAdminTab;
    window.deleteOwner          = deleteOwner;
    window.editOwner            = editOwner;
    window.testWebhook          = testWebhook;
    window.deleteWebhook        = deleteWebhook;
    window.handleSignupRequest  = handleSignupRequest;

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

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
      el.style.cssText = 'display:flex;align-items:center;gap:8px;justify-content:flex-end;margin-top:8px;font-size:12px;color:#191f28;flex-wrap:wrap';
      el.innerHTML = `<span>${start + 1}–${Math.min(end, total)} / ${total}</span>` +
        `<select onchange="_pgSize('${key}',this.value)" style="background:#f7f8fa;border:1px solid #e5e8eb;color:#191f28;border-radius:6px;padding:3px 6px;font-size:12px">${sizes.map(s => `<option value="${s}"${s === st.size ? ' selected' : ''}>${s}</option>`).join('')}</select>` +
        `<button class="secondary" style="width:auto;padding:2px 9px;font-size:12px" onclick="_pgGo('${key}',-1)" ${st.page <= 1 ? 'disabled' : ''}>이전</button>` +
        `<span>${st.page}/${pages}</span>` +
        `<button class="secondary" style="width:auto;padding:2px 9px;font-size:12px" onclick="_pgGo('${key}',1)" ${st.page >= pages ? 'disabled' : ''}>다음</button>`;
      container.appendChild(el);
    }
    window._pgApply = _pgApply;
    window._pgSize = function(key, v) { const st = _pg[key]; if (!st) return; st.size = parseInt(v, 10) || 10; st.page = 1; _pgApply(st.container); };
    window._pgGo = function(key, d) { const st = _pg[key]; if (!st) return; st.page += d; _pgApply(st.container); };

    function logUserAction(action, detail) {
      fetch('/admin/action-audit-log', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ action, detail }),
      }).catch(() => {});
    }

    function formatTime(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString('ko-KR', { hour12: false });
    }

    function renderPreferenceGroup(container, labels, values, prefix) {
      container.innerHTML = Object.entries(labels).map(([key, label]) => `
        <label class="toggle-item" for="${prefix}_${escapeHtml(key)}">
          <span>${escapeHtml(tt('admin.dyn.pref.' + prefix + '.' + key, label))}</span>
          <input type="checkbox" id="${prefix}_${escapeHtml(key)}" data-pref-key="${escapeHtml(key)}" ${values[key] !== false ? 'checked' : ''} />
        </label>
      `).join('');
    }

    function renderDashboardPreferences() {
      renderPreferenceGroup(userDashboardCardsEl, userDashboardCardLabels, userDashboardPreferences.cards || {}, 'user_card');
      renderPreferenceGroup(userDashboardSectionsEl, userDashboardSectionLabels, userDashboardPreferences.sections || {}, 'user_section');
      renderPreferenceGroup(userDashboardAssetColumnsEl, userDashboardAssetColumnLabels, userDashboardPreferences.asset_columns || {}, 'user_asset_col');
      renderPreferenceGroup(userDashboardGuidesEl, userDashboardGuideLabels, userDashboardPreferences.guides || {}, 'user_guide');
    }

    function readPreferenceGroup(container) {
      return Object.fromEntries(Array.from(container.querySelectorAll('[data-pref-key]')).map((input) => [input.dataset.prefKey, input.checked]));
    }

    async function loadDashboardPreferences() {
      dashboardPreferencesStatusEl.textContent = 'user dashboard settings loading...';
      try {
        const response = await fetch('/admin/dashboard/preferences');
        const data = await response.json();
        if (!response.ok) {
          dashboardPreferencesStatusEl.textContent = `settings load failed: HTTP ${response.status}`;
          return;
        }
        docsPortalUrlEl.value = data.docs_url || window.__MORI_ADMIN__.docsUrl;
        userDashboardPreferences = data.user_dashboard || JSON.parse(JSON.stringify(defaultUserDashboardPreferences));
        renderDashboardPreferences();
        dashboardPreferencesStatusEl.textContent = 'user dashboard settings loaded';
      } catch (error) {
        dashboardPreferencesStatusEl.textContent = `settings load failed: ${error.message}`;
      }
    }

    async function saveDashboardPreferences() {
      dashboardPreferencesStatusEl.textContent = 'saving user dashboard settings...';
      const payload = {
        docs_url: docsPortalUrlEl.value.trim() || window.__MORI_ADMIN__.docsUrl,
        user_dashboard: {
          cards: readPreferenceGroup(userDashboardCardsEl),
          sections: readPreferenceGroup(userDashboardSectionsEl),
          asset_columns: readPreferenceGroup(userDashboardAssetColumnsEl),
          guides: readPreferenceGroup(userDashboardGuidesEl),
        },
      };
      try {
        const response = await fetch('/admin/dashboard/preferences', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) {
          dashboardPreferencesStatusEl.textContent = `settings save failed: HTTP ${response.status}`;
          setResultError(JSON.stringify(data, null, 2));
          return;
        }
        docsPortalUrlEl.value = data.docs_url || payload.docs_url;
        userDashboardPreferences = data.user_dashboard || payload.user_dashboard;
        renderDashboardPreferences();
        dashboardPreferencesStatusEl.textContent = 'user dashboard settings saved';
      } catch (error) {
        dashboardPreferencesStatusEl.textContent = `settings save failed: ${error.message}`;
      }
    }

    function compactScope() {
      const scope = {
        time_range: timeRangeEl.value.trim() || '24h',
        host_id: hostIdEl.value.trim(),
        hostname: hostnameEl.value.trim(),
        severity: severityEl.value.trim(),
        source: sourceEl.value.trim(),
      };
      return Object.fromEntries(Object.entries(scope).filter(([, value]) => value));
    }

    function setQueryMode(mode) {
      queryMode = mode;
    }

    function populateFormFromPayload(payload, options = {}) {
      intentEl.value = payload.intent || defaultPayload.intent;
      const scope = payload.scope || {};
      timeRangeEl.value = scope.time_range || '24h';
      hostIdEl.value = scope.host_id || '';
      hostnameEl.value = scope.hostname || '';
      severityEl.value = scope.severity || '';
      sourceEl.value = scope.source || '';
      filtersEl.value = JSON.stringify(payload.filters || {}, null, 2);
      setQueryMode(options.mode || 'structured');
      syncPayload();
    }

    function syncPayload() {
      let filters = {};
      try {
        filters = filtersEl.value.trim() ? JSON.parse(filtersEl.value) : {};
      } catch (error) {
        queryStatusEl.textContent = `${tt('admin.dyn.filters_json_error','filters JSON 오류: ')}${error.message}`;
        return null;
      }
      const payload = { intent: intentEl.value, scope: compactScope(), filters };
      payloadEl.value = JSON.stringify(payload, null, 2);
      queryStatusEl.textContent = 'payload ready';
      return payload;
    }

    function normalizeGuideExamples(examples) {
      return Array.isArray(examples) && examples.length ? examples : guideExamples;
    }

    function renderGuideButtons(container, examples) {
      const items = normalizeGuideExamples(examples);
      container.innerHTML = items.map((example, index) => `
        <button class="ghost chip" type="button" data-guide-index="${index}">${escapeHtml(tt('admin.dyn.nlq_ex.' + index, example))}</button>
      `).join('');
      container.querySelectorAll('[data-guide-index]').forEach((button) => {
        button.addEventListener('click', () => {
          const idx = Number(button.dataset.guideIndex);
          const example = tt('admin.dyn.nlq_ex.' + idx, items[idx] || '');
          nlpTextEl.value = example;
          setQueryMode('natural');
          queryStatusEl.textContent = `guide loaded: ${example}`;
          if (guideModalEl.open) {
            guideModalEl.close();
          }
        });
      });
    }

    function renderInterpretationHint(data) {
      const warnings = Array.isArray(data?.warnings) ? data.warnings : [];
      if (!warnings.length && data?.recognized !== false) {
        interpretationHintEl.innerHTML = '';
        return;
      }
      const tone = data?.recognized === false ? 'need-guide' : 'warning';
      const title = data?.recognized === false ? tt('admin.dyn.hint_rewrite','이 질문은 다시 써주는 편이 좋습니다.') : tt('admin.dyn.hint_more','추가 힌트가 있습니다.');
      interpretationHintEl.innerHTML = `
        <div class="guide-banner ${escapeHtml(tone)}">
          <strong>${escapeHtml(title)}</strong>
          ${warnings.map((warning) => `<div>${escapeHtml(warning)}</div>`).join('')}
        </div>
      `;
    }

    function openGuideModal(message, examples) {
      guideMessageEl.textContent = message || tt('admin.dyn.guide_default_msg','질문 의도를 정확히 해석하지 못하면 아래 예시를 눌러 다시 시작할 수 있습니다.');
      renderGuideButtons(guideListEl, examples);
      if (guideModalEl.open) {
        return;
      }
      if (typeof guideModalEl.showModal === 'function') {
        guideModalEl.showModal();
        return;
      }
      guideModalEl.setAttribute('open', 'open');
    }

    function openOverviewModal(title, description, bodyHtml) {
      overviewModalTitleEl.textContent = title;
      overviewModalCopyEl.textContent = description;
      overviewModalBodyEl.innerHTML = bodyHtml;
      if (overviewModalEl.open) {
        return;
      }
      if (typeof overviewModalEl.showModal === 'function') {
        overviewModalEl.showModal();
        return;
      }
      overviewModalEl.setAttribute('open', 'open');
    }

    function renderDetailTable(columns, items, emptyText) {
      if (!items.length) {
        return `<div class="empty">${escapeHtml(emptyText)}</div>`;
      }
      return `
        <div class="table-wrap">
          <table>
            <thead>
              <tr>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('')}</tr>
            </thead>
            <tbody>
              ${items.map((item) => `
                <tr>
                  ${columns.map((column) => `<td>${column.render(item)}</td>`).join('')}
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    function renderHostCell(item) {
      const name = item.source_url
        ? `<a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer"><strong>${escapeHtml(item.hostname)}</strong></a>`
        : `<strong>${escapeHtml(item.hostname)}</strong>`;
      return `${name}<br /><span class="subtext">${escapeHtml(item.host_id)}</span>`;
    }

    function renderStatusDetailTable(items) {
      return renderDetailTable([
        { label: 'Host', render: (item) => renderHostCell(item) },
        { label: 'Status', render: (item) => `<span class="badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>` },
        { label: 'Risk', render: (item) => escapeHtml(item.risk_score) },
        { label: 'Last Seen', render: (item) => escapeHtml(formatTime(item.last_seen_at)) },
        { label: 'Last Alert', render: (item) => escapeHtml(formatTime(item.last_alert_at)) },
      ], items, tt('admin.dyn.none_show_hosts','표시할 호스트가 없습니다.'));
    }

    const UI_TRIAGE_COLORS = {new:'#f5a623', acknowledged:'#3182f6', investigating:'#3182f6', closed:'#15c47e', false_positive:'#191f28'};
    let uiTriageData = {};
    async function loadUiTriageData() {
      try { const r = await fetch('/alerts'); const d = await r.json(); (d.alerts||[]).forEach(a => { uiTriageData[a.alert_id] = a.triage || {status:'pending'}; }); } catch(_) {}
    }

    function renderAlertDetailTable(items) {
      return renderDetailTable([
        { label: 'Time', render: (item) => escapeHtml(formatTime(item.observed_at)) },
        {
          label: 'Host',
          render: (item) => `<strong>${escapeHtml(item.hostname || '-')}</strong><br /><span class="subtext">${escapeHtml(item.host_id || '-')}</span>`,
        },
        { label: tt('admin.dyn.col.owner','담당자'), render: (item) => `<span style="color:#15c47e">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Severity', render: (item) => escapeHtml(item.severity) },
        { label: 'Message', render: (item) => escapeHtml(item.message) },
        {
          label: 'Triage',
          render: (item) => {
            const tr = uiTriageData[item.alert_id] || {status:'new'};
            const st = tr.status || 'new';
            const color = UI_TRIAGE_COLORS[st] || '#191f28';
            return `<span style="background:${color}22;color:${color};padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">${escapeHtml(st)}</span>`;
          }
        },
      ], items, tt('admin.dyn.none_alert_24h','최근 24시간 high / critical alert가 없습니다.'));
    }

    function renderVulnerabilityDetailTable(items) {
      return renderDetailTable([
        { label: 'Detected', render: (item) => escapeHtml(formatTime(item.detected_at)) },
        {
          label: 'Host',
          render: (item) => `<strong>${escapeHtml(item.hostname || item.host_id)}</strong><br /><span class="subtext">${escapeHtml(item.host_id)}</span>`,
        },
        { label: tt('admin.dyn.col.owner','담당자'), render: (item) => `<span style="color:#15c47e">${escapeHtml(item.owner || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'CVE', render: (item) => escapeHtml(item.cve || '-') },
        { label: 'Package', render: (item) => escapeHtml(item.package_name || '-') },
        { label: tt('admin.dyn.col.action_plan','조치 계획'), render: (item) => {
          if (!item.plan_text) return `<span style="color:#191f28;font-size:11px">${tt('admin.dyn.unset','미설정')}</span>`;
          const tgt = item.plan_target_date ? `<br /><span style="color:#191f28;font-size:11px">~${escapeHtml(item.plan_target_date)}</span>` : '';
          const by = item.plan_updated_by ? ` <span style="color:#191f28;font-size:11px">(${escapeHtml(item.plan_updated_by)})</span>` : '';
          return `<span style="color:#15c47e;font-size:12px" title="${escapeHtml(item.plan_text)}">${escapeHtml(item.plan_text.substring(0,30))}${item.plan_text.length>30?'…':''}</span>${by}${tgt}`;
        }},
        { label: tt('admin.dyn.col.exception','조치 예외'), render: (item) => {
          if (!item.exception_until) return `<span style="color:#191f28;font-size:11px">${tt('admin.dyn.none_word','없음')}</span>`;
          const reason = item.exception_reason ? `<br /><span style="color:#191f28;font-size:11px">${escapeHtml(item.exception_reason.substring(0,30))}${item.exception_reason.length>30?'…':''}</span>` : '';
          return `<span style="color:#f5a623;font-size:12px">~${escapeHtml(item.exception_until)}</span>${reason}`;
        }},
      ], items, tt('admin.dyn.none_critical_vuln2','critical 취약점이 없습니다.'));
    }

    function renderSourceDetailTable(items) {
      return renderDetailTable([
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Hosts', render: (item) => escapeHtml(item.host_count) },
        { label: 'Status', render: (item) => escapeHtml(item.status) },
        { label: 'Last Sync', render: (item) => escapeHtml(formatTime(item.last_sync_at)) },
        { label: 'Message', render: (item) => escapeHtml(item.message || '-') },
      ], items, tt('admin.dyn.none_show_source','표시할 source 상태가 없습니다.'));
    }

    function renderIngestedDetailTable(items) {
      return renderDetailTable([
        { label: 'Entity', render: (item) => escapeHtml(item.entity_type) },
        { label: 'Count', render: (item) => escapeHtml(item.count) },
      ], items, tt('admin.dyn.none_records','수집된 레코드가 없습니다.'));
    }

    async function showOverviewDetail(key, label) {
      const items = Array.isArray(dashboardDetails[key]) ? dashboardDetails[key] : [];
      const renderers = {
        total_hosts: [renderStatusDetailTable, tt('admin.dyn.desc.total_hosts','현재 알려진 전체 호스트 목록입니다.')],
        offline_hosts: [renderStatusDetailTable, tt('admin.dyn.desc.offline_hosts','즉시 확인이 필요한 offline 호스트 목록입니다.')],
        alerts_24h: [renderAlertDetailTable, tt('admin.dyn.desc.alerts_24h','최근 24시간 high / critical alert 목록입니다.')],
        critical_vulns: [renderVulnerabilityDetailTable, tt('admin.dyn.desc.critical_vulns','현재 critical 취약점 목록입니다.')],
        sources_reporting: [renderSourceDetailTable, tt('admin.dyn.desc.sources_reporting','호스트를 보고 중인 source 목록입니다.')],
        sources_healthy: [renderSourceDetailTable, tt('admin.dyn.desc.sources_healthy','최근 sync가 success인 collector 목록입니다.')],
        ingested_records: [renderIngestedDetailTable, tt('admin.dyn.desc.ingested_records','저장된 엔터티 타입별 레코드 수입니다.')],
      };
      if (key === 'alerts_24h') await loadUiTriageData();
      const [renderer, description] = renderers[key] || [renderIngestedDetailTable, tt('admin.dyn.desc.default','선택한 카드의 상세 데이터입니다.')];
      openOverviewModal(label, description, renderer(items));
    }

    function renderOverview(overview) {
      if (!overview || typeof overview !== 'object') overview = {};
      const o = {
        total_hosts: overview.total_hosts ?? 0, online_hosts: overview.online_hosts ?? 0,
        offline_hosts: overview.offline_hosts ?? 0, unknown_hosts: overview.unknown_hosts ?? 0,
        alerts_24h: overview.alerts_24h ?? 0, critical_vulns: overview.critical_vulns ?? 0,
        high_vulns: overview.high_vulns ?? 0, sources_reporting: overview.sources_reporting ?? 0,
        sources_healthy: overview.sources_healthy ?? 0, ingested_records: overview.ingested_records ?? 0,
      };
      // 요약 스트립(시안): 수집 소스/연결 호스트/응답 없음 — 실데이터
      try {
        const sb = document.getElementById('admin_state_strip_body');
        const ss = document.getElementById('admin_state_strip');
        if (sb && ss) {
          const srcOk = o.sources_reporting > 0 && o.sources_healthy >= o.sources_reporting;
          sb.innerHTML =
            `<div class="ms-metric"><span class="ms-k">${escapeHtml(tt('admin.strip.sources','수집 소스'))}</span><span class="ms-v ${srcOk ? 'green' : 'red'}">${o.sources_healthy}<small>/${o.sources_reporting} ${escapeHtml(tt('admin.strip.ok','정상'))}</small></span></div>`
            + `<div class="ms-div"></div><div class="ms-metric"><span class="ms-k">${escapeHtml(tt('admin.strip.hosts','연결 호스트'))}</span><span class="ms-v">${o.total_hosts}</span></div>`
            + `<div class="ms-div"></div><div class="ms-metric"><span class="ms-k">${escapeHtml(tt('admin.strip.offline','응답 없음'))}</span><span class="ms-v ${o.offline_hosts > 0 ? 'red' : 'green'}">${o.offline_hosts}</span></div>`;
          ss.style.display = '';
        }
      } catch (e) {}
      const cards = [
        ['total_hosts', 'Total Hosts', o.total_hosts, `${o.online_hosts} online / ${o.unknown_hosts} unknown`],
        ['offline_hosts', 'Offline Hosts', o.offline_hosts, tt('admin.dyn.sub.offline','즉시 확인 대상')],
        ['alerts_24h', 'High Alerts 24h', o.alerts_24h, 'high + critical'],
        ['critical_vulns', 'Critical Vulns', o.critical_vulns, `high ${o.high_vulns}`],
        ['sources_reporting', 'Sources Reporting', o.sources_reporting, 'fleet / wazuh / zabbix / trivy / host_log'],
        ['sources_healthy', 'Healthy Collectors', o.sources_healthy, tt('admin.dyn.sub.healthy','최근 sync success 기준')],
        ['ingested_records', 'Ingested Records', o.ingested_records, 'alerts + vulns + queries + observations'],
      ];
      overviewCardsEl.innerHTML = cards.map(([key, label, value, sub]) => `
        <section class="card metric-card" role="button" tabindex="0" data-overview-key="${escapeHtml(key)}" data-overview-label="${escapeHtml(label)}">
          <div class="metric-label">${escapeHtml(label)}</div>
          <div class="metric-value">${escapeHtml(value)}</div>
          <div class="metric-sub">${escapeHtml(sub)}</div>
        </section>
      `).join('');
      overviewCardsEl.querySelectorAll('[data-overview-key]').forEach((card) => {
        const open = () => showOverviewDetail(card.dataset.overviewKey, card.dataset.overviewLabel || 'Overview');
        card.addEventListener('click', open);
        card.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            open();
          }
        });
      });
    }

    // ── 온보딩(실사용 시작) 카드 — 첫 실행 체크리스트 + 커넥터 연결 상태 ──────────
    // admin·security 전용 엔드포인트라 403 이면 카드를 조용히 숨긴다(다른 롤엔 노출 안 함).
    async function renderOnboarding() {
      const card = document.getElementById('onboarding_card');
      if (!card) return;
      let status, connectors, scan, golive;
      try {
        const [sr, cr, xr, gr] = await Promise.all([
          fetch('/onboarding/status'), fetch('/onboarding/connectors'),
          fetch('/onboarding/scan-setup'), fetch('/onboarding/go-live'),
        ]);
        if (!sr.ok || !cr.ok) { card.style.display = 'none'; return; }
        status = await sr.json();
        connectors = (await cr.json()).connectors || [];
        scan = xr.ok ? await xr.json() : null;
        golive = gr.ok ? await gr.json() : null;
      } catch (e) { card.style.display = 'none'; return; }

      const cl = status.checklist || { steps: [], done_count: 0, total: 0 };
      // 진행바 + 스텝 칩(완료=초록/대기=흐림/다음할일=파랑). 장식 이모지 없이 텍스트 배지.
      const stepChips = (cl.steps || []).map((s) => {
        const isNext = cl.next_step === s.id;
        const label = escapeHtml(tt('onboarding.step.' + s.id, s.label_ko));
        const badge = s.done
          ? `<span class="badge online">${escapeHtml(tt('onboarding.done','완료'))}</span>`
          : (isNext
              ? `<span class="badge" style="background:#1f6feb;color:#fff">${escapeHtml(tt('onboarding.next','지금 할 일'))}</span>`
              : `<span class="badge unknown">${escapeHtml(tt('onboarding.pending','대기'))}</span>`);
        return `<div class="coverage-item" style="min-width:140px"><div class="metric-sub">${label}</div>${badge}</div>`;
      }).join('');

      // 보안 태세 배지(hardened=초록 / insecure=빨강) — 실배포 안전 신호.
      const posture = status.security_posture || 'unknown';
      const postureBadge = posture === 'hardened'
        ? `<span class="badge online">${escapeHtml(tt('onboarding.posture.hardened','보안 강화됨'))}</span>`
        : `<span class="badge offline">${escapeHtml(tt('onboarding.posture.insecure','보안 취약(기본값 점검)'))}</span>`;
      // 운영 모드인데 HTTPS 미구성이면 명시적 사유 힌트(하드거부 아닌 개선 유도).
      const httpsHint = (status.production_mode && status.https_ok === false)
        ? `<div class="status-line" style="color:#b93838">${escapeHtml(tt('onboarding.https_hint','운영 모드이나 HTTPS 미구성 — MORI_PUBLIC_URL 을 https 로 하거나 MORI_BEHIND_TLS_PROXY=true'))}</div>`
        : '';

      // 커넥터 성숙도 배지: verified=초록 / partial=노랑 / scaffold=중립(정직한 표기).
      const matBadge = (m) => {
        if (m === 'verified') return `<span class="badge online">${escapeHtml(tt('onboarding.mat.verified','실검증'))}</span>`;
        if (m === 'partial') return `<span class="badge" style="background:#f5a623;color:#000">${escapeHtml(tt('onboarding.mat.partial','부분(수신형)'))}</span>`;
        return `<span class="badge unknown">${escapeHtml(tt('onboarding.mat.scaffold','준비중'))}</span>`;
      };
      const stateLabel = (st) => tt('onboarding.state.' + st, {
        connected: '연결됨', configured: '설정됨(수집 대기)', waiting: '수신 대기', not_configured: '미설정',
      }[st] || st);
      const connRows = connectors.map((c) => {
        const testBtn = c.testable
          ? `<button class="secondary" style="width:auto;padding:4px 12px;font-size:12px" data-conn-test="${escapeHtml(c.id)}">${escapeHtml(tt('onboarding.test','연결 테스트'))}</button>`
          : '';
        const miss = (c.missing_env && c.missing_env.length)
          ? `<div class="status-line" style="color:#b93838">${escapeHtml(tt('onboarding.missing','미설정 env'))}: ${escapeHtml(c.missing_env.join(', '))}</div>` : '';
        const sync = c.last_success_at
          ? `<div class="metric-sub">last sync: ${escapeHtml(formatTime(c.last_success_at))} · records ${escapeHtml(c.records_collected)}</div>` : '';
        return `
        <div class="coverage-item" style="min-width:220px">
          <div class="metric-label">${escapeHtml(c.label_ko)}</div>
          <div class="metric-sub">${matBadge(c.maturity)} <span class="badge unknown">${escapeHtml(stateLabel(c.state))}</span></div>
          ${sync}${miss}
          <div class="actions" style="margin-top:6px">${testBtn}<span class="status-line" data-conn-result="${escapeHtml(c.id)}"></span></div>
        </div>`;
      }).join('');

      // 코드 스캔 붙이기(무료 기본) — 3스텝 + 필요 GitHub 시크릿 + 워크플로 복사(접이식).
      let scanHtml = '';
      if (scan) {
        const steps = (scan.steps || []).map((s, i) =>
          `<li>${escapeHtml(tt('onboarding.scan.step.' + s.id, s.ko))}</li>`).join('');
        const secrets = (scan.github_secrets || []).map((sec) => {
          const tag = sec.required
            ? `<span class="badge offline">${escapeHtml(tt('onboarding.scan.required','필수'))}</span>`
            : `<span class="badge unknown">${escapeHtml(tt('onboarding.scan.optional','선택'))}</span>`;
          return `<div class="metric-sub"><code>${escapeHtml(sec.name)}</code> ${tag} — ${escapeHtml(sec.note_ko || '')}</div>`;
        }).join('');
        const readyBadge = scan.ready
          ? `<span class="badge online">${escapeHtml(tt('onboarding.scan.ready','준비됨'))}</span>`
          : `<span class="badge offline">${escapeHtml(tt('onboarding.scan.set_public','MORI_PUBLIC_URL 먼저 설정'))}</span>`;
        scanHtml =
          `<details class="card" style="padding:0;margin-top:14px"><summary style="cursor:pointer;padding:12px 14px;font-weight:800;font-size:14px">`
          + `${escapeHtml(tt('onboarding.scan.title','코드 스캔 붙이기 (무료 기본 · Semgrep)'))} ${readyBadge}</summary>`
          + `<div style="padding:0 14px 14px">`
          + `<div class="metric-sub" style="margin-bottom:6px">${escapeHtml(tt('onboarding.scan.free_note','ANTHROPIC 키 없이 무료로 시작합니다. AI 심층(유료)은 선택 업그레이드입니다.'))}</div>`
          + `<ol style="margin:8px 0 8px 18px;padding:0">${steps}</ol>`
          + `<div style="margin:6px 0">${secrets}</div>`
          + `<div class="actions" style="margin-top:8px"><button class="secondary" style="width:auto;padding:4px 12px;font-size:12px" data-scan-copy>${escapeHtml(tt('onboarding.scan.copy','워크플로 복사'))}</button>`
          + `<span class="metric-sub"><code>${escapeHtml(scan.workflow_filename || '')}</code></span>`
          + `<span class="status-line" data-scan-copy-result></span></div></div></details>`;
      }

      // 데모→실전 전환 준비(비파괴) — 5개 항목 체크 + 전환 안내(접이식).
      let goLiveHtml = '';
      if (golive) {
        const gsteps = (golive.steps || []).map((s) => {
          const b = s.done
            ? `<span class="badge online">${escapeHtml(tt('onboarding.done','완료'))}</span>`
            : `<span class="badge unknown">${escapeHtml(tt('onboarding.pending','대기'))}</span>`;
          return `<div class="metric-sub">${b} ${escapeHtml(tt('onboarding.golive.step.' + s.id, s.ko))}</div>`;
        }).join('');
        const rb = golive.ready
          ? `<span class="badge online">${escapeHtml(tt('onboarding.golive.ready','실전 준비됨'))}</span>`
          : `<span class="badge" style="background:#f5a623;color:#000">${golive.done_count}/${golive.total}</span>`;
        goLiveHtml =
          `<details class="card" style="padding:0;margin-top:10px"><summary style="cursor:pointer;padding:12px 14px;font-weight:800;font-size:14px">`
          + `${escapeHtml(tt('onboarding.golive.title','데모 → 실전 전환 준비'))} ${rb}</summary>`
          + `<div style="padding:0 14px 14px">${gsteps}`
          + `<div class="status-line" style="margin-top:8px">${escapeHtml(tt('onboarding.golive.clear_hint', golive.clear_demo_hint_ko || ''))}</div></div></details>`;
      }

      card.innerHTML =
        `<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px">`
        + `<h2 style="margin:0">${escapeHtml(tt('onboarding.title','실사용 시작 · 온보딩'))}</h2>`
        + `<div>${escapeHtml(tt('onboarding.progress','진행'))} <strong>${cl.done_count}/${cl.total}</strong> &nbsp; ${postureBadge}</div></div>`
        + `<div class="coverage" style="margin-bottom:8px">${stepChips}</div>`
        + httpsHint
        + `<h2 style="margin:10px 0 8px;font-size:15px">${escapeHtml(tt('onboarding.connectors','커넥터 연결 상태'))}</h2>`
        + `<div class="coverage">${connRows}</div>`
        + scanHtml
        + goLiveHtml;
      card.style.display = '';

      // 워크플로 복사 — 클립보드에 워크플로 YAML 을 담아 고객 레포에 붙여넣게 한다.
      const copyBtn = card.querySelector('[data-scan-copy]');
      if (copyBtn && scan && scan.workflow_content) {
        copyBtn.addEventListener('click', async () => {
          const out = card.querySelector('[data-scan-copy-result]');
          try {
            await navigator.clipboard.writeText(scan.workflow_content);
            if (out) { out.style.color = '#2f7d32'; out.textContent = tt('onboarding.scan.copied','복사됨'); }
          } catch (e) {
            if (out) { out.style.color = '#b93838'; out.textContent = tt('onboarding.scan.copy_fail','복사 실패 — 수동 선택'); }
          }
        });
      }

      // 연결 테스트 버튼 — 현재 서버 env 로 라이브 시도, 성공/실패를 그 자리에 정직 표기.
      card.querySelectorAll('[data-conn-test]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.connTest;
          const out = card.querySelector(`[data-conn-result="${id}"]`);
          const orig = btn.textContent;
          btn.disabled = true; btn.textContent = tt('onboarding.testing','테스트 중...');
          if (out) { out.textContent = ''; out.style.color = ''; }
          try {
            const r = await fetch(`/onboarding/connectors/${encodeURIComponent(id)}/test`, { method: 'POST' });
            const d = await r.json();
            if (out) {
              if (d.ok) { out.style.color = '#2f7d32'; out.textContent = `${tt('onboarding.test.ok','연결 성공')} · ${tt('onboarding.test.sample','표본')} ${d.sample_count} (${d.elapsed_ms}ms)`; }
              else { out.style.color = '#b93838'; out.textContent = `${tt('onboarding.test.fail','연결 실패')}: ${escapeHtml(d.error || d.detail || '')}`.slice(0, 200); }
            }
          } catch (e) {
            if (out) { out.style.color = '#b93838'; out.textContent = `${tt('onboarding.test.fail','연결 실패')}: ${e.message}`; }
          } finally {
            btn.disabled = false; btn.textContent = orig;
          }
        });
      });
    }

    function renderSourceCoverage(items) {
      if (!items.length) {
        sourceCoverageEl.innerHTML = `<div class="empty">${tt('admin.dyn.none_source_alias','아직 연결된 source alias가 없습니다.')}</div>`;
        return;
      }
      const statusToBadge = { success: 'online', error: 'offline', running: 'unknown', unknown: 'unknown' };
      sourceCoverageEl.innerHTML = items.map((item) => {
        const staleBadge = item.is_stale ? ' <span class="badge" style="background:#f5a623;color:#000">STALE</span>' : '';
        return `
        <div class="coverage-item">
          <div class="metric-label">${escapeHtml(item.source.toUpperCase())}</div>
          <strong>${escapeHtml(item.host_count)}</strong>
          <div class="metric-sub">${tt('admin.dyn.host_word','호스트')} · <span class="badge ${escapeHtml(statusToBadge[item.status] || 'unknown')}">${escapeHtml(item.status)}</span>${staleBadge}</div>
          <div class="metric-sub">last sync: ${escapeHtml(formatTime(item.last_sync_at))}</div>
          <div class="metric-sub">records ${escapeHtml(item.records_collected)} / entities ${escapeHtml(item.entities_saved)}</div>
          <div class="status-line">${escapeHtml(item.message || tt('admin.dyn.no_sync_record','아직 sync 기록 없음'))}</div>
        </div>`;
      }).join('');
    }

    function renderLatestStatus(items) {
      if (!items.length) {
        latestStatusEl.innerHTML = `<div class="empty">${tt('admin.dyn.none_hosts','아직 호스트 데이터가 없습니다.')}</div>`;
        return;
      }
      latestStatusEl.innerHTML = `
        <table>
          <thead>
            <tr><th>Host</th><th>Status</th><th>Risk</th><th>Last Seen</th><th>Last Alert</th></tr>
          </thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${renderHostCell(item)}</td>
                <td><span class="badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></td>
                <td>${escapeHtml(item.risk_score)}</td>
                <td>${escapeHtml(formatTime(item.last_seen_at))}</td>
                <td>${escapeHtml(formatTime(item.last_alert_at))}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderRiskSummary(items) {
      if (!items.length) {
        riskSummaryEl.innerHTML = `<div class="empty">${tt('admin.dyn.none_risk','아직 위험 요약 데이터가 없습니다.')}</div>`;
        return;
      }
      riskSummaryEl.innerHTML = `
        <table>
          <thead>
            <tr><th>Host</th><th>Risk</th><th>Alerts 24h</th><th>Critical</th><th>High</th><th>Vulns</th></tr>
          </thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td><strong>${escapeHtml(item.hostname)}</strong><br /><span class="subtext">${escapeHtml(item.host_id)}</span></td>
                <td>${escapeHtml(item.risk_score)}</td>
                <td>${escapeHtml(item.alert_count_24h)}</td>
                <td>${escapeHtml(item.critical_alert_count_24h)}</td>
                <td>${escapeHtml(item.high_alert_count_24h)}</td>
                <td>${escapeHtml(item.vuln_count)} (C:${escapeHtml(item.critical_vuln_count)} / H:${escapeHtml(item.high_vuln_count)})</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderRecentActivity(items) {
      if (!items.length) {
        recentActivityEl.innerHTML = `<div class="empty">${tt('admin.dyn.none_recent','아직 최근 활동 데이터가 없습니다.')}</div>`;
        return;
      }
      recentActivityEl.innerHTML = items.map((item) => `
        <div class="list-item">
          <div class="top">
            <strong>${escapeHtml(item.summary)}</strong>
            <span class="meta">${escapeHtml(formatTime(item.observed_at))}</span>
          </div>
          <div class="meta">${escapeHtml(item.entity_type)} · ${escapeHtml(item.source)} · ${escapeHtml(item.host_id || '-')}</div>
        </div>
      `).join('');
    }

    function renderQuickQueries(items) {
      if (!items.length) {
        quickQueriesEl.innerHTML = `<div class="empty">${tt('admin.dyn.none_quick','추천 질의가 없습니다.')}</div>`;
        return;
      }
      quickQueriesEl.innerHTML = items.map((item, index) => `
        <button class="ghost" type="button" data-quick-index="${index}">${escapeHtml(item.label)}</button>
      `).join('');
      quickQueriesEl.querySelectorAll('[data-quick-index]').forEach((button) => {
        button.addEventListener('click', () => {
          const item = items[Number(button.dataset.quickIndex)];
          nlpTextEl.value = item.text || '';
          populateFormFromPayload(item.payload || defaultPayload, { mode: 'natural' });
          queryStatusEl.textContent = `quick query loaded: ${item.label}`;
        });
      });
    }

    async function loadCatalog() {
      try {
        const response = await fetch('/catalog');
        const data = await response.json();
        const queries = data.queries || [];
        intentEl.innerHTML = queries.map((query) => `<option value="${query.intent}">${escapeHtml(query.name)} (${escapeHtml(query.intent)})</option>`).join('');
        populateFormFromPayload(defaultPayload, { mode: 'natural' });
        queryStatusEl.textContent = `catalog loaded: ${queries.length} queries`;
      } catch (error) {
        queryStatusEl.textContent = `catalog load failed: ${error.message}`;
      }
    }

    async function loadDashboard() {
      dashboardStatusEl.textContent = 'dashboard loading...';
      try {
        const response = await fetch('/dashboard/summary');
        const data = await response.json();
        if (!response.ok) {
          dashboardStatusEl.textContent = `dashboard load failed: HTTP ${response.status}`;
          return;
        }
        dashboardDetails = data.overview_details || {};
        renderOnboarding();   // 온보딩 카드(실사용 시작) — 실패해도 대시보드 로드를 막지 않음
        renderOverview(data.overview || {});
        renderSourceCoverage(data.source_coverage || []);
        renderLatestStatus(data.latest_status || []);
        renderRiskSummary(data.risk_summary || []);
        renderRecentActivity(data.recent_activity || []);
        renderQuickQueries(data.recommended_queries || []);
        dashboardStatusEl.textContent = `dashboard updated at ${formatTime(data.generated_at)}`;
      } catch (error) {
        dashboardStatusEl.textContent = `dashboard load failed: ${error.message}`;
      }
    }

    async function interpretNaturalText(options = {}) {
      const text = nlpTextEl.value.trim();
      if (!text) {
        queryStatusEl.textContent = tt('admin.dyn.enter_nlq','자연어 질문을 입력하세요.');
        renderInterpretationHint({ warnings: [tt('admin.dyn.enter_question_first','질문을 먼저 입력해 주세요.')], recognized: false });
        return null;
      }
      queryStatusEl.textContent = options.statusText || 'interpreting text...';
      try {
        const response = await fetch('/interpret', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text }),
        });
        const data = await response.json();
        if (!response.ok) {
          queryStatusEl.textContent = `interpret failed: HTTP ${response.status}`;
          return null;
        }
        renderInterpretationHint(data);
        const examples = normalizeGuideExamples(data.guide_examples);
        renderGuideButtons(guideExamplesEl, examples);
        if (data.recognized === false) {
          if (options.openGuideOnUnrecognized !== false) {
            openGuideModal((data.warnings || [])[0], examples);
          }
          queryStatusEl.textContent = 'interpret needs guide examples';
          return { recognized: false, data };
        }
        const payload = { intent: data.intent, scope: data.scope || {}, filters: data.filters || {} };
        populateFormFromPayload(payload, { mode: 'natural' });
        logUserAction('INTERPRET', text.substring(0, 200));
        queryStatusEl.textContent = (data.warnings || []).length ? 'interpret completed with hints' : 'interpret completed';
        return { recognized: true, data, payload };
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `interpret failed: ${error.message}`;
        return null;
      }
    }

    async function resolvePayloadForRun() {
      if (queryMode === 'natural' && nlpTextEl.value.trim()) {
        const interpreted = await interpretNaturalText({ statusText: 'interpreting text before query...' });
        if (!interpreted || interpreted.recognized === false) {
          return null;
        }
        return interpreted.payload;
      }
      return syncPayload();
    }

    function extractFilename(response) {
      const disposition = response.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="?([^";]+)"?/i);
      return match ? match[1] : 'mori-query.csv';
    }

    function queryResultCount(data) {
      if (typeof data?.meta?.count === 'number') {
        return data.meta.count;
      }
      return Array.isArray(data?.evidence) ? data.evidence.length : 0;
    }

    function hasQueryResults(data) {
      return queryResultCount(data) > 0;
    }

    function showNoResultsAlert(data) {
      const message = typeof data?.summary === 'string' && data.summary.trim()
        ? data.summary.trim()
        : tt('admin.dyn.none_query_result','조회 결과가 없습니다.');
      window.alert(message);
    }

    function downloadTextFile(text, filename, mimeType = 'text/csv;charset=utf-8') {
      const blob = new Blob([text], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    }

    function setResultText(msg) {
      resultEl.innerHTML = `<span class="result-placeholder">${escapeHtml(String(msg))}</span>`;
    }

    function setResultError(msg) {
      resultEl.innerHTML = `<div class="result-error">${escapeHtml(String(msg))}</div>`;
    }

    function renderQueryResult(data) {
      const evidence = Array.isArray(data?.evidence) ? data.evidence : [];
      const summary = typeof data?.summary === 'string' ? data.summary : '';
      const count = typeof data?.meta?.count === 'number' ? data.meta.count : evidence.length;

      let html = '';
      if (summary) {
        html += `<div class="result-summary">${escapeHtml(summary)}</div>`;
      }
      if (!evidence.length) {
        html += `<span class="result-placeholder">${tt('admin.dyn.none_query_result','조회 결과가 없습니다.')}</span>`;
        resultEl.innerHTML = html;
        return;
      }

      const badgeClass = (src) => {
        const s = (src || '').toLowerCase();
        if (s.includes('wazuh')) return 'wazuh';
        if (s.includes('zabbix')) return 'zabbix';
        if (s.includes('fleet')) return 'fleet';
        if (s.includes('trivy')) return 'trivy';
        if (s.includes('host')) return 'hosts';
        return '';
      };

      html += `
        <table class="result-table">
          <thead><tr>
            <th>#</th><th>Source</th><th>Summary</th><th>Record ID</th>
          </tr></thead>
          <tbody>
            ${evidence.map((ev, i) => `
              <tr>
                <td>${i + 1}</td>
                <td><span class="result-badge ${escapeHtml(badgeClass(ev.source))}">${escapeHtml(ev.source || '-')}</span></td>
                <td>${escapeHtml(ev.summary || ev.raw_ref || '-')}</td>
                <td><span class="mono" style="font-size:11px;color:#191f28;">${escapeHtml(ev.record_id || '-')}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <div class="status-line" style="margin-top:8px;">${tt('admin.dyn.total_prefix','총 ')}${escapeHtml(String(count))}${tt('admin.dyn.queried_suffix','건 조회됨')}</div>`;
      resultEl.innerHTML = html;
    }

    async function runQuery() {
      const payload = await resolvePayloadForRun();
      if (!payload) return;
      queryStatusEl.textContent = 'query running...';
      try {
        const response = await fetch('/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            const data = await response.json();
            setResultError(JSON.stringify(data, null, 2));
          } else {
            setResultError(await response.text());
          }
          queryStatusEl.textContent = `query failed: HTTP ${response.status}`;
          return;
        }
        const data = await response.json();
        if (!hasQueryResults(data)) {
          setResultText(tt('admin.dyn.none_query_result','조회 결과가 없습니다.'));
          queryStatusEl.textContent = 'query returned no results';
          showNoResultsAlert(data);
          return;
        }
        renderQueryResult(data);
        queryStatusEl.textContent = 'query completed';
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `query failed: ${error.message}`;
      }
    }

    async function downloadCsv() {
      const payload = await resolvePayloadForRun();
      if (!payload) return;
      queryStatusEl.textContent = 'checking query results before csv download...';
      try {
        const previewResponse = await fetch('/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const previewData = await previewResponse.json();
        if (!previewResponse.ok) {
          setResultError(JSON.stringify(previewData, null, 2));
          queryStatusEl.textContent = `query failed: HTTP ${previewResponse.status}`;
          return;
        }
        if (!hasQueryResults(previewData)) {
          setResultText(tt('admin.dyn.none_query_result','조회 결과가 없습니다.'));
          queryStatusEl.textContent = 'csv download skipped: no results';
          showNoResultsAlert(previewData);
          return;
        }

        const response = await fetch('/query?format=csv', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            const data = await response.json();
            setResultError(JSON.stringify(data, null, 2));
          } else {
            setResultError(await response.text());
          }
          queryStatusEl.textContent = `csv download failed: HTTP ${response.status}`;
          return;
        }
        const csvText = await response.text();
        const filename = extractFilename(response);
        downloadTextFile(csvText, filename, response.headers.get('content-type') || 'text/csv;charset=utf-8');
        renderQueryResult(previewData);
        queryStatusEl.textContent = `csv download started: ${filename}`;
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `csv download failed: ${error.message}`;
      }
    }

    async function interpretText() {
      await interpretNaturalText();
    }

    function resetForm() {
      nlpTextEl.value = tt('admin.s.nlq_default','오프라인 호스트 보여줘');
      populateFormFromPayload(defaultPayload, { mode: 'natural' });
      setResultText(tt('admin.dyn.not_run_yet','아직 실행 전입니다.'));
      interpretationHintEl.innerHTML = '';
      queryStatusEl.textContent = 'form reset';
    }

    async function copyPayload() {
      try {
        await navigator.clipboard.writeText(payloadEl.value);
        queryStatusEl.textContent = 'payload copied';
      } catch (error) {
        queryStatusEl.textContent = `copy failed: ${error.message}`;
      }
    }

    nlpTextEl.addEventListener('input', () => setQueryMode('natural'));
    [intentEl, timeRangeEl, hostIdEl, hostnameEl, severityEl, sourceEl].forEach((element) => {
      const handleStructuredInput = () => {
        setQueryMode('structured');
        syncPayload();
      };
      element.addEventListener('input', handleStructuredInput);
      element.addEventListener('change', handleStructuredInput);
    });
    filtersEl.addEventListener('input', () => {
      setQueryMode('structured');
      syncPayload();
    });
    document.getElementById('interpret')?.addEventListener('click', interpretText);
    document.getElementById('run')?.addEventListener('click', runQuery);
    document.getElementById('download_csv')?.addEventListener('click', downloadCsv);
    document.getElementById('reset')?.addEventListener('click', resetForm);
    document.getElementById('copy_payload')?.addEventListener('click', copyPayload);
    document.getElementById('query_guide')?.addEventListener('click', () => openGuideModal('', guideExamples));
    document.getElementById('refresh_dashboard')?.addEventListener('click', loadDashboard);
    document.getElementById('save_dashboard_preferences')?.addEventListener('click', saveDashboardPreferences);
    filtersEl.value = JSON.stringify(defaultPayload.filters, null, 2);
    renderGuideButtons(guideExamplesEl, guideExamples);

    // ── Asset Owners ───────────────────────────────────────────────────────
    const ownersListEl = document.getElementById('owners_list');
    const ownerStatusEl = document.getElementById('owner_status');
    const ownHostnameEl = document.getElementById('own_hostname');
    const ownOwnerEl = document.getElementById('own_owner');
    const ownEmailEl = document.getElementById('own_email');
    const ownTeamEl = document.getElementById('own_team');
    const ownCategoryEl = document.getElementById('own_category');
    const ownImportanceEl = document.getElementById('own_importance');
    const ownerFormTitleEl = document.getElementById('owner_form_title');
    const cancelEditBtn = document.getElementById('cancel_edit_owner');
    let _editingHostname = null; // track if we are editing

    const impLabel = { '상':tt('admin.s.opt.high','상'), '중':tt('admin.s.opt.mid','중'), '하':tt('admin.s.opt.low','하') };
    const impColor = { '상':'#f04452', '중':'#f5a623', '하':'#15c47e' };

    async function loadOwners() {
      ownersListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/assets/owners');
        const data = await res.json();
        const list = data.owners || [];
        if (!list.length) { ownersListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_owners','등록된 담당자 없음')}</span>`; return; }
        const rows = list.map(o => {
          const imp = o.importance || '';
          const impBadge = imp ? `<span style="background:#e5e8eb;color:${impColor[imp]||'#191f28'};padding:1px 6px;border-radius:4px;font-size:11px;font-weight:700;margin-left:6px">${escapeHtml(impLabel[imp]||imp)}</span>` : '';
          const catBadge = o.category ? `<span style="color:#3182f6;font-size:11px;margin-left:6px">[${escapeHtml(o.category)}]</span>` : '';
          const tags = (o.scope_tags||[]).map(t=>`<span style="color:#3182f6;border:1px solid #3182f6;border-radius:5px;padding:0 5px;font-size:10px;margin-left:3px">${escapeHtml(t)}</span>`).join('');
          return `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;border-bottom:1px solid #e5e8eb;font-size:13px;gap:8px">
            <div style="flex:1;min-width:0">
              <strong style="color:#191f28">${escapeHtml(o.hostname)}</strong>${catBadge}${impBadge}${tags}
              <br><span style="color:#15c47e;font-size:12px">${escapeHtml(o.owner||'-')}</span>
              ${o.team ? `<span style="color:#191f28;margin-left:6px;font-size:12px">(${escapeHtml(o.team)})</span>` : ''}
              ${o.email ? `<span style="color:#191f28;font-size:11px;margin-left:6px">${escapeHtml(o.email)}</span>` : ''}
            </div>
            <div style="display:flex;gap:6px;flex-shrink:0">
              <button onclick="editScopeTags('${escapeHtml(o.hostname)}')" style="background:#e5e8eb;border:1px solid #e5e8eb;color:#3182f6;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px">${tt('admin.dyn.scope','범위태그')}</button>
              <button onclick="editOwner('${escapeHtml(o.hostname)}')" style="background:#e5e8eb;border:1px solid #e5e8eb;color:#3182f6;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px">${tt('admin.dyn.edit','수정')}</button>
              <button onclick="deleteOwner('${escapeHtml(o.hostname)}')" style="background:#fdecee;border:none;color:#f04452;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px">${tt('admin.dyn.delete','삭제')}</button>
            </div>
          </div>`;
        }).join('');
        ownersListEl.innerHTML = `<div id="scope_cov_box" style="margin-bottom:8px"></div>` + rows;
        loadScopeCoverage();
      } catch(e) { ownersListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`; }
    }

    // ── 인증범위 태그·커버리지(#12) ────────────────────────────────────────────────
    async function loadScopeCoverage() {
      const box = document.getElementById('scope_cov_box');
      if (!box) return;
      try {
        const res = await fetch('/assets/scope-coverage');
        if (!res.ok) return;
        const d = await res.json();
        const is = d.in_scope || {};
        const tagChips = (d.tags||[]).map(t=>{
          const col = t.coverage_pct>=90?'#15c47e':(t.coverage_pct>=60?'#f5a623':'#f04452');
          return `<span style="border:1px solid ${col};color:${col};border-radius:5px;padding:1px 6px;font-size:11px;margin:2px 4px 2px 0;display:inline-block">${escapeHtml(t.tag)} ${t.monitored}/${t.assets} (${t.coverage_pct}%)</span>`;
        }).join('');
        box.innerHTML = `<div style="border:1px solid #e5e8eb;border-radius:8px;padding:8px 10px;font-size:12px">
          <div style="font-weight:600;color:#191f28">${tt('admin.dyn.scope_cov','인증범위 커버리지')}</div>
          <div style="font-size:11px;color:#191f28;margin:2px 0 6px;line-height:1.5">${tt('admin.dyn.scope_help','읽는 법: 자산에 붙인 범위 태그별로 <b>기술 신호(모니터링)로 커버되는 비율</b>이에요. ‘인증범위 포함’ 태그 자산 중 실제 수집되는 자산 비율이 인증범위 커버리지예요. 초록≥90%·노랑≥60%·빨강 미만. 미커버 자산은 증적 공백 후보예요.')}</div>
          <div><b>${tt('admin.dyn.scope_inscope','인증범위 포함')}</b>: ${is.monitored||0}/${is.assets||0} (${is.coverage_pct||0}%)${is.unmonitored?` · <span style="color:#f04452">${tt('admin.dyn.scope_uncov','미커버')} ${is.unmonitored}</span>`:''}</div>
          <div style="margin-top:4px">${tagChips||`<span style="color:#8b95a1;font-size:11px">${tt('admin.dyn.scope_notag','범위 태그가 붙은 자산이 없어요. ‘범위태그’ 버튼으로 지정하세요.')}</span>`}</div>
        </div>`;
      } catch(e) { /* silent */ }
    }
    window.loadScopeCoverage = loadScopeCoverage;
    async function editScopeTags(hostname) {
      try {
        const res = await fetch('/assets/owners');
        const list = (await res.json()).owners || [];
        const o = list.find(x => x.hostname === hostname) || {};
        const cur = (o.scope_tags||[]).join(', ');
        const val = prompt(tt('admin.dyn.scope_prompt','인증범위 태그(쉼표 구분). 예: 인증범위 포함, 개인정보처리시스템, 운영환경'), cur);
        if (val === null) return;
        await fetch('/assets/owners', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({hostname, scope_tags: val})});
        await loadOwners();
      } catch(e) { alert(tt('admin.dyn.error_prefix','오류: ')+e.message); }
    }
    window.editScopeTags = editScopeTags;

    // ── 자산 정보를 폼에 채워서 수정 모드 진입 ──
    let _ownersCache = [];
    async function editOwner(hostname) {
      // fetch latest owner data
      try {
        const res = await fetch('/assets/owners');
        const data = await res.json();
        _ownersCache = data.owners || [];
      } catch(e) { /* use empty */ }
      const o = _ownersCache.find(x => x.hostname === hostname);
      if (!o) { ownerStatusEl.textContent = `'${hostname}' ${tt('admin.dyn.info_not_found','정보를 찾을 수 없습니다.')}`; return; }
      _editingHostname = hostname;
      ownHostnameEl.value = o.hostname;
      ownHostnameEl.readOnly = true;
      ownHostnameEl.style.opacity = '0.6';
      ownOwnerEl.value = o.owner || '';
      ownEmailEl.value = o.email || '';
      ownTeamEl.value = o.team || '';
      ownCategoryEl.value = o.category || '';
      ownImportanceEl.value = o.importance || '';
      ownerFormTitleEl.textContent = `${hostname} ${tt('admin.dyn.editing','수정 중')}`;
      ownerFormTitleEl.style.color = '#f5a623';
      cancelEditBtn.style.display = '';
      ownerStatusEl.textContent = '';
      // scroll form into view
      ownerFormTitleEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    function _resetOwnerForm() {
      _editingHostname = null;
      ownHostnameEl.value = ''; ownOwnerEl.value = ''; ownEmailEl.value = '';
      ownTeamEl.value = ''; ownCategoryEl.value = ''; ownImportanceEl.value = '';
      ownHostnameEl.readOnly = false;
      ownHostnameEl.style.opacity = '1';
      ownerFormTitleEl.textContent = tt('admin.dyn.new_asset','새 자산 등록');
      ownerFormTitleEl.style.color = '#3182f6';
      cancelEditBtn.style.display = 'none';
    }

    cancelEditBtn?.addEventListener('click', () => { _resetOwnerForm(); ownerStatusEl.textContent = tt('admin.dyn.edit_cancelled','수정 취소됨'); });

    async function deleteOwner(hostname) {
      if (!confirm(`'${hostname}' ${tt('admin.dyn.confirm_delete_owner','자산 정보를 삭제하시겠습니까?')}`)) return;
      try {
        await fetch(`/assets/owners/${encodeURIComponent(hostname)}`, {method:'DELETE'});
        if (_editingHostname === hostname) _resetOwnerForm();
        await loadOwners();
      } catch(e) { ownerStatusEl.textContent = `${tt('admin.dyn.delete_fail_prefix','삭제 실패: ')}${e.message}`; }
    }

    document.getElementById('add_owner')?.addEventListener('click', async () => {
      const hostname = ownHostnameEl.value.trim();
      if (!hostname) { ownerStatusEl.textContent = tt('admin.dyn.enter_hostname','호스트명을 입력하세요.'); return; }
      ownerStatusEl.textContent = tt('admin.dyn.saving','저장 중…');
      try {
        const res = await fetch('/assets/owners', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({
            hostname,
            owner: ownOwnerEl.value.trim(),
            email: ownEmailEl.value.trim(),
            team: ownTeamEl.value.trim(),
            category: ownCategoryEl.value.trim(),
            importance: ownImportanceEl.value,
          })
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        _resetOwnerForm();
        ownerStatusEl.textContent = tt('admin.dyn.save_done','저장 완료 ');
        await loadOwners();
      } catch(e) { ownerStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
    });
    document.getElementById('reload_owners')?.addEventListener('click', loadOwners);

    // ── Webhooks ───────────────────────────────────────────────────────────
    async function loadWebhooks() {
      webhooksListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/webhooks');
        const data = await res.json();
        const whs = data.webhooks || [];
        if (!whs.length) { webhooksListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_webhooks','등록된 webhook 없음')}</span>`; return; }
        webhooksListEl.innerHTML = whs.map(w => `
          <div class="list-item">
            <div class="top"><strong>${escapeHtml(w.name)}</strong><span class="meta">${escapeHtml(w.created_at||'')}</span></div>
            <div class="meta mono" style="word-break:break-all">${escapeHtml(w.url)}</div>
            <div style="margin-top:8px;display:flex;gap:8px">
              <button class="secondary" style="width:auto;padding:4px 12px;font-size:12px" onclick="testWebhook('${escapeHtml(w.id)}', this)">${tt('admin.dyn.test','테스트')}</button>
              <button class="ghost" style="width:auto;padding:4px 12px;font-size:12px;border-color:#f04452;color:#f04452" onclick="deleteWebhook('${escapeHtml(w.id)}', this)">${tt('admin.dyn.delete','삭제')}</button>
            </div>
          </div>
        `).join('');
      } catch(e) { webhooksListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`; }
    }
    async function testWebhook(id, btn) {
      btn.textContent = tt('admin.dyn.sending','전송 중…'); btn.disabled = true;
      try {
        const res = await fetch(`/webhooks/${id}/test`, {method:'POST'});
        btn.textContent = res.ok ? tt('admin.dyn.success_check','성공') : tt('admin.dyn.fail_check','× 실패');
      } catch(e) { btn.textContent = tt('admin.dyn.error_check','× 오류'); }
      setTimeout(() => { btn.textContent = tt('admin.dyn.test','테스트'); btn.disabled = false; }, 2000);
    }
    async function deleteWebhook(id, btn) {
      if (!confirm(tt('admin.dyn.confirm_delete_webhook','이 webhook을 삭제하시겠습니까?'))) return;
      btn.textContent = tt('admin.dyn.deleting','삭제 중…'); btn.disabled = true;
      try {
        const res = await fetch(`/webhooks/${id}`, {method:'DELETE'});
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        await loadWebhooks();
      } catch(e) { webhookStatusEl.textContent = `${tt('admin.dyn.delete_fail_prefix','삭제 실패: ')}${e.message}`; btn.disabled = false; btn.textContent = tt('admin.dyn.delete','삭제'); }
    }
    document.getElementById('add_webhook')?.addEventListener('click', async () => {
      const url = whUrlEl.value.trim();
      if (!url) { webhookStatusEl.textContent = tt('admin.dyn.enter_url','URL을 입력하세요.'); return; }
      webhookStatusEl.textContent = tt('admin.dyn.adding','추가 중…');
      try {
        const res = await fetch('/webhooks', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name: whNameEl.value.trim() || 'Slack Webhook', url})});
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        whNameEl.value = ''; whUrlEl.value = '';
        webhookStatusEl.textContent = tt('admin.dyn.add_done','추가 완료 ');
        await loadWebhooks();
      } catch(e) { webhookStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
    });
    document.getElementById('reload_webhooks')?.addEventListener('click', loadWebhooks);

    // ── Guide Editor ───────────────────────────────────────────────────────
    const guideEditSelectEl = document.getElementById('guide_edit_select');
    const guideEditTitleEl = document.getElementById('guide_edit_title');
    const guideEditContentEl = document.getElementById('guide_edit_content');
    const guideEditStatusEl = document.getElementById('guide_edit_status');

    async function loadGuideForEdit(guideId) {
      guideEditStatusEl.textContent = tt('admin.dyn.loading_data','불러오는 중…');
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`);
        if (!res.ok) throw new Error(res.status);
        const g = await res.json();
        guideEditTitleEl.value = g.title || '';
        guideEditContentEl.value = g.content || '';
        guideEditStatusEl.textContent = g.updated_at ? `${tt('admin.dyn.last_saved_prefix','마지막 저장: ')}${g.updated_at.slice(0,19).replace('T',' ')}` : tt('admin.dyn.default_content','(기본 내용)');
      } catch(e) { guideEditStatusEl.textContent = `${tt('admin.dyn.load_data_fail_prefix','불러오기 실패: ')}${e.message}`; }
    }

    document.getElementById('guide_edit_load')?.addEventListener('click', () => {
      loadGuideForEdit(guideEditSelectEl.value);
    });
    guideEditSelectEl.addEventListener('change', () => {
      loadGuideForEdit(guideEditSelectEl.value);
    });
    document.getElementById('guide_edit_save')?.addEventListener('click', async () => {
      const guideId = guideEditSelectEl.value;
      const title = guideEditTitleEl.value.trim();
      const content = guideEditContentEl.value;
      if (!title) { guideEditStatusEl.textContent = tt('admin.dyn.enter_title','제목을 입력하세요.'); return; }
      guideEditStatusEl.textContent = tt('admin.dyn.saving','저장 중…');
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`, {
          method: 'PUT', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({title, content}),
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        guideEditStatusEl.textContent = tt('admin.dyn.save_done','저장 완료 ');
      } catch(e) { guideEditStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
    });

    /* ── Admin Tab switching ──────────────────────────────── */
    function switchAdminTab(tab) {
      document.querySelectorAll('.atab-panel').forEach(el => el.classList.remove('active'));
      // 상단 탭 + 하단 탭 모두 active 동기화
      document.querySelectorAll('#admin_tabs_nav button, #admin_bottom_nav button').forEach(btn => btn.classList.remove('active'));
      const panel = document.getElementById('atab_' + tab);
      if (panel) panel.classList.add('active');
      document.querySelectorAll('[data-atab="' + tab + '"]').forEach(btn => btn.classList.add('active'));
      window.scrollTo({ top: 0, behavior: 'smooth' });
      // 탭별 lazy 로더 dispatch (Phase 2)
      if (tab === 'logs') { loadUnifiedLog(); }
      if (tab === 'remediation') { loadAdminVulnActions(); loadAdminActionPlans(); }
      if (tab === 'overview') { loadAdminPhase2Health(); loadAdminSourceFreshness(); }
      if (tab === 'access') { loadRolePermissions(); loadUserTabPermissions(); loadSignupRequests(); loadLdapUsers(); loadAccountViewRoles(); loadAccountCollection(); }
    }

    // i18n: refresh the active admin tab's dynamic content when the language changes
    window.onLangChange = function() {
      const activePanel = document.querySelector('.atab-panel.active');
      const tab = activePanel ? activePanel.id.replace('atab_', '') : 'overview';
      try {
        switchAdminTab(tab);
        // settings/access 탭은 init 시 1회 렌더되므로 언어 변경 시 직접 재렌더
        if (tab === 'settings') { renderDashboardPreferences(); renderGuideButtons(guideExamplesEl, guideExamples); }
        if (tab === 'access') { loadRolePermissions(); loadUserTabPermissions(); loadSignupRequests(); loadLdapUsers(); loadAccountViewRoles(); loadAccountCollection(); }
      } catch (e) { /* best-effort */ }
    };

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

    // ── Signup Requests ────────────────────────────────────────────────────
    const signupListEl = document.getElementById('signup_requests_list');
    const signupStatusEl = document.getElementById('signup_requests_status');

    async function loadSignupRequests() {
      if (!signupListEl) return;
      signupListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/auth/signup-requests');
        const data = await res.json();
        // 처리 대기(pending)만 표시 — 승인 계정은 아래 LDAP 사용자 관리로, 이력은 통합 로그에서 확인
        const reqs = (data.requests || []).filter(r => r.status === 'pending');
        if (reqs.length === 0) {
          signupListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_signup_pending','처리할 가입 요청이 없습니다.')}</span>`;
          return;
        }
        const statusBadge = s => ({pending:tt('admin.dyn.signup.pending','대기중'), approved:tt('admin.dyn.signup.approved','승인됨'), rejected:tt('admin.dyn.signup.rejected','거절됨')}[s] || s);
        signupListEl.innerHTML = reqs.map(r => `
          <div class="owner-row" style="border:1px solid #e5e8eb;border-radius:10px;padding:12px;margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
              <div>
                <strong>${r.name}</strong> <span style="color:#191f28;font-size:12px;">${r.email}</span>
                ${r.username ? `<span style="color:#3182f6;font-size:12px;margin-left:6px;font-family:monospace">@${r.username}</span>` : ''}
                ${r.department ? `<span style="color:#191f28;font-size:12px;margin-left:6px;">[${r.department}]</span>` : ''}
                <div style="font-size:12px;color:#191f28;margin-top:4px;">${r.reason || tt('admin.dyn.no_reason','(사유 없음)')}</div>
                <div style="font-size:11px;color:#191f28;margin-top:4px;">${tt('admin.dyn.col.created','요청일')}: ${r.created_at || '-'}${r.reviewed_at ? ' / ' + tt('admin.dyn.col.reviewed','처리일') + ': ' + r.reviewed_at : ''}</div>
                ${r.status === 'approved' && r.username ? `<div style="font-size:11px;color:#15c47e;margin-top:3px">${tt('admin.dyn.signup.provisioned','계정 생성됨')}: ${r.username} (${r.role || 'user'}, ${r.backend || ''})</div>` : ''}
              </div>
              <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                <span>${statusBadge(r.status)}</span>
                ${r.status === 'pending' ? `
                  <select id="surole_${r.id}" class="inp-sm" style="font-size:12px;padding:4px 8px" title="${tt('admin.dyn.signup.role','부여 역할')}">
                    <option value="user">user</option><option value="helpdesk">helpdesk</option><option value="monitor">monitor</option><option value="auditor">auditor</option><option value="security">security</option><option value="admin">admin</option>
                  </select>
                  <input id="supw_${r.id}" class="inp-sm" placeholder="${tt('admin.dyn.signup.pw_ph','초기 PW(비우면 자동)')}" style="font-size:12px;padding:4px 8px;width:130px" />
                  <button class="secondary" style="font-size:12px;padding:4px 10px" onclick="handleSignupRequest('${r.id}','approved')">${tt('admin.dyn.approve','승인')}</button>
                  <button class="danger" style="font-size:12px;padding:4px 10px" onclick="handleSignupRequest('${r.id}','rejected')">${tt('admin.dyn.reject','거절')}</button>
                ` : ''}
              </div>
            </div>
          </div>`).join('');
      } catch(e) {
        signupListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${e.message}</span>`;
      }
    }

    async function handleSignupRequest(id, status) {
      if (!signupStatusEl) return;
      signupStatusEl.textContent = tt('admin.dyn.processing','처리 중…');
      const body = { status };
      if (status === 'approved') {
        body.role = document.getElementById('surole_' + id)?.value || 'user';
        const pw = (document.getElementById('supw_' + id)?.value || '').trim();
        if (pw) body.password = pw;
      }
      try {
        const res = await fetch(`/auth/signup-requests/${id}`, {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || res.status);
        if (status === 'approved' && data.username) {
          signupStatusEl.innerHTML = `${tt('admin.dyn.approve_done','승인 완료')} <strong>${data.username}</strong> (${data.role}, ${data.backend}) · ${tt('admin.dyn.signup.initpw','초기 비밀번호')}: <code style="background:#ffffff;padding:1px 6px;border-radius:4px;color:#f5a623">${data.initial_password}</code> ${tt('admin.dyn.signup.copy_note','(사용자에게 전달, 1회 표시)')}`;
        } else {
          signupStatusEl.textContent = tt('admin.dyn.reject_done','거절 완료');
        }
        await loadSignupRequests();
      } catch(e) {
        signupStatusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
      }
    }

    if (document.getElementById('reload_signup_requests')) {
      document.getElementById('reload_signup_requests')?.addEventListener('click', loadSignupRequests);
    }

    // ── LDAP 사용자 관리 (admin 전용) ──────────────────────────────────────────
    const ldapListEl = document.getElementById('ldap_users_list');
    const ldapStatusMsgEl = document.getElementById('ldap_users_status');
    let _ldapRoles = ['user','helpdesk','monitor','auditor','security','admin'];
    async function loadLdapUsers() {
      if (!ldapListEl) return;
      const badge = document.getElementById('ldap_status_badge');
      const form = document.getElementById('ldap_add_form');
      ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const sres = await fetch('/admin/ldap/status');
        if (!sres.ok) { ldapListEl.innerHTML = `<span class="empty">${sres.status===401||sres.status===403 ? tt('admin.dyn.ldap.reauth','세션이 만료됐습니다. 새로고침 후 다시 로그인하세요.') : tt('admin.dyn.error_prefix','오류: ')+('HTTP '+sres.status)}</span>`; return; }
        const st = await sres.json();
        if (!st.enabled) {
          if (badge) { badge.textContent = tt('admin.dyn.ldap.disabled','● 비활성'); badge.style.color = '#191f28'; }
          if (form) form.style.display = 'none';
          ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.ldap.off_note','LDAP이 꺼져 있습니다. .env 의 MORI_LDAP_ENABLED=true 로 켜면 여기서 관리할 수 있습니다.')}</span>`;
          return;
        }
        if (badge) { badge.textContent = `● ${tt('admin.dyn.ldap.enabled','활성')} · ${st.url} · ${st.base_dn}`; badge.style.color = '#15c47e'; }
        if (Array.isArray(st.roles) && st.roles.length) _ldapRoles = st.roles;
        if (form) form.style.display = 'flex';
        const res = await fetch('/admin/ldap/users');
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        const data = await res.json();
        const users = data.users || [];
        if (!users.length) { ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.ldap.none','디렉터리에 사용자가 없습니다.')}</span>`; return; }
        ldapListEl.innerHTML = users.map(u => {
          const roleOpts = _ldapRoles.map(r => `<option value="${r}"${u.role===r?' selected':''}>${r}</option>`).join('');
          return `<div class="owner-row" style="border:1px solid #e5e8eb;border-radius:10px;padding:10px 12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
            <div>
              <strong style="font-family:monospace;color:#3182f6">${escapeHtml(u.uid)}</strong>
              <span style="color:#191f28;font-size:13px;margin-left:6px">${escapeHtml(u.cn||'')}</span>
              ${u.mail ? `<span style="color:#191f28;font-size:12px;margin-left:6px">${escapeHtml(u.mail)}</span>` : ''}
            </div>
            <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
              <select onchange="ldapSetRole('${escapeHtml(u.uid)}', this.value)" class="inp-sm" style="font-size:12px;padding:4px 8px" title="${tt('admin.dyn.ldap.role','MORI 역할')}">${roleOpts}</select>
              <button class="secondary" style="font-size:12px;padding:3px 9px" onclick="ldapResetPw('${escapeHtml(u.uid)}')">${tt('admin.dyn.ldap.resetpw','비번 재설정')}</button>
              <button class="danger" style="font-size:12px;padding:3px 9px" onclick="ldapDeleteUser('${escapeHtml(u.uid)}')">${tt('admin.dyn.delete','삭제')}</button>
            </div>
          </div>`;
        }).join('');
      } catch(e) {
        ldapListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
    }
    window.loadLdapUsers = loadLdapUsers;

    async function ldapAddUser() {
      const g = id => document.getElementById(id);
      const uid = g('ldap_new_uid').value.trim();
      const password = g('ldap_new_pw').value.trim();
      if (!uid || !password) { if (ldapStatusMsgEl) ldapStatusMsgEl.textContent = tt('admin.dyn.ldap.need_uid_pw','uid 와 초기 비밀번호는 필수입니다.'); return; }
      const body = { uid, cn: g('ldap_new_cn').value.trim(), mail: g('ldap_new_mail').value.trim(), password, role: g('ldap_new_role').value };
      try {
        const res = await fetch('/admin/ldap/users', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        const d = await res.json();
        if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.added','추가됨')}: ${d.uid} (${d.role})`; ldapStatusMsgEl.style.color = '#15c47e'; }
        ['ldap_new_uid','ldap_new_cn','ldap_new_mail','ldap_new_pw'].forEach(i => g(i).value = '');
        await loadLdapUsers();
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#f04452'; } }
    }
    window.ldapAddUser = ldapAddUser;

    async function ldapDeleteUser(uid) {
      if (!confirm(tt('admin.dyn.ldap.confirm_del','LDAP 사용자를 삭제할까요? ') + uid)) return;
      try {
        const res = await fetch('/admin/ldap/users/' + encodeURIComponent(uid), { method:'DELETE' });
        const d = await res.json(); if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.deleted','삭제됨')}: ${uid}`; ldapStatusMsgEl.style.color = '#191f28'; }
        await loadLdapUsers();
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#f04452'; } }
    }
    window.ldapDeleteUser = ldapDeleteUser;

    async function ldapResetPw(uid) {
      const pw = prompt(tt('admin.dyn.ldap.newpw_prompt','새 비밀번호를 입력하세요:') + ' ' + uid);
      if (!pw) return;
      try {
        const res = await fetch('/admin/ldap/users/' + encodeURIComponent(uid) + '/password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password: pw}) });
        const d = await res.json(); if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.pw_done','비밀번호 재설정됨')}: ${uid}`; ldapStatusMsgEl.style.color = '#15c47e'; }
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#f04452'; } }
    }
    window.ldapResetPw = ldapResetPw;

    async function ldapSetRole(uid, role) {
      try {
        const res = await fetch('/admin/ldap/users/' + encodeURIComponent(uid) + '/role', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({role}) });
        const d = await res.json(); if (!res.ok) throw new Error(d.detail || res.status);
        if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.ldap.role_done','역할 변경됨')}: ${uid} → ${role}`; ldapStatusMsgEl.style.color = '#15c47e'; }
      } catch(e) { if (ldapStatusMsgEl) { ldapStatusMsgEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; ldapStatusMsgEl.style.color='#f04452'; } }
    }
    window.ldapSetRole = ldapSetRole;

    document.getElementById('reload_ldap_users')?.addEventListener('click', loadLdapUsers);


    // ── 통합 이력 로그 (모든 이력 소스 병합 + 검색) ───────────────────────────
    const ulogListEl = document.getElementById('ulog_list');
    const ulogStatusEl = document.getElementById('ulog_status');
    // 분류 → [표시 라벨 i18n키·기본, 색상]
    const ULOG_CAT = {
      login: ['admin.dyn.cat.login', '로그인', '#3182f6'],
      action: ['admin.dyn.cat.action', '행동', '#3182f6'],
      asset: ['admin.dyn.cat.asset', '자산', '#f5a623'],
      vuln: ['admin.dyn.cat.vuln', '취약점', '#f04452'],
      triage: ['admin.dyn.cat.triage', '트리아지', '#15c47e'],
      incident: ['admin.dyn.cat.incident', '인시던트', '#f5a623'],
      evidence: ['admin.dyn.cat.evidence', '증적', '#3182f6'],
      account: ['admin.dyn.cat.account', '계정', '#3182f6'],
      control_evidence: ['admin.dyn.cat.control_evidence', '통제증적', '#15c47e'],
    };
    async function loadUnifiedLog() {
      if (!ulogListEl) return;
      ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      const q = (document.getElementById('ulog_q')?.value || '').trim();
      const category = document.getElementById('ulog_category')?.value || '';
      const df = document.getElementById('ulog_from')?.value || '';
      const dt = document.getElementById('ulog_to')?.value || '';
      const params = new URLSearchParams();
      if (q) params.set('q', q);
      if (category) params.set('category', category);
      if (df) params.set('date_from', df);
      if (dt) params.set('date_to', dt);
      let url = '/admin/logs';
      if (params.toString()) url += '?' + params.toString();
      try {
        const res = await fetch(url);
        if (!res.ok) { ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.load_fail','로드 실패')}</span>`; return; }
        const data = await res.json();
        const logs = data.logs || [];
        if (!logs.length) { ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_log','이력 없음')}</span>`; return; }
        ulogListEl.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead><tr style="background:#f7f8fa;">
            <th style="padding:8px;color:#3182f6;text-align:left">${tt('admin.dyn.col.time','시각')}</th>
            <th style="padding:8px;color:#3182f6;text-align:left">${tt('admin.dyn.col.category','분류')}</th>
            <th style="padding:8px;color:#3182f6;text-align:left">${tt('admin.dyn.col.actor','행위자')}</th>
            <th style="padding:8px;color:#3182f6;text-align:left">${tt('admin.dyn.col.action','액션')}</th>
            <th style="padding:8px;color:#3182f6;text-align:left">${tt('admin.dyn.col.target','대상')}</th>
            <th style="padding:8px;color:#3182f6;text-align:left">${tt('admin.dyn.col.detail','상세')}</th>
          </tr></thead>
          <tbody>
          ${logs.map(l => { const c = ULOG_CAT[l.category] || ['', l.category, '#191f28']; return `<tr style="border-bottom:1px solid #e5e8eb;">
            <td style="padding:7px 8px;color:#191f28;white-space:nowrap">${escapeHtml(formatTime(l.ts))}</td>
            <td style="padding:7px 8px;font-weight:600;color:${c[2]}">${escapeHtml(tt(c[0], c[1]))}</td>
            <td style="padding:7px 8px;color:#191f28">${escapeHtml(l.actor || '-')}</td>
            <td style="padding:7px 8px;color:#f5a623">${escapeHtml(l.action || '-')}</td>
            <td style="padding:7px 8px;color:#191f28">${escapeHtml(l.target || '-')}</td>
            <td style="padding:7px 8px;color:#191f28">${escapeHtml(l.detail || '-')}</td>
          </tr>`; }).join('')}
          </tbody></table>`;
        _pgApply(ulogListEl);
        if (ulogStatusEl) ulogStatusEl.textContent = `${tt('admin.dyn.col.total','총')} ${data.total}${tt('admin.dyn.count_suffix','건')}`;
      } catch(e) {
        ulogListEl.innerHTML = `<span class="empty">${tt('admin.dyn.error_prefix','오류: ')}${escapeHtml(e.message)}</span>`;
      }
    }
    document.getElementById('ulog_reload')?.addEventListener('click', loadUnifiedLog);
    document.getElementById('ulog_search_btn')?.addEventListener('click', loadUnifiedLog);
    document.getElementById('ulog_category')?.addEventListener('change', loadUnifiedLog);
    document.getElementById('ulog_q')?.addEventListener('keydown', e => { if (e.key === 'Enter') loadUnifiedLog(); });

    // ── Role Permissions ─────────────────────────────────────────────────────
    const ROLE_PERM_TABS = [
      { id: 'dashboard', label: '대시보드', labelKey: 'admin.dyn.tab.dashboard' },
      { id: 'triage', label: 'Alert Triage', labelKey: 'admin.dyn.tab.triage' },
      { id: 'incidents', label: '인시던트', labelKey: 'admin.dyn.tab.incidents' },
      { id: 'assets', label: '자산 현황', labelKey: 'admin.dyn.tab.assets' },
      { id: 'compliance', label: 'Compliance PDCA', labelKey: 'admin.dyn.tab.compliance' },
      { id: 'guides', label: '가이드', labelKey: 'admin.dyn.tab.guides' },
    ];
    const ROLE_PERM_ROLES = [
      { key: 'security', label: '보안담당자 (security)', labelKey: 'admin.dyn.role.security' },
      { key: 'monitor', label: '서버모니터 (monitor)', labelKey: 'admin.dyn.role.monitor' },
      { key: 'auditor', label: '감사자 (auditor)', labelKey: 'admin.dyn.role.auditor' },
      { key: 'helpdesk', label: '헬프데스크 (helpdesk)', labelKey: 'admin.dyn.role.helpdesk' },
      { key: 'user', label: '일반사용자 (user)', labelKey: 'admin.dyn.role.user' },
    ];

    async function loadRolePermissions() {
      const listEl = document.getElementById('roleperm_list');
      const statusEl = document.getElementById('roleperm_status');
      if (!listEl) return;
      listEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/admin/role-permissions');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const perms = data.permissions || {};
        listEl.innerHTML = ROLE_PERM_ROLES.map(role => {
          const allowed = perms[role.key] || [];
          const checks = ROLE_PERM_TABS.map(tab => {
            const checked = allowed.includes(tab.id) ? 'checked' : '';
            return `<label style="display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid #e5e8eb;border-radius:8px;background:#ffffff;cursor:pointer">
              <input type="checkbox" data-role="${role.key}" data-tab="${tab.id}" ${checked} style="width:auto;margin:0" />
              <span style="font-size:13px">${tt(tab.labelKey, tab.label)}</span>
            </label>`;
          }).join('');
          return `<div style="background:#f7f8fa;border:1px solid #e5e8eb;border-radius:12px;padding:14px">
            <div style="font-weight:700;color:#3182f6;margin-bottom:10px">${escapeHtml(tt(role.labelKey, role.label))}</div>
            <div style="display:flex;flex-wrap:wrap;gap:8px">${checks}</div>
          </div>`;
        }).join('');
      } catch(e) {
        listEl.innerHTML = `<span class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span>`;
      }
    }

    if (document.getElementById('reload_roleperm')) {
      document.getElementById('reload_roleperm')?.addEventListener('click', loadRolePermissions);
    }
    if (document.getElementById('save_roleperm')) {
      document.getElementById('save_roleperm')?.addEventListener('click', async () => {
        const statusEl = document.getElementById('roleperm_status');
        const checkboxes = document.querySelectorAll('#roleperm_list input[type=checkbox]');
        const payload = {};
        checkboxes.forEach(cb => {
          const role = cb.dataset.role;
          const tab = cb.dataset.tab;
          if (!payload[role]) payload[role] = [];
          if (cb.checked) payload[role].push(tab);
        });
        statusEl.textContent = tt('admin.dyn.saving','저장 중...');
        try {
          const res = await fetch('/admin/role-permissions', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
          });
          if (!res.ok) throw new Error(await res.text());
          statusEl.style.color = '#15c47e';
          statusEl.textContent = tt('admin.dyn.roleperm_saved','권한이 저장되었습니다. 해당 역할 사용자 재로그인 후 적용됩니다.');
        } catch(e) {
          statusEl.style.color = '#f04452';
          statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
        }
      });
    }

    // ── 계정 거버넌스 열람 역할 (admin 조정) ───────────────────────────────
    async function loadAccountViewRoles() {
      const listEl = document.getElementById('acctrole_list');
      if (!listEl) return;
      listEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/accounts/view-roles');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const roles = data.roles || ['admin','security'];
        const locked = data.locked || ['admin'];
        const all = data.all_roles || ['admin','security','monitor','auditor','helpdesk','user'];
        listEl.innerHTML = all.map(r => {
          const isLocked = locked.includes(r);
          const checked = roles.includes(r) ? 'checked' : '';
          const dis = isLocked ? 'disabled' : '';
          const meta = ROLE_PERM_ROLES.find(x => x.key === r);
          const lbl = r === 'admin' ? tt('admin.dyn.role.admin','관리자 (admin)') : (meta ? tt(meta.labelKey, meta.label) : r);
          return `<label style="display:flex;align-items:center;gap:8px;padding:8px 12px;border:1px solid #e5e8eb;border-radius:8px;background:#ffffff;cursor:${isLocked?'not-allowed':'pointer'};opacity:${isLocked?'0.65':'1'}">
            <input type="checkbox" data-acctrole="${r}" ${checked} ${dis} style="width:auto;margin:0" />
            <span style="font-size:13px">${escapeHtml(lbl)}${isLocked?` <span style="color:#191f28;font-size:11px">${tt('admin.dyn.locked','(항상 포함)')}</span>`:''}</span>
          </label>`;
        }).join('');
      } catch(e) {
        listEl.innerHTML = `<span class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span>`;
      }
    }
    window.loadAccountViewRoles = loadAccountViewRoles;
    document.getElementById('reload_acctrole')?.addEventListener('click', loadAccountViewRoles);
    document.getElementById('save_acctrole')?.addEventListener('click', async () => {
      const statusEl = document.getElementById('acctrole_status');
      const roles = [...document.querySelectorAll('#acctrole_list input[type=checkbox]:checked')].map(cb => cb.dataset.acctrole);
      statusEl.textContent = tt('admin.dyn.saving','저장 중...');
      try {
        const res = await fetch('/accounts/view-roles', {
          method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({roles}),
        });
        if (!res.ok) throw new Error(await res.text());
        statusEl.style.color = '#15c47e';
        statusEl.textContent = tt('admin.dyn.acctrole_saved','저장되었습니다. 대상 사용자 재로그인 후 계정 탭이 보입니다.');
      } catch(e) {
        statusEl.style.color = '#f04452';
        statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`;
      }
    });

    // ── 계정 수집 on/off + 수집 경로 (admin 조정) ──────────────────────────
    function _acctColRenderHint() {
      const src = document.getElementById('acctcol_source')?.value || 'fleet';
      const on = !!document.getElementById('acctcol_enabled')?.checked;
      const hint = document.getElementById('acctcol_hint');
      const cmd = document.getElementById('acctcol_cmd');
      if (!hint || !cmd) return;
      // 스크립트 경로일 때만 복붙 명령 노출. 토큰은 환경변수로 넘겨 화면 노출 방지.
      const show = on && src === 'script';
      hint.style.display = show ? 'block' : 'none';
      if (show) {
        const base = location.origin;
        cmd.textContent =
          `# 대상 서버에서 (토큰은 환경변수로 주입 — 화면/스크린샷에 남기지 마세요)\n` +
          `export MORI_INGEST_URL=${base}\n` +
          `export MORI_INGEST_TOKEN=<서버 .env 의 MORI_INGEST_TOKEN>\n` +
          `sudo -E bash scripts/mori-collect-accounts.sh --cron`;
      }
    }
    async function loadAccountCollection() {
      const en = document.getElementById('acctcol_enabled');
      const sel = document.getElementById('acctcol_source');
      if (!en || !sel) return;
      try {
        const res = await fetch('/accounts/collection');
        if (!res.ok) throw new Error(res.status);
        const d = await res.json();
        en.checked = d.enabled !== false;
        sel.value = d.source || 'fleet';
      } catch (e) { /* 기본값 유지 */ }
      _acctColRenderHint();
    }
    window.loadAccountCollection = loadAccountCollection;
    document.getElementById('acctcol_enabled')?.addEventListener('change', _acctColRenderHint);
    document.getElementById('acctcol_source')?.addEventListener('change', _acctColRenderHint);
    document.getElementById('reload_acctcol')?.addEventListener('click', loadAccountCollection);
    document.getElementById('save_acctcol')?.addEventListener('click', async () => {
      const statusEl = document.getElementById('acctcol_status');
      const enabled = !!document.getElementById('acctcol_enabled')?.checked;
      const source = document.getElementById('acctcol_source')?.value || 'fleet';
      statusEl.textContent = tt('admin.dyn.saving', '저장 중...');
      try {
        const res = await fetch('/accounts/collection', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({enabled, source}),
        });
        if (!res.ok) throw new Error(await res.text());
        statusEl.style.color = '#15c47e';
        statusEl.textContent = enabled
          ? tt('admin.dyn.acctcol_on', '저장되었습니다. 계정 수집이 켜졌습니다.')
          : tt('admin.dyn.acctcol_off', '저장되었습니다. 계정 수집이 꺼져 MORI가 계정 데이터를 받지 않습니다.');
        _acctColRenderHint();
      } catch (e) {
        statusEl.style.color = '#f04452';
        statusEl.textContent = `${tt('admin.dyn.error_prefix', '오류: ')}${e.message}`;
      }
    });

    // ── 유저별 탭 권한 관리 ────────────────────────────────────────────────
    async function loadUserTabPermissions() {
      const listEl = document.getElementById('usertab_list');
      const statusEl = document.getElementById('usertab_status');
      if (!listEl) return;
      listEl.innerHTML = `<span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span>`;
      try {
        const res = await fetch('/admin/user-tab-permissions');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const users = data.users || [];
        if (users.length === 0) {
          listEl.innerHTML = `<span class="empty">${tt('admin.dyn.none_users','등록된 사용자가 없습니다.')}</span>`;
          return;
        }
        listEl.innerHTML = users.map(u => {
          const activeTabs = u.has_override ? u.user_tabs : u.role_default_tabs;
          const overrideBadge = u.has_override
            ? `<span style="background:#fef3d6;color:#f5a623;padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px">${tt('admin.dyn.override_custom','개별 설정')}</span>`
            : `<span style="background:#e5e8eb;color:#3182f6;padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px">${tt('admin.dyn.override_default','역할 기본값')}</span>`;
          const checks = ROLE_PERM_TABS.map(tab => {
            const checked = activeTabs.includes(tab.id) ? 'checked' : '';
            return `<label style="display:flex;align-items:center;gap:6px;padding:5px 8px;border:1px solid #e5e8eb;border-radius:6px;background:#ffffff;cursor:pointer;font-size:12px">
              <input type="checkbox" data-user="${escapeHtml(u.username)}" data-utab="${tab.id}" ${checked} style="width:auto;margin:0" onchange="_onUserTabChange('${escapeHtml(u.username)}')" />
              <span>${tt(tab.labelKey, tab.label)}</span>
            </label>`;
          }).join('');
          const resetBtn = u.has_override
            ? `<button onclick="_resetUserTabs('${escapeHtml(u.username)}')" style="font-size:11px;padding:3px 10px;background:#fdecee;color:#f04452;border:1px solid #fdecee;border-radius:6px;cursor:pointer;margin-left:8px">${tt('admin.dyn.reset','초기화')}</button>`
            : '';
          return `<div style="background:#f7f8fa;border:1px solid #e5e8eb;border-radius:12px;padding:14px" id="usertab_row_${escapeHtml(u.username)}">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px">
              <div>
                <strong style="color:#191f28">${escapeHtml(u.username)}</strong>
                <span style="color:#191f28;font-size:12px;margin-left:6px">(${escapeHtml(u.role)})</span>
                ${overrideBadge}
              </div>
              <div style="display:flex;gap:6px;align-items:center">${resetBtn}</div>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">${checks}</div>
            <div class="status-line" id="usertab_status_${escapeHtml(u.username)}" style="margin-top:6px;font-size:12px"></div>
          </div>`;
        }).join('');
      } catch(e) {
        listEl.innerHTML = `<span class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span>`;
      }
    }

    async function _onUserTabChange(username) {
      const checkboxes = document.querySelectorAll(`input[data-user="${username}"][data-utab]`);
      const tabs = [];
      checkboxes.forEach(cb => { if (cb.checked) tabs.push(cb.dataset.utab); });
      const statusEl = document.getElementById('usertab_status_' + username);
      if (statusEl) { statusEl.style.color = '#191f28'; statusEl.textContent = tt('admin.dyn.saving','저장 중…'); }
      try {
        const res = await fetch(`/admin/user-tab-permissions/${encodeURIComponent(username)}`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ tabs }),
        });
        if (!res.ok) throw new Error(await res.text());
        if (statusEl) { statusEl.style.color = '#15c47e'; statusEl.textContent = tt('admin.dyn.saved_relogin','저장됨 (재로그인 후 적용)'); }
        // 배지 업데이트
        setTimeout(() => loadUserTabPermissions(), 500);
      } catch(e) {
        if (statusEl) { statusEl.style.color = '#f04452'; statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
      }
    }
    window._onUserTabChange = _onUserTabChange;

    async function _resetUserTabs(username) {
      if (!confirm(`${username}${tt('admin.dyn.confirm_reset_usertabs',' 유저의 개별 탭 설정을 초기화하시겠습니까?\n역할 기본값으로 돌아갑니다.')}`)) return;
      const statusEl = document.getElementById('usertab_status_' + username);
      try {
        const res = await fetch(`/admin/user-tab-permissions/${encodeURIComponent(username)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await res.text());
        if (statusEl) { statusEl.style.color = '#15c47e'; statusEl.textContent = tt('admin.dyn.reset_done','초기화됨'); }
        setTimeout(() => loadUserTabPermissions(), 500);
      } catch(e) {
        if (statusEl) { statusEl.style.color = '#f04452'; statusEl.textContent = `${tt('admin.dyn.error_prefix','오류: ')}${e.message}`; }
      }
    }
    window._resetUserTabs = _resetUserTabs;

    if (document.getElementById('reload_usertab')) {
      document.getElementById('reload_usertab')?.addEventListener('click', loadUserTabPermissions);
    }


    // ── Phase 2: Overview · Compliance · Triage · Remediation 로더 ───────────
    const STATUS_BADGE = {
      pass:'<span style="background:rgba(21,196,126,.12);color:#15c47e;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700">PASS</span>',
      fail:'<span style="background:rgba(240,68,82,.12);color:#f04452;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700">FAIL</span>',
      warning:'<span style="background:rgba(245,166,35,.12);color:#f5a623;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700">WARN</span>',
      not_applicable:'<span style="background:rgba(139,149,161,.12);color:#191f28;padding:2px 8px;border-radius:6px;font-size:12px">N/A</span>',
      not_checked:`<span style="background:rgba(139,149,161,.12);color:#191f28;padding:2px 8px;border-radius:6px;font-size:12px">${tt('admin.dyn.metric.not_checked','미점검')}</span>`,
    };
    const _statusBadge = (s) => STATUS_BADGE[s] || `<span>${escapeHtml(s||'')}</span>`;
    const _sourceBadge = (src) => {
      const map = { control_check:'#3182f6', trivy:'#f5a623', alert:'#f04452' };
      const color = map[src] || '#191f28';
      return `<span style="background:rgba(49,130,246,.08);color:${color};padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700">${escapeHtml(src||'-')}</span>`;
    };

    async function loadAdminPhase2Health() {
      const el = document.getElementById('phase2_health');
      if (!el) return;
      el.innerHTML = `<div class="coverage-item"><span style="color:#191f28">${tt('admin.dyn.loading','로딩 중…')}</span></div>`;
      try {
        const res = await fetch('/compliance/pdca');
        const data = res.ok ? await res.json() : { summary: {}, pending_count: 0 };
        const summary = data.summary || {};
        const total = Object.values(summary).reduce((a,b)=>a+(b||0),0);
        const items = [
          { label: 'Control Checks', value: total, hint: 'control_check_results' },
          { label: tt('admin.dyn.metric.pending','미조치'), value: data.pending_count || 0, hint: 'fail + warning + Trivy + Alert' },
          { label: tt('admin.dyn.metric.overdue','기한 초과'), value: data.overdue_count || 0, hint: `remediation_due_at ${tt('admin.dyn.elapsed','경과')}` },
        ];
        const inc = await fetch('/incidents').then(r => r.ok ? r.json() : { total: 0 }).catch(() => ({ total: 0 }));
        items.push({ label: 'Incidents', value: inc.total || (inc.incidents||[]).length, hint: 'incident_store' });
        el.innerHTML = items.map(it => `
          <div class="coverage-item">
            <div style="color:#191f28;font-size:12px">${escapeHtml(it.label)}</div>
            <strong style="color:${it.value>0?'#15c47e':'#f04452'}">${it.value}</strong>
            <div style="color:#191f28;font-size:11px;margin-top:4px">${escapeHtml(it.hint)}</div>
          </div>`).join('');
      } catch (e) {
        el.innerHTML = `<div class="coverage-item"><span style="color:#f04452">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span></div>`;
      }
    }

    // 초 단위 lag을 사람이 읽을 수 있는 문자열로 변환
    function _humanizeLag(seconds) {
      if (seconds == null || !isFinite(seconds)) return '-';
      const s = Math.max(0, Math.floor(seconds));
      const U = (k, f) => tt('admin.dyn.unit.' + k, f);
      if (s < 60) return s + U('sec','초');
      if (s < 3600) return Math.floor(s/60) + U('min','분');
      if (s < 86400) {
        const h = Math.floor(s/3600); const m = Math.floor((s%3600)/60);
        return m ? `${h}${U('hour','시간')} ${m}${U('min','분')}` : `${h}${U('hour','시간')}`;
      }
      const d = Math.floor(s/86400); const h = Math.floor((s%86400)/3600);
      return h ? `${d}${U('day','일')} ${h}${U('hour','시간')}` : `${d}${U('day','일')}`;
    }

    async function loadAdminSourceFreshness() {
      const el = document.getElementById('admin_source_freshness');
      if (!el) return;
      el.innerHTML = `<div class="empty">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/dashboard');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const rows = data.source_coverage || [];
        if (!rows.length) {
          el.innerHTML = `<div class="empty">${tt('admin.dyn.none_source_syncs','source_syncs 기록 없음')}</div>`;
          return;
        }
        const nowMs = Date.now();
        const fmt = (rec) => {
          const lastOk = rec.last_success_at ? new Date(rec.last_success_at).getTime() : null;
          const lastErr = rec.last_error_at ? new Date(rec.last_error_at).getTime() : null;
          const lagSec = lastOk != null ? (nowMs - lastOk) / 1000 : null;
          const sla = rec.stale_threshold_seconds || null;
          let statusColor = '#15c47e', statusLabel = (rec.status||'unknown').toUpperCase();
          if (rec.status === 'error') { statusColor = '#f04452'; }
          else if (rec.is_stale) { statusColor = '#f5a623'; statusLabel = 'STALE'; }
          else if (rec.status === 'running') { statusColor = '#3182f6'; }
          const lagColor = rec.is_stale ? '#f5a623' : (lagSec != null ? '#191f28' : '#191f28');
          const slaText = sla ? _humanizeLag(sla) : '-';
          const errBadge = lastErr ? `<div style="color:#f04452;font-size:11px;margin-top:2px">${tt('admin.dyn.recent_error_prefix','최근 에러: ')}${escapeHtml(formatTime(rec.last_error_at))}</div>` : '';
          return `<tr>
            <td><strong>${escapeHtml((rec.source||'-').toUpperCase())}</strong></td>
            <td><span style="background:rgba(49,130,246,.08);color:${statusColor};padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700">${escapeHtml(statusLabel)}</span></td>
            <td style="text-align:right">${rec.host_count||0}</td>
            <td style="color:${lagColor}">${lagSec != null ? _humanizeLag(lagSec) + tt('admin.dyn.ago_suffix',' 전') : '-'}</td>
            <td style="color:#191f28;font-size:12px">${escapeHtml(slaText)}</td>
            <td style="text-align:right;color:#191f28">${rec.records_collected||0}<div style="color:#191f28;font-size:11px">env ${rec.envelopes_normalized||0} · save ${rec.entities_saved||0}</div></td>
            <td style="color:#191f28;font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(rec.message||'-')}${errBadge}</td>
          </tr>`;
        };
        el.innerHTML = `<table class="result-table">
          <thead><tr><th>Source</th><th>Status</th><th style="text-align:right">${tt('admin.dyn.col.host','호스트')}</th><th>Lag</th><th>SLA</th><th style="text-align:right">${tt('admin.dyn.col.collected','수집')}</th><th>${tt('admin.dyn.col.message','메시지')}</th></tr></thead>
          <tbody>${rows.map(fmt).join('')}</tbody></table>`;
          _pgApply(el);
      } catch (e) {
        el.innerHTML = `<div class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_freshness')) {
      document.getElementById('admin_reload_freshness').addEventListener('click', loadAdminSourceFreshness);
    }

    async function loadAdminCompliance() {  // (deprecated Compliance는 /ui 에서만 편집)
      const cardsEl = document.getElementById('admin_compliance_cards');
      const catEl = document.getElementById('admin_compliance_categories');
      const pendingEl = document.getElementById('admin_compliance_pending');
      if (!cardsEl) return;
      cardsEl.innerHTML = `<div class="metric-card card"><span class="empty">${tt('admin.dyn.loading','로딩 중…')}</span></div>`;
      try {
        const res = await fetch('/compliance/pdca');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const s = data.summary || {};
        const total = (s.pass||0)+(s.fail||0)+(s.warning||0)+(s.not_applicable||0)+(s.not_checked||0);
        const passRate = total > 0 ? Math.round(((s.pass||0)/total)*100) : null;
        const ps = data.pending_sources || {};
        cardsEl.innerHTML = `
          <div class="metric-card card"><div class="metric-label">${tt('admin.dyn.metric.total_checks','전체 점검')}</div><div class="metric-value">${total}</div></div>
          <div class="metric-card card"><div class="metric-label">Pass</div><div class="metric-value" style="color:#15c47e">${s.pass||0}</div></div>
          <div class="metric-card card"><div class="metric-label">Fail</div><div class="metric-value" style="color:#f04452">${s.fail||0}</div></div>
          <div class="metric-card card"><div class="metric-label">Warning</div><div class="metric-value" style="color:#f5a623">${s.warning||0}</div></div>
          <div class="metric-card card"><div class="metric-label">Pass Rate</div><div class="metric-value" style="color:#3182f6">${passRate===null?'':passRate+'%'}</div></div>
          <div class="metric-card card"><div class="metric-label">${tt('admin.dyn.metric.pending_icon','미조치')}</div><div class="metric-value" style="color:#f5a623">${data.pending_count||0}</div><div class="metric-sub">${tt('admin.dyn.col.control','통제')} ${ps.control_check||0} · Trivy ${ps.trivy||0} · Alert ${ps.alert||0}</div></div>
        `;
        const cats = data.categories || [];
        if (!cats.length) {
          catEl.innerHTML = `<div class="empty">${tt('admin.dyn.none_category','카테고리 데이터 없음 시드 누락 가능성')}</div>`;
        } else {
          catEl.innerHTML = `<table class="result-table">
            <thead><tr><th>${tt('admin.dyn.col.category','카테고리')}</th><th>${tt('admin.dyn.col.total','총')}</th><th style="color:#15c47e">Pass</th><th style="color:#f04452">Fail</th><th style="color:#f5a623">Warning</th><th style="color:#191f28">N/A</th><th style="color:#191f28">${tt('admin.dyn.col.not_checked','미점검')}</th></tr></thead>
            <tbody>${cats.map(c => `<tr>
              <td><strong>${escapeHtml(c.category||'-')}</strong></td>
              <td>${c.total||0}</td>
              <td style="color:#15c47e">${c.pass||0}</td>
              <td style="color:#f04452">${c.fail||0}</td>
              <td style="color:#f5a623">${c.warning||0}</td>
              <td style="color:#191f28">${c.not_applicable||0}</td>
              <td style="color:#191f28">${c.not_checked||0}</td>
            </tr>`).join('')}</tbody></table>`;
            _pgApply(catEl);
        }
        const pending = data.pending_remediations || [];
        if (!pending.length) {
          pendingEl.innerHTML = `<div class="empty">${tt('admin.dyn.none_pending','미조치 항목 없음 ')}</div>`;
        } else {
          pendingEl.innerHTML = `<table class="result-table">
            <thead><tr><th>${tt('admin.dyn.col.source','출처')}</th><th>${tt('admin.dyn.col.control_id','통제 ID')}</th><th>${tt('admin.dyn.col.target','대상')}</th><th>${tt('admin.dyn.col.status','상태')}</th><th>${tt('admin.dyn.col.owner','담당자')}</th><th>${tt('admin.dyn.col.due','조치기한')}</th><th>${tt('admin.dyn.col.note','비고')}</th></tr></thead>
            <tbody>${pending.slice(0,100).map(p => `<tr>
              <td>${_sourceBadge(p.source)}</td>
              <td><strong>${escapeHtml(p.control_id||'-')}</strong></td>
              <td>${escapeHtml(p.entity_id||'-')}</td>
              <td>${_statusBadge(p.status)}</td>
              <td>${escapeHtml(p.owner||'-')}</td>
              <td style="${p.overdue?'color:#f04452;font-weight:700':''}">${p.overdue?'':''}${escapeHtml(p.remediation_due_at?formatTime(p.remediation_due_at):'-')}</td>
              <td style="color:#191f28;font-size:12px">${escapeHtml(p.note||'')}</td>
            </tr>`).join('')}${pending.length>100?`<tr><td colspan="7" style="color:#191f28;text-align:center;padding:8px">… ${pending.length-100}${tt('admin.dyn.more_rows_suffix','건 더 (CSV 다운로드 권장)')}</td></tr>`:''}</tbody></table>`;
            _pgApply(pendingEl);
        }
      } catch (e) {
        cardsEl.innerHTML = `<div class="metric-card card"><span class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</span></div>`;
        if (catEl) catEl.innerHTML = '';
        if (pendingEl) pendingEl.innerHTML = '';
      }
    }
    if (document.getElementById('admin_reload_compliance')) {
      document.getElementById('admin_reload_compliance').addEventListener('click', loadAdminCompliance);
    }

    // ── Triage 로더 (alert triage_store 상태 요약) ────────────────────────
    async function loadAdminTriage() {
      const el = document.getElementById('admin_triage_list');
      if (!el) return;
      el.innerHTML = `<div class="empty">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/alerts');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const alerts = data.alerts || [];
        // triage가 pending이 아닌 항목 우선 + critical/high만 표시 (최대 100건)
        const rows = alerts
          .filter(a => (a.triage && a.triage.status && a.triage.status !== 'pending') || ['critical','high'].includes(a.severity))
          .slice(0, 100);
        if (!rows.length) {
          el.innerHTML = `<div class="empty">${tt('admin.dyn.none_alert','표시할 alert 없음')}</div>`;
          return;
        }
        const TRIAGE_LABEL = { pending:tt('admin.dyn.atriage.pending','대기'), reviewing:tt('admin.dyn.atriage.reviewing','검토중'), resolved:tt('admin.dyn.atriage.resolved','조치') };
        el.innerHTML = `<table class="result-table">
          <thead><tr><th>${tt('admin.dyn.col.severity','심각도')}</th><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.message','메시지')}</th><th>Triage</th><th>${tt('admin.dyn.col.analyst','분석관')}</th><th>${tt('admin.dyn.col.observed','발생 시각')}</th></tr></thead>
          <tbody>${rows.map(a => {
            const sev = a.severity || '-';
            const sevColor = sev==='critical'?'#f04452':sev==='high'?'#f5a623':'#191f28';
            const t = a.triage || {};
            return `<tr>
              <td><strong style="color:${sevColor}">${escapeHtml(sev.toUpperCase())}</strong></td>
              <td>${escapeHtml(a.hostname||a.host_id||'-')}</td>
              <td style="color:#191f28;max-width:380px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(a.message||'')}</td>
              <td>${escapeHtml(TRIAGE_LABEL[t.status]||t.status||tt('admin.dyn.atriage.pending','대기'))}</td>
              <td style="color:#3182f6">${escapeHtml(t.analyst||'-')}</td>
              <td style="color:#191f28;font-size:12px">${escapeHtml(formatTime(a.observed_at))}</td>
            </tr>`;
          }).join('')}</tbody></table>`;
          _pgApply(el);
      } catch (e) {
        el.innerHTML = `<div class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_triage')) {
      document.getElementById('admin_reload_triage').addEventListener('click', loadAdminTriage);
    }

    // ── Incidents 로더 (incident_store 요약) ──────────────────────────────
    async function loadAdminIncidents() {
      const el = document.getElementById('admin_incidents_list');
      if (!el) return;
      el.innerHTML = `<div class="empty">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/incidents');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const list = data.incidents || [];
        if (!list.length) {
          el.innerHTML = `<div class="empty">${tt('admin.dyn.none_incidents','등록된 인시던트 없음')}</div>`;
          return;
        }
        const STATUS_COLOR = { open:'#f04452', investigating:'#f5a623', resolved:'#15c47e', closed:'#191f28' };
        el.innerHTML = `<table class="result-table">
          <thead><tr><th>${tt('admin.dyn.col.title','제목')}</th><th>${tt('admin.dyn.col.status','상태')}</th><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.handler','담당자')}</th><th>${tt('admin.dyn.col.analyst','분석관')}</th><th>${tt('admin.dyn.col.created','등록일')}</th><th>${tt('admin.dyn.col.updated','업데이트')}</th></tr></thead>
          <tbody>${list.slice(0,100).map(i => `<tr>
            <td><strong>${escapeHtml(i.title||'-')}</strong></td>
            <td><span style="background:rgba(49,130,246,.08);color:${STATUS_COLOR[i.status]||'#191f28'};padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700">${escapeHtml((i.status||'').toUpperCase())}</span></td>
            <td>${escapeHtml(i.hostname||'-')}</td>
            <td>${escapeHtml(i.handler||'-')}</td>
            <td style="color:#3182f6">${escapeHtml(i.analyst||'-')}</td>
            <td style="color:#191f28;font-size:12px">${escapeHtml(formatTime(i.created_at))}</td>
            <td style="color:#191f28;font-size:12px">${escapeHtml(formatTime(i.status_updated_at))}</td>
          </tr>`).join('')}</tbody></table>`;
          _pgApply(el);
      } catch (e) {
        el.innerHTML = `<div class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_incidents')) {
      document.getElementById('admin_reload_incidents').addEventListener('click', loadAdminIncidents);
    }

    // ── Remediation: vuln_actions (Trivy 조치) ────────────────────────────
    async function loadAdminVulnActions() {
      const el = document.getElementById('admin_vuln_actions');
      if (!el) return;
      el.innerHTML = `<div class="empty">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/trivy/vulnerabilities?severity=critical');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const hosts = data.hosts || [];
        // by_host 구조: { host_id, hostname, vulnerabilities: [{vuln_id, cve, severity, package_name, action: {plan_text,...}}] }
        const flatRows = [];
        hosts.forEach(h => {
          (h.vulnerabilities || []).forEach(v => flatRows.push({ ...v, hostname: h.hostname || h.host_id }));
        });
        if (!flatRows.length) {
          el.innerHTML = `<div class="empty">${tt('admin.dyn.none_critical_vuln','Critical 취약점 없음')}</div>`;
          return;
        }
        el.innerHTML = `<table class="result-table">
          <thead><tr><th>${tt('admin.dyn.col.host','호스트')}</th><th>CVE</th><th>${tt('admin.dyn.col.package','패키지')}</th><th>${tt('admin.dyn.col.severity','심각도')}</th><th>${tt('admin.dyn.col.action_plan','조치 계획')}</th><th>${tt('admin.dyn.col.exception','예외')}</th></tr></thead>
          <tbody>${flatRows.slice(0,150).map(v => {
            const act = v.action || {};
            const planTxt = act.plan_text ? `<div>${escapeHtml(act.plan_text.substring(0,80))}${act.plan_text.length>80?'…':''}</div><div style="color:#191f28;font-size:11px">${tt('admin.dyn.due_prefix','기한 ')}${escapeHtml(act.plan_target_date||'-')} · ${escapeHtml(act.plan_updated_by||'-')}</div>` : `<span style="color:#191f28">${tt('admin.dyn.unregistered','미등록')}</span>`;
            const excTxt = act.exception_until ? `<div style="color:#f5a623">~${escapeHtml(act.exception_until)}</div><div style="color:#191f28;font-size:11px">${escapeHtml((act.exception_reason||'').substring(0,60))}</div>` : '<span style="color:#191f28">-</span>';
            return `<tr>
              <td><strong>${escapeHtml(v.hostname||'-')}</strong></td>
              <td style="font-family:ui-monospace">${escapeHtml(v.cve||v.vuln_id||'-')}</td>
              <td style="color:#191f28">${escapeHtml(v.package_name||'-')}</td>
              <td><strong style="color:${v.severity==='critical'?'#f04452':'#f5a623'}">${escapeHtml((v.severity||'').toUpperCase())}</strong></td>
              <td style="color:#191f28;font-size:12px">${planTxt}</td>
              <td style="font-size:12px">${excTxt}</td>
            </tr>`;
          }).join('')}${flatRows.length>150?`<tr><td colspan="6" style="color:#191f28;text-align:center;padding:8px">… ${flatRows.length-150}${tt('admin.dyn.more_rows_short','건 더')}</td></tr>`:''}</tbody></table>`;
          _pgApply(el);
      } catch (e) {
        el.innerHTML = `<div class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }
    if (document.getElementById('admin_reload_vulns')) {
      document.getElementById('admin_reload_vulns').addEventListener('click', loadAdminVulnActions);
    }

    // ── Remediation: asset action_plans (host별 계획) ────────────────────
    async function loadAdminActionPlans() {
      const el = document.getElementById('admin_action_plans');
      if (!el) return;
      el.innerHTML = `<div class="empty">${tt('admin.dyn.loading','로딩 중…')}</div>`;
      try {
        const res = await fetch('/assets');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        // build_assets_payload returns nested structure; collect plans from zabbix/fleet/trivy hosts
        const seen = new Set();
        const rows = [];
        const collect = (arr) => {
          (arr || []).forEach(h => {
            const plan = h.plan || {};
            if (plan.text || plan.target_date) {
              const key = h.host_id || h.hostname;
              if (seen.has(key)) return;
              seen.add(key);
              rows.push({ hostname: h.hostname || h.host_id, plan });
            }
          });
        };
        collect((data.zabbix||{}).by_host);
        collect((data.fleet||{}).by_host);
        collect((data.trivy||{}).by_host);
        if (!rows.length) {
          el.innerHTML = `<div class="empty">${tt('admin.dyn.none_action_plans','등록된 조치 계획 없음')}</div>`;
          return;
        }
        el.innerHTML = `<table class="result-table">
          <thead><tr><th>${tt('admin.dyn.col.host','호스트')}</th><th>${tt('admin.dyn.col.target_date','목표일')}</th><th>${tt('admin.dyn.col.plan_content','계획 내용')}</th><th>${tt('admin.dyn.col.updated','업데이트')}</th></tr></thead>
          <tbody>${rows.slice(0,100).map(r => `<tr>
            <td><strong>${escapeHtml(r.hostname)}</strong></td>
            <td style="color:#f5a623">${escapeHtml(r.plan.target_date||'-')}</td>
            <td style="color:#191f28">${escapeHtml((r.plan.text||'').substring(0,200))}${(r.plan.text||'').length>200?'…':''}</td>
            <td style="color:#191f28;font-size:12px">${escapeHtml(formatTime(r.plan.updated_at)||'-')} · ${escapeHtml(r.plan.updated_by||'-')}</td>
          </tr>`).join('')}</tbody></table>`;
          _pgApply(el);
      } catch (e) {
        el.innerHTML = `<div class="empty">${tt('admin.dyn.load_fail_prefix','로드 실패: ')}${escapeHtml(e.message)}</div>`;
      }
    }

    /* ── 관리자 콘솔 역할별 탭 제한 ────────────────────────────────────────── */
    const _adminRoleLabel = (r) => tt('admin.dyn.rolename.' + r, ({ admin: '어드민', security: '보안담당자', monitor: '서버모니터', auditor: '감사자', helpdesk: '헬프데스크', user: '사용자' })[r] || r);
    // admin: 전체, monitor: 모니터링/자산, security: 모니터링/자산/권한관리,
    // auditor: 모니터링/변경이력(읽기전용), helpdesk: 모니터링/자산
    const _ADMIN_TAB_BY_ROLE = {
      admin:    ['overview','compliance','triage','remediation','assets','access','logs','settings'],
      monitor:  ['overview','compliance','triage','assets'],
      security: ['overview','compliance','triage','remediation','assets','access','logs'],
      auditor:  ['overview','compliance','logs'],
      helpdesk: ['overview','assets'],
      user:     ['overview'],
    };
    let _adminCurrentRole = 'user';
    async function applyAdminRoleTabs() {
      try {
        const res = await fetch('/auth/me');
        if (!res.ok) return;
        const me = await res.json();
        const role = me.role || 'user';
        _adminCurrentRole = role;
        const allowed = _ADMIN_TAB_BY_ROLE[role] || _ADMIN_TAB_BY_ROLE['user'];
        const allTabs = ['overview','compliance','triage','remediation','assets','access','logs','settings'];
        allTabs.forEach(tab => {
          const visible = allowed.includes(tab);
          document.querySelectorAll('[data-atab="'+tab+'"]').forEach(btn => btn.style.display = visible ? '' : 'none');
        });
        // 현재 활성 탭이 허용되지 않으면 첫 번째 허용 탭으로 전환
        const activePanel = document.querySelector('.atab-panel.active');
        const activeId = activePanel ? activePanel.id.replace('atab_','') : 'overview';
        if (!allowed.includes(activeId) && allowed.length > 0) {
          switchAdminTab(allowed[0]);
        }
        // 상단 헤더에 사용자/역할 배지 표시
        const badge = document.getElementById('admin_user_badge');
        if (badge && me.username) {
          const roleLabel = _adminRoleLabel(role);
          badge.innerHTML = '<strong style="color:#3182f6">' + me.username + '</strong> <span style="background:#e5e8eb;color:#3182f6;padding:2px 8px;border-radius:6px;font-size:12px">' + roleLabel + '</span>';
        }
      } catch(e) { /* ignore */ }
    }

    async function initialize() {
      await applyAdminRoleTabs();
      await loadDashboardPreferences();
      await loadCatalog();
      await loadDashboard();
      await loadOwners();
      await loadWebhooks();
      await loadGuideForEdit(guideEditSelectEl.value);
      await loadSignupRequests();
      await loadRolePermissions();
      await loadUserTabPermissions();
      // Phase 2 lazy loaders: overview는 즉시, 나머지는 탭 전환 시
      loadAdminPhase2Health().catch(() => {});
      loadAdminSourceFreshness().catch(() => {});
    }

    initialize().catch(err => {
      console.error('[MORI Admin] initialize error:', err);
      if (dashboardStatusEl) dashboardStatusEl.textContent = `${tt('admin.dyn.init_error','초기화 오류: ')}${err.message}`;
    });
