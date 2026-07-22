"""어드민 콘솔 탭 패널 HTML (P7-3) — console.py에서 분리.
각 상수는 원본 소스 텍스트를 그대로 옮겨 담아 렌더 결과가 바이트동일하다.
__PAYLOAD_JSON__·__DOCS_PORTAL_URL__ placeholder는 console.py 치환 체인에서 해소된다.
"""
_ATAB_OVERVIEW_HTML = """    <!-- ── Tab: Overview ──────────────────────────────────────────────────── -->
    <div class="atab-panel active" id="atab_overview">
      <!-- 온보딩(실사용 시작) 카드: 첫 실행 체크리스트 + 커넥터 연결 상태. renderOnboarding 가 실데이터로 채운다. -->
      <section class="card" id="onboarding_card" style="display:none;padding:20px 22px;margin-bottom:16px"></section>
      <!-- 요약 스트립: 수집 소스/연결 호스트/응답 없음 (renderOverview 가 실데이터로 채움) -->
      <section class="card" id="admin_state_strip" style="display:none;padding:20px 22px;margin-bottom:16px">
        <div class="mori-strip" id="admin_state_strip_body"></div>
      </section>
      <section class="metrics" id="overview_cards"></section>
      <div class="stack">
        <!-- 시스템 진단(보조): 데이터 헬스·커버리지·수집기 신선도 → 접이식으로 내려 운영 카드 우선 -->
        <details class="card" style="padding:0">
          <summary style="cursor:pointer;padding:16px 18px;font-weight:800;font-size:15px;letter-spacing:-0.02em" data-i18n="admin.h.diagnostics">시스템 진단 · 데이터 헬스 · 커버리지 · 수집기 신선도 (펼치기)</summary>
          <div style="padding:0 18px 18px;display:grid;gap:18px">
            <section>
              <h2 data-i18n="admin.h.phase2_health">Phase 2 데이터 헬스</h2>
              <div class="subtext" data-i18n="admin.s.sub.phase2_health">PostgreSQL → InMemoryQueryStore 로 로드된 Phase 2 시드 데이터의 현재 카운트입니다. 0이면 시드 누락 또는 schema 002 미적용일 수 있습니다.</div>
              <div class="coverage" id="phase2_health"></div>
            </section>
            <section>
              <h2 data-i18n="admin.h.source_coverage">Source Coverage</h2>
              <div class="subtext" data-i18n="admin.s.sub.source_coverage">Fleet / Wazuh / Zabbix / Trivy / host logs 기준으로 현재 MORI에 연결된 호스트 수입니다.</div>
              <div class="coverage" id="source_coverage"></div>
              <div class="status-line" id="dashboard_status">dashboard loading...</div>
            </section>
            <section>
              <h2 data-i18n="admin.h.collector_health">Collector Health · Source Freshness</h2>
              <div class="subtext" data-i18n="admin.s.sub.collector_health">수집기별 마지막 성공 시각과 SLA 임계 대비 지연(lag)을 표시합니다. SLA 초과 시 STALE, 마지막 sync가 error면 표시됩니다.</div>
              <div class="actions" style="margin-bottom:10px">
                <button id="admin_reload_freshness" class="secondary" data-i18n="admin.s.btn.refresh">새로고침</button>
              </div>
              <div class="table-wrap" id="admin_source_freshness"></div>
            </section>
          </div>
        </details>
        <section class="card">
          <h2 data-i18n="admin.h.latest_status">Latest Host Status</h2>
          <div class="subtext" data-i18n="admin.s.sub.latest_status">offline / unknown 호스트를 우선 배치합니다.</div>
          <div class="table-wrap" id="latest_status"></div>
        </section>
        <section class="card">
          <h2 data-i18n="admin.h.risk_summary">Risk Summary</h2>
          <div class="subtext" data-i18n="admin.s.sub.risk_summary">24시간 alert와 누적 취약점 기준 상위 호스트입니다.</div>
          <div class="table-wrap" id="risk_summary"></div>
        </section>
        <section class="card">
          <h2 data-i18n="admin.h.recent_activity">Recent Activity</h2>
          <div class="subtext" data-i18n="admin.s.sub.recent_activity">최근 alert / observation / fleet query 결과를 시간순으로 합쳐 보여줍니다.</div>
          <div class="list" id="recent_activity"></div>
        </section>
      </div>
    </div>

"""

_ATAB_REMEDIATION_HTML = """    <!-- ── Tab: Remediation (vuln_actions + action_plans) ────────────────── -->
    <div class="atab-panel" id="atab_remediation">
      <div class="stack">
        <section class="card">
          <h2 data-i18n="admin.h.trivy_remediation">Trivy 취약점 조치 상태</h2>
          <div class="subtext" data-i18n-html="admin.s.sub.trivy">
            Critical / High 취약점과 등록된 조치 계획(plan) · 예외(exception) 입니다.
            편집은 <a href="/ui#assets" style="color:#3182f6">사용자 대시보드 Assets 탭의 취약점 카드</a>에서 가능합니다.
          </div>
          <div class="actions" style="margin-bottom:12px">
            <button id="admin_reload_vulns" class="secondary" data-i18n="admin.s.btn.refresh">새로고침</button>
            <a href="/trivy/vulnerabilities?format=csv&amp;severity=critical" class="ghost" style="display:inline-flex;align-items:center;justify-content:center;text-decoration:none" data-i18n="admin.s.btn.critical_csv">Critical CSV</a>
          </div>
          <div class="table-wrap" id="admin_vuln_actions"></div>
        </section>
        <section class="card">
          <h2 data-i18n="admin.h.action_plans">자산 조치 계획 (action_plans)</h2>
          <div class="subtext" data-i18n="admin.s.sub.action_plans">호스트별 등록된 조치 계획(target_date / text)을 표시합니다.</div>
          <div class="table-wrap" id="admin_action_plans"></div>
        </section>
      </div>
    </div>

"""

_ATAB_ASSETS_HTML = """    <!-- ── Tab: 자산 관리 ────────────────────────────────────────────────── -->
    <div class="atab-panel" id="atab_assets">
      <section class="card">
        <h2 data-i18n="admin.h.asset_owners">자산 담당자 관리</h2>
        <div class="subtext" data-i18n="admin.s.sub.asset_owners">서버·PC 자산의 담당자와 팀을 등록합니다. 호스트명과 정확히 일치해야 합니다.</div>
        <div id="owners_list" class="list" style="margin-bottom:16px;max-height:360px;overflow-y:auto"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
        <div id="owner_form_title" style="font-size:14px;font-weight:700;color:#3182f6;margin-bottom:8px;" data-i18n="admin.dyn.new_asset">새 자산 등록</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <div class="row"><label data-i18n="admin.s.lbl.hostname">호스트명</label><input id="own_hostname" placeholder="예: db-prod-01" data-i18n-placeholder="admin.s.ph.hostname" /></div>
          <div class="row"><label data-i18n="admin.s.lbl.owner">담당자</label><input id="own_owner" placeholder="예: 홍길동" data-i18n-placeholder="admin.s.ph.owner" /></div>
          <div class="row"><label data-i18n="admin.s.lbl.email">이메일</label><input id="own_email" placeholder="예: hong@company.com" data-i18n-placeholder="admin.s.ph.email" /></div>
          <div class="row"><label data-i18n="admin.s.lbl.team">팀</label><input id="own_team" placeholder="예: 인프라팀" data-i18n-placeholder="admin.s.ph.team" /></div>
          <div class="row"><label data-i18n="admin.s.lbl.category">분류 (카테고리)</label><input id="own_category" placeholder="예: DB서버, 웹서버, AP서버" data-i18n-placeholder="admin.s.ph.category" /></div>
          <div class="row"><label data-i18n="admin.s.lbl.importance">중요도</label><select id="own_importance"><option value="" data-i18n="admin.s.opt.auto">자동 (기본)</option><option value="상" data-i18n="admin.s.opt.high">상</option><option value="중" data-i18n="admin.s.opt.mid">중</option><option value="하" data-i18n="admin.s.opt.low">하</option></select></div>
        </div>
        <div class="actions">
          <button id="add_owner" data-i18n="admin.s.btn.add_edit">등록 / 수정</button>
          <button id="cancel_edit_owner" class="ghost" style="display:none" data-i18n="admin.dyn.cancel">취소</button>
          <button id="reload_owners" class="secondary" data-i18n="admin.s.btn.reload_list">목록 새로고침</button>
        </div>
        <div class="status-line" id="owner_status"></div>
      </section>
    </div>

"""

_ATAB_SETTINGS_HTML = """    <!-- ── Tab: 쿼리 ─────────────────────────────────────────────────────── -->
    <!-- ── Tab: 설정 (대시보드 / Webhook / 가이드 / Dev Tools 통합) ───── -->
    <div class="atab-panel" id="atab_settings">
      <div class="stack">
        <section class="card">
          <h2 data-i18n="admin.h.dashboard_prefs">사용자 대시보드 설정</h2>
          <div class="subtext" data-i18n="admin.s.sub.dashboard_prefs">`/ui` 에서 사용자에게 보이는 카드와 섹션을 제어합니다. 재시작 시 초기값으로 돌아갑니다.</div>
          <div class="row"><label for="docs_portal_url" data-i18n="admin.s.lbl.docs_url">문서 / 포털 URL</label><input id="docs_portal_url" value="__DOCS_PORTAL_URL__" /></div>
          <div class="row"><label data-i18n="admin.s.lbl.user_cards">사용자 요약 카드</label><div class="toggle-grid" id="user_dashboard_cards"></div></div>
          <div class="row"><label data-i18n="admin.s.lbl.user_sections">사용자 섹션</label><div class="toggle-grid" id="user_dashboard_sections"></div></div>
          <div class="row"><label data-i18n="admin.s.lbl.asset_columns">자빅스 자산 테이블 컬럼 표시</label><div class="toggle-grid" id="user_dashboard_asset_columns"></div></div>
          <div class="row"><label data-i18n="admin.s.lbl.guide_tabs">가이드 탭 노출 설정</label><div class="toggle-grid" id="user_dashboard_guides"></div></div>
          <div class="actions">
            <button id="save_dashboard_preferences" class="primary" data-i18n="admin.s.btn.save">저장</button>
            <a href="/ui" data-i18n="admin.s.btn.open_user_ui">사용자 화면 열기</a>
          </div>
          <div class="status-line" id="dashboard_preferences_status">user dashboard settings loading...</div>
        </section>
        <section class="card">
          <h2 data-i18n="admin.h.slack">Slack Webhook 관리</h2>
          <div class="subtext" data-i18n="admin.s.sub.slack">Critical 경보 발생 시 자동으로 알림을 전송할 Slack Incoming Webhook을 등록합니다.</div>
          <div id="webhooks_list" class="list" style="margin-bottom:12px"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="row"><label for="wh_name" data-i18n="admin.s.lbl.channel_name">채널 이름 (식별용)</label><input id="wh_name" placeholder="예: #soc-alerts" data-i18n-placeholder="admin.s.ph.channel" /></div>
            <div class="row"><label for="wh_url">Webhook URL</label><input id="wh_url" placeholder="https://hooks.slack.com/services/..." /></div>
          </div>
          <div class="actions">
            <button id="add_webhook" data-i18n="admin.s.btn.add">추가</button>
            <button id="reload_webhooks" class="secondary" data-i18n="admin.s.btn.refresh">새로고침</button>
          </div>
          <div class="status-line" id="webhook_status"></div>
        </section>
        <section class="card">
          <h2 data-i18n="admin.h.guides_editor">가이드 &amp; 메뉴얼 편집</h2>
          <div class="subtext" data-i18n="admin.s.sub.guides_editor">사용자 UI에 표시되는 가이드 내용을 수정합니다. 마크다운 형식을 지원합니다.</div>
          <div class="row"><label for="guide_edit_select" data-i18n="admin.s.lbl.guide_select">가이드 선택</label>
            <select id="guide_edit_select">
              <option value="zabbix_setup" data-i18n="admin.s.gopt.zabbix_setup">Zabbix 에이전트 설정</option>
              <option value="fleet_install" data-i18n="admin.s.gopt.fleet_install">Fleet 에이전트 설치</option>
              <option value="isms_criteria" data-i18n="admin.s.gopt.isms_criteria">ISMS-P 심사 기준</option>
              <option value="iso27001_criteria" data-i18n="admin.s.gopt.iso27001_criteria">ISO 27001 심사 기준</option>
              <option value="ldap_setup" data-i18n="admin.s.gopt.ldap_setup">LDAP 통합 설정</option>
              <option value="incident_response" data-i18n="admin.s.gopt.incident_response">인시던트 대응 절차</option>
              <option value="security_policy" data-i18n="admin.s.gopt.security_policy">보안 정책 가이드</option>
            </select>
          </div>
          <div class="row"><label for="guide_edit_title" data-i18n="admin.s.lbl.title">제목</label><input id="guide_edit_title" placeholder="가이드 제목" data-i18n-placeholder="admin.s.ph.guide_title" /></div>
          <div class="row"><label for="guide_edit_content" data-i18n="admin.s.lbl.content_md">내용 (마크다운)</label><textarea id="guide_edit_content" style="min-height:280px;font-family:monospace;font-size:12px"></textarea></div>
          <div class="actions">
            <button id="guide_edit_load" class="secondary" data-i18n="admin.s.btn.load">불러오기</button>
            <button id="guide_edit_save" data-i18n="admin.s.btn.save">저장</button>
          </div>
          <div class="status-line" id="guide_edit_status"></div>
        </section>

        <!-- ── Dev Tools (자연어 / 구조화 질의 접기 기본) ───────────── -->
        <details class="card" style="padding:0">
          <summary style="cursor:pointer;padding:18px 22px;font-size:18px;font-weight:700;color:#191f28;list-style:none">
            Dev Tools <span style="color:#191f28;font-weight:400;font-size:13px" data-i18n="admin.s.devtools_tag"> 자연어 / 구조화 질의 (개발자용)</span>
          </summary>
          <div style="padding:0 22px 22px 22px">
            <div class="subtext" style="margin-bottom:12px" data-i18n-html="admin.s.sub.devtools">관리자가 직접 백엔드 질의를 시험하기 위한 도구입니다. 일반 사용자 화면은 <a href="/ui" style="color:#3182f6">/ui</a> 를 참고하세요.</div>
            <section style="margin-bottom:18px">
              <h3 style="margin:0 0 8px 0;font-size:15px;color:#191f28" data-i18n="admin.h.quick_actions">Quick Actions</h3>
              <div class="quick-actions" id="quick_queries"></div>
            </section>
            <section style="margin-bottom:18px">
              <h3 style="margin:0 0 8px 0;font-size:15px;color:#191f28" data-i18n="admin.h.nlq">Natural Language Query</h3>
              <div class="subtext"><span data-i18n="admin.s.sub.nlq">자연스럽게 질문하면 의도를 해석해 실행합니다.</span> <a href="#" id="query_guide_link" style="color:#3182f6;" data-i18n="admin.s.link.query_guide">질의 가이드</a></div>
              <div class="row">
                <label for="nlp_text" data-i18n="admin.s.lbl.question">질문</label>
                <textarea id="nlp_text" data-i18n="admin.s.nlq_default">오프라인 호스트 보여줘</textarea>
              </div>
              <div class="guide-chips" id="guide_examples"></div>
              <div class="actions">
                <button id="interpret" class="secondary">Interpret Text</button>
                <button id="run">Run Query</button>
                <button id="download_csv" class="ghost">Download CSV</button>
              </div>
              <div id="interpretation_hint"></div>
              <div class="status-line" id="query_status">catalog loading...</div>
            </section>
            <section style="margin-bottom:18px">
              <h3 style="margin:0 0 8px 0;font-size:15px;color:#191f28" data-i18n="admin.h.query_builder">Structured Query Builder</h3>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                <div class="row"><label for="intent">Intent</label><select id="intent"></select></div>
                <div class="row"><label for="time_range">time_range</label><input id="time_range" value="24h" /></div>
                <div class="row"><label for="host_id">host_id</label><input id="host_id" placeholder="예: host-1" data-i18n-placeholder="admin.s.ph.host_id" /></div>
                <div class="row"><label for="hostname">hostname</label><input id="hostname" placeholder="예: mbp-01" data-i18n-placeholder="admin.s.ph.dev_hostname" /></div>
                <div class="row"><label for="severity">severity</label><input id="severity" placeholder="예: high,critical" data-i18n-placeholder="admin.s.ph.severity" /></div>
                <div class="row"><label for="source">source</label><input id="source" placeholder="예: wazuh" data-i18n-placeholder="admin.s.ph.source" /></div>
              </div>
              <div class="row"><label for="filters">filters (JSON)</label><textarea id="filters">{}</textarea></div>
              <div class="actions">
                <button id="reset" class="secondary">Reset</button>
                <button id="copy_payload" class="ghost">Copy Payload</button>
              </div>
            </section>
            <section>
              <h3 style="margin:0 0 8px 0;font-size:15px;color:#191f28" data-i18n="admin.h.request_response">Request / Response</h3>
              <div class="row"><label for="payload">Request Payload</label><textarea id="payload">__PAYLOAD_JSON__</textarea></div>
              <div class="row"><label>Response</label><div id="result" class="query-result-area"><span class="result-placeholder" data-i18n="admin.dyn.not_run_yet">아직 실행 전입니다.</span></div></div>
            </section>
          </div>
        </details>
      </div>
    </div>

"""

_ATAB_ACCESS_HTML = """    <!-- ── Tab: Access Control (가입 요청 + RBAC 통합) ─────────────────── -->
    <div class="atab-panel" id="atab_access">
      <div class="stack">
        <section class="card">
          <h2 data-i18n="admin.h.signup_requests">가입 요청 관리</h2>
          <div class="subtext" data-i18n="admin.s.sub.signup_requests">사용자가 제출한 가입 요청 목록입니다. 역할·초기 비밀번호를 정해 승인하면 계정이 자동 생성됩니다(LDAP 활성 시 디렉터리, 아니면 로컬). 초기 비밀번호는 1회 표시됩니다.</div>
          <div class="actions" style="margin-bottom:12px">
            <button id="reload_signup_requests" class="secondary" data-i18n="admin.s.btn.refresh">새로고침</button>
          </div>
          <div id="signup_requests_list" class="list"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
          <div class="status-line" id="signup_requests_status"></div>
        </section>

        <!-- LDAP 사용자 관리 (admin 전용, LDAP 활성 시) -->
        <section class="card">
          <div class="row-between">
            <h2 style="margin:0" data-i18n="admin.h.ldap">LDAP 사용자 관리</h2>
            <span id="ldap_status_badge" style="font-size:12px;color:#191f28"></span>
          </div>
          <div class="subtext" data-i18n="admin.s.sub.ldap">디렉터리에 사용자를 직접 추가·삭제하고 비밀번호·역할을 바꿉니다. 여기서 만든 계정은 같은 LDAP을 보는 Grafana/Zabbix/Fleet 에서도 로그인됩니다. (LDAP 비활성 시 .env의 MORI_LDAP_ENABLED=true 필요)</div>
          <div id="ldap_add_form" style="display:none;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0">
            <input id="ldap_new_uid" class="inp-sm" placeholder="uid (아이디)" data-i18n-placeholder="admin.s.ph.ldap_uid" style="width:130px" />
            <input id="ldap_new_cn" class="inp-sm" placeholder="이름(cn)" data-i18n-placeholder="admin.s.ph.ldap_cn" style="width:120px" />
            <input id="ldap_new_mail" class="inp-sm" placeholder="email" style="width:160px" />
            <input id="ldap_new_pw" class="inp-sm" placeholder="초기 비밀번호" data-i18n-placeholder="admin.s.ph.ldap_pw" style="width:140px" />
            <select id="ldap_new_role" class="inp-sm"><option value="user">user</option><option value="helpdesk">helpdesk</option><option value="monitor">monitor</option><option value="auditor">auditor</option><option value="security">security</option><option value="admin">admin</option></select>
            <button class="secondary" style="width:auto;padding:7px 14px;font-size:13px" onclick="ldapAddUser()" data-i18n="admin.s.btn.ldap_add">+ 추가</button>
            <button id="reload_ldap_users" class="secondary" style="width:auto;padding:7px 12px;font-size:13px" data-i18n="admin.s.btn.refresh">새로고침</button>
          </div>
          <div id="ldap_users_list" class="list"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
          <div class="status-line" id="ldap_users_status"></div>
        </section>

        <section class="card">
          <h2 data-i18n="admin.h.role_perms">역할별 탭 권한 관리</h2>
          <div class="subtext" data-i18n="admin.s.sub.role_perms">각 계정 역할에서 보이는 탭을 설정합니다. 저장 후 다음 로그인부터 적용됩니다.</div>
          <div id="roleperm_list" style="display:grid;gap:16px;margin-bottom:16px"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
          <div class="actions">
            <button id="save_roleperm" data-i18n="admin.s.btn.save">저장</button>
            <button id="reload_roleperm" class="secondary" data-i18n="admin.s.btn.refresh">새로고침</button>
          </div>
          <div class="status-line" id="roleperm_status"></div>
        </section>

        <section class="card">
          <h2 data-i18n="admin.h.acct_roles">계정 거버넌스 열람 역할</h2>
          <div class="subtext" data-i18n="admin.s.sub.acct_roles">계정 탭·호스트 상세 계정 섹션·/accounts API를 볼 수 있는 역할을 지정합니다. admin은 항상 포함됩니다. 저장 후 다음 로그인부터 적용됩니다.</div>
          <div id="acctrole_list" style="display:flex;flex-wrap:wrap;gap:14px;margin:14px 0"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
          <div class="actions">
            <button id="save_acctrole" data-i18n="admin.s.btn.save">저장</button>
            <button id="reload_acctrole" class="secondary" data-i18n="admin.s.btn.refresh">새로고침</button>
          </div>
          <div class="status-line" id="acctrole_status"></div>
        </section>

        <section class="card">
          <h2 data-i18n="admin.h.acct_collect">계정 수집</h2>
          <div class="subtext" data-i18n="admin.s.sub.acct_collect">서버·PC의 로컬 계정 인벤토리를 수집할지 정합니다. 민감정보라 끄면 MORI가 계정 데이터를 아예 받지 않습니다(/ingest/accounts 403). 기본 수집 경로는 Fleet(osquery)이며, Fleet이 없는 호스트는 스크립트로 push합니다.</div>
          <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin:14px 0">
            <label style="display:inline-flex;align-items:center;gap:8px;cursor:pointer">
              <input type="checkbox" id="acctcol_enabled" />
              <span data-i18n="admin.s.lbl.acct_collect_on">계정 수집 사용</span>
            </label>
            <label style="display:inline-flex;align-items:center;gap:8px">
              <span data-i18n="admin.s.lbl.acct_collect_src">수집 경로</span>
              <select id="acctcol_source">
                <option value="fleet" data-i18n="admin.s.opt.acct_src_fleet">Fleet (osquery) — 기본</option>
                <option value="script" data-i18n="admin.s.opt.acct_src_script">스크립트 push (Fleet 없는 호스트)</option>
              </select>
            </label>
          </div>
          <div id="acctcol_hint" style="display:none;margin:10px 0;padding:10px 12px;background:#f7f8fa;border:1px solid #e5e8eb;border-left:3px solid #3182f6;border-radius:8px;font-size:12px;color:#4e5968;line-height:1.7">
            <div data-i18n="admin.s.acct_collect_script_hint">Fleet이 없는 서버에서는 아래 스크립트를 실행하면 로컬 계정이 수집됩니다(cron 등록 포함). 토큰은 서버의 환경변수로 넘기세요 — 화면에 노출하지 않습니다.</div>
            <pre id="acctcol_cmd" style="margin:8px 0 0;padding:8px 10px;background:#ffffff;border:1px solid #e5e8eb;border-radius:6px;overflow-x:auto;font-size:11px;color:#191f28"></pre>
          </div>
          <div class="actions">
            <button id="save_acctcol" data-i18n="admin.s.btn.save">저장</button>
            <button id="reload_acctcol" class="secondary" data-i18n="admin.s.btn.refresh">새로고침</button>
          </div>
          <div class="status-line" id="acctcol_status"></div>
        </section>

        <section class="card">
          <h2 data-i18n="admin.h.user_tabs">유저별 대시보드 탭 관리</h2>
          <div class="subtext" data-i18n="admin.s.sub.user_tabs">개별 유저에게 역할 기본값과 다른 탭을 지정합니다. 유저별 설정이 있으면 역할 기본값보다 우선 적용됩니다.</div>
          <div class="actions" style="margin-bottom:12px">
            <button id="reload_usertab" class="secondary" data-i18n="admin.s.btn.refresh_icon">새로고침</button>
          </div>
          <div id="usertab_list" style="display:grid;gap:14px;margin-bottom:16px"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
          <div class="status-line" id="usertab_status"></div>
        </section>
      </div>
    </div>

"""

_ATAB_LOGS_HTML = """    <!-- ── Tab: Audit·Logs (자산 변경 이력 + 사용자 행동 로그 통합) ─── -->
    <div class="atab-panel" id="atab_logs">
      <div class="stack">
        <section class="card">
          <h2 data-i18n="admin.h.unified_log">통합 이력 로그</h2>
          <div class="subtext" data-i18n="admin.s.sub.unified_log">로그인·자산·취약점·트리아지·인시던트·증적·계정·통제 등 모든 변경 이력을 한곳에서 검색합니다.</div>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
            <input id="ulog_q" class="inp-sm" placeholder="행위자·대상·내용 검색" data-i18n-placeholder="admin.s.ph.ulog_q" style="width:220px" />
            <select id="ulog_category" class="inp-sm">
              <option value="" data-i18n="admin.s.opt.all_cat">전체 분류</option>
              <option value="login" data-i18n="admin.s.opt.cat_login">로그인</option>
              <option value="action" data-i18n="admin.s.opt.cat_action">사용자 행동</option>
              <option value="asset" data-i18n="admin.s.opt.cat_asset">자산 변경</option>
              <option value="vuln" data-i18n="admin.s.opt.cat_vuln">취약점 조치</option>
              <option value="triage" data-i18n="admin.s.opt.cat_triage">트리아지</option>
              <option value="incident" data-i18n="admin.s.opt.cat_incident">인시던트</option>
              <option value="evidence" data-i18n="admin.s.opt.cat_evidence">증적</option>
              <option value="account" data-i18n="admin.s.opt.cat_account">계정 승인</option>
              <option value="control_evidence" data-i18n="admin.s.opt.cat_control_evidence">통제 증적</option>
            </select>
            <input id="ulog_from" class="inp-sm" type="date" title="시작일" data-i18n-title="admin.s.ph.ulog_from" style="width:150px" />
            <input id="ulog_to" class="inp-sm" type="date" title="종료일" data-i18n-title="admin.s.ph.ulog_to" style="width:150px" />
            <button id="ulog_search_btn" class="secondary" style="padding:6px 14px" data-i18n="admin.s.btn.search">검색</button>
            <button id="ulog_reload" class="secondary" style="padding:6px 14px" data-i18n="admin.s.btn.refresh">새로고침</button>
          </div>
          <div id="ulog_list" class="list"><span class="empty" data-i18n="admin.dyn.loading">로딩 중…</span></div>
          <div class="status-line" id="ulog_status"></div>
        </section>
      </div>
    </div>
"""

ADMIN_TABS_HTML = _ATAB_OVERVIEW_HTML + _ATAB_REMEDIATION_HTML + _ATAB_ASSETS_HTML + _ATAB_SETTINGS_HTML + _ATAB_ACCESS_HTML + _ATAB_LOGS_HTML
