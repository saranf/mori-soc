"""HTML page templates for the MORI SOC web UI (Task J-2 modularization).

The render functions here build the standalone HTML pages served by the FastAPI
app in :mod:`mori_soc.api.server`. They depend only on the i18n runtime helpers
(:mod:`mori_soc.api.i18n`) so they can be imported without pulling in the route
layer. The larger dashboard/console templates are moved here incrementally.
"""

import json

from mori_soc.api.i18n import (
    _i18n_script,
    _i18n_toggle_html,
    _LOGIN_I18N,
    _SIGNUP_I18N,
)


def render_login_html(error: str = "", next_url: str = "/ui") -> str:
    """로그인 페이지 HTML 반환 (KO/EN 토글 지원)."""
    error_html = f'<div class="login-error">{error}</div>' if error else ""
    i18n_runtime = _i18n_script(_LOGIN_I18N)
    toggle_widget = _i18n_toggle_html()
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title data-i18n-doctitle="login.doctitle">MORI SOC — 로그인</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a1628; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
    .login-card {{ background: #0f2035; border: 1px solid #1e3a5f; border-radius: 16px; padding: 40px 36px;
                   width: 100%; max-width: 400px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }}
    .login-logo {{ text-align: center; margin-bottom: 28px; }}
    .login-logo h1 {{ font-size: 28px; font-weight: 800; color: #7dd3fc; letter-spacing: -0.5px; }}
    .login-logo p {{ font-size: 13px; color: #64748b; margin-top: 6px; }}
    label {{ display: block; font-size: 12px; color: #94a3b8; margin-bottom: 5px; font-weight: 600; letter-spacing: .5px; }}
    input {{ width: 100%; background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px;
             color: #e2e8f0; padding: 10px 14px; font-size: 14px; outline: none; transition: border-color .2s; }}
    input:focus {{ border-color: #3b82f6; }}
    .field {{ margin-bottom: 16px; }}
    .btn {{ width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 15px; font-weight: 700;
            cursor: pointer; transition: all .2s; margin-top: 8px; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .login-error {{ background: #450a0a; border: 1px solid #991b1b; color: #fca5a5; border-radius: 8px;
                    padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; color: #64748b; }}
    .login-footer a {{ color: #7dd3fc; text-decoration: none; }}
    .status-line {{ font-size: 12px; color: #94a3b8; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  {toggle_widget}
  <div class="login-card">
    <div class="login-logo">
      <h1>🛡️ MORI SOC</h1>
      <p data-i18n="login.brand_sub">Audit-Ready Security Operations</p>
    </div>
    {error_html}
    <div class="field"><label data-i18n="login.label.username">아이디</label><input id="username" type="text" autocomplete="username" placeholder="admin" data-i18n-placeholder="login.placeholder.username" /></div>
    <div class="field"><label data-i18n="login.label.password">비밀번호</label><input id="password" type="password" autocomplete="current-password" placeholder="••••••" /></div>
    <button class="btn btn-primary" id="login_btn" data-i18n="login.button.login">로그인</button>
    <div class="status-line" id="status"></div>
    <div class="login-footer">
      <span data-i18n="login.footer.no_account">계정이 없으신가요?</span> <a href="/signup-request" data-i18n="login.footer.signup_link">가입 요청 →</a>
    </div>
  </div>
  {i18n_runtime}
  <script>
    const nextUrl = {json.dumps(next_url)};
    async function doLogin() {{
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;
      const statusEl = document.getElementById('status');
      if (!username || !password) {{ statusEl.textContent = window.t('login.error.empty'); return; }}
      statusEl.textContent = window.t('login.status.loading');
      try {{
        const res = await fetch('/auth/login', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{username, password}})
        }});
        if (res.ok) {{
          window.location.href = nextUrl || '/ui';
        }} else {{
          const d = await res.json().catch(() => ({{}}));
          statusEl.textContent = d.detail || window.t('login.error.invalid');
        }}
      }} catch(e) {{ statusEl.textContent = window.t('login.error.network') + e.message; }}
    }}
    document.getElementById('login_btn').addEventListener('click', doLogin);
    document.addEventListener('keydown', e => {{ if (e.key === 'Enter') doLogin(); }});
  </script>
</body>
</html>"""


def render_signup_request_html(success: bool = False) -> str:
    """가입 요청 페이지 HTML 반환 (KO/EN 토글 지원)."""
    body_html = """
    <p data-i18n="signup.intro" style="color:#94a3b8;font-size:14px;margin-bottom:20px;">계정 사용을 원하시면 아래 정보를 입력하고 운영자에게 가입을 요청하세요.</p>
    <div class="field"><label data-i18n="signup.label.name">이름 *</label><input id="req_name" placeholder="홍길동" data-i18n-placeholder="signup.placeholder.name" /></div>
    <div class="field"><label data-i18n="signup.label.email">이메일 *</label><input id="req_email" type="email" placeholder="hong@company.com" /></div>
    <div class="field"><label data-i18n="signup.label.dept">부서</label><input id="req_dept" placeholder="보안팀" data-i18n-placeholder="signup.placeholder.dept" /></div>
    <div class="field"><label data-i18n="signup.label.reason">요청 사유</label><textarea id="req_reason" style="width:100%;background:#0a1628;border:1px solid #1e3a5f;border-radius:8px;color:#e2e8f0;padding:10px 14px;font-size:14px;min-height:80px;outline:none;" placeholder="업무 목적 및 필요 권한을 간략히 작성해주세요." data-i18n-placeholder="signup.placeholder.reason"></textarea></div>
    <button class="btn btn-primary" id="submit_btn" data-i18n="signup.button.submit">가입 요청 제출</button>
    <div class="status-line" id="status"></div>
    <div class="login-footer"><a href="/login" data-i18n="signup.back">← 로그인으로 돌아가기</a></div>
    <script>
      document.getElementById('submit_btn').addEventListener('click', async () => {
        const name = document.getElementById('req_name').value.trim();
        const email = document.getElementById('req_email').value.trim();
        const department = document.getElementById('req_dept').value.trim();
        const reason = document.getElementById('req_reason').value.trim();
        const statusEl = document.getElementById('status');
        if (!name || !email) { statusEl.textContent = window.t('signup.error.required'); return; }
        statusEl.textContent = window.t('signup.status.submitting');
        try {
          const res = await fetch('/auth/signup-request', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, email, department, reason})
          });
          if (res.ok) {
            const title = window.t('signup.success.title');
            const bodyHtml = window.t('signup.success.body');
            const back = window.t('signup.back');
            document.querySelector('.login-card').innerHTML = '<div style="text-align:center;padding:40px 0"><div style="font-size:48px">✅</div><h2 style="color:#22c55e;margin:16px 0 8px">' + title + '</h2><p style="color:#94a3b8">' + bodyHtml + '</p><div style="margin-top:24px"><a href="/login" style="color:#7dd3fc">' + back + '</a></div></div>';
          } else {
            const d = await res.json().catch(() => ({}));
            statusEl.textContent = d.detail || window.t('signup.error.generic');
          }
        } catch(e) { statusEl.textContent = window.t('signup.error.network') + e.message; }
      });
    </script>""" if not success else '<div style="text-align:center;padding:40px 0"><div style="font-size:48px">✅</div><h2 data-i18n="signup.success.title" style="color:#22c55e">가입 요청 완료</h2><p data-i18n-html="signup.success.body" style="color:#94a3b8;margin-top:8px">운영자 승인 후 계정이 생성됩니다.<br>이메일로 안내드리겠습니다.</p><div style="margin-top:24px"><a href="/login" data-i18n="signup.back" style="color:#7dd3fc">← 로그인으로 돌아가기</a></div></div>'
    i18n_runtime = _i18n_script(_SIGNUP_I18N)
    toggle_widget = _i18n_toggle_html()
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title data-i18n-doctitle="signup.doctitle">MORI SOC — 가입 요청</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a1628; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
    .login-card {{ background: #0f2035; border: 1px solid #1e3a5f; border-radius: 16px; padding: 40px 36px;
                   width: 100%; max-width: 440px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }}
    .login-logo {{ text-align: center; margin-bottom: 24px; }}
    .login-logo h1 {{ font-size: 24px; font-weight: 800; color: #7dd3fc; }}
    label {{ display: block; font-size: 12px; color: #94a3b8; margin-bottom: 5px; font-weight: 600; letter-spacing: .5px; }}
    input {{ width: 100%; background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px;
             color: #e2e8f0; padding: 10px 14px; font-size: 14px; outline: none; transition: border-color .2s; }}
    input:focus {{ border-color: #3b82f6; }}
    .field {{ margin-bottom: 14px; }}
    .btn {{ width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 15px; font-weight: 700;
            cursor: pointer; transition: all .2s; margin-top: 4px; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; }}
    .login-footer a {{ color: #7dd3fc; text-decoration: none; }}
    .status-line {{ font-size: 12px; color: #ef4444; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  {toggle_widget}
  <div class="login-card">
    <div class="login-logo"><h1 data-i18n="signup.brand_title">🛡️ MORI SOC 가입 요청</h1></div>
    {body_html}
  </div>
  {i18n_runtime}
</body>
</html>"""
