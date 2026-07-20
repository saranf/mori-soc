"""로그인/가입 요청 페이지 (render_login_html, render_signup_request_html)."""
from mori_soc.api.templates._common import *  # noqa: F401,F403


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
  <title data-i18n-doctitle="login.doctitle">MORI SOC 로그인</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #f2f4f6; color: #191f28; font-family: -apple-system, BlinkMacSystemFont, "Pretendard", "Apple SD Gothic Neo", "Malgun Gothic", "Segoe UI", sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; -webkit-font-smoothing: antialiased; }}
    .login-card {{ background: #ffffff; border: 1px solid #e5e8eb; border-radius: 20px; padding: 40px 36px;
                   width: 100%; max-width: 400px; box-shadow: 0 1px 3px rgba(15,23,42,.04), 0 12px 32px rgba(15,23,42,.06); }}
    .login-logo {{ text-align: center; margin-bottom: 28px; }}
    .login-logo .mark {{ width: 52px; height: 52px; border-radius: 15px; background: #3182f6; color: #fff;
                         display: flex; align-items: center; justify-content: center; font-size: 26px; font-weight: 800;
                         margin: 0 auto 14px; letter-spacing: -1px; }}
    .login-logo h1 {{ font-size: 24px; font-weight: 800; color: #191f28; letter-spacing: -0.5px; }}
    .login-logo p {{ font-size: 13px; color: #8b95a1; margin-top: 6px; font-weight: 500; }}
    label {{ display: block; font-size: 12px; color: #4e5968; margin-bottom: 6px; font-weight: 700; }}
    input {{ width: 100%; background: #f7f8fa; border: 1px solid #e5e8eb; border-radius: 12px;
             color: #191f28; padding: 12px 14px; font-size: 14.5px; outline: none; transition: border-color .15s, background .15s; }}
    input:focus {{ border-color: #3182f6; background: #ffffff; }}
    .field {{ margin-bottom: 16px; }}
    .btn {{ width: 100%; padding: 13px; border: none; border-radius: 13px; font-size: 15px; font-weight: 800;
            cursor: pointer; transition: filter .15s; margin-top: 8px; }}
    .btn-primary {{ background: #3182f6; color: #fff; }}
    .btn-primary:hover {{ filter: brightness(.96); }}
    .login-error {{ background: #fdecee; border: 1px solid #f04452; color: #f04452; border-radius: 12px;
                    padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; color: #8b95a1; }}
    .login-footer a {{ color: #3182f6; text-decoration: none; font-weight: 700; }}
    .status-line {{ font-size: 12px; color: #8b95a1; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  {toggle_widget}
  <div class="login-card">
    <div class="login-logo">
      <div class="mark">M</div>
      <h1>MORI SOC</h1>
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
    <p data-i18n="signup.intro" style="color:#191f28;font-size:14px;margin-bottom:20px;">계정 사용을 원하시면 아래 정보를 입력하고 운영자에게 가입을 요청하세요.</p>
    <div class="field"><label data-i18n="signup.label.name">이름</label><input id="req_name" placeholder="홍길동" data-i18n-placeholder="signup.placeholder.name" /></div>
    <div class="field"><label data-i18n="signup.label.username">로그인 아이디</label><input id="req_username" placeholder="hong" autocomplete="off" data-i18n-placeholder="signup.placeholder.username" /></div>
    <div class="field"><label data-i18n="signup.label.email">이메일</label><input id="req_email" type="email" placeholder="hong@company.com" /></div>
    <div class="field"><label data-i18n="signup.label.dept">부서</label><input id="req_dept" placeholder="보안팀" data-i18n-placeholder="signup.placeholder.dept" /></div>
    <div class="field"><label data-i18n="signup.label.reason">요청 사유</label><textarea id="req_reason" style="min-height:80px" placeholder="업무 목적 및 필요 권한을 간략히 작성해주세요." data-i18n-placeholder="signup.placeholder.reason"></textarea></div>
    <button class="btn btn-primary" id="submit_btn" data-i18n="signup.button.submit">가입 요청 제출</button>
    <div class="status-line" id="status"></div>
    <div class="login-footer"><a href="/login" data-i18n="signup.back">← 로그인으로 돌아가기</a></div>
    <script>
      document.getElementById('submit_btn').addEventListener('click', async () => {
        const name = document.getElementById('req_name').value.trim();
        const username = document.getElementById('req_username').value.trim();
        const email = document.getElementById('req_email').value.trim();
        const department = document.getElementById('req_dept').value.trim();
        const reason = document.getElementById('req_reason').value.trim();
        const statusEl = document.getElementById('status');
        if (!name || !email) { statusEl.textContent = window.t('signup.error.required'); return; }
        statusEl.textContent = window.t('signup.status.submitting');
        try {
          const res = await fetch('/auth/signup-request', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, username, email, department, reason})
          });
          if (res.ok) {
            const title = window.t('signup.success.title');
            const bodyHtml = window.t('signup.success.body');
            const back = window.t('signup.back');
            document.querySelector('.login-card').innerHTML = '<div style="text-align:center;padding:40px 0"><div style="font-size:48px"></div><h2 style="color:#15c47e;margin:16px 0 8px">' + title + '</h2><p style="color:#191f28">' + bodyHtml + '</p><div style="margin-top:24px"><a href="/login" style="color:#3182f6">' + back + '</a></div></div>';
          } else {
            const d = await res.json().catch(() => ({}));
            statusEl.textContent = d.detail || window.t('signup.error.generic');
          }
        } catch(e) { statusEl.textContent = window.t('signup.error.network') + e.message; }
      });
    </script>""" if not success else '<div style="text-align:center;padding:40px 0"><div style="font-size:48px"></div><h2 data-i18n="signup.success.title" style="color:#15c47e">가입 요청 완료</h2><p data-i18n-html="signup.success.body" style="color:#191f28;margin-top:8px">운영자 승인 후 계정이 생성됩니다.<br>이메일로 안내드리겠습니다.</p><div style="margin-top:24px"><a href="/login" data-i18n="signup.back" style="color:#3182f6">← 로그인으로 돌아가기</a></div></div>'
    i18n_runtime = _i18n_script(_SIGNUP_I18N)
    toggle_widget = _i18n_toggle_html()
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title data-i18n-doctitle="signup.doctitle">MORI SOC 가입 요청</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #f2f4f6; color: #191f28; font-family: -apple-system, BlinkMacSystemFont, "Pretendard", "Apple SD Gothic Neo", "Malgun Gothic", "Segoe UI", sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; -webkit-font-smoothing: antialiased; }}
    .login-card {{ background: #ffffff; border: 1px solid #e5e8eb; border-radius: 20px; padding: 40px 36px;
                   width: 100%; max-width: 440px; box-shadow: 0 1px 3px rgba(15,23,42,.04), 0 12px 32px rgba(15,23,42,.06); }}
    .login-logo {{ text-align: center; margin-bottom: 24px; }}
    .login-logo .mark {{ width: 48px; height: 48px; border-radius: 14px; background: #3182f6; color: #fff;
                         display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 800;
                         margin: 0 auto 12px; letter-spacing: -1px; }}
    .login-logo h1 {{ font-size: 22px; font-weight: 800; color: #191f28; letter-spacing: -0.5px; }}
    label {{ display: block; font-size: 12px; color: #4e5968; margin-bottom: 6px; font-weight: 700; }}
    input, textarea {{ width: 100%; background: #f7f8fa; border: 1px solid #e5e8eb; border-radius: 12px;
             color: #191f28; padding: 12px 14px; font-size: 14.5px; outline: none; transition: border-color .15s, background .15s; font-family: inherit; }}
    input:focus, textarea:focus {{ border-color: #3182f6; background: #ffffff; }}
    .field {{ margin-bottom: 14px; }}
    .btn {{ width: 100%; padding: 13px; border: none; border-radius: 13px; font-size: 15px; font-weight: 800;
            cursor: pointer; transition: filter .15s; margin-top: 4px; }}
    .btn-primary {{ background: #3182f6; color: #fff; }}
    .btn-primary:hover {{ filter: brightness(.96); }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; color: #8b95a1; }}
    .login-footer a {{ color: #3182f6; text-decoration: none; font-weight: 700; }}
    .status-line {{ font-size: 12px; color: #f04452; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  {toggle_widget}
  <div class="login-card">
    <div class="login-logo"><div class="mark">M</div><h1 data-i18n="signup.brand_title">MORI SOC 가입 요청</h1></div>
    {body_html}
  </div>
  {i18n_runtime}
</body>
</html>"""

