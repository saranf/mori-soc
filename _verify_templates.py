"""Temp harness: SHA256 of the four rendered pages (J-2 lossless check)."""

import hashlib

from mori_soc.api.server import (
    render_login_html,
    render_signup_request_html,
    render_user_dashboard_html,
    render_query_console_html,
)


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


pages = {
    "login": render_login_html(),
    "login_err": render_login_html(error="bad creds", next_url="/admin"),
    "signup": render_signup_request_html(),
    "signup_ok": render_signup_request_html(success=True),
    "dashboard": render_user_dashboard_html(),
    "console": render_query_console_html(),
}

for name, html in pages.items():
    print(f"{name}\t{len(html)}\t{_h(html)}")
