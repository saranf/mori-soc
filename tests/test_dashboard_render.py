"""dashboard 렌더 안전그물망 — dashboard.py 리팩터링용 회귀 가드.

구조 불변식 + 결정성 검증(바이트 골든 대신 — 동시편집·정당한 내용변경에 견딤).
P1(CSS)·P2(JS) 외부화 반영: HTML은 부트스트랩+`<script src>`, JS 함수·gap키는
static/js/dashboard.js 에 있다. 외부 JS는 node --check / 헤드리스 가드로 별도 검증.
"""
from __future__ import annotations

import pathlib
import unittest

import mori_soc.api.templates.dashboard as _dash_mod
from mori_soc.api.templates.dashboard import render_user_dashboard_html

_JS_PATH = pathlib.Path(_dash_mod.__file__).parent.parent / "static" / "js" / "dashboard.js"


class DashboardRenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = render_user_dashboard_html()
        cls.js = _JS_PATH.read_text(encoding="utf-8")

    def test_renders_nontrivial_string(self) -> None:
        self.assertIsInstance(self.html, str)
        self.assertGreater(len(self.html), 20_000)  # JS 외부화 후 ~45KB
        self.assertIn("<!doctype html>", self.html)

    def test_deterministic(self) -> None:
        self.assertEqual(self.html, render_user_dashboard_html())

    def test_tab_panels_present(self) -> None:
        for tab in ("tab_triage", "tab_incidents", "tab_assets",
                    "tab_compliance", "tab_guides", "tab_accounts"):
            self.assertIn(f'id="{tab}"', self.html, f"탭 패널 {tab} 누락")
        self.assertGreaterEqual(self.html.count('class="tab-panel"'), 6)

    def test_css_and_js_externalized(self) -> None:
        self.assertIn('href="/static/css/dashboard.css"', self.html)          # P1
        self.assertIn('<script src="/static/js/dashboard.js"></script>', self.html)  # P2
        self.assertIn("window.__MORI__ = {", self.html)                       # 부트스트랩

    def test_no_server_placeholder_leftover(self) -> None:
        # 렌더 후 서버 placeholder 가 남아있으면 안 됨(치환 누락)
        import re
        leftover = re.findall(r"__[A-Z]+_[A-Z_]*(?:URL|JSON|EXAMPLES|SCRIPT|TOGGLE)__", self.html)
        self.assertEqual(leftover, [], f"치환 안 된 placeholder: {set(leftover)}")

    def test_key_js_functions_in_external(self) -> None:
        for fn in ("function loadCompliance", "function loadAccountsGov",
                   "function loadSoaSummary", "function loadAccessTrail",
                   "function switchTab"):
            self.assertIn(fn, self.js, f"JS 함수 {fn} 누락(dashboard.js)")

    def test_js_uses_bootstrap_not_placeholder(self) -> None:
        self.assertIn("window.__MORI__", self.js)
        import re
        self.assertFalse(re.search(r"__[A-Z]+_[A-Z_]*(?:URL|JSON|EXAMPLES)__", self.js),
                         "dashboard.js 에 서버 placeholder 잔존")

    def test_session_features_present(self) -> None:
        for marker in ("soa_card", "acc_trail"):        # HTML 탭
            self.assertIn(marker, self.html, f"마커 {marker} 누락(html)")
        self.assertIn("access_uncovered", self.js)       # gap 타일 키(JS)

    def test_i18n_driven(self) -> None:
        self.assertGreaterEqual(self.html.count("data-i18n"), 200)


if __name__ == "__main__":
    unittest.main()
