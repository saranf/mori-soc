"""admin 콘솔 렌더 안전그물망 (P7-0) — console.py 리팩터용 회귀 가드.

dashboard 스모크와 동형: 구조 불변식 + 결정성. CSS/JS 외부화(P7-1/2)로 마커가
이동하면 이 테스트를 함께 갱신한다(현재는 인라인 <style>/<script>).
"""
from __future__ import annotations

import unittest

from mori_soc.api.templates.console import render_query_console_html


class ConsoleRenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = render_query_console_html()

    def test_renders_nontrivial_string(self) -> None:
        self.assertIsInstance(self.html, str)
        self.assertGreater(len(self.html), 50_000)
        self.assertIn("<!doctype html>", self.html)

    def test_deterministic(self) -> None:
        self.assertEqual(self.html, render_query_console_html())

    def test_no_server_placeholder_leftover(self) -> None:
        import re
        leftover = re.findall(r"__[A-Z]+_[A-Z_]*(?:URL|JSON|EXAMPLES|SCRIPT|TOGGLE|LABELS)__", self.html)
        self.assertEqual(leftover, [], f"치환 안 된 placeholder: {set(leftover)}")

    def test_admin_structure(self) -> None:
        # HTML 셸: 탭 패널 + 부트스트랩. JS 함수 마커는 console.js(P7-2 외부화)에서 확인
        self.assertIn("atab_", self.html)               # admin 탭 패널
        self.assertIn("window.__MORI_ADMIN__", self.html)
        import pathlib
        js = (pathlib.Path(__file__).resolve().parent.parent / "src" / "mori_soc"
              / "api" / "static" / "js" / "console.js").read_text(encoding="utf-8")
        for fn in ("function switchAdminTab", "function loadAdminCompliance",
                   "function loadAdminTriage", "function applyAdminRoleTabs"):
            self.assertIn(fn, js, f"admin JS 함수 {fn} 누락(console.js)")

    def test_stylesheet_and_script(self) -> None:
        # P7-1 CSS + P7-2 JS 모두 외부화
        self.assertIn('href="/static/css/console.css"', self.html)
        self.assertIn('src="/static/js/console.js"', self.html)

    def test_i18n_driven(self) -> None:
        self.assertGreaterEqual(self.html.count("data-i18n"), 100)


if __name__ == "__main__":
    unittest.main()
