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
        self.assertIn("switchAdminTab", self.html)
        self.assertIn("atab_", self.html)               # admin 탭 패널
        for fn in ("function switchAdminTab", "function loadAdminCompliance",
                   "function loadAdminTriage", "function applyAdminRoleTabs"):
            self.assertIn(fn, self.html, f"admin JS 함수 {fn} 누락")

    def test_stylesheet_and_script(self) -> None:
        # P7-1: CSS 외부화(/static/css/console.css). JS는 아직 인라인 <script>(P7-2 예정)
        self.assertIn('href="/static/css/console.css"', self.html)
        self.assertIn("<script", self.html)

    def test_i18n_driven(self) -> None:
        self.assertGreaterEqual(self.html.count("data-i18n"), 100)


if __name__ == "__main__":
    unittest.main()
