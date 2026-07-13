"""dashboard 렌더 안전그물망 (P0) — dashboard.py 리팩터링용 회귀 가드.

동시편집 HOT 파일이라 바이트 골든 대신 **구조 불변식 + 결정성**을 검증한다.
정당한 내용 변경에는 견디고, 리팩터 중 구조 붕괴(탭 소실·스크립트 누락·비결정 출력)는 잡는다.
CSS/JS 외부화(P1/P2)로 마커가 이동하면 이 테스트를 함께 갱신한다.
"""
from __future__ import annotations

import unittest

from mori_soc.api.templates.dashboard import render_user_dashboard_html


class DashboardRenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = render_user_dashboard_html()

    def test_renders_nontrivial_string(self) -> None:
        self.assertIsInstance(self.html, str)
        self.assertGreater(len(self.html), 100_000)  # ~400KB 규모
        self.assertIn("<!doctype html>", self.html)

    def test_deterministic(self) -> None:
        # 같은 입력 → 같은 출력(비결정 요소 없음). 향후 골든 스냅샷의 전제.
        self.assertEqual(self.html, render_user_dashboard_html())

    def test_tab_panels_present(self) -> None:
        for tab in ("tab_triage", "tab_incidents", "tab_assets",
                    "tab_compliance", "tab_guides", "tab_accounts"):
            self.assertIn(f'id="{tab}"', self.html, f"탭 패널 {tab} 누락")
        self.assertGreaterEqual(self.html.count('class="tab-panel"'), 6)

    def test_stylesheet_and_script(self) -> None:
        # CSS는 외부화(P1: /static/css/dashboard.css), JS는 아직 인라인 <script>
        self.assertIn('href="/static/css/dashboard.css"', self.html)
        self.assertIn("<script", self.html)

    def test_key_js_functions_present(self) -> None:
        for fn in ("function loadCompliance", "function loadAccountsGov",
                   "function loadSoaSummary", "function loadAccessTrail",
                   "function switchTab"):
            self.assertIn(fn, self.html, f"JS 함수 {fn} 누락")

    def test_session_features_present(self) -> None:
        # 이번 세션 추가 UI가 렌더에 살아있는지(접속발자취·SoA 카드·gap 타일)
        for marker in ("soa_card", "acc_trail", "access_uncovered"):
            self.assertIn(marker, self.html, f"마커 {marker} 누락")

    def test_i18n_driven(self) -> None:
        self.assertGreaterEqual(self.html.count("data-i18n"), 200)


if __name__ == "__main__":
    unittest.main()
