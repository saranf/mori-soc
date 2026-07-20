"""모리다움 6색 팔레트 가드레일 — 토스 개편 회귀 방지(#redesign-toss).

색 = 상태 규율: 렌더된 UI(대시보드·콘솔·로그인) + CSS/JS 자산에 **토스 6색 팔레트 밖 hex**나
**장식 그라디언트**가 새로 섞이면 실패시킨다. 구팔레트(#2563eb 등)로의 역행도 차단.
값 골든이 아니라 '허용셋' 방식 — 정당한 신규 색은 허용셋에 추가하면 되고, 무단 색은 걸린다.
"""
from __future__ import annotations

import pathlib
import re
import unittest

import mori_soc.api.templates.dashboard as _dash_mod
from mori_soc.api.templates.auth_pages import render_login_html
from mori_soc.api.templates.console import render_query_console_html
from mori_soc.api.templates.dashboard import render_user_dashboard_html

_STATIC = pathlib.Path(_dash_mod.__file__).parent.parent / "static"
# 증적 PDF/SVG 생성기(개인정보 처리흐름표·SoA·공용 PDF) — UI와 같은 6색 규율.
_SERVICES = pathlib.Path(_dash_mod.__file__).parent.parent.parent / "services"

# 토스 6색 팔레트 + 중성/틴트(색=상태). 6자리 hex 소문자 기준.
_ALLOWED_HEX = {
    # 상태 6색
    "3182f6", "1b64da",           # 파(현재/링크) + 진한 파
    "f04452",                     # 빨(위험)
    "15c47e",                     # 초(완료)
    "f5a623",                     # 노(주의)
    "191f28", "4e5968", "8b95a1",  # 잉크/보조/뮤트
    "ffffff",                     # 종이
    # 중성/틴트(각 상태색의 옅은 배경 + 앱 배경/라인/서피스)
    "f2f4f6", "f7f8fa", "eef1f4", "e5e8eb",
    "eaf1fe", "e3f8ef", "fdecee", "fef3d6",
}

# 구팔레트/6색 밖 잔재 — 하나라도 다시 나타나면 역행이므로 차단.
_FORBIDDEN_HEX = {
    "2563eb", "dc2626", "16a34a", "ca8a04", "7c3aed",
    "111827", "e5e7eb", "f9fafb", "f3f4f6", "6b7280",
    "dbeafe", "fef9c3", "dcfce7", "fee2e2", "a16207",
    "e2e8f0", "d1d5db", "cbd5e1", "4b5563", "f1f5f9", "f7f8fb",
}

_HEX_RE = re.compile(r"#([0-9a-fA-F]{6})\b")


def _hexes(text: str) -> set[str]:
    return {m.lower() for m in _HEX_RE.findall(text)}


class TossPaletteGuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets: dict[str, str] = {
            "dashboard.html": render_user_dashboard_html(),
            "console.html": render_query_console_html(),
            "login.html": render_login_html(),
            "dashboard.css": (_STATIC / "css" / "dashboard.css").read_text(encoding="utf-8"),
            "console.css": (_STATIC / "css" / "console.css").read_text(encoding="utf-8"),
            "dashboard.js": (_STATIC / "js" / "dashboard.js").read_text(encoding="utf-8"),
            "console.js": (_STATIC / "js" / "console.js").read_text(encoding="utf-8"),
            # 증적 산출물 생성기 소스(색 상수만 텍스트 스캔 — 모듈 임포트/reportlab 불필요).
            "pdf.py": (_SERVICES / "pdf.py").read_text(encoding="utf-8"),
            "data_flow.py": (_SERVICES / "data_flow.py").read_text(encoding="utf-8"),
            "soa.py": (_SERVICES / "soa.py").read_text(encoding="utf-8"),
        }

    def test_no_forbidden_legacy_hex(self) -> None:
        """구팔레트/6색 밖 색으로의 역행 차단."""
        for name, text in self.assets.items():
            found = _hexes(text) & _FORBIDDEN_HEX
            self.assertEqual(found, set(), f"{name}: 6색 밖/구팔레트 색 역행 {sorted(found)}")

    def test_all_hex_within_palette(self) -> None:
        """모든 6자리 hex 가 토스 허용셋 안. (신규 색은 _ALLOWED_HEX 에 명시적으로 추가할 것)"""
        for name, text in self.assets.items():
            stray = _hexes(text) - _ALLOWED_HEX
            self.assertEqual(stray, set(), f"{name}: 허용셋 밖 hex {sorted(stray)} — 색=상태 규율 확인")

    def test_no_decorative_gradients(self) -> None:
        """장식 그라디언트 금지(6색 규율)."""
        for name, text in self.assets.items():
            self.assertNotIn("linear-gradient", text, f"{name}: 장식 그라디언트")
            self.assertNotIn("radial-gradient", text, f"{name}: 장식 그라디언트")


if __name__ == "__main__":
    unittest.main()
