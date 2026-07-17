"""i18n 키 드리프트 방지(#35) — 모든 사전에서 KO/EN 키 집합이 정확히 일치해야 한다.

UI 변경 후 한쪽 언어에만 키를 추가/삭제하면(과거 반복된 실수) 언어 토글 시 누락/폴백이
생긴다. 이 테스트가 CI 에서 그 드리프트를 막는다.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

import mori_soc.api
from mori_soc.api.i18n import (
    _ADMIN_I18N,
    _DASHBOARD_I18N,
    _LOGIN_I18N,
    _SIGNUP_I18N,
)

_DICTS = {
    "_LOGIN_I18N": _LOGIN_I18N,
    "_SIGNUP_I18N": _SIGNUP_I18N,
    "_DASHBOARD_I18N": _DASHBOARD_I18N,
    "_ADMIN_I18N": _ADMIN_I18N,
}


class I18nParityTests(unittest.TestCase):
    def test_ko_en_key_sets_match(self) -> None:
        for name, d in _DICTS.items():
            self.assertIn("ko", d, name)
            self.assertIn("en", d, name)
            ko, en = set(d["ko"]), set(d["en"])
            missing_en = ko - en   # KO 에만 있는 키(EN 누락)
            missing_ko = en - ko   # EN 에만 있는 키(KO 누락)
            self.assertEqual(missing_en, set(), f"{name}: EN 에 누락된 키 {sorted(missing_en)}")
            self.assertEqual(missing_ko, set(), f"{name}: KO 에 누락된 키 {sorted(missing_ko)}")

    def test_ko_has_no_empty_values(self) -> None:
        # KO 는 기준 언어 — 빈 값은 실수. (EN 은 카운터 접미사 등 의도적 공백이 있어 제외.)
        for name, d in _DICTS.items():
            empties = [k for k, v in d["ko"].items() if not str(v).strip()]
            self.assertEqual(empties, [], f"{name}[ko] 빈 값 키 {empties}")


if __name__ == "__main__":
    unittest.main()


class I18nCoverageTests(unittest.TestCase):
    """KO/EN 대칭만으로는 못 잡는 결함: 양쪽 사전에 *모두* 없는 키.

    tt('key','한국어 폴백') 은 키가 없으면 조용히 폴백을 쓴다. 그래서 키를 아예 안 넣으면
    parity 테스트는 통과하는데 영어 모드에서 한국어가 그대로 노출된다(실제로 174건 발생).
    각 페이지의 JS 가 쓰는 tt() 키가 그 페이지 사전에 실제로 있는지 검증한다.
    """

    _TT = re.compile(r"""tt\(\s*['"]([\w.\-]+)['"]\s*,\s*['"]([^'"]*)['"]""")
    _KOREAN = re.compile(r"[가-힣]")

    # JS 파일 -> 그 페이지에 주입되는 사전
    _PAGES = (
        ("dashboard.js", "_DASHBOARD_I18N", _DASHBOARD_I18N),
        ("console.js", "_ADMIN_I18N", _ADMIN_I18N),
    )

    @staticmethod
    def _js_dir() -> Path:
        return Path(mori_soc.api.__file__).parent / "static" / "js"

    def test_every_tt_key_exists_in_page_dictionary(self) -> None:
        for filename, dict_name, table in self._PAGES:
            source = (self._js_dir() / filename).read_text(encoding="utf-8")
            missing = sorted(
                key
                for key, fallback in self._TT.findall(source)
                if key not in table["en"] and self._KOREAN.search(fallback)
            )
            self.assertEqual(
                missing,
                [],
                f"{filename}: 아래 키가 {dict_name} 에 없어 영어 모드에서 한국어 폴백이 노출된다 -> {missing}",
            )

    def test_english_values_have_no_korean(self) -> None:
        for name, d in _DICTS.items():
            leftover = sorted(k for k, v in d["en"].items() if self._KOREAN.search(str(v)))
            self.assertEqual(leftover, [], f"{name}: EN 값에 한국어가 남아 있다 -> {leftover}")
