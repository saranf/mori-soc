"""i18n 키 드리프트 방지(#35) — 모든 사전에서 KO/EN 키 집합이 정확히 일치해야 한다.

UI 변경 후 한쪽 언어에만 키를 추가/삭제하면(과거 반복된 실수) 언어 토글 시 누락/폴백이
생긴다. 이 테스트가 CI 에서 그 드리프트를 막는다.
"""
from __future__ import annotations

import unittest

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
