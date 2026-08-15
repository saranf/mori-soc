"""i18n 정합(개선③) — 코드가 런타임에 합성하는 tt() 키가 사전(ko·en)에 실제로 있는지.

`tt('onboarding.step.'+id, ...)` 처럼 접두사+변수로 만드는 키는 기계적 grep 으로 못 잡는다.
서비스가 내는 실제 id 로 완성 키를 만들어 사전 존재를 검증 → '새 id 추가 시 조용히 한글 폴백' 차단.
"""
from __future__ import annotations

import unittest

from mori_soc.api import i18n
from mori_soc.services.onboarding import (
    build_checklist,
    build_go_live,
    build_scan_setup,
    connector_catalog,
)

_ADMIN = i18n._ADMIN_I18N


def _all_admin_keys() -> set[str]:
    return set(_ADMIN.get("ko", {})) & set(_ADMIN.get("en", {}))


class ComposedI18nKeyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = _all_admin_keys()

    def _assert_keys(self, prefix: str, ids: list[str]) -> None:
        missing = [f"{prefix}{i}" for i in ids if f"{prefix}{i}" not in self.keys]
        self.assertEqual(missing, [], f"사전에 없는 합성 키(→영어서 한글 폴백): {missing}")

    def test_checklist_step_keys(self) -> None:
        ids = [s["id"] for s in build_checklist({})["steps"]]
        self._assert_keys("onboarding.step.", ids)

    def test_connector_state_keys(self) -> None:
        # build_connectors 가 낼 수 있는 모든 state 값.
        self._assert_keys("onboarding.state.", ["connected", "configured", "waiting", "not_configured"])

    def test_golive_step_keys(self) -> None:
        g = build_go_live(True, False, False, False, False)
        self._assert_keys("onboarding.golive.step.", [s["id"] for s in g["steps"]])

    def test_scan_step_keys(self) -> None:
        s = build_scan_setup("https://m")
        self._assert_keys("onboarding.scan.step.", [x["id"] for x in s["steps"]])

    def test_maturity_and_mat_keys(self) -> None:
        # 커넥터 성숙도 배지 키(onboarding.mat.<maturity>).
        mats = sorted({c["maturity"] for c in connector_catalog()})
        self._assert_keys("onboarding.mat.", mats)


if __name__ == "__main__":
    unittest.main()
