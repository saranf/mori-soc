"""공용 유틸(util.now_iso·to_utf8_bom) — C6/C4 중복 제거 헬퍼."""
from __future__ import annotations

import unittest

from mori_soc.util import now_iso, to_utf8_bom


class UtilTest(unittest.TestCase):
    def test_now_iso_utc(self) -> None:
        s = now_iso()
        self.assertIn("T", s)
        self.assertTrue(s.endswith("+00:00") or s.endswith("Z"))

    def test_to_utf8_bom_prepends_once(self) -> None:
        b = to_utf8_bom("a,b\n1,2")
        self.assertTrue(b.startswith(b"\xef\xbb\xbf"))       # UTF-8 BOM
        self.assertEqual(b.count(b"\xef\xbb\xbf"), 1)
        # 이미 BOM 이면 중복 안 붙임
        self.assertEqual(to_utf8_bom("﻿x"), "﻿x".encode("utf-8"))
