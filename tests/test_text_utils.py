"""services.text_utils.parse_iso — 공통화 C11 회귀 방지."""
from __future__ import annotations

import unittest
from datetime import timezone

from mori_soc.services.text_utils import parse_iso


class ParseIsoTests(unittest.TestCase):
    def test_z_suffix_and_offset(self) -> None:
        dt = parse_iso("2026-07-20T00:00:00Z")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_assume_utc_for_naive(self) -> None:
        self.assertIsNone(parse_iso("2026-07-20T00:00:00").tzinfo)
        self.assertEqual(parse_iso("2026-07-20T00:00:00", assume_utc=True).tzinfo, timezone.utc)

    def test_empty_and_invalid_and_none(self) -> None:
        self.assertIsNone(parse_iso(""))
        self.assertIsNone(parse_iso(None))
        self.assertIsNone(parse_iso("not-a-date"))
        self.assertIsNone(parse_iso("   "))


if __name__ == "__main__":
    unittest.main()
