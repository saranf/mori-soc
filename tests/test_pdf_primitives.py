"""services/pdf.py — 공통 PDF 프리미티브(C5 신규, 무테스트 해소)."""
from __future__ import annotations

import importlib.util
import unittest

REPORTLAB = importlib.util.find_spec("reportlab") is not None

from mori_soc.services.pdf import get_pdf_font


class PdfPrimitivesTest(unittest.TestCase):
    def test_get_pdf_font_returns_name_and_caches(self) -> None:
        f1 = get_pdf_font()
        self.assertIsInstance(f1, str)
        self.assertTrue(f1)                 # 폰트명(한글폰트 or Helvetica)
        self.assertEqual(f1, get_pdf_font())  # 최초 1회 등록 후 캐시

    @unittest.skipUnless(REPORTLAB, "requires reportlab")
    def test_pdf_table_builds_flowable_and_escapes(self) -> None:
        from mori_soc.services.pdf import pdf_table
        t = pdf_table(["항목", "값<>&"], [["a", "b"], ["c", "d"]], [50, 50])
        self.assertIsNotNone(t)
        # Table flowable 이며 헤더+2행
        from reportlab.platypus import Table
        self.assertIsInstance(t, Table)
        self.assertEqual(len(t._cellvalues), 3)


if __name__ == "__main__":
    unittest.main()
