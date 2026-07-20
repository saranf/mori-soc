"""api.http_helpers 공용 응답 헬퍼 — 공통화 C6."""
from __future__ import annotations

import unittest

from mori_soc.api.http_helpers import pdf_response


class PdfResponseTests(unittest.TestCase):
    def test_pdf_response_headers(self) -> None:
        resp = pdf_response(b"%PDF-1.4 x", "mori-report", timestamp="20260720T000000Z")
        self.assertEqual(resp.media_type, "application/pdf")
        self.assertEqual(resp.body, b"%PDF-1.4 x")
        self.assertIn("mori-report-20260720T000000Z.pdf", resp.headers["content-disposition"])

    def test_pdf_response_auto_timestamp(self) -> None:
        resp = pdf_response(b"x", "mori-soa")
        cd = resp.headers["content-disposition"]
        self.assertTrue(cd.startswith('attachment; filename="mori-soa-'))
        self.assertTrue(cd.endswith('.pdf"'))


if __name__ == "__main__":
    unittest.main()
