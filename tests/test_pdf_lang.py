"""PDF lang 스모크(R6) — ko/en 양쪽이 크래시 없이 유효 PDF 로 렌더되는지.

(reportlab 이 매 렌더에 타임스탬프를 넣어 바이트가 달라지므로 바이트 동등 비교는 하지 않는다.
 언어별 텍스트 정합은 poppler 추출로 별도 검증됨 — 여기선 lang 배선·무크래시 회귀만 잡는다.)
"""
from __future__ import annotations

import importlib.util
import unittest

_HAS_RL = importlib.util.find_spec("reportlab") is not None

from mori_soc.services.control_catalog import evidence_document_pdf  # noqa: E402
from mori_soc.services.data_flow import render_data_flow_pdf  # noqa: E402


@unittest.skipUnless(_HAS_RL, "requires reportlab")
class PdfLangTest(unittest.TestCase):
    def test_evidence_pdf_both_langs_valid(self) -> None:
        doc = {"control": {"id": "1.1", "title_ko": "정보자산 식별", "title_en": "Asset identification",
                           "intent_ko": "의도", "intent_en": "intent"},
               "inventory": [{"hostname": "h", "ip": "1.1.1.1", "status": "online", "source": "fleet"}],
               "records": [], "generated_at": "2026-07-22T00:00:00", "status": "planned"}
        for lang in ("ko", "en"):
            pdf = evidence_document_pdf(doc, lang=lang)
            self.assertTrue(pdf.startswith(b"%PDF-"), lang)
            self.assertGreater(len(pdf), 800, lang)

    def test_privacy_flow_pdf_both_langs_valid(self) -> None:
        rows = [{"item": "이름", "category": "일반", "collection_source": "회원가입",
                 "storage_location": "User.name", "storage_table": "src/user.py:12",
                 "purpose": "본인확인", "destruction": "탈퇴 시 삭제", "third_party": "배송사",
                 "source": "pii_scan"}]
        for lang in ("ko", "en"):
            pdf = render_data_flow_pdf(rows, generated_at="2026-07-22", gaps=["파기 미정의"],
                                       summary={"encryption": "AES-256"}, lang=lang)
            self.assertTrue(pdf.startswith(b"%PDF-"), lang)
            self.assertGreater(len(pdf), 1500, lang)

    def test_default_lang_is_ko_and_renders(self) -> None:
        # 기본(lang 미지정)도 크래시 없이 렌더(하위호환).
        pdf = render_data_flow_pdf([{"item": "x", "source": "pii_scan"}])
        self.assertTrue(pdf.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
