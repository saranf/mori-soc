"""SoA(ISO 27001 적용선언서) 생성 로직 — 적용/제외·근거·이행상태·CSV.

순수 로직 + CSV(stdlib)만 검증(PDF는 reportlab 필요라 라이브에서). fastapi 불필요.
"""
from __future__ import annotations

import unittest

from mori_soc.services.soa import build_soa_rows, soa_summary, soa_to_csv

CATALOG = {"controls": [
    {"id": "A.8.15", "framework": "iso27001", "title_en": "Logging", "status": "reviewed",
     "intent_en": "Produce and protect logs.", "evidence_sources": ["loki", "wazuh"]},
    {"id": "A.8.2", "framework": "iso27001", "title_en": "Privileged access rights", "status": "draft",
     "intent_en": "Restrict privileged access.", "evidence_sources": []},
    {"id": "A.7.1", "framework": "iso27001", "title_en": "Physical security perimeters", "status": "draft",
     "intent_en": "Define secure areas.", "evidence_sources": []},
    {"id": "2.9.4", "framework": "isms-p", "title_ko": "로그관리"},  # ISO 아님 → 제외
]}
STATUS = {
    "A.8.15": {"status": "이행", "owner": "sec", "exception_reason": ""},
    "A.7.1": {"status": "해당없음", "exception_reason": "No physical datacenter; cloud-only."},
}


class BuildSoaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = build_soa_rows(CATALOG, STATUS)

    def test_only_iso_and_sorted(self) -> None:
        self.assertEqual([r["id"] for r in self.rows], ["A.7.1", "A.8.2", "A.8.15"])

    def test_implemented(self) -> None:
        r = next(r for r in self.rows if r["id"] == "A.8.15")
        self.assertTrue(r["applicable"])
        self.assertEqual(r["impl_status"], "Implemented")
        self.assertEqual(r["justification"], "Produce and protect logs.")
        self.assertTrue(r["reviewed"])

    def test_excluded_uses_reason(self) -> None:
        r = next(r for r in self.rows if r["id"] == "A.7.1")
        self.assertFalse(r["applicable"])
        self.assertEqual(r["impl_status"], "N/A")
        self.assertEqual(r["justification"], "No physical datacenter; cloud-only.")

    def test_no_status_defaults_applicable_planned(self) -> None:
        r = next(r for r in self.rows if r["id"] == "A.8.2")
        self.assertTrue(r["applicable"])
        self.assertEqual(r["impl_status"], "Planned")

    def test_summary(self) -> None:
        self.assertEqual(soa_summary(self.rows),
                         {"total": 3, "applicable": 2, "excluded": 1, "implemented": 1, "evidence_wired": 1})

    def test_csv_header_and_rows(self) -> None:
        csv_text = soa_to_csv(self.rows)
        lines = csv_text.strip().splitlines()
        self.assertEqual(lines[0], "Control,Title,Applicable,Implementation,Justification,Owner,Evidence sources,Reviewed")
        self.assertEqual(len(lines), 4)  # header + 3
        self.assertIn("A.8.15", csv_text)
        self.assertIn("No", csv_text)  # A.7.1 applicable=No


if __name__ == "__main__":
    unittest.main()
