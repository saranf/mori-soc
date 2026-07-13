"""통제 성숙도 도출(#46)."""
from __future__ import annotations

import unittest

from mori_soc.services.control_catalog import (
    control_maturity_level,
    mapped_control_ids,
    maturity_summary,
)


class MaturityTests(unittest.TestCase):
    def test_levels_from_signals(self) -> None:
        mapped = {"1.1.1"}
        auto = {"2.8.1"}
        self.assertEqual(control_maturity_level({"id": "9.9.9", "status": "draft"}, mapped, auto), "draft")
        self.assertEqual(control_maturity_level({"id": "5.5.5", "status": "reviewed"}, mapped, auto), "reviewed")
        self.assertEqual(control_maturity_level({"id": "1.1.1", "status": "reviewed"}, mapped, auto), "mapped")
        # auto_evidence 는 검토 상태와 무관하게 최상위
        self.assertEqual(control_maturity_level({"id": "2.8.1", "status": "draft"}, mapped, auto), "auto_evidence")

    def test_mapped_ids_extracted(self) -> None:
        cat = {"mappings": [{"isms_p": "1.1.1", "iso27001": ["A.5.1", "A.5.4"]}]}
        self.assertEqual(mapped_control_ids(cat), {"1.1.1", "A.5.1", "A.5.4"})

    def test_summary_counts_sum_to_total(self) -> None:
        s = maturity_summary(auto_ids={"2.8.1"})
        self.assertEqual(sum(s["levels"].values()), s["total"])
        self.assertEqual(set(s["levels"].keys()), set(s["order"]))


if __name__ == "__main__":
    unittest.main()
