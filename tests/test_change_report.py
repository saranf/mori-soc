import unittest

from mori_soc.services.change_report import build_evidence_change_report, month_bounds


class ChangeReportTests(unittest.TestCase):
    def test_month_bounds(self) -> None:
        self.assertEqual(month_bounds("2026-07"),
                         ("2026-07-01T00:00:00+00:00", "2026-08-01T00:00:00+00:00"))
        self.assertEqual(month_bounds("2026-12")[1], "2027-01-01T00:00:00+00:00")
        with self.assertRaises(ValueError):
            month_bounds("2026-13")

    def test_report_aggregation(self) -> None:
        start, end = month_bounds("2026-07")
        evidence = [
            {"control_id": "2.9.4", "generated_at": "2026-07-05T00:00:00+00:00"},
            {"control_id": "2.9.4", "generated_at": "2026-07-20T00:00:00+00:00"},
            {"control_id": "3.1.1", "generated_at": "2026-06-30T00:00:00+00:00"},  # 기간 밖
        ]
        approvals = [
            {"status": "approved", "created_at": "2026-07-10T00:00:00+00:00"},
            {"status": "superseded", "created_at": "2026-07-11T00:00:00+00:00"},
            {"status": "approved", "created_at": "2026-05-01T00:00:00+00:00"},  # 기간 밖
        ]
        gaps = [
            {"gap_id": "g1", "title": "파기 미발견", "control_id": "3.4.1",
             "created_at": "2026-07-02T00:00:00+00:00",
             "history": [
                 {"action": "transition", "to": "remediation", "ts": "2026-07-06T00:00:00+00:00"},
                 {"action": "transition", "to": "resolved", "ts": "2026-07-15T00:00:00+00:00"},
             ]},
            {"gap_id": "g2", "title": "예외", "control_id": "2.7.1",
             "created_at": "2026-06-01T00:00:00+00:00",
             "history": [{"action": "transition", "to": "accepted_exception",
                          "ts": "2026-07-09T00:00:00+00:00"}]},
        ]
        rep = build_evidence_change_report(start, end, evidence=evidence,
                                           approvals=approvals, gaps=gaps)
        self.assertEqual(rep["new_evidence_count"], 2)
        self.assertEqual(rep["new_evidence_by_control"], {"2.9.4": 2})
        self.assertEqual(rep["approvals_by_status"], {"approved": 1, "superseded": 1})
        self.assertEqual(rep["new_gap_count"], 1)          # g1 만 7월 생성
        self.assertEqual(rep["gap_transitions"]["resolved"], 1)
        self.assertEqual([r["gap_id"] for r in rep["resolved_gaps"]], ["g1"])
        self.assertEqual([r["gap_id"] for r in rep["new_exceptions"]], ["g2"])

    def test_empty(self) -> None:
        start, end = month_bounds("2026-07")
        rep = build_evidence_change_report(start, end)
        self.assertEqual(rep["new_evidence_count"], 0)
        self.assertEqual(rep["gap_transitions"], {})


if __name__ == "__main__":
    unittest.main()
