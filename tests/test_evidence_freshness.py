import unittest

from mori_soc.services.evidence_freshness import compute_freshness


class EvidenceFreshnessTests(unittest.TestCase):
    NOW = "2026-07-17T00:00:00+00:00"

    def test_no_evidence(self) -> None:
        fr = compute_freshness([], self.NOW)
        self.assertEqual(fr["status"], "no_evidence")
        self.assertEqual(fr["count"], 0)

    def test_fresh_available_needs_review(self) -> None:
        recs = [{"generated_at": "2026-07-10T00:00:00+00:00", "source": "code_review"}]
        fr = compute_freshness(recs, self.NOW)
        self.assertEqual(fr["status"], "evidence_available")  # 최신이나 검토 전
        self.assertFalse(fr["stale"])
        self.assertEqual(fr["age_days"], 7)
        self.assertEqual(fr["sources"], ["code_review"])

    def test_stale_evidence(self) -> None:
        recs = [{"generated_at": "2026-01-01T00:00:00+00:00", "source": "zabbix"}]
        fr = compute_freshness(recs, self.NOW, stale_days=90)
        self.assertEqual(fr["status"], "evidence_stale")
        self.assertTrue(fr["stale"])

    def test_human_verified_when_approved_and_recent(self) -> None:
        recs = [{"generated_at": "2026-07-15T00:00:00+00:00", "source": "api"}]
        approval = {"approved_at": "2026-07-16T00:00:00+00:00"}
        fr = compute_freshness(recs, self.NOW, approval=approval, approval_status="approved")
        self.assertEqual(fr["status"], "human_verified")
        self.assertEqual(fr["review_age_days"], 1)

    def test_approved_but_review_old_needs_review(self) -> None:
        recs = [{"generated_at": "2026-07-15T00:00:00+00:00", "source": "api"}]
        approval = {"approved_at": "2025-01-01T00:00:00+00:00"}
        fr = compute_freshness(recs, self.NOW, approval=approval, approval_status="approved",
                               review_stale_days=180)
        self.assertEqual(fr["status"], "review_required")

    def test_applied_missing_summed(self) -> None:
        recs = [
            {"generated_at": "2026-07-15T00:00:00+00:00", "source": "api", "applied": 1200, "missing": 28},
            {"generated_at": "2026-07-14T00:00:00+00:00", "source": "api", "applied": 46, "missing": 0},
        ]
        fr = compute_freshness(recs, self.NOW)
        self.assertEqual(fr["applied"], 1246)
        self.assertEqual(fr["missing"], 28)


if __name__ == "__main__":
    unittest.main()
