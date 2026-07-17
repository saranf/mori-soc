"""account_recon.reconcile — 계정 거버넌스 4대 판정 테스트(리뷰: 핵심 로직 무테스트 해소)."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from mori_soc.services.account_recon import reconcile


class ReconcileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 17, tzinfo=timezone.utc)

    def _run(self, host_accounts, directory, approvals):
        return reconcile(host_accounts, directory, approvals, self.now, dormant_days=90)

    def test_leaver_disabled_in_directory(self) -> None:
        r = self._run({"srv-1": [{"username": "alice", "host_type": "server"}]},
                      [{"username": "alice", "status": "disabled"}], [])
        self.assertEqual(r["counts"]["leaver"], 1)
        self.assertIn("leaver", r["accounts"][0]["findings"])

    def test_orphan_privileged_not_in_dir_not_approved(self) -> None:
        r = self._run({"srv-1": [{"username": "root2", "host_type": "server", "is_privileged": True}]},
                      [], [])
        self.assertEqual(r["counts"]["orphan_priv"], 1)

    def test_privileged_but_approved_is_clean(self) -> None:
        r = self._run({"srv-1": [{"username": "svc", "host_type": "server", "is_privileged": True}]},
                      [], [{"scope": "global", "username": "svc", "kind": "account"}])
        self.assertEqual(r["counts"]["orphan_priv"], 0)

    def test_unapproved_sudo_needs_sudo_approval(self) -> None:
        # account 승인만 있으면 sudo 는 여전히 미승인
        r = self._run({"srv-1": [{"username": "bob", "host_type": "server", "is_sudo": True}]},
                      [{"username": "bob", "status": "active"}],
                      [{"scope": "global", "username": "bob", "kind": "account"}])
        self.assertEqual(r["counts"]["unapproved_sudo"], 1)
        # sudo 승인이 있으면 clean
        r2 = self._run({"srv-1": [{"username": "bob", "host_type": "server", "is_sudo": True}]},
                       [{"username": "bob", "status": "active"}],
                       [{"scope": "global", "username": "bob", "kind": "sudo"}])
        self.assertEqual(r2["counts"]["unapproved_sudo"], 0)

    def test_dormant_by_login_age(self) -> None:
        r = self._run({"srv-1": [{"username": "old", "host_type": "server",
                                  "last_login": "2026-01-01T00:00:00+00:00"}]},
                      [{"username": "old", "status": "active"}], [])
        self.assertEqual(r["counts"]["dormant"], 1)
        self.assertGreater(r["accounts"][0]["login_age_days"], 90)

    def test_host_scoped_approval_does_not_cover_other_host(self) -> None:
        r = self._run({"srv-2": [{"username": "svc", "host_type": "server", "is_privileged": True}]},
                      [], [{"scope": "host", "host_key": "srv-1", "username": "svc", "kind": "account"}])
        self.assertEqual(r["counts"]["orphan_priv"], 1)   # srv-1 승인은 srv-2 를 못 덮음

    def test_summary_counts(self) -> None:
        r = self._run({"srv-1": [{"username": "a", "host_type": "server", "is_privileged": True}],
                       "pc-1": [{"username": "b", "host_type": "pc"}]},
                      [{"username": "a", "status": "active"}], [])
        self.assertEqual(r["summary"]["hosts"], 2)
        self.assertEqual(r["summary"]["accounts"], 2)
        self.assertEqual(r["summary"]["privileged"], 1)


if __name__ == "__main__":
    unittest.main()
