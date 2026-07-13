"""감사로그 hash chain 변조 감지(#20)."""
from __future__ import annotations

import unittest

from mori_soc.api.server import _audit_entry_hash, verify_audit_chain


def _chain(n):
    """유효한 체인 n건 생성(_log_action 과 동일 규칙)."""
    log = []
    for i in range(1, n + 1):
        prev = log[-1]["hash"] if log else "GENESIS"
        e = {"seq": i, "ts": f"2026-01-01T00:00:0{i}Z", "username": "u",
             "action": "LOGIN", "detail": f"d{i}", "prev_hash": prev}
        e["hash"] = _audit_entry_hash(prev, e)
        log.append(e)
    return log


class AuditChainTests(unittest.TestCase):
    def test_valid_chain_verifies(self) -> None:
        v = verify_audit_chain(_chain(5))
        self.assertTrue(v["ok"])
        self.assertEqual(v["count"], 5)
        self.assertIsNone(v["broken_at"])
        self.assertEqual(len(v["root_hash"]), 64)

    def test_tampered_entry_detected(self) -> None:
        log = _chain(5)
        log[2]["detail"] = "TAMPERED"     # 3번째 항목 내용 변조 → 해시 불일치
        v = verify_audit_chain(log)
        self.assertFalse(v["ok"])
        self.assertEqual(v["broken_at"], 3)

    def test_deleted_entry_breaks_link(self) -> None:
        log = _chain(5)
        del log[2]                        # 항목 삭제 → 링크 끊김
        v = verify_audit_chain(log)
        self.assertFalse(v["ok"])

    def test_empty_chain_ok(self) -> None:
        v = verify_audit_chain([])
        self.assertTrue(v["ok"])
        self.assertEqual(v["root_hash"], "GENESIS")


if __name__ == "__main__":
    unittest.main()
