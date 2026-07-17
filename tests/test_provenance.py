"""증적 출처·신뢰수준 provenance(#1 — 모리다움)."""
from __future__ import annotations

import unittest

from mori_soc.services.evidence import stamp_evidence
from mori_soc.services.provenance import attach_provenance, tags_for_source


class ProvenanceTests(unittest.TestCase):
    def test_source_mapping(self) -> None:
        self.assertEqual(tags_for_source("zabbix"), ["API"])
        self.assertEqual(tags_for_source("trivy"), ["API"])
        self.assertEqual(tags_for_source("manual"), ["HUMAN"])
        self.assertEqual(tags_for_source("ai_flow"), ["AI"])
        self.assertEqual(tags_for_source("pii_scan"), ["CODE", "RULE"])

    def test_code_review_tool_precision(self) -> None:
        # Semgrep=규칙+코드 / Claude=AI 로 정밀 분류
        self.assertEqual(tags_for_source("code_review", tool="Semgrep(무료)"), ["RULE", "CODE"])
        self.assertEqual(tags_for_source("code_review", tool="Claude(유료)"), ["AI"])

    def test_unknown_source_human_by_creator(self) -> None:
        self.assertEqual(tags_for_source("weird", created_by="alice"), ["HUMAN"])
        self.assertEqual(tags_for_source("weird", created_by="code_review"), [])

    def test_attach_reads_envelope_tool(self) -> None:
        rec = {"source": "code_review", "envelope": {"tool": "Claude(유료)"}}
        attach_provenance(rec)
        self.assertEqual(rec["provenance"], ["AI"])

    def test_stamp_evidence_includes_provenance(self) -> None:
        rec = {"id": "x", "control_id": "3.1.1", "title": "t", "body": "b",
               "source": "privacy_flow", "created_at": "2026-01-01T00:00:00Z"}
        stamp_evidence(rec)
        self.assertEqual(rec["provenance"], ["CODE", "RULE"])
        self.assertEqual(len(rec["content_hash"]), 64)   # 기존 provenance(#21)와 공존


if __name__ == "__main__":
    unittest.main()
