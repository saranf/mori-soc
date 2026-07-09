"""M2-8: 카탈로그 편집 오버레이 + NLP 임포트 + 증적 CSV 서비스 단위 테스트."""
from __future__ import annotations

import unittest

from mori_soc.services.catalog_nlp import parse_regulation_text
from mori_soc.services.control_catalog import (
    build_control_detail,
    build_tree,
    control_evidence_csv,
    merge_edits,
)

_BASE = {
    "meta": {}, "mappings": [], "defects": [],
    "controls": [
        {"id": "2.11.2", "framework": "isms-p", "domain": "D", "section": "S",
         "title_ko": "기존통제", "title_en": "Existing", "evidence_sources": ["zabbix"]},
    ],
}


class MergeEditsTests(unittest.TestCase):
    def test_upsert_adds_new_control(self) -> None:
        edits = {"CUS-1": {"op": "upsert", "control_id": "CUS-1", "framework": "custom",
                           "title_ko": "새 통제", "evidence_sources": ["fleet"], "origin": "manual"}}
        merged = merge_edits(_BASE, edits)
        ids = {c["id"] for c in merged["controls"]}
        self.assertEqual(ids, {"2.11.2", "CUS-1"})
        new = next(c for c in merged["controls"] if c["id"] == "CUS-1")
        self.assertEqual(new["title_ko"], "새 통제")
        self.assertTrue(new["_edited"])

    def test_upsert_overrides_base_fields_only_when_present(self) -> None:
        edits = {"2.11.2": {"op": "upsert", "control_id": "2.11.2", "title_ko": "수정됨"}}
        merged = merge_edits(_BASE, edits)
        c = next(x for x in merged["controls"] if x["id"] == "2.11.2")
        self.assertEqual(c["title_ko"], "수정됨")
        # 빈 값은 base 를 덮어쓰지 않는다
        self.assertEqual(c["title_en"], "Existing")

    def test_delete_hides_base_control(self) -> None:
        edits = {"2.11.2": {"op": "delete", "control_id": "2.11.2"}}
        merged = merge_edits(_BASE, edits)
        self.assertEqual(merged["controls"], [])

    def test_no_edits_returns_same_catalog(self) -> None:
        self.assertIs(merge_edits(_BASE, None), _BASE)

    def test_custom_framework_renders_in_tree(self) -> None:
        edits = {"REG-1": {"op": "upsert", "control_id": "REG-1", "framework": "개인정보보호법",
                           "title_ko": "파기"}}
        tree = build_tree(merge_edits(_BASE, edits))
        fws = [fw["framework"] for fw in tree["tree"]]
        self.assertIn("개인정보보호법", fws)


class NlpHeuristicTests(unittest.TestCase):
    def test_clause_split(self) -> None:
        text = "제5조 접근통제\n권한을 최소화한다.\n제6조 접속기록\n1년 이상 보관한다."
        res = parse_regulation_text(text, framework="개인정보보호법", id_prefix="PIPA")
        self.assertEqual(res["method"], "heuristic")
        self.assertEqual(res["count"], 2)
        ids = [c["id"] for c in res["controls"]]
        self.assertEqual(ids, ["PIPA-5", "PIPA-6"])
        self.assertEqual(res["controls"][0]["title_ko"], "접근통제")
        self.assertIn("최소화", res["controls"][0]["intent_ko"])
        self.assertEqual(res["controls"][0]["origin"], "nlp")
        self.assertEqual(res["controls"][0]["status"], "draft")

    def test_empty_text(self) -> None:
        self.assertEqual(parse_regulation_text("  ")["count"], 0)

    def test_paragraph_fallback_without_clause_markers(self) -> None:
        res = parse_regulation_text("개인정보 파기 절차를 마련한다", id_prefix="X")
        self.assertEqual(res["count"], 1)
        self.assertTrue(res["controls"][0]["id"].startswith("X-"))


class EvidenceCsvTests(unittest.TestCase):
    def test_csv_includes_live_and_manual(self) -> None:
        records = [{"title": "회의록", "body": "본문", "collected_by": "admin",
                    "collected_at": "2026-07-01", "reference": "http://x"}]
        csv_text = control_evidence_csv("2.11.2", catalog=_BASE, evidence_records=records)
        self.assertIsNotNone(csv_text)
        self.assertIn("회의록", csv_text)
        self.assertIn("manual", csv_text)
        self.assertIn("control_id", csv_text.splitlines()[0])

    def test_csv_none_for_unknown_control(self) -> None:
        self.assertIsNone(control_evidence_csv("NOPE", catalog=_BASE))

    def test_detail_sorts_manual_evidence_desc(self) -> None:
        records = [
            {"title": "old", "collected_at": "2026-01-01"},
            {"title": "new", "collected_at": "2026-07-01"},
        ]
        d = build_control_detail("2.11.2", catalog=_BASE, evidence_records=records)
        self.assertEqual([r["title"] for r in d["evidence_records"]], ["new", "old"])


if __name__ == "__main__":
    unittest.main()
