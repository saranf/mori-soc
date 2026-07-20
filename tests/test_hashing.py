"""services.hashing 단일 소스 검증 — 기존 각 구현과 바이트 동일 출력 보장(공통화 C1).

핵심: 이 통합이 감사 해시(content_hash·결정적 id)의 출력을 **바꾸면 안 된다**. 기존 공식과
동일 결과임을 여기서 고정한다(회귀 방지).
"""
from __future__ import annotations

import hashlib
import json
import unittest

from mori_soc.services.hashing import (
    CANONICALIZATION,
    canonical_json,
    content_hash,
    sha256_hex,
    short_id,
)


class HashingTests(unittest.TestCase):
    def test_canonical_json_default_and_compact(self) -> None:
        obj = {"z": 1, "a": "한글"}
        self.assertEqual(canonical_json(obj),
                         json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        self.assertEqual(canonical_json(obj, compact=True),
                         json.dumps(obj, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8"))

    def test_content_hash_include_matches_evidence_formula(self) -> None:
        keys = ("control_id", "title", "body")
        rec = {"control_id": "c1", "title": "제목", "body": "본문", "ignored": "x"}
        old = hashlib.sha256(json.dumps(
            {k: rec.get(k) for k in keys if k in rec},
            sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        self.assertEqual(content_hash(rec, include=keys), old)

    def test_content_hash_exclude_prefix_matches_governance_formula(self) -> None:
        vol = {"content_hash", "id", "status"}
        rec = {"a": "값", "b": 2, "status": "active", "id": "x"}
        old = "sha256:" + hashlib.sha256(json.dumps(
            {k: v for k, v in rec.items() if k not in vol},
            ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(content_hash(rec, exclude=vol, prefix="sha256:"), old)

    def test_content_hash_stable_across_volatile_change(self) -> None:
        base = {"a": "값", "status": "draft"}
        active = {"a": "값", "status": "active"}
        self.assertEqual(content_hash(base, exclude={"status"}),
                         content_hash(active, exclude={"status"}))

    def test_short_id_matches_pipe_sha1_formula(self) -> None:
        self.assertEqual(short_id("trivy", "3.4.1", "k", prefix="gap"),
                         "gap-" + hashlib.sha1("trivy|3.4.1|k".encode()).hexdigest()[:16])
        # None/빈값은 "" 로 결합(기존 str(x or "") 재현)
        self.assertEqual(short_id("a", None, "b"),
                         hashlib.sha1("a||b".encode()).hexdigest()[:16])

    def test_sha256_hex(self) -> None:
        self.assertEqual(sha256_hex(b"abc"), hashlib.sha256(b"abc").hexdigest())

    def test_canonicalization_constant(self) -> None:
        self.assertEqual(CANONICALIZATION, "mori-jcs-v1")


if __name__ == "__main__":
    unittest.main()
