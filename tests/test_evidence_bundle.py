"""Signed Evidence Bundle — 매니페스트 무결성·서명 검증(정리·제품화 C4)."""
from __future__ import annotations

import io
import json
import unittest
import zipfile

from mori_soc.services.evidence_bundle import (
    MANIFEST_NAME,
    build_signed_manifest,
    verify_signed_manifest,
    write_bundle_with_manifest,
)


class EvidenceBundleTests(unittest.TestCase):
    FILES = {"a.csv": b"col\n1\n", "b.json": '{"k":"값"}'.encode("utf-8")}

    def test_unsigned_manifest_has_hashes(self) -> None:
        m = build_signed_manifest(self.FILES, generated_at="2026-07-17T00:00:00+00:00")
        self.assertFalse(m["signed"])
        self.assertEqual(set(m["files"]), {"a.csv", "b.json"})
        self.assertEqual(len(m["files"]["a.csv"]["sha256"]), 64)
        self.assertIn("bundle_hash", m)

    def test_signed_manifest_verifies_and_detects_tamper(self) -> None:
        secret = "s3cr3t-key"
        m = build_signed_manifest(self.FILES, generated_at="2026-07-17T00:00:00+00:00",
                                  key_id="k1", secret=secret)
        self.assertTrue(m["signed"])
        self.assertEqual(m["signature_algorithm"], "hmac-sha256")
        # 원본 그대로 → 파일·서명 모두 OK
        v = verify_signed_manifest(m, self.FILES, secret=secret)
        self.assertTrue(v["ok"])
        self.assertTrue(v["files_ok"])
        self.assertTrue(v["signature_ok"])
        # 파일 내용 변조 → files_ok False
        tampered = dict(self.FILES, **{"a.csv": b"col\n999\n"})
        v2 = verify_signed_manifest(m, tampered, secret=secret)
        self.assertFalse(v2["ok"])
        self.assertIn("a.csv", v2["mismatched"])
        # 서명 변조(잘못된 키) → signature_ok False
        v3 = verify_signed_manifest(m, self.FILES, secret="wrong-key")
        self.assertFalse(v3["signature_ok"])

    def test_extra_files_flagged_as_tamper(self) -> None:
        secret = "k"
        m = build_signed_manifest(self.FILES, generated_at="t", secret=secret)
        v = verify_signed_manifest(m, dict(self.FILES, **{"sneak.txt": b"x"}), secret=secret)
        self.assertIn("sneak.txt", v["mismatched"])

    def test_write_bundle_into_zip_includes_manifest(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            m = write_bundle_with_manifest(zf, self.FILES, generated_at="t", secret="k", key_id="k1")
        names = set(zipfile.ZipFile(io.BytesIO(buf.getvalue())).namelist())
        self.assertIn(MANIFEST_NAME, names)
        self.assertIn("a.csv", names)
        # ZIP 안의 매니페스트로 재검증 가능
        z = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
        loaded = json.loads(z.read(MANIFEST_NAME))
        extracted = {n: z.read(n) for n in names if n != MANIFEST_NAME}
        self.assertTrue(verify_signed_manifest(loaded, extracted, secret="k")["ok"])
        self.assertEqual(m["key_id"], "k1")


if __name__ == "__main__":
    unittest.main()


def test_bundle_writer_streams_and_verifies():
    import io
    import json
    import zipfile

    from mori_soc.services.evidence_bundle import (
        MANIFEST_NAME,
        BundleWriter,
        verify_signed_manifest,
    )
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,"w") as z:
        w=BundleWriter(z, secret="k")
        w.add("a/x.pdf", b"PDF-A"); w.add("b/y.csv", b"col\n1")
        m=w.finalize(generated_at="2026-07-17", extra={"bundle":"t"})
    assert m["signed"] is True and m["files"]["a/x.pdf"]["bytes"]==5
    # 매니페스트 파일명이 소문자 비충돌(대소문자 충돌 방지)
    assert MANIFEST_NAME=="integrity-manifest.json"
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as z:
        names=set(z.namelist()); assert MANIFEST_NAME in names
        files={n:z.read(n) for n in names if n!=MANIFEST_NAME}
        man=json.loads(z.read(MANIFEST_NAME))
    v=verify_signed_manifest(man, files, secret="k")
    assert v["ok"] and v["files_ok"] and v["signature_ok"] is True
    # 변조 감지
    files["a/x.pdf"]=b"TAMPERED"
    assert verify_signed_manifest(man, files, secret="k")["files_ok"] is False
