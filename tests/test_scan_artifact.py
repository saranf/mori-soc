"""is_scan_artifact(R8) — 이미지 스캔 대상 vs 실제 호스트 식별(카운트 불변, 표기용)."""
from __future__ import annotations

import unittest

from mori_soc.api.payloads import is_scan_artifact


class ScanArtifactTest(unittest.TestCase):
    def test_image_tag_is_artifact(self) -> None:
        self.assertTrue(is_scan_artifact("alpine:3.19"))
        self.assertTrue(is_scan_artifact("registry.io/app:latest"))
        self.assertTrue(is_scan_artifact("ubuntu:22.04"))

    def test_real_host_is_not_artifact(self) -> None:
        self.assertFalse(is_scan_artifact("web-server-01"))
        self.assertFalse(is_scan_artifact("db-primary"))
        self.assertFalse(is_scan_artifact(""))

    def test_host_port_is_not_artifact(self) -> None:
        # host:port(콜론 뒤 숫자)는 실제 호스트로 본다.
        self.assertFalse(is_scan_artifact("myhost:8080"))
        self.assertFalse(is_scan_artifact("10.0.0.5:5432"))


if __name__ == "__main__":
    unittest.main()
