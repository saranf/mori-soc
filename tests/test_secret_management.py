"""Docker secrets(_FILE) 로딩 + 로그 시크릿 마스킹(#15)."""
from __future__ import annotations

import logging
import os
import tempfile
import unittest
from unittest.mock import patch

from mori_soc.api.server import _load_file_secrets, _SecretRedactionFilter


class FileSecretTests(unittest.TestCase):
    def test_file_suffix_loads_when_base_unset(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "tok")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("  secret-xyz\n")   # 공백/개행 trim 확인
            with patch.dict(os.environ, {"MORI_UNITTEST_SECRET_FILE": p}, clear=False):
                os.environ.pop("MORI_UNITTEST_SECRET", None)
                _load_file_secrets()
                self.assertEqual(os.environ.get("MORI_UNITTEST_SECRET"), "secret-xyz")
                os.environ.pop("MORI_UNITTEST_SECRET", None)

    def test_file_suffix_does_not_override_existing(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "tok")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("from-file")
            with patch.dict(os.environ, {"MORI_UNITTEST_SECRET2_FILE": p,
                                         "MORI_UNITTEST_SECRET2": "from-env"}, clear=False):
                _load_file_secrets()
                self.assertEqual(os.environ.get("MORI_UNITTEST_SECRET2"), "from-env")  # env 우선


class RedactionTests(unittest.TestCase):
    def test_secret_value_masked_in_logs(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "supertoken1234"}, clear=False):
            rec = logging.LogRecord("x", logging.INFO, "", 0,
                                    "push with supertoken1234 ok", (), None)
            _SecretRedactionFilter().filter(rec)
            self.assertNotIn("supertoken1234", rec.getMessage())
            self.assertIn("***REDACTED***", rec.getMessage())


if __name__ == "__main__":
    unittest.main()
