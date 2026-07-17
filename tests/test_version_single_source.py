"""버전 단일 출처 검증 — version.py = 패키지 메타 = FastAPI app version.

이전엔 pyproject 0.6.0 / FastAPI 0.2.0 / CHANGELOG v0.18.x 3중 불일치였다(신뢰 훼손).
이 테스트가 드리프트를 막는다.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch


class VersionSingleSourceTests(unittest.TestCase):
    def test_version_py_is_source(self) -> None:
        import mori_soc
        from mori_soc.version import __version__
        self.assertEqual(mori_soc.__version__, __version__)
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+")

    def test_package_metadata_matches(self) -> None:
        from importlib.metadata import version

        from mori_soc.version import __version__
        self.assertEqual(version("mori-soc"), __version__)

    def test_fastapi_app_version_matches(self) -> None:
        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        from mori_soc.version import __version__
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": ""}, clear=False):
            app = create_app(QueryService(InMemoryQueryStore()))
        self.assertEqual(app.version, __version__)


if __name__ == "__main__":
    unittest.main()
