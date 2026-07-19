"""Swagger 기능별 분류 완전성 가드 — 토스 개편(#redesign-toss).

엔드포인트에 붙은 모든 `tags=["X"]` 는 server.py 의 MORI_OPENAPI_TAGS 에 **설명과 함께**
그룹으로 정의돼 있어야 한다(기능별 분류의 정직성). 새 태그가 메타에 빠지면 실패.
fastapi 미설치 환경에서도 돌도록 소스 AST + 정규식으로 검증(앱 임포트 없이).
"""
from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import unittest

# 앱을 임포트하지 않고(=fastapi 의존 없이) server.py 경로만 확보.
_spec = importlib.util.find_spec("mori_soc.api.server")
assert _spec and _spec.origin, "mori_soc.api.server 를 찾을 수 없습니다"
_SRC = pathlib.Path(_spec.origin)
_ROUTES_DIR = _SRC.parent / "routes"
_TAG_RE = re.compile(r'tags=\[\s*"([^"]+)"\s*\]')


def _extract_openapi_tags() -> list[dict]:
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if getattr(tgt, "id", None) == "MORI_OPENAPI_TAGS":
                    return ast.literal_eval(node.value)
    raise AssertionError("server.py 에 MORI_OPENAPI_TAGS 상수가 없습니다")


def _used_tags() -> set[str]:
    used: set[str] = set()
    for f in _ROUTES_DIR.glob("*.py"):
        used |= set(_TAG_RE.findall(f.read_text(encoding="utf-8")))
    return used


class OpenApiTagsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tags = _extract_openapi_tags()
        cls.names = [t["name"] for t in cls.tags]
        cls.used = _used_tags()

    def test_metadata_wellformed(self) -> None:
        self.assertGreater(len(self.tags), 0)
        for t in self.tags:
            self.assertIn("name", t)
            self.assertTrue(t.get("description", "").strip(), f"태그 {t.get('name')} 설명 누락")

    def test_no_duplicate_tag_names(self) -> None:
        self.assertEqual(len(self.names), len(set(self.names)), "중복 태그 그룹명")

    def test_every_route_tag_is_grouped(self) -> None:
        """라우트가 쓰는 모든 태그는 그룹 메타에 정의돼 있어야(분류 누락 차단)."""
        missing = self.used - set(self.names)
        self.assertEqual(
            missing, set(),
            f"그룹 메타에 없는 태그 {sorted(missing)} — server.py MORI_OPENAPI_TAGS 에 설명과 함께 추가",
        )

    def test_at_least_one_route_uses_tags(self) -> None:
        self.assertGreater(len(self.used), 5, "라우트 태그 스캔 실패(경로 확인)")


if __name__ == "__main__":
    unittest.main()
