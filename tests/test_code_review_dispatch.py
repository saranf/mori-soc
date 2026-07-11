"""Option A — GitHub 코드 보안 리뷰 원격 트리거(dispatch) 테스트.

URL 파싱(순수)·dispatch 요청 구성(httpx mock)·엔드포인트 인증/검증(항상 실행).
실제 GitHub 호출은 토큰·레포가 필요하므로 여기서는 요청 구성까지만 검증한다.
"""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import MagicMock, patch

from mori_soc.services.code_review_dispatch import dispatch_workflow, parse_github_repo

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


class ParseGithubRepoTests(unittest.TestCase):
    def test_accepts_common_formats(self) -> None:
        cases = {
            "https://github.com/acme/webapp": ("acme", "webapp"),
            "https://github.com/acme/webapp.git": ("acme", "webapp"),
            "https://github.com/acme/webapp/tree/main": ("acme", "webapp"),
            "http://www.github.com/acme/webapp/": ("acme", "webapp"),
            "git@github.com:acme/webapp.git": ("acme", "webapp"),
            "acme/webapp": ("acme", "webapp"),
        }
        for url, expected in cases.items():
            self.assertEqual(parse_github_repo(url), expected, url)

    def test_rejects_invalid(self) -> None:
        for bad in ("", "   ", "https://github.com/onlyowner", "not a url"):
            with self.assertRaises(ValueError):
                parse_github_repo(bad)


class DispatchWorkflowTests(unittest.TestCase):
    def test_success_204_builds_correct_request(self) -> None:
        resp = MagicMock(status_code=204)
        with patch("httpx.post", return_value=resp) as post:
            out = dispatch_workflow("acme", "webapp", "ghp_x", ref="dev")
        self.assertEqual(out, {"ok": True, "status": 204})
        url = post.call_args.args[0]
        self.assertEqual(url, "https://api.github.com/repos/acme/webapp/actions/workflows/security-review.yml/dispatches")
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer ghp_x")
        self.assertEqual(post.call_args.kwargs["json"], {"ref": "dev", "inputs": {}})

    def test_error_status_raises_with_hint(self) -> None:
        resp = MagicMock(status_code=404)
        resp.json.return_value = {"message": "Not Found"}
        with patch("httpx.post", return_value=resp):
            with self.assertRaises(RuntimeError) as ctx:
                dispatch_workflow("acme", "webapp", "ghp_x")
        self.assertIn("404", str(ctx.exception))
        self.assertIn("security-review.yml", str(ctx.exception))  # 404 힌트

    def test_missing_token_raises(self) -> None:
        with self.assertRaises(ValueError):
            dispatch_workflow("acme", "webapp", "")


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class ScanEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        # MORI_AUTH_ENABLED 는 "존재하면 참"이라 비활성화하려면 빈 문자열이어야 한다.
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": ""}, clear=False):
            self.client = TestClient(create_app(QueryService(InMemoryQueryStore())))

    def test_missing_repo_url_400(self) -> None:
        r = self.client.post("/controls/code-review/scan", json={"github_token": "ghp_x"})
        self.assertEqual(r.status_code, 400)

    def test_missing_token_400(self) -> None:
        r = self.client.post("/controls/code-review/scan", json={"repo_url": "acme/webapp"})
        self.assertEqual(r.status_code, 400)

    def test_dispatch_called_and_token_not_echoed(self) -> None:
        with patch("mori_soc.services.code_review_dispatch.dispatch_workflow", return_value={"ok": True}) as disp:
            r = self.client.post("/controls/code-review/scan",
                                 json={"repo_url": "https://github.com/acme/webapp", "github_token": "ghp_secret", "ref": "main"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual((body["owner"], body["repo"]), ("acme", "webapp"))
        self.assertNotIn("ghp_secret", r.text)  # 토큰은 응답에 절대 노출 안 됨
        disp.assert_called_once()


if __name__ == "__main__":
    unittest.main()
