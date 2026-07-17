"""POST /ingest/code-review — 코드 보안 리뷰 findings 인제스트.

전체 적재(→PostgreSQL)는 postgres 백엔드가 필요하므로 여기서는 인증/본문검증
경로(항상 실행) + 컬렉터 정규화(순수 로직)를 확인한다. 실적재는 라이브
postgres 에서 별도 검증됨(/ingest/wazuh 와 동형).
"""
from __future__ import annotations

import importlib.util
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.collectors import CodeReviewCollector
from mori_soc.models import Alert, Host
from mori_soc.services.query_service import InMemoryQueryStore, QueryService

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None

_FINDING = {
    "id": "cr-1", "rule_id": "py/sql-injection", "severity": "high",
    "title": "SQL injection via string formatting", "file": "src/app.py", "line": 42,
    "message": "User input flows into a raw SQL string.", "repo": "saranf/mori-soc",
}
_SARIF = {
    "runs": [{
        "tool": {"driver": {"name": "claude-code-security-review"}},
        "results": [{
            "ruleId": "py/hardcoded-secret", "level": "error",
            "message": {"text": "Hardcoded API key"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/config.py"},
                "region": {"startLine": 10}}}],
        }],
    }],
}


class CodeReviewCollectorTests(unittest.TestCase):
    def test_finding_normalizes_to_hostless_alert(self) -> None:
        collector = CodeReviewCollector(findings=[_FINDING], repo="saranf/mori-soc")
        records = list(collector.collect())
        self.assertEqual(len(records), 1)
        env = next(iter(collector.normalize(records[0])))
        self.assertEqual(env.entity_type, "alert")
        self.assertEqual(env.source, "code_review")
        self.assertEqual(env.normalized["severity"], "high")
        # 코드 findings 는 host 에 묶이지 않는다 → alias 없음
        self.assertEqual(env.normalized.get("host_id"), None)
        self.assertIn("src/app.py:42", env.normalized["message"])

    def test_sarif_level_maps_to_severity(self) -> None:
        from mori_soc.api.routes.sources import _extract_code_findings
        findings = _extract_code_findings(_SARIF)
        self.assertEqual(len(findings), 1)
        env = next(CodeReviewCollector(findings=findings).normalize(
            next(iter(CodeReviewCollector(findings=findings).collect()))))
        self.assertEqual(env.normalized["severity"], "high")  # SARIF error → high
        self.assertEqual(env.normalized["rule_id"], "py/hardcoded-secret")

    def test_real_ccsr_schema_maps_category_and_description(self) -> None:
        # claude-code-security-review 실제 finding: title/message/rule_id 없이
        # category·description·severity(대문자)만 온다 → 컬렉터가 정렬돼야 한다.
        ccsr = {"file": "src/db.py", "line": 88, "severity": "HIGH",
                "category": "sql_injection", "description": "User input in raw SQL",
                "recommendation": "Use parameterized queries", "confidence": 0.95}
        env = next(CodeReviewCollector(findings=[ccsr]).normalize(
            next(iter(CodeReviewCollector(findings=[ccsr]).collect()))))
        self.assertEqual(env.normalized["severity"], "high")          # HIGH → high
        self.assertEqual(env.normalized["rule_id"], "sql_injection")  # category → rule_id
        self.assertEqual(env.normalized["rule_name"], "User input in raw SQL")  # description → title
        self.assertIn("src/db.py:88", env.normalized["message"])

    def test_ids_are_stable_and_prefixed(self) -> None:
        a = next(iter(CodeReviewCollector(findings=[_FINDING]).collect()))
        env1 = next(CodeReviewCollector(findings=[_FINDING]).normalize(a))
        env2 = next(CodeReviewCollector(findings=[_FINDING]).normalize(a))
        self.assertEqual(env1.entity_id, env2.entity_id)
        self.assertTrue(env1.entity_id.startswith("code_review-"))


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class IngestCodeReviewApiTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore(
            hosts=[Host(host_id="h1", hostname="web-01", status="online",
                        last_seen_at=datetime.now(tz=timezone.utc))]
        )
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0"}, clear=False):
            self.client = TestClient(create_app(QueryService(store)))

    def test_requires_token_when_configured(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret", "MORI_AUTH_ENABLED": "true"}, clear=False):
            r = self.client.post("/ingest/code-review", json={"findings": [_FINDING]})
            self.assertEqual(r.status_code, 401)

    def test_rejects_wrong_token(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret"}, clear=False):
            r = self.client.post("/ingest/code-review", json={"findings": [_FINDING]},
                                 headers={"Authorization": "Bearer nope"})
            self.assertEqual(r.status_code, 401)

    def test_token_ok_no_db_returns_503(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret", "MORI_DATABASE_URL": ""}, clear=False):
            r = self.client.post("/ingest/code-review", json={"findings": [_FINDING]},
                                 headers={"X-MORI-Token": "s3cret"})
            self.assertEqual(r.status_code, 503)


class CodeReviewFindingsCsvTests(unittest.TestCase):
    def _client(self, alerts):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore(alerts=alerts)
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": ""}, clear=False):
            return TestClient(create_app(QueryService(store)))

    def test_findings_csv_exports_code_review_only_and_filters_by_repo(self) -> None:
        now = datetime.now(tz=timezone.utc)
        alerts = [
            Alert(alert_id="c1", source="code_review", observed_at=now, message="sql injection (app.py:10)",
                  severity="high", rule_id="py/sql", rule_name="SQL Injection",
                  raw_payload={"file": "app.py", "line": 10,
                               "_provenance": {"repo": "org/app", "commit": "deadbeefcafe", "verified": True}}),
            Alert(alert_id="c2", source="code_review", observed_at=now, message="xss (ui.js:3)",
                  severity="low", rule_id="js/xss",
                  raw_payload={"file": "ui.js", "line": 3,
                               "_provenance": {"repo": "org/other", "commit": "0000", "verified": False}}),
            Alert(alert_id="w1", source="wazuh", observed_at=now, message="ssh brute", severity="high"),
        ]
        client = self._client(alerts)

        r = client.get("/controls/code-review/findings.csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r.headers["content-type"])
        body = r.text
        self.assertIn("org/app", body)
        self.assertIn("org/other", body)
        self.assertNotIn("ssh brute", body)          # wazuh 제외
        self.assertIn("검증됨", body)
        self.assertIn("미검증", body)

        r2 = client.get("/controls/code-review/findings.csv", params={"repo": "org/app"})
        self.assertEqual(r2.status_code, 200)
        self.assertIn("org/app", r2.text)
        self.assertNotIn("org/other", r2.text)

        r3 = client.get("/controls/code-review/findings.csv", params={"repo": "org/app", "commit": "deadbeef"})
        self.assertIn("org/app", r3.text)            # prefix commit 매칭
        self.assertNotIn("org/other", r3.text)

    def test_alerts_triage_excludes_code_review(self) -> None:
        # Alert Triage(/alerts)는 운영 경보 중심 — code_review 정적 결함은 제외한다.
        now = datetime.now(tz=timezone.utc)
        alerts = [
            Alert(alert_id="c1", source="code_review", observed_at=now, message="sql injection", severity="high"),
            Alert(alert_id="w1", source="wazuh", observed_at=now, message="ssh brute", severity="high"),
        ]
        client = self._client(alerts)
        data = client.get("/alerts").json()
        ids = {a["alert_id"] for a in data["alerts"]}
        self.assertIn("w1", ids)
        self.assertNotIn("c1", ids)                  # code_review 제외
        self.assertEqual(data["total"], 1)


class PdcaCodeReviewSplitTests(unittest.TestCase):
    def test_code_review_alerts_counted_separately(self) -> None:
        from mori_soc.api.payloads import build_pdca_payload

        now = datetime.now(tz=timezone.utc)
        store = InMemoryQueryStore(
            hosts=[Host(host_id="h1", hostname="web-01", status="online", last_seen_at=now)],
            alerts=[
                Alert(alert_id="a1", source="wazuh", observed_at=now, message="ssh brute", severity="high"),
                Alert(alert_id="c1", source="code_review", observed_at=now, message="sql injection", severity="high"),
            ],
        )
        pdca = build_pdca_payload(QueryService(store))
        srcs = pdca["pending_sources"]
        self.assertEqual(srcs["alert"], 1)          # 인프라 경보만
        self.assertEqual(srcs["code_review"], 1)    # 코드 리뷰는 분리 집계


if __name__ == "__main__":
    unittest.main()


class IngestReplayGuardTests(unittest.TestCase):
    """Ingest replay 방지(#11) — 동일 OIDC jti 재사용 감지."""

    def setUp(self) -> None:
        from mori_soc.api.routes.sources import _INGEST_REPLAY_SEEN
        _INGEST_REPLAY_SEEN.clear()

    def test_jti_replay_detected(self) -> None:
        from mori_soc.api.routes.sources import _is_replayed
        self.assertFalse(_is_replayed(None))                      # OIDC 없음
        self.assertFalse(_is_replayed({"jti": "tok-1"}))          # 처음
        self.assertTrue(_is_replayed({"jti": "tok-1"}))           # 재전송 → replay
        self.assertFalse(_is_replayed({"jti": "tok-2"}))          # 다른 토큰
        self.assertFalse(_is_replayed({"repository": "o/r"}))     # jti 없으면 멱등성에 위임
