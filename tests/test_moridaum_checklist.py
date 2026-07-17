"""모리다움(MORI 정체성) 체크리스트 테스트 — 정체성 가드레일을 코드로 고정한다.

사용자 지시(2026-07): 모든 개발이 끝나면 **모리다움 체크리스트 원칙으로 테스트 케이스를 생성**한다.
mori-identity 의 8원칙을 자동 검증으로 박아, 앞으로 어떤 기능이 들어와도 모리답지 않으면 깨진다.

원칙:
 1. 증적 층이지 보는 층이 아니다      5. 후보이지 확정이 아니다
 2. 코드를 읽지 않는다               6. 소규모 팀 운영성(역할 가시성)
 3. 정직(Honest by design)          7. 표현 규율(6색·이모지 금지·i18n 파리티)
 4. 변조·유실 방지(결정적 id·해시)    8. 공통화·부팅 안전
"""
from __future__ import annotations

import os
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src" / "mori_soc"


def _client(alerts=None, auth: bool = False):
    from fastapi.testclient import TestClient

    from mori_soc.api.server import create_app
    from mori_soc.services.query_service import InMemoryQueryStore, QueryService
    env = {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1" if auth else ""}
    with patch.dict(os.environ, env, clear=False):
        return TestClient(create_app(QueryService(InMemoryQueryStore(alerts=alerts or []))))


class Principle2_NeverReadsCode(unittest.TestCase):
    """코드를 읽지 않는다 — 스캔은 고객 CI, MORI 는 구조화 결과만 수신."""

    def test_code_review_excluded_from_alert_triage(self) -> None:
        from mori_soc.services.query_service import Alert
        now = datetime.now(tz=timezone.utc)
        c = _client(alerts=[
            Alert(alert_id="c1", source="code_review", observed_at=now, message="x", severity="high"),
            Alert(alert_id="w1", source="wazuh", observed_at=now, message="y", severity="high"),
        ])
        ids = {a["alert_id"] for a in c.get("/alerts").json()["alerts"]}
        self.assertEqual(ids, {"w1"})


class Principle3_HonestByDesign(unittest.TestCase):
    """정직 — '초록 Compliant' 하나로 뭉뚱그리지 않고 신뢰 품질을 구분한다."""

    def test_evidence_freshness_has_distinct_statuses(self) -> None:
        from mori_soc.services.evidence_freshness import STATUSES, compute_freshness
        self.assertIn("evidence_stale", STATUSES)
        self.assertIn("human_verified", STATUSES)
        now = "2026-07-17T00:00:00+00:00"
        stale = compute_freshness([{"generated_at": "2026-01-01T00:00:00+00:00"}], now)
        self.assertEqual(stale["status"], "evidence_stale")


class Principle4_TamperEvident(unittest.TestCase):
    """변조·유실 방지 — 결정적 id·content_hash."""

    def test_deterministic_ids(self) -> None:
        from mori_soc.services.gap_workflow import gap_id_for
        from mori_soc.services.provenance import scan_input_signature
        self.assertEqual(gap_id_for("s", "c", "k"), gap_id_for("s", "c", "k"))
        self.assertEqual(scan_input_signature("r", "c1", "semgrep", "0.6", "rs", ""),
                         scan_input_signature("r", "c1", "semgrep", "0.6", "rs", ""))

    def test_governance_content_hash_is_stable(self) -> None:
        from mori_soc.services.control_governance import content_hash
        a = {"x": 1, "created_at": "2026-01-01"}
        b = {"x": 1, "created_at": "2030-12-31"}
        self.assertEqual(content_hash(a), content_hash(b))  # 시각 무시, 내용만


class Principle5_CandidateNotDetermination(unittest.TestCase):
    """후보이지 확정이 아니다 — 개인정보 자동분류는 담당자 확인 필요."""

    def test_external_recipients_require_human_confirm(self) -> None:
        from mori_soc.services.data_flow import classify_external_recipients
        recs = classify_external_recipients([{"item": "이메일", "third_party": "AWS", "overseas": "us"}])
        self.assertTrue(recs)
        for r in recs:
            self.assertEqual(r["confirm"], "담당자 확인 필요")

    def test_policy_compare_returns_candidates_not_verdicts(self) -> None:
        from mori_soc.services.data_flow import compare_policy_to_flow
        d = compare_policy_to_flow(["이메일"], "즉시 파기", [{"item": "생년월일", "retention": "365일"}])
        # 확정이 아니라 후보 집합(코드에만/방침에만/보유기간 불일치)
        self.assertIn("only_in_code", d)
        self.assertIn("retention_mismatch", d)


class Principle6_RoleVisibility(unittest.TestCase):
    """소규모 팀 운영성 — 개인정보·통제 운영은 admin·security 전용."""

    def test_privacy_and_governance_require_role(self) -> None:
        c = _client(auth=True)  # 인증 켜짐, 세션 없음 → 차단(401 미인증 / 403 권한없음)
        for path in ("/privacy/data-flow", "/privacy/processing-tasks",
                     "/governance/frameworks", "/controls/evidence-freshness"):
            self.assertIn(c.get(path).status_code, (401, 403), f"{path} 가 무권한에 열림")


class Principle7_ExpressionDiscipline(unittest.TestCase):
    """표현 규율 — i18n ko/en 파리티 + 산출물에 장식 이모지 금지."""

    def test_i18n_ko_en_parity(self) -> None:
        from mori_soc.api.i18n import (
            _ADMIN_I18N,
            _DASHBOARD_I18N,
            _LOGIN_I18N,
            _SIGNUP_I18N,
        )
        for name, d in {"login": _LOGIN_I18N, "signup": _SIGNUP_I18N,
                        "dash": _DASHBOARD_I18N, "admin": _ADMIN_I18N}.items():
            self.assertEqual(set(d["ko"]), set(d["en"]), f"{name} 키 파리티 불일치")

    def test_no_decorative_emoji_in_i18n(self) -> None:
        from mori_soc.api.i18n import (
            _ADMIN_I18N,
            _DASHBOARD_I18N,
            _LOGIN_I18N,
            _SIGNUP_I18N,
        )
        emoji = re.compile(
            "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U00002B00-\U00002BFF\U0001F1E6-\U0001F1FF]")
        for name, d in {"login": _LOGIN_I18N, "signup": _SIGNUP_I18N,
                        "dash": _DASHBOARD_I18N, "admin": _ADMIN_I18N}.items():
            for lang in ("ko", "en"):
                for k, v in d[lang].items():
                    self.assertIsNone(emoji.search(str(v)), f"{name}[{lang}] {k} 에 장식 이모지")


class Principle8_CommonHelpers(unittest.TestCase):
    """공통화 — 새 CSV 출력은 공통 헬퍼(render_csv/csv_streaming_response)를 쓴다."""

    def test_new_features_use_common_csv_helper(self) -> None:
        privacy = (_SRC / "api" / "routes" / "privacy.py").read_text(encoding="utf-8")
        # 처리업무·외부수신자 CSV 는 공통 csv_streaming_response 를 통해 나간다.
        self.assertIn("csv_streaming_response(build_processing_tasks", privacy)
        self.assertIn("csv_streaming_response(classify_external_recipients", privacy)


if __name__ == "__main__":
    unittest.main()
