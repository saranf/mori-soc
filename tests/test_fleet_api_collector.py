"""FleetApiCollector 단위테스트 — F0 실캡처 fixture 기반.

HTTP 만 대체하고(``_get``), 파싱·정규화는 실제 코드를 그대로 태운다.
fixture 출처·한계는 tests/fixtures/fleet/README.md 참고.
"""
from __future__ import annotations

import copy
import json
import pathlib
import unittest

from mori_soc.collectors.fleet_api import FleetApiCollector
from mori_soc.services.normalization import ASSET_BUCKET_BY_SOURCE, EnvelopeEntityMapper

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "fleet"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class _StubCollector(FleetApiCollector):
    """네트워크 대신 F0 캡처 응답을 돌려준다."""

    def __init__(self, hosts: dict, detail: dict, **kwargs) -> None:
        super().__init__(api_url="http://fleet:1337", token="test-token", **kwargs)
        self._hosts = hosts
        self._detail = detail
        self.calls: list[str] = []

    def _get(self, path: str, params=None) -> dict:  # type: ignore[override]
        self.calls.append(path)
        if path == "/api/v1/fleet/hosts":
            return self._hosts
        if path.startswith("/api/v1/fleet/hosts/"):
            return self._detail
        raise AssertionError(f"예상치 못한 경로: {path}")


class FleetApiCollectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.hosts = _load("hosts_list.json")
        cls.detail = _load("host_detail.json")

    def _collector(self, **kwargs) -> _StubCollector:
        return _StubCollector(copy.deepcopy(self.hosts), copy.deepcopy(self.detail), **kwargs)

    # ── 수집 ───────────────────────────────────────────────────────
    def test_collects_host_record_from_real_capture(self) -> None:
        records = list(self._collector(include_software=False).collect())
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.source, "fleet")
        self.assertEqual(rec.record_type, "host")
        self.assertEqual(rec.external_id, "1")
        # F0 캡처의 실제 값
        self.assertIn("3e053e4bbd21", rec.host_aliases)          # hostname
        self.assertIn("cffb0424-b716-4c63-ab7b-b2fe3deb5020", rec.host_aliases)  # uuid

    def test_no_vulnerabilities_in_current_capture(self) -> None:
        # F0 캡처의 software 93건은 vulnerabilities 가 전부 null → 취약점 레코드 0
        # (CVE 실린 fixture는 F3 실호스트에서 추가한다. 스키마 추측 금지.)
        collector = self._collector()
        records = list(collector.collect())
        self.assertEqual([r.record_type for r in records], ["host"])
        self.assertIn("/api/v1/fleet/hosts/1", collector.calls)  # 상세는 실제로 조회했다

    def test_software_without_vulns_is_not_ingested_as_vulnerability(self) -> None:
        collector = self._collector()
        software = collector._detail["host"]["software"]
        self.assertGreater(len(software), 50)                      # 93건
        self.assertTrue(all(s.get("vulnerabilities") is None for s in software))
        self.assertEqual([r for r in collector.collect() if r.record_type == "software_vuln"], [])

    # ── 정규화: 호스트 → 자산 ───────────────────────────────────────
    def test_normalizes_host_to_host_observation(self) -> None:
        collector = self._collector(include_software=False)
        record = next(iter(collector.collect()))
        env = next(iter(collector.normalize(record)))
        self.assertEqual(env.entity_type, "host_observation")
        self.assertEqual(env.source, "fleet")
        n = env.normalized
        self.assertEqual(n["hostname"], "3e053e4bbd21")
        self.assertEqual(n["platform"], "ubuntu")
        self.assertEqual(n["primary_ip"], "172.18.0.17")
        self.assertEqual(n["status"], "online")
        self.assertEqual(n["metric_name"], "fleet_agent_status")
        self.assertEqual(n["metric_value"], "available")
        # 접두사는 수집기가 아니라 정규화 계층이 붙인다
        self.assertFalse(str(n["host_id"]).startswith("pc-"))

    def test_host_id_gets_pc_prefix_via_normalizer(self) -> None:
        """수집기→Normalizer 통합: fleet 소스는 pc- 버킷으로 스코프된다."""
        self.assertEqual(ASSET_BUCKET_BY_SOURCE["fleet"], "pc")
        collector = self._collector(include_software=False)
        record = next(iter(collector.collect()))
        env = next(iter(collector.normalize(record)))
        entities = EnvelopeEntityMapper().map_envelope(env)
        hosts = [e for e in entities if type(e).__name__ == "Host"]
        self.assertEqual(len(hosts), 1)
        # payloads.py 가 pc-* 자산에 Fleet 딥링크를 건다 → 접두사가 반드시 있어야 한다
        self.assertTrue(hosts[0].host_id.startswith("pc-"), hosts[0].host_id)
        self.assertEqual(hosts[0].platform, "ubuntu")
        self.assertEqual(hosts[0].status, "online")

    def test_deterministic_ids(self) -> None:
        a = self._collector(include_software=False)
        b = self._collector(include_software=False)
        id_a = next(iter(a.normalize(next(iter(a.collect()))))).entity_id
        id_b = next(iter(b.normalize(next(iter(b.collect()))))).entity_id
        self.assertEqual(id_a, id_b)   # stable=True — 같은 호스트는 같은 관측 ID

    # ── 정규화: 취약점 (합성 입력 — 캡처엔 CVE가 없다) ──────────────
    def test_normalizes_vulnerability_when_present(self) -> None:
        """캡처엔 CVE가 없으므로, Fleet 이 vulnerabilities 를 채웠을 때의 매핑을 검증한다.

        입력은 F0 캡처의 software 항목에 vulnerabilities 만 얹은 것이다(형태는 캡처의 키 그대로).
        """
        collector = self._collector()
        collector._detail["host"]["software"][0]["vulnerabilities"] = [
            {"cve": "CVE-2024-0001", "cvss_score": 9.8, "resolved_in_version": "2021.03.26"}
        ]
        vulns = [r for r in collector.collect() if r.record_type == "software_vuln"]
        self.assertEqual(len(vulns), 1)
        env = next(iter(collector.normalize(vulns[0])))
        self.assertEqual(env.entity_type, "vulnerability")
        n = env.normalized
        self.assertEqual(n["cve"], "CVE-2024-0001")
        self.assertEqual(n["severity"], "critical")            # cvss 9.8
        self.assertEqual(n["package_name"], "ubuntu-keyring")  # 캡처의 software[0]
        self.assertEqual(n["installed_version"], "2020.02.11.4")
        self.assertEqual(n["fixed_version"], "2021.03.26")

        entities = EnvelopeEntityMapper().map_envelope(env)
        vuln_rows = [e for e in entities if type(e).__name__ == "Vulnerability"]
        self.assertEqual(len(vuln_rows), 1)
        self.assertEqual(vuln_rows[0].source, "fleet")
        self.assertEqual(vuln_rows[0].severity, "critical")
        self.assertTrue(vuln_rows[0].host_id.startswith("pc-"))

    def test_severity_without_cvss_is_info_not_guessed(self) -> None:
        collector = self._collector()
        collector._detail["host"]["software"][0]["vulnerabilities"] = [{"cve": "CVE-2024-0002"}]
        vuln = next(r for r in collector.collect() if r.record_type == "software_vuln")
        env = next(iter(collector.normalize(vuln)))
        self.assertEqual(env.normalized["severity"], "info")   # 추정하지 않는다
        self.assertEqual(env.raw_payload["vulnerability"]["cve"], "CVE-2024-0002")  # 원본 보존

    def test_rejects_unknown_record_type(self) -> None:
        from datetime import datetime, timezone

        from mori_soc.collectors.base import CollectorRecord

        bad = CollectorRecord(source="fleet", record_type="nope", observed_at=datetime.now(timezone.utc))
        with self.assertRaises(ValueError):
            list(self._collector().normalize(bad))


if __name__ == "__main__":
    unittest.main()
