import json
import tempfile
import unittest
from datetime import datetime, timezone

from mori_soc.collectors import TrivyCollector


class TrivyCollectorTests(unittest.TestCase):
    def test_collect_and_normalize_inline_report(self) -> None:
        report = {
            "CreatedAt": "2026-03-24T10:00:00Z",
            "ArtifactName": "srv-01",
            "ArtifactType": "filesystem",
            "Results": [
                {
                    "Target": "/",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                            "Severity": "CRITICAL",
                        }
                    ],
                }
            ],
        }
        collector = TrivyCollector(reports=[report], host_aliases=["srv-01", "10.0.0.10"], hostname="srv-01")

        records = list(collector.collect())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].observed_at, datetime(2026, 3, 24, 10, 0, tzinfo=timezone.utc))
        self.assertIn("srv-01", records[0].host_aliases)
        self.assertIn("10.0.0.10", records[0].host_aliases)

        normalized = list(collector.normalize(records[0]))[0]
        self.assertEqual(normalized.entity_type, "vulnerability")
        self.assertEqual(normalized.source, "trivy")
        self.assertEqual(normalized.normalized["cve"], "CVE-2026-0001")
        self.assertEqual(normalized.normalized["package_name"], "openssl")
        self.assertEqual(normalized.normalized["severity"], "critical")

    def test_collect_report_from_file_path(self) -> None:
        report = {
            "CreatedAt": "2026-03-24T10:00:00Z",
            "ArtifactName": "image:latest",
            "ArtifactType": "container_image",
            "Results": [{"Target": "image:latest", "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0002", "PkgName": "libssl", "InstalledVersion": "2.0", "Severity": "HIGH"}]}],
        }
        with tempfile.NamedTemporaryFile("w+", suffix=".json") as handle:
            json.dump(report, handle)
            handle.flush()

            collector = TrivyCollector(report_paths=[handle.name])
            records = list(collector.collect())

        self.assertEqual(len(records), 1)
        self.assertIn("image:latest", records[0].host_aliases)


if __name__ == "__main__":
    unittest.main()