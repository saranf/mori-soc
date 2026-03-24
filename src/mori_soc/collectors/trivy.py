from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope


class TrivyCollector(BaseCollector):
    """Collector for Trivy JSON vulnerability reports."""

    def __init__(
        self,
        report_paths: Iterable[str] = (),
        reports: Iterable[dict[str, Any]] = (),
        *,
        host_aliases: Iterable[str] = (),
        hostname: str | None = None,
    ) -> None:
        self._report_paths = tuple(report_paths)
        self._reports = tuple(report for report in reports)
        self._host_aliases = tuple(alias for alias in host_aliases if alias)
        self._hostname = hostname.strip() if hostname and hostname.strip() else None

    @property
    def source_name(self) -> str:
        return "trivy"

    def collect(self) -> Iterable[CollectorRecord]:
        for index, report in enumerate(self._reports):
            yield from self.collect_report(report, raw_ref_prefix=f"trivy:inline:{index}")
        for path in self._report_paths:
            with open(path, "r", encoding="utf-8") as handle:
                yield from self.collect_report(json.load(handle), raw_ref_prefix=f"trivy:file:{path}")

    def collect_report(self, report: dict[str, Any], *, raw_ref_prefix: str = "trivy") -> list[CollectorRecord]:
        if not isinstance(report, dict):
            raise ValueError("Trivy report must be a JSON object")

        observed_at = self._extract_timestamp(report)
        report_aliases = self._extract_host_aliases(report)
        artifact_name = self._string_value(report.get("ArtifactName"))
        artifact_type = self._string_value(report.get("ArtifactType"))
        results = report.get("Results")
        if not isinstance(results, list):
            return []

        records: list[CollectorRecord] = []
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            vulnerabilities = result.get("Vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for vuln_index, vulnerability in enumerate(vulnerabilities):
                if not isinstance(vulnerability, dict):
                    continue
                payload = dict(vulnerability)
                payload["artifact_name"] = artifact_name
                payload["artifact_type"] = artifact_type
                payload["target"] = self._string_value(result.get("Target"))
                payload["target_class"] = self._string_value(result.get("Class"))
                payload["target_type"] = self._string_value(result.get("Type"))
                payload["hostname"] = self._hostname
                payload["raw_ref"] = f"{raw_ref_prefix}:{result_index}:{vuln_index}"
                records.append(
                    CollectorRecord(
                        source=self.source_name,
                        record_type="vulnerability",
                        observed_at=observed_at,
                        external_id=self._external_id(payload, result_index, vuln_index),
                        host_aliases=list(report_aliases),
                        payload=payload,
                    )
                )
        return records

    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        if record.record_type != "vulnerability":
            raise ValueError(f"Unsupported Trivy record_type: {record.record_type}")
        payload = record.payload
        host_alias = record.host_aliases[0] if record.host_aliases else self._string_value(payload.get("artifact_name"))
        source_aliases = list(record.host_aliases) or ([host_alias] if host_alias else [])
        normalized = {
            "host_id": host_alias,
            "source_aliases": source_aliases,
            "hostname": self._string_value(payload.get("hostname")) or host_alias,
            "cve": self._string_value(payload.get("VulnerabilityID")),
            "severity": self._normalize_severity(payload.get("Severity")),
            "package_name": self._string_value(payload.get("PkgName")),
            "installed_version": self._string_value(payload.get("InstalledVersion")),
            "fixed_version": self._string_value(payload.get("FixedVersion")),
            "artifact_name": self._string_value(payload.get("artifact_name")),
            "artifact_type": self._string_value(payload.get("artifact_type")),
            "target": self._string_value(payload.get("target")),
        }
        yield NormalizedEnvelope(
            entity_type="vulnerability",
            entity_id=self._make_id(record),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=self._string_value(payload.get("raw_ref")),
            normalized=normalized,
            raw_payload=payload,
        )

    def _extract_host_aliases(self, report: dict[str, Any]) -> list[str]:
        aliases: list[str] = []
        for candidate in (*self._host_aliases, self._hostname, report.get("ArtifactName")):
            self._append_alias(aliases, candidate)
        metadata = report.get("Metadata")
        if isinstance(metadata, dict):
            repo_tags = metadata.get("RepoTags")
            if isinstance(repo_tags, list):
                for value in repo_tags:
                    self._append_alias(aliases, value)
        return aliases

    def _append_alias(self, aliases: list[str], candidate: object) -> None:
        text = self._string_value(candidate)
        if text and text not in aliases:
            aliases.append(text)

    def _extract_timestamp(self, report: dict[str, Any]) -> datetime:
        created_at = self._string_value(report.get("CreatedAt"))
        if created_at:
            parsed = self._parse_datetime(created_at)
            if parsed is not None:
                return parsed
        return datetime.now(tz=timezone.utc)

    def _parse_datetime(self, value: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _normalize_severity(self, value: object) -> str:
        if not isinstance(value, str):
            return "info"
        normalized = value.strip().lower()
        return normalized if normalized in {"critical", "high", "medium", "low", "info"} else "info"

    def _external_id(self, payload: dict[str, Any], result_index: int, vuln_index: int) -> str:
        parts = (
            self._string_value(payload.get("artifact_name")),
            self._string_value(payload.get("target")),
            self._string_value(payload.get("PkgName")),
            self._string_value(payload.get("InstalledVersion")),
            self._string_value(payload.get("VulnerabilityID")),
            str(result_index),
            str(vuln_index),
        )
        return "|".join(part for part in parts if part)

    def _make_id(self, record: CollectorRecord) -> str:
        digest = hashlib.sha1(
            f"trivy|{record.external_id}|{record.observed_at.isoformat()}|{record.payload}".encode("utf-8")
        ).hexdigest()
        return f"trivy-vuln-{digest[:16]}"

    def _string_value(self, value: object) -> str | None:
        if isinstance(value, str) and value:
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        return None