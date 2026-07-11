from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope


class CodeReviewCollector(BaseCollector):
    """Collector for AI code-security-review findings (claude-code-security-review).

    코드 리뷰 findings 를 **호스트에 묶이지 않는 alert** 로 정규화한다 — SDLC/개발보안
    (ISMS-P 2.8 · ISO A.8.25~28) 증적 소스. MORI 는 코드를 읽지 않고 CI 가 이미 낸
    결과(finding)만 받는다(Trivy 리포트 push 와 동형).

    각 finding 은 dict:
      {"id": "...", "rule_id": "py/sql-injection", "title": "...", "severity": "high",
       "file": "src/x.py", "line": 42, "message": "...", "repo": "org/app", "pr": 12}
    severity 는 critical|high|medium|low|info 또는 SARIF level(error/warning/note) 허용.
    """

    def __init__(self, findings: Iterable[dict[str, Any]] = (), *, repo: str | None = None) -> None:
        self._findings = tuple(f for f in findings if isinstance(f, dict))
        self._repo = (repo or "").strip() or None

    @property
    def source_name(self) -> str:
        return "code_review"

    def collect(self) -> Iterable[CollectorRecord]:
        for index, finding in enumerate(self._findings):
            external_id = str(finding.get("id") or finding.get("rule_id") or finding.get("category") or f"cr-{index}")
            yield CollectorRecord(
                source=self.source_name,
                record_type="code_finding",
                observed_at=self._extract_timestamp(finding),
                external_id=external_id,
                host_aliases=[],  # 코드 findings 는 호스트 자산에 묶이지 않는다
                payload=finding,
            )

    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        if record.record_type == "code_finding":
            yield self._normalize_finding(record)
            return
        raise ValueError(f"Unsupported code_review record_type: {record.record_type}")

    def _normalize_finding(self, record: CollectorRecord) -> NormalizedEnvelope:
        f = record.payload
        severity = self._normalize_severity(f.get("severity") or f.get("level"))
        # claude-code-security-review finding: {file,line,severity,category,description,...}
        # (title/message/rule_id 는 MORI 네이티브·SARIF 대비 폴백 순서로 둔다)
        title = self._str(f.get("title")) or self._str(f.get("description")) or self._str(f.get("message")) or "code review finding"
        rule_id = self._str(
            f.get("rule_id") or f.get("ruleId") or f.get("category") or (str(f.get("rule")) if f.get("rule") else None)
        )
        file_path = self._str(f.get("file") or f.get("path"))
        line = f.get("line")
        repo = self._str(f.get("repo")) or self._repo
        loc = f" ({file_path}:{line})" if file_path and line is not None else (f" ({file_path})" if file_path else "")
        message = (self._str(f.get("message")) or self._str(f.get("description")) or title) + loc

        normalized = {
            # host_id/source_aliases 를 비워 두면 매퍼가 host 없는 alert 로 적재한다.
            "source_event_id": record.external_id,
            "severity": severity,
            "original_severity": self._str(str(f.get("severity") or f.get("level") or "")) or None,
            "rule_name": title,
            "rule_id": rule_id,
            "message": message,
        }
        raw_ref_bits = "|".join(x for x in [repo, rule_id, file_path, str(line) if line is not None else "", record.external_id] if x)
        return NormalizedEnvelope(
            entity_type="alert",
            entity_id=self._make_id(raw_ref_bits or record.external_id, record.observed_at),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"code_review:{repo or ''}:{record.external_id}",
            normalized=normalized,
            raw_payload=f,
        )

    def _extract_timestamp(self, finding: dict[str, Any]) -> datetime:
        ts = finding.get("detected_at") or finding.get("timestamp") or finding.get("created_at")
        if isinstance(ts, str) and ts:
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+0000", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                pass
        return datetime.now(tz=timezone.utc)

    def _normalize_severity(self, value: object) -> str:
        s = str(value or "").strip().lower()
        # SARIF level → MORI severity
        sarif = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
        if s in sarif:
            return sarif[s]
        if s in {"critical", "high", "medium", "low", "info"}:
            return s
        return "info"

    def _make_id(self, seed: str, observed_at: datetime) -> str:
        digest = hashlib.sha1(f"code_review|{seed}".encode("utf-8")).hexdigest()
        return f"code_review-{digest[:16]}"

    def _str(self, value: object) -> str | None:
        return value if isinstance(value, str) and value else None
