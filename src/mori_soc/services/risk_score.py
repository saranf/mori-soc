from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from mori_soc.models import Alert, Host, Vulnerability

# 스키마 4-3, 4-4 기준 severity별 가중치
ALERT_WEIGHTS: dict[str, int] = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}

VULN_WEIGHTS: dict[str, int] = {
    "critical": 15,
    "high": 8,
    "medium": 3,
    "low": 1,
    "info": 0,
}

MAX_RISK_SCORE = 100


class RiskScoreCalculator:
    """Alert 건수 + Vulnerability 건수 기반 단순 가산 위험 점수 계산기.

    스키마 4-1 hosts.risk_score 업데이트에 사용.
    점수 상한은 100.
    """

    def calculate(
        self,
        alerts: list[Alert],
        vulnerabilities: list[Vulnerability],
    ) -> int:
        """단일 호스트 위험 점수를 계산한다."""
        score = sum(ALERT_WEIGHTS.get(a.severity, 0) for a in alerts)
        score += sum(VULN_WEIGHTS.get(v.severity, 0) for v in vulnerabilities)
        return min(score, MAX_RISK_SCORE)

    def recalculate_hosts(
        self,
        hosts: list[Host],
        alerts: list[Alert],
        vulnerabilities: list[Vulnerability],
    ) -> list[Host]:
        """전체 호스트 목록에 대해 위험 점수를 재계산하고 갱신된 Host 리스트를 반환한다."""
        host_alerts: dict[str, list[Alert]] = defaultdict(list)
        host_vulns: dict[str, list[Vulnerability]] = defaultdict(list)

        for alert in alerts:
            if alert.host_id:
                host_alerts[alert.host_id].append(alert)
        for vuln in vulnerabilities:
            host_vulns[vuln.host_id].append(vuln)

        return [
            replace(host, risk_score=self.calculate(host_alerts[host.host_id], host_vulns[host.host_id]))
            for host in hosts
        ]

