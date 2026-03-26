"""감사 증적용 리포트 생성 모듈.

5가지 리포트 타입을 JSON / CSV 형식으로 생성한다.
- asset_inspection      : 자산 점검 리포트
- account_privilege      : 계정/권한 점검 리포트
- log_collection_status  : 로그 수집 상태 리포트
- vulnerability_assessment : 취약점 점검 리포트
- monthly_operations     : 월간 운영 리포트
"""

from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from mori_soc.services.query_service import InMemoryQueryStore, QueryService
from mori_soc.services.views import host_risk_summary_view, latest_host_status_view

REPORT_TYPES = [
    "asset_inspection",
    "account_privilege",
    "log_collection_status",
    "vulnerability_assessment",
    "monthly_operations",
]


def _isoformat(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# 1. 자산 점검 리포트
# ---------------------------------------------------------------------------

def build_asset_inspection_report(service: QueryService) -> dict[str, Any]:
    """자산 현황, 상태 분포, source 매핑, 위험 점수를 종합한 자산 점검 리포트."""
    store = service.store
    now = _now()
    status_rows = latest_host_status_view(store)
    risk_rows = host_risk_summary_view(store)

    # Source 별 호스트 매핑
    source_hosts: dict[str, set[str]] = defaultdict(set)
    for alias in store.host_aliases:
        source_hosts[alias.source].add(alias.host_id)

    # Source coverage per host
    sources_per_host: dict[str, set[str]] = defaultdict(set)
    for alias in store.host_aliases:
        sources_per_host[alias.host_id].add(alias.source)

    hosts_data = []
    for h in store.hosts:
        hosts_data.append({
            "host_id": h.host_id,
            "hostname": h.hostname,
            "platform": h.platform,
            "primary_ip": h.primary_ip,
            "status": h.status,
            "risk_score": h.risk_score,
            "last_seen_at": _isoformat(h.last_seen_at),
            "mapped_sources": sorted(sources_per_host.get(h.host_id, set())),
            "source_count": len(sources_per_host.get(h.host_id, set())),
        })

    status_dist = Counter(h.status for h in store.hosts)
    return {
        "report_type": "asset_inspection",
        "generated_at": _isoformat(now),
        "title": "자산 점검 리포트",
        "summary": {
            "total_hosts": len(store.hosts),
            "online": status_dist.get("online", 0),
            "offline": status_dist.get("offline", 0),
            "unknown": status_dist.get("unknown", 0),
            "avg_risk_score": round(sum(h.risk_score for h in store.hosts) / max(len(store.hosts), 1), 1),
            "source_coverage": {src: len(ids) for src, ids in sorted(source_hosts.items())},
            "unmapped_hosts": sum(1 for h in store.hosts if not sources_per_host.get(h.host_id)),
        },
        "hosts": sorted(hosts_data, key=lambda x: (-x["risk_score"], x["hostname"])),
    }


# ---------------------------------------------------------------------------
# 2. 계정/권한 점검 리포트
# ---------------------------------------------------------------------------

def build_account_privilege_report(service: QueryService) -> dict[str, Any]:
    """계정, 권한 바인딩, 그룹 멤버십을 종합한 계정/권한 점검 리포트."""
    store = service.store
    now = _now()

    # Privilege summary per account
    priv_by_account: dict[str, list[dict]] = defaultdict(list)
    for pb in store.privilege_bindings:
        priv_by_account[pb.account_id].append({
            "binding_id": pb.binding_id,
            "privilege_type": pb.privilege_type,
            "target": pb.target,
            "granted_at": _isoformat(pb.granted_at),
            "expires_at": _isoformat(pb.expires_at),
            "granted_by": pb.granted_by,
        })

    # Group memberships per account
    groups_by_account: dict[str, list[str]] = defaultdict(list)
    for gm in store.group_memberships:
        groups_by_account[gm.account_id].append(gm.group_name)

    accounts_data = []
    for acc in store.directory_accounts:
        accounts_data.append({
            "account_id": acc.account_id,
            "username": acc.username,
            "display_name": acc.display_name,
            "email": acc.email,
            "department": acc.department,
            "status": acc.status,
            "is_privileged": acc.is_privileged,
            "last_login_at": _isoformat(acc.last_login_at),
            "password_last_set": _isoformat(acc.password_last_set),
            "privilege_count": len(priv_by_account.get(acc.account_id, [])),
            "privileges": priv_by_account.get(acc.account_id, []),
            "groups": groups_by_account.get(acc.account_id, []),
        })

    status_dist = Counter(a.status for a in store.directory_accounts)
    privileged_count = sum(1 for a in store.directory_accounts if a.is_privileged)

    # Account observations (login failures etc.)
    obs_by_type: dict[str, int] = Counter()
    for obs in store.account_observations:
        obs_by_type[obs.observation_type] += 1

    return {
        "report_type": "account_privilege",
        "generated_at": _isoformat(now),
        "title": "계정/권한 점검 리포트",
        "summary": {
            "total_accounts": len(store.directory_accounts),
            "active": status_dist.get("active", 0),
            "disabled": status_dist.get("disabled", 0),
            "locked": status_dist.get("locked", 0),
            "expired": status_dist.get("expired", 0),
            "privileged_accounts": privileged_count,
            "total_privilege_bindings": len(store.privilege_bindings),
            "total_group_memberships": len(store.group_memberships),
            "observation_counts": dict(obs_by_type),
        },
        "accounts": sorted(accounts_data, key=lambda x: (-x["privilege_count"], x["username"])),
    }


# ---------------------------------------------------------------------------
# 3. 로그 수집 상태 리포트
# ---------------------------------------------------------------------------

def build_log_collection_report(service: QueryService) -> dict[str, Any]:
    """Source sync 현황, 수집 레코드 수, 에러율을 종합한 로그 수집 상태 리포트."""
    store = service.store
    now = _now()

    source_host_counts: dict[str, int] = defaultdict(int)
    for alias in store.host_aliases:
        source_host_counts[alias.source] += 1

    syncs_data = []
    for sync in store.source_syncs:
        syncs_data.append({
            "source": sync.source,
            "status": sync.status,
            "last_sync_at": _isoformat(sync.last_sync_at),
            "last_success_at": _isoformat(sync.last_success_at),
            "last_error_at": _isoformat(sync.last_error_at),
            "message": sync.message,
            "records_collected": sync.records_collected,
            "envelopes_normalized": sync.envelopes_normalized,
            "entities_saved": sync.entities_saved,
            "host_count": source_host_counts.get(sync.source, 0),
        })

    # Collection error observations
    error_keywords = {"error", "fail", "timeout", "unreachable"}
    error_obs = [
        o for o in store.observations
        if any(kw in (o.observation_type or "").lower() or kw in (o.metric_name or "").lower() for kw in error_keywords)
    ]

    return {
        "report_type": "log_collection_status",
        "generated_at": _isoformat(now),
        "title": "로그 수집 상태 리포트",
        "summary": {
            "total_sources": len(store.source_syncs),
            "healthy_sources": sum(1 for s in store.source_syncs if s.status == "success"),
            "error_sources": sum(1 for s in store.source_syncs if s.status == "error"),
            "total_records_collected": sum(s.records_collected for s in store.source_syncs),
            "total_entities_saved": sum(s.entities_saved for s in store.source_syncs),
            "collection_error_count": len(error_obs),
        },
        "sources": sorted(syncs_data, key=lambda x: x["source"]),
        "recent_errors": [
            {
                "host_id": o.host_id,
                "source": o.source,
                "type": o.observation_type,
                "metric": o.metric_name,
                "observed_at": _isoformat(o.observed_at),
            }
            for o in sorted(error_obs, key=lambda x: x.observed_at, reverse=True)[:20]
        ],
    }


# ---------------------------------------------------------------------------
# 4. 취약점 점검 리포트
# ---------------------------------------------------------------------------

def build_vulnerability_report(service: QueryService) -> dict[str, Any]:
    """호스트별/심각도별 취약점 현황을 종합한 취약점 점검 리포트."""
    store = service.store
    now = _now()
    hostnames = {h.host_id: h.hostname for h in store.hosts}

    sev_counts: dict[str, int] = Counter()
    by_host: dict[str, dict[str, Any]] = {}
    for v in store.vulnerabilities:
        sev_counts[v.severity] += 1
        bucket = by_host.setdefault(v.host_id, {
            "host_id": v.host_id,
            "hostname": hostnames.get(v.host_id, v.host_id),
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0,
            "cves": [],
        })
        bucket[v.severity] = bucket.get(v.severity, 0) + 1
        bucket["total"] += 1
        if v.cve:
            bucket["cves"].append(v.cve)

    resolved = sum(1 for v in store.vulnerabilities if v.resolved_at is not None)
    unresolved = len(store.vulnerabilities) - resolved

    vuln_rows = sorted(by_host.values(), key=lambda x: (-x["critical"], -x["high"], -x["total"]))
    for row in vuln_rows:
        row["cves"] = sorted(set(row["cves"]))[:10]  # top 10 unique CVEs

    return {
        "report_type": "vulnerability_assessment",
        "generated_at": _isoformat(now),
        "title": "취약점 점검 리포트",
        "summary": {
            "total_vulnerabilities": len(store.vulnerabilities),
            "resolved": resolved,
            "unresolved": unresolved,
            "severity_distribution": dict(sev_counts),
            "affected_hosts": len(by_host),
        },
        "by_host": vuln_rows,
    }


# ---------------------------------------------------------------------------
# 5. 월간 운영 리포트
# ---------------------------------------------------------------------------

def build_monthly_operations_report(service: QueryService) -> dict[str, Any]:
    """자산/경보/취약점/수집/통제를 월간 기준으로 종합한 운영 리포트."""
    store = service.store
    now = _now()
    since_30d = now - timedelta(days=30)

    alerts_30d = [a for a in store.alerts if a.observed_at >= since_30d]
    vulns_30d = [v for v in store.vulnerabilities if v.detected_at >= since_30d]
    resolved_30d = [v for v in store.vulnerabilities if v.resolved_at and v.resolved_at >= since_30d]

    alert_sev = Counter(a.severity for a in alerts_30d)
    alert_src = Counter(a.source for a in alerts_30d)
    vuln_sev = Counter(v.severity for v in vulns_30d)

    # Compliance summary
    checks = store.control_checks
    status_counts = Counter(c.status for c in checks)
    checked = len(checks) - status_counts.get("not_checked", 0) - status_counts.get("not_applicable", 0)
    pass_rate = round(status_counts.get("pass", 0) / max(checked, 1) * 100, 1)

    # Account summary
    priv_count = sum(1 for a in store.directory_accounts if a.is_privileged)

    return {
        "report_type": "monthly_operations",
        "generated_at": _isoformat(now),
        "title": "월간 운영 리포트",
        "period": {"from": _isoformat(since_30d), "to": _isoformat(now)},
        "assets": {
            "total_hosts": len(store.hosts),
            "online": sum(1 for h in store.hosts if h.status == "online"),
            "offline": sum(1 for h in store.hosts if h.status == "offline"),
        },
        "alerts": {
            "total_30d": len(alerts_30d),
            "by_severity": dict(alert_sev),
            "by_source": dict(alert_src),
        },
        "vulnerabilities": {
            "new_30d": len(vulns_30d),
            "resolved_30d": len(resolved_30d),
            "by_severity": dict(vuln_sev),
        },
        "collection": {
            "sources": len(store.source_syncs),
            "healthy": sum(1 for s in store.source_syncs if s.status == "success"),
        },
        "compliance": {
            "total_checks": len(checks),
            "pass_rate": pass_rate,
            "status_counts": dict(status_counts),
        },
        "identity": {
            "total_accounts": len(store.directory_accounts),
            "privileged_accounts": priv_count,
        },
    }


# ---------------------------------------------------------------------------
# Registry & CSV helpers
# ---------------------------------------------------------------------------

_REPORT_BUILDERS: dict[str, Any] = {
    "asset_inspection": build_asset_inspection_report,
    "account_privilege": build_account_privilege_report,
    "log_collection_status": build_log_collection_report,
    "vulnerability_assessment": build_vulnerability_report,
    "monthly_operations": build_monthly_operations_report,
}


def generate_report(report_type: str, service: QueryService) -> dict[str, Any]:
    """리포트 타입에 따라 적절한 빌더를 호출한다."""
    builder = _REPORT_BUILDERS.get(report_type)
    if builder is None:
        raise ValueError(f"Unknown report type: {report_type}. Valid types: {', '.join(REPORT_TYPES)}")
    return builder(service)


def report_to_csv(report: dict[str, Any]) -> str:
    """리포트 JSON을 CSV 문자열로 변환한다."""
    rtype = report.get("report_type", "")
    buf = io.StringIO()

    if rtype == "asset_inspection":
        _write_asset_csv(buf, report)
    elif rtype == "account_privilege":
        _write_account_csv(buf, report)
    elif rtype == "log_collection_status":
        _write_log_collection_csv(buf, report)
    elif rtype == "vulnerability_assessment":
        _write_vulnerability_csv(buf, report)
    elif rtype == "monthly_operations":
        _write_monthly_csv(buf, report)
    else:
        # Fallback: write summary as key-value
        writer = csv.writer(buf)
        writer.writerow(["key", "value"])
        for k, v in report.get("summary", {}).items():
            writer.writerow([k, str(v)])

    return buf.getvalue()


def _write_asset_csv(buf: io.StringIO, report: dict) -> None:
    fieldnames = ["host_id", "hostname", "platform", "primary_ip", "status",
                  "risk_score", "last_seen_at", "mapped_sources", "source_count"]
    header_map = {"host_id": "호스트ID", "hostname": "호스트명", "platform": "플랫폼",
                  "primary_ip": "IP주소", "status": "상태", "risk_score": "위험점수",
                  "last_seen_at": "최종확인일시", "mapped_sources": "매핑소스", "source_count": "소스수"}
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writerow(header_map)
    for h in report.get("hosts", []):
        row = {**h, "mapped_sources": ",".join(h.get("mapped_sources", []))}
        writer.writerow(row)


def _write_account_csv(buf: io.StringIO, report: dict) -> None:
    fieldnames = ["account_id", "username", "display_name", "email", "department",
                  "status", "is_privileged", "last_login_at", "password_last_set",
                  "privilege_count", "groups"]
    header_map = {"account_id": "계정ID", "username": "사용자명", "display_name": "표시명",
                  "email": "이메일", "department": "부서", "status": "상태",
                  "is_privileged": "특권여부", "last_login_at": "최종로그인",
                  "password_last_set": "비밀번호설정일", "privilege_count": "권한수", "groups": "그룹"}
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writerow(header_map)
    for a in report.get("accounts", []):
        row = {**a, "groups": ",".join(a.get("groups", []))}
        writer.writerow(row)


def _write_log_collection_csv(buf: io.StringIO, report: dict) -> None:
    fieldnames = ["source", "status", "last_sync_at", "last_success_at",
                  "records_collected", "entities_saved", "host_count", "message"]
    header_map = {"source": "소스", "status": "상태", "last_sync_at": "최종동기화",
                  "last_success_at": "최종성공", "records_collected": "수집레코드수",
                  "entities_saved": "저장엔티티수", "host_count": "호스트수", "message": "메시지"}
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writerow(header_map)
    writer.writerows(report.get("sources", []))


def _write_vulnerability_csv(buf: io.StringIO, report: dict) -> None:
    fieldnames = ["host_id", "hostname", "critical", "high", "medium", "low", "info", "total", "cves"]
    header_map = {"host_id": "호스트ID", "hostname": "호스트명", "critical": "심각",
                  "high": "높음", "medium": "중간", "low": "낮음", "info": "정보",
                  "total": "합계", "cves": "CVE목록"}
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writerow(header_map)
    for row in report.get("by_host", []):
        r = {**row, "cves": ",".join(row.get("cves", []))}
        writer.writerow(r)


def _write_monthly_csv(buf: io.StringIO, report: dict) -> None:
    """월간 운영 리포트를 섹션별 key-value CSV로 출력."""
    writer = csv.writer(buf)
    writer.writerow(["섹션", "지표", "값"])
    for section_key in ("assets", "alerts", "vulnerabilities", "collection", "compliance", "identity"):
        section = report.get(section_key, {})
        for k, v in section.items():
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    writer.writerow([section_key, f"{k}.{sub_k}", str(sub_v)])
            else:
                writer.writerow([section_key, k, str(v)])

