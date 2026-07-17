"""인증범위 태그·커버리지(#12).

풀 인증범위 관리 모듈(조직도·사업장·계약)은 MORI 범위가 아니다. 대신 자산에 **범위 태그**만 붙이고,
**인증범위 자산 중 기술 신호(모니터링)로 커버되는 비율**을 보여준다(모리다움 — 작게, 증적 중심).

순수 함수 — I/O 없음.
"""
from __future__ import annotations

from typing import Any, Iterable

# 기본 인증범위 태그(어드민이 자산에 자유롭게 부여). in-scope 판정 기본 태그는 첫 항목.
DEFAULT_SCOPE_TAGS = ("인증범위 포함", "개인정보처리시스템", "운영환경", "쇼핑몰 서비스")
IN_SCOPE_TAG = "인증범위 포함"


def normalize_tags(raw: Any) -> list[str]:
    """태그 입력(list 또는 콤마/줄바꿈 구분 문자열)을 정규화한다(중복·공백 제거, 순서 유지)."""
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace("\n", ",").replace("·", ",").split(",")]
    elif isinstance(raw, (list, tuple)):
        parts = [str(p).strip() for p in raw]
    else:
        parts = []
    out: list[str] = []
    for p in parts:
        if p and p not in out:
            out.append(p[:60])
    return out[:20]


def _host_key(v: Any) -> str:
    return str(v or "").strip().lower()


def compute_scope_coverage(
    owners: Iterable[dict[str, Any]],
    monitored_hosts: Iterable[str],
    *,
    in_scope_tag: str = IN_SCOPE_TAG,
) -> dict[str, Any]:
    """자산 담당자 레코드의 범위 태그로 태그별·인증범위 커버리지를 계산한다.

    - monitored: 해당 자산 hostname 이 기술 신호(호스트 인벤토리)에 존재 = 모니터링 커버됨.
    - coverage_pct: 태그가 붙은 자산 중 모니터링되는 비율(인증범위 자산의 증적 커버리지 근사).
    """
    mon = {_host_key(h) for h in monitored_hosts if _host_key(h)}
    owners = list(owners)

    tag_assets: dict[str, list[str]] = {}
    for o in owners:
        host = str(o.get("hostname") or "").strip()
        for t in normalize_tags(o.get("scope_tags")):
            tag_assets.setdefault(t, []).append(host)

    def _cov(hosts: list[str]) -> dict[str, Any]:
        total = len(hosts)
        monitored = sum(1 for h in hosts if _host_key(h) in mon)
        pct = round(monitored * 100 / total) if total else 0
        return {"assets": total, "monitored": monitored,
                "unmonitored": total - monitored, "coverage_pct": pct}

    tags = []
    for t in sorted(tag_assets):
        row = {"tag": t}
        row.update(_cov(tag_assets[t]))
        tags.append(row)

    in_scope = {"tag": in_scope_tag}
    in_scope.update(_cov(tag_assets.get(in_scope_tag, [])))

    return {"tags": tags, "in_scope": in_scope,
            "total_assets": len(owners), "monitored_hosts": len(mon)}


__all__ = ["DEFAULT_SCOPE_TAGS", "IN_SCOPE_TAG", "normalize_tags", "compute_scope_coverage"]
