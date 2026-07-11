"""Loki HTTP 클라이언트 — 접속기록(access-record) 증적용 최소 조회.

MORI는 "증명하는 층"이라 로그를 재저장·재조회하지 않는다. 대신 Loki(보는 층)에
LogQL로 **'접속기록이 언제부터, 얼마나 있는가'**만 물어 보존현황·건수를 증적화한다.
(개인정보 안전성 확보조치 기준 제8조 / ISMS-P 2.9.4 / ISO 27001 A.8.15)

라이브 조회는 env ``MORI_LOKI_URL`` 이 설정된 경우에만 시도하고, 미설정·오류 시
``available=False`` 로 조용히 degrade 한다(관측 기반 추정으로 폴백). HTTP 경계는
얇게 두고 응답 파싱은 순수 함수(``parse_query_range``)로 분리해 네트워크 없이
단위테스트한다.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib import error, parse, request

_ACCEPTED = "Accepted password"
_FAILED = "Failed password"

# (selector, target_days) → (epoch_seconds, summary) 60초 TTL 캐시. 대시보드 새로고침마다
# Loki를 두드리지 않도록. Date.now 대체로 호출자가 now를 주입.
_CACHE: dict[tuple[str, int], tuple[float, dict[str, Any]]] = {}
_TTL_SECONDS = 60.0


def loki_base_url() -> str:
    """라이브 조회 대상 Loki HTTP 주소. 미설정이면 빈 문자열(→ degrade)."""
    return os.getenv("MORI_LOKI_URL", "").rstrip("/")


def access_selector() -> str:
    """접속기록 LogQL 셀렉터. 전용 라벨(authlog.template.conf)이 기본.

    라벨 분리 전 배포는 ``MORI_LOKI_ACCESS_SELECTOR='{job="fluent-bit",source="host"}'``
    로 덮어쓸 수 있다.
    """
    return os.getenv("MORI_LOKI_ACCESS_SELECTOR", '{job="authlog"}')


def parse_query_range(payload: dict[str, Any]) -> dict[str, Any]:
    """Loki ``query_range`` 응답에서 (건수, 최古 나노초 타임스탬프)를 뽑는 순수 함수.

    resultType=streams(원시 로그)와 matrix/vector(count_over_time 등 집계) 모두 처리.
    반환: ``{"count": int, "oldest_ns": int | None}``.
    """
    data = (payload or {}).get("data", {}) or {}
    rtype = data.get("resultType", "")
    result = data.get("result", []) or []
    count = 0
    oldest: int | None = None
    if rtype == "streams":
        for stream in result:
            for pair in stream.get("values", []) or []:
                if not pair:
                    continue
                count += 1
                try:
                    ns = int(pair[0])
                except (TypeError, ValueError):
                    continue
                if oldest is None or ns < oldest:
                    oldest = ns
    else:  # matrix | vector — 집계값 합산
        for series in result:
            vals = series.get("values")
            if vals is None:
                v = series.get("value")
                vals = [v] if v else []
            for pair in vals:
                if not pair or len(pair) < 2:
                    continue
                try:
                    count += int(float(pair[1]))
                    ns = int(float(pair[0]) * 1e9)
                except (TypeError, ValueError):
                    continue
                if oldest is None or ns < oldest:
                    oldest = ns
    return {"count": count, "oldest_ns": oldest}


def _http_get_json(url: str, params: dict[str, str], timeout: int) -> dict[str, Any]:
    req = request.Request(f"{url}?{parse.urlencode(params)}", headers={"Accept": "application/json"})
    with request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (신뢰된 내부 Loki)
        return json.loads(resp.read().decode("utf-8"))


def _empty() -> dict[str, Any]:
    return {"available": False, "count": 0, "accepted": 0, "failed": 0, "oldest": None, "span_days": None}


def access_log_summary(target_days: int, now: datetime | None = None, *,
                       base_url: str | None = None, selector: str | None = None,
                       timeout: int = 8) -> dict[str, Any]:
    """접속기록 보존현황 요약(Loki 라이브). 미설정/오류 시 ``available=False``.

    반환: ``{available, count, accepted, failed, oldest(YYYY-MM-DD), span_days}``.
    건수는 근사(전 구간 count_over_time 합)이며, 보존 판정의 핵심은 ``oldest``·``span_days``.
    """
    base = base_url if base_url is not None else loki_base_url()
    if not base:
        return _empty()
    sel = selector if selector is not None else access_selector()
    now = now or datetime.now(tz=timezone.utc)
    key = (sel, int(target_days))
    cached = _CACHE.get(key)
    if cached and (now.timestamp() - cached[0]) < _TTL_SECONDS:
        return cached[1]

    end_ns = int(now.timestamp() * 1e9)
    window = target_days + 60  # 목표 + 여유
    start_ns = end_ns - int(window * 86400 * 1e9)
    qr = f"{base}/loki/api/v1/query_range"
    out = _empty()
    try:
        oldest_ns = parse_query_range(_http_get_json(
            qr, {"query": sel, "start": str(start_ns), "end": str(end_ns),
                 "direction": "forward", "limit": "1"}, timeout))["oldest_ns"]
        accepted = parse_query_range(_http_get_json(
            qr, {"query": f'count_over_time({sel} |= "{_ACCEPTED}" [{window}d])',
                 "start": str(start_ns), "end": str(end_ns), "step": f"{window}d"}, timeout))["count"]
        failed = parse_query_range(_http_get_json(
            qr, {"query": f'count_over_time({sel} |= "{_FAILED}" [{window}d])',
                 "start": str(start_ns), "end": str(end_ns), "step": f"{window}d"}, timeout))["count"]
        out = {"available": True, "count": accepted + failed, "accepted": accepted,
               "failed": failed, "oldest": None, "span_days": None}
        if oldest_ns:
            oldest_dt = datetime.fromtimestamp(oldest_ns / 1e9, tz=timezone.utc)
            out["oldest"] = oldest_dt.strftime("%Y-%m-%d")
            out["span_days"] = int((now - oldest_dt).total_seconds() // 86400)
    except (error.URLError, error.HTTPError, ValueError, KeyError, OSError, TimeoutError):
        return _empty()
    _CACHE[key] = (now.timestamp(), out)
    return out


# ── 접속 발자취(Access Trail) — 실제 로그 라인 미리보기 파싱 ──────────────────────
_RE_AUTH = re.compile(r"(Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9a-fA-F:.]+)")
_RE_SUDO = re.compile(r"sudo:\s+(\S+)\s*:.*?COMMAND=(\S+)")
_RE_SESSION = re.compile(r"session\s+(opened|closed)\s+for\s+user\s+(\S+)")


def _parse_access_line(line: str) -> dict[str, Any] | None:
    """sshd/sudo 로그 한 줄 → {user, source_ip, event, result[, detail]}. 매칭 실패 시 None."""
    m = _RE_AUTH.search(line)
    if m:
        return {"user": m.group(2), "source_ip": m.group(3), "event": "login",
                "result": "success" if m.group(1) == "Accepted" else "fail"}
    m = _RE_SUDO.search(line)
    if m:
        return {"user": m.group(1), "source_ip": "", "event": "sudo",
                "result": "success", "detail": m.group(2)}
    m = _RE_SESSION.search(line)
    if m:
        return {"user": m.group(2), "source_ip": "", "event": f"session_{m.group(1)}",
                "result": "info"}
    return None


def parse_access_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Loki query_range(streams) 응답 → 접속기록 행 목록(최신순). 순수 함수(테스트용)."""
    result = ((payload or {}).get("data", {}) or {}).get("result", []) or []
    out: list[dict[str, Any]] = []
    for stream in result:
        labels = stream.get("stream", {}) or {}
        host = labels.get("host") or labels.get("hostname") or labels.get("filename") or ""
        for pair in stream.get("values", []) or []:
            if not pair or len(pair) < 2:
                continue
            parsed = _parse_access_line(str(pair[1]))
            if not parsed:
                continue
            try:
                ns = int(pair[0])
                parsed["time"] = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                ns, parsed["time"] = 0, ""
            parsed["_ns"] = ns
            parsed["host"] = parsed.get("host") or host
            out.append(parsed)
    out.sort(key=lambda e: e.get("_ns", 0), reverse=True)
    for e in out:
        e.pop("_ns", None)
    return out


def access_log_recent(limit: int = 30, now: datetime | None = None, *,
                      base_url: str | None = None, selector: str | None = None,
                      lookback_days: int = 30, timeout: int = 8) -> dict[str, Any]:
    """최근 접속기록 미리보기(전체 아님 — 전체는 Loki/Grafana). 미설정/오류 시 available=False."""
    base = base_url if base_url is not None else loki_base_url()
    if not base:
        return {"available": False, "entries": []}
    sel = selector if selector is not None else access_selector()
    now = now or datetime.now(tz=timezone.utc)
    end_ns = int(now.timestamp() * 1e9)
    start_ns = end_ns - int(lookback_days * 86400 * 1e9)
    qr = f"{base}/loki/api/v1/query_range"
    try:
        payload = _http_get_json(qr, {"query": sel, "start": str(start_ns), "end": str(end_ns),
                                      "direction": "backward",
                                      "limit": str(max(1, min(limit * 5, 500)))}, timeout)
        return {"available": True, "entries": parse_access_entries(payload)[:limit]}
    except (error.URLError, error.HTTPError, ValueError, KeyError, OSError, TimeoutError):
        return {"available": False, "entries": []}
