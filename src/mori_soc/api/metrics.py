"""경량 관측성 메트릭(#40) — 외부 의존성 없이 Prometheus 텍스트 노출.

인메모리 카운터(단일 인스턴스 전제). 라벨은 method + status 만 써서 카디널리티 폭증을
막는다(전체 경로를 라벨로 쓰지 않음). `/metrics` 로 Prometheus exposition format 을 낸다.
"""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock


class Metrics:
    def __init__(self) -> None:
        self._lock = Lock()
        self._requests: dict[tuple[str, str], int] = defaultdict(int)   # (method, status) -> count
        self._dur_sum: dict[tuple[str, str], float] = defaultdict(float)
        self._errors = 0          # 5xx 합계
        self._ingest = 0          # /ingest/* 요청 합계

    def observe(self, method: str, status: int, duration: float, path: str) -> None:
        key = (method.upper(), str(status))
        with self._lock:
            self._requests[key] += 1
            self._dur_sum[key] += duration
            if status >= 500:
                self._errors += 1
            if path.startswith("/ingest/"):
                self._ingest += 1

    def render(self) -> str:
        lines = [
            "# HELP mori_http_requests_total Total HTTP requests by method and status.",
            "# TYPE mori_http_requests_total counter",
        ]
        with self._lock:
            for (method, status), n in sorted(self._requests.items()):
                lines.append(f'mori_http_requests_total{{method="{method}",status="{status}"}} {n}')
            lines += [
                "# HELP mori_http_request_duration_seconds_sum Sum of request durations by method and status.",
                "# TYPE mori_http_request_duration_seconds_sum counter",
            ]
            for (method, status), s in sorted(self._dur_sum.items()):
                lines.append(
                    f'mori_http_request_duration_seconds_sum{{method="{method}",status="{status}"}} {s:.6f}')
            lines += [
                "# HELP mori_errors_total Total 5xx responses.",
                "# TYPE mori_errors_total counter",
                f"mori_errors_total {self._errors}",
                "# HELP mori_ingest_requests_total Total /ingest/* requests.",
                "# TYPE mori_ingest_requests_total counter",
                f"mori_ingest_requests_total {self._ingest}",
            ]
        return "\n".join(lines) + "\n"


def build_metrics_middleware(metrics: Metrics):
    """각 요청의 method·status·소요시간을 metrics 에 기록하는 미들웨어."""
    from starlette.middleware.base import BaseHTTPMiddleware

    class _MetricsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            start = time.perf_counter()
            status = 500
            try:
                response = await call_next(request)
                status = response.status_code
                return response
            finally:
                metrics.observe(request.method, status, time.perf_counter() - start, request.url.path)

    return _MetricsMiddleware
