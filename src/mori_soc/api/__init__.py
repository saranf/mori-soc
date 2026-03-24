"""API helpers and contracts for MORI query endpoints."""

from .contracts import EvidenceRef, QueryRequest, QueryResponse, QueryScope

__all__ = [
    "EvidenceRef",
    "QueryRequest",
    "QueryResponse",
    "QueryScope",
    "DEFAULT_UI_PAYLOAD",
    "build_dashboard_payload",
    "build_query_request",
    "create_app",
    "create_app_from_env",
    "create_query_service",
    "create_query_service_from_env",
    "interpret_query_text",
    "render_query_console_html",
]


_SERVER_EXPORTS = {
    "DEFAULT_UI_PAYLOAD",
    "build_dashboard_payload",
    "build_query_request",
    "create_app",
    "create_app_from_env",
    "create_query_service",
    "create_query_service_from_env",
    "interpret_query_text",
    "render_query_console_html",
}


def __getattr__(name: str):
    if name in _SERVER_EXPORTS:
        from . import server

        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")