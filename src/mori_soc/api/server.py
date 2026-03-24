from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.services import PHASE1_QUERY_CATALOG, InMemoryQueryStore, QueryService

try:
    from fastapi import FastAPI, HTTPException
except ImportError:  # pragma: no cover - exercised by runtime guard tests
    FastAPI = None
    HTTPException = None


def create_query_service(store: InMemoryQueryStore | None = None) -> QueryService:
    return QueryService(store or InMemoryQueryStore())


def create_query_service_from_env() -> QueryService:
    backend = os.getenv("MORI_QUERY_BACKEND", "memory").strip().lower()
    if backend == "memory":
        return create_query_service()
    if backend == "postgres":
        database_url = os.getenv("MORI_DATABASE_URL")
        if not database_url:
            raise RuntimeError("MORI_DATABASE_URL must be set when MORI_QUERY_BACKEND=postgres")
        from mori_soc.repositories import PostgresRepository, snapshot_to_query_store

        repository = PostgresRepository(database_url)
        return QueryService(snapshot_to_query_store(repository.snapshot()))
    raise RuntimeError(f"Unsupported MORI_QUERY_BACKEND: {backend}")


def build_query_request(payload: Mapping[str, Any]) -> QueryRequest:
    intent = payload.get("intent")
    if not isinstance(intent, str) or not intent.strip():
        raise ValueError("query payload must include a non-empty string intent")

    scope_payload = payload.get("scope") or {}
    if not isinstance(scope_payload, Mapping):
        raise ValueError("query payload scope must be an object")

    filters_payload = payload.get("filters") or {}
    if not isinstance(filters_payload, Mapping):
        raise ValueError("query payload filters must be an object")

    scope = QueryScope(
        time_range=_optional_string(scope_payload.get("time_range")) or "24h",
        host_id=_optional_string(scope_payload.get("host_id")),
        hostname=_optional_string(scope_payload.get("hostname")),
        severity=_optional_string(scope_payload.get("severity")),
        source=_optional_string(scope_payload.get("source")),
    )
    return QueryRequest(intent=intent.strip(), scope=scope, filters=dict(filters_payload))


def create_app(service: QueryService | None = None, service_factory=None) -> Any:
    if FastAPI is None or HTTPException is None:
        raise RuntimeError(
            "FastAPI is not installed. Install fastapi and uvicorn to run MVC 1 HTTP server."
        )

    app = FastAPI(title="MORI SOC Query API", version="0.1.0")

    def get_query_service() -> QueryService:
        if service is not None:
            return service
        if service_factory is not None:
            return service_factory()
        return create_query_service()

    @app.get("/health")
    def health() -> dict[str, Any]:
        try:
            query_service = get_query_service()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"query service unavailable: {exc}") from exc
        return {
            "status": "ok",
            "engine": type(query_service.store).__name__,
            "query_count": len(PHASE1_QUERY_CATALOG),
        }

    @app.get("/catalog")
    def catalog() -> dict[str, Any]:
        return {
            "queries": [
                {
                    "query_id": query.query_id,
                    "intent": query.intent,
                    "name": query.name,
                    "default_window": query.default_window,
                    "required_filters": list(query.required_filters),
                    "evidence_sources": list(query.evidence_sources),
                }
                for query in PHASE1_QUERY_CATALOG
            ]
        }

    @app.post("/query")
    def query(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            request = build_query_request(payload)
            response = get_query_service().execute(request)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"query execution failed: {exc}") from exc
        return response.to_dict()

    return app


def create_app_from_env() -> Any:
    return create_app(service_factory=create_query_service_from_env)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("query scope values must be strings")
    value = value.strip()
    return value or None


__all__ = [
    "build_query_request",
    "create_app",
    "create_app_from_env",
    "create_query_service",
    "create_query_service_from_env",
]