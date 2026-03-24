"""Repository contracts and implementations for Phase 1 entities."""

from .base import BaseRepository, RepositorySnapshot
from .memory import InMemoryRepository

__all__ = [
    "BaseRepository",
    "RepositorySnapshot",
    "InMemoryRepository",
    "PostgresRepository",
    "PSYCOPG_AVAILABLE",
    "snapshot_to_query_store",
]


_POSTGRES_EXPORTS = {"PostgresRepository", "PSYCOPG_AVAILABLE", "snapshot_to_query_store"}


def __getattr__(name: str):
    if name in _POSTGRES_EXPORTS:
        from . import postgres

        return getattr(postgres, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")