"""Repository contracts and implementations.

Phase 1 normalized entities (``BaseRepository``) and the Phase 2 UI
operational-state stores (``StateRepository``; see ``state_*.py``).
"""

from .base import BaseRepository, RepositorySnapshot
from .memory import InMemoryRepository
from .state_base import StateRepository
from .state_memory import InMemoryStateRepository

__all__ = [
    "BaseRepository",
    "RepositorySnapshot",
    "InMemoryRepository",
    "PostgresRepository",
    "PSYCOPG_AVAILABLE",
    "snapshot_to_query_store",
    "StateRepository",
    "InMemoryStateRepository",
    "PostgresStateRepository",
]


_POSTGRES_EXPORTS = {"PostgresRepository", "PSYCOPG_AVAILABLE", "snapshot_to_query_store"}


def __getattr__(name: str):
    if name in _POSTGRES_EXPORTS:
        from . import postgres

        return getattr(postgres, name)
    if name == "PostgresStateRepository":
        from . import state_postgres

        return state_postgres.PostgresStateRepository
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")