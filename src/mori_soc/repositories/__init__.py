"""Repository contracts and in-memory implementations for Phase 1 entities."""

from .base import BaseRepository, RepositorySnapshot
from .memory import InMemoryRepository

__all__ = ["BaseRepository", "RepositorySnapshot", "InMemoryRepository"]