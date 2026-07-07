from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class StateRepository(ABC):
    """Persistence contract for the Phase 2 UI operational-state stores (M2-1).

    These back the 6 in-memory containers the API mutates at runtime
    (user_profiles / asset_owners / asset_audit_log / vuln_actions /
    triage_store / incidents). Route handlers keep the in-memory dict as a
    read cache and write through here on each mutation; ``load_*`` is called
    once at boot to warm the cache.
    """

    # ── user_profiles: username -> record ──────────────────────────────────────
    @abstractmethod
    def load_user_profiles(self) -> dict[str, dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def save_user_profile(self, username: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    # ── asset_owners: hostname -> record ───────────────────────────────────────
    @abstractmethod
    def load_asset_owners(self) -> dict[str, dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def save_asset_owner(self, hostname: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete_asset_owner(self, hostname: str) -> None:
        raise NotImplementedError

    # ── asset_audit_log: append-only list ──────────────────────────────────────
    @abstractmethod
    def load_asset_audit_log(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def append_asset_audit(self, record: dict[str, Any]) -> None:
        raise NotImplementedError

    # ── vuln_actions: vuln_id -> record ────────────────────────────────────────
    @abstractmethod
    def load_vuln_actions(self) -> dict[str, dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def save_vuln_action(self, vuln_id: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    # ── triage_store: alert_id -> record ───────────────────────────────────────
    @abstractmethod
    def load_triage(self) -> dict[str, dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def save_triage(self, alert_id: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    # ── incidents: incident_id -> record ───────────────────────────────────────
    @abstractmethod
    def load_incidents(self) -> dict[str, dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def save_incident(self, incident_id: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    # ── risk_register: vuln_id -> record (R-2) ─────────────────────────────────
    @abstractmethod
    def load_risk_register(self) -> dict[str, dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def save_risk_assessment(self, vuln_id: str, record: dict[str, Any]) -> None:
        raise NotImplementedError

    # ── evidence_events: append-only CSOP diff envelopes (keyed by id) ─────────
    @abstractmethod
    def load_evidence_events(self, limit: int = 500) -> list[dict[str, Any]]:
        """Most-recent-first evidence events, capped at ``limit``."""
        raise NotImplementedError

    @abstractmethod
    def save_evidence_event(self, event_id: str, record: dict[str, Any]) -> None:
        """Upsert one evidence event (idempotent on ``event_id``)."""
        raise NotImplementedError


__all__ = ["StateRepository"]
