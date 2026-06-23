from __future__ import annotations

import copy
from typing import Any

from .state_base import StateRepository


class InMemoryStateRepository(StateRepository):
    """Functional in-memory backend — the default when no database is configured.

    Stores deep copies so the persisted view reflects only explicit saves,
    which keeps it usable as a test spy. For the running app the in-memory
    dicts in ``create_app`` remain the read path; this backend is the
    write-through target and is warmed back into those dicts at boot (a fresh
    instance loads empty, identical to the pre-persistence behaviour).
    """

    def __init__(self) -> None:
        self._user_profiles: dict[str, dict[str, Any]] = {}
        self._asset_owners: dict[str, dict[str, Any]] = {}
        self._asset_audit_log: list[dict[str, Any]] = []
        self._vuln_actions: dict[str, dict[str, Any]] = {}
        self._triage: dict[str, dict[str, Any]] = {}
        self._incidents: dict[str, dict[str, Any]] = {}

    # ── user_profiles ──────────────────────────────────────────────────────────
    def load_user_profiles(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._user_profiles)

    def save_user_profile(self, username: str, record: dict[str, Any]) -> None:
        self._user_profiles[username] = copy.deepcopy(record)

    # ── asset_owners ───────────────────────────────────────────────────────────
    def load_asset_owners(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._asset_owners)

    def save_asset_owner(self, hostname: str, record: dict[str, Any]) -> None:
        self._asset_owners[hostname] = copy.deepcopy(record)

    def delete_asset_owner(self, hostname: str) -> None:
        self._asset_owners.pop(hostname, None)

    # ── asset_audit_log ────────────────────────────────────────────────────────
    def load_asset_audit_log(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._asset_audit_log)

    def append_asset_audit(self, record: dict[str, Any]) -> None:
        self._asset_audit_log.append(copy.deepcopy(record))

    # ── vuln_actions ───────────────────────────────────────────────────────────
    def load_vuln_actions(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._vuln_actions)

    def save_vuln_action(self, vuln_id: str, record: dict[str, Any]) -> None:
        self._vuln_actions[vuln_id] = copy.deepcopy(record)

    # ── triage_store ───────────────────────────────────────────────────────────
    def load_triage(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._triage)

    def save_triage(self, alert_id: str, record: dict[str, Any]) -> None:
        self._triage[alert_id] = copy.deepcopy(record)

    # ── incidents ──────────────────────────────────────────────────────────────
    def load_incidents(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._incidents)

    def save_incident(self, incident_id: str, record: dict[str, Any]) -> None:
        self._incidents[incident_id] = copy.deepcopy(record)


__all__ = ["InMemoryStateRepository"]
