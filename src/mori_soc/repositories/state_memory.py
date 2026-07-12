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
        self._risk_register: dict[str, dict[str, Any]] = {}
        self._evidence_events: dict[str, dict[str, Any]] = {}
        self._settings: dict[str, str] = {}
        self._control_status: dict[str, dict[str, Any]] = {}
        self._host_accounts: dict[str, list[dict[str, Any]]] = {}
        self._account_approvals: dict[str, dict[str, Any]] = {}
        self._catalog_edits: dict[str, dict[str, Any]] = {}
        self._control_evidence: dict[str, dict[str, Any]] = {}
        self._personal_data_flow: dict[str, dict[str, Any]] = {}

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

    # ── risk_register ──────────────────────────────────────────────────────────
    def load_risk_register(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._risk_register)

    def save_risk_assessment(self, vuln_id: str, record: dict[str, Any]) -> None:
        self._risk_register[vuln_id] = copy.deepcopy(record)

    # ── evidence_events ────────────────────────────────────────────────────────
    def load_evidence_events(self, limit: int = 500) -> list[dict[str, Any]]:
        events = sorted(
            self._evidence_events.values(),
            key=lambda r: r.get("received_at") or "",
            reverse=True,
        )
        return copy.deepcopy(events[: max(0, limit)])

    def save_evidence_event(self, event_id: str, record: dict[str, Any]) -> None:
        self._evidence_events[event_id] = copy.deepcopy(record)

    # ── settings ────────────────────────────────────────────────────────────────
    def load_settings(self) -> dict[str, str]:
        return dict(self._settings)

    def save_setting(self, key: str, value: str, updated_by: str = "") -> None:
        self._settings[key] = value

    # ── control_status ──────────────────────────────────────────────────────────
    def load_control_status(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._control_status)

    def save_control_status(self, control_id: str, record: dict[str, Any]) -> None:
        self._control_status[control_id] = copy.deepcopy(record)

    # ── host_accounts ────────────────────────────────────────────────────────────
    def load_host_accounts(self) -> dict[str, list[dict[str, Any]]]:
        return copy.deepcopy(self._host_accounts)

    def save_host_accounts(self, host_key: str, accounts: list[dict[str, Any]]) -> None:
        self._host_accounts[host_key] = copy.deepcopy(accounts)

    # ── account_approvals ────────────────────────────────────────────────────────
    def load_account_approvals(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._account_approvals)

    def save_account_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        self._account_approvals[approval_id] = copy.deepcopy(record)

    def delete_account_approval(self, approval_id: str) -> None:
        self._account_approvals.pop(approval_id, None)

    # ── catalog_controls (편집/NLP 오버레이) ──────────────────────────────────────
    def load_catalog_edits(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._catalog_edits)

    def save_catalog_edit(self, control_id: str, record: dict[str, Any]) -> None:
        self._catalog_edits[control_id] = copy.deepcopy(record)

    def delete_catalog_edit(self, control_id: str) -> None:
        self._catalog_edits.pop(control_id, None)

    # ── control_evidence (수기 증적 레코드) ───────────────────────────────────────
    def load_control_evidence(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._control_evidence)

    def save_control_evidence(self, evidence_id: str, record: dict[str, Any]) -> None:
        self._control_evidence[evidence_id] = copy.deepcopy(record)

    def delete_control_evidence(self, evidence_id: str) -> None:
        self._control_evidence.pop(evidence_id, None)

    # ── personal_data_flow (개인정보 처리흐름표) ─────────────────────────────────
    def load_personal_data_flow(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._personal_data_flow)

    def save_personal_data_flow(self, flow_id: str, record: dict[str, Any]) -> None:
        self._personal_data_flow[flow_id] = copy.deepcopy(record)

    def delete_personal_data_flow(self, flow_id: str) -> None:
        self._personal_data_flow.pop(flow_id, None)


__all__ = ["InMemoryStateRepository"]
