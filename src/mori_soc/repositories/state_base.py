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

    def apply_schema(self) -> None:
        """Idempotently ensure the DB schema exists before the boot warm-cache.

        No-op by default (in-memory backends have no schema). SQL-backed repos
        override this to run ``schema/*.sql`` (all ``CREATE TABLE IF NOT EXISTS``)
        at every boot, so a DB whose volume predates a newly-added table still
        gets it — ``docker-entrypoint-initdb.d`` only runs on a *fresh* volume.
        """
        return None

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

    # ── action audit log: append-only, hash-chained (#20). 기본 no-op(인메모리 repo) ──
    def append_audit_event(self, entry: dict[str, Any]) -> None:
        """감사 항목 1건 append(무결성상 update/delete 없음). 기본 no-op."""
        return None

    def load_audit_events(self, limit: int = 2000) -> list[dict[str, Any]]:
        """최근 감사 항목을 seq 오름차순으로(체인 검증용). 기본 빈 목록."""
        return []

    def latest_audit_event(self) -> dict[str, Any] | None:
        """가장 최신 감사 항목(재시작 후 체인 head 시딩용). 기본 None."""
        return None

    # ── evidence_approvals: 증적 승인 스냅샷(불변, #4). 기본 no-op ──────────────
    def save_evidence_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        return None

    def load_evidence_approvals(self, control_id: str | None = None) -> list[dict[str, Any]]:
        return []

    # ── gaps: 기술 Gap 워크플로(#5). 기본 no-op ────────────────────────────────
    def save_gap(self, gap_id: str, record: dict[str, Any]) -> None:
        return None

    def load_gaps(self, status: str | None = None) -> list[dict[str, Any]]:
        return []

    # ── control_governance: 통제 운영 플랫폼 객체(통제 신규 에픽). 기본 no-op ──────────
    def load_governance(self, kind: str) -> list[dict[str, Any]]:
        """kind(framework|framework_version|…) 의 모든 레코드. 기본 빈 목록."""
        return []

    def save_governance(self, kind: str, entity_id: str, record: dict[str, Any]) -> None:
        """(kind, entity_id) upsert. 버전 불변은 서비스층에서 새 entity_id 로 보장."""
        return None

    def delete_governance(self, kind: str, entity_id: str) -> None:
        return None

    # ── control_governance_events: append-only hash chain(S3). 기본 no-op ──────────
    def append_governance_event(self, entry: dict[str, Any]) -> None:
        """거버넌스 변경 이벤트 1건 append(UPDATE/DELETE 없음). 기본 no-op."""
        return None

    def load_governance_events(self, kind: str | None = None, entity_id: str | None = None,
                               limit: int = 2000) -> list[dict[str, Any]]:
        """이벤트를 seq 오름차순으로(체인 검증·revision 계산용). 기본 빈 목록."""
        return []

    def latest_governance_event(self) -> dict[str, Any] | None:
        """가장 최신 이벤트(재시작 후 체인 head 시딩용). 기본 None."""
        return None

    @abstractmethod
    def delete_evidence_event(self, event_id: str) -> None:
        """Remove one evidence event."""
        raise NotImplementedError

    # ── settings: org-wide key -> value string (e.g. risk_doa) ─────────────────
    @abstractmethod
    def load_settings(self) -> dict[str, str]:
        """All persisted org settings as a flat ``{key: value}`` map."""
        raise NotImplementedError

    @abstractmethod
    def save_setting(self, key: str, value: str, updated_by: str = "") -> None:
        """Upsert one org setting (idempotent on ``key``)."""
        raise NotImplementedError

    # ── control_status: control_id -> runtime 이행 상태 (M2-7) ──────────────────
    @abstractmethod
    def load_control_status(self) -> dict[str, dict[str, Any]]:
        """All persisted control-status records keyed by control_id."""
        raise NotImplementedError

    @abstractmethod
    def save_control_status(self, control_id: str, record: dict[str, Any]) -> None:
        """Upsert one control-status record (idempotent on ``control_id``)."""
        raise NotImplementedError

    # ── host_accounts: host_key -> list of local accounts (osquery push) ───────
    @abstractmethod
    def load_host_accounts(self) -> dict[str, list[dict[str, Any]]]:
        """All host account inventories keyed by host_key."""
        raise NotImplementedError

    @abstractmethod
    def save_host_accounts(self, host_key: str, accounts: list[dict[str, Any]]) -> None:
        """Replace a host's full account set (idempotent per host_key)."""
        raise NotImplementedError

    # ── account_approvals: id -> approval record (allow-list) ──────────────────
    @abstractmethod
    def load_account_approvals(self) -> dict[str, dict[str, Any]]:
        """All account-approval records keyed by id."""
        raise NotImplementedError

    @abstractmethod
    def save_account_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        """Upsert one approval record (idempotent on ``id``)."""
        raise NotImplementedError

    @abstractmethod
    def delete_account_approval(self, approval_id: str) -> None:
        """Remove one approval record."""
        raise NotImplementedError

    # ── catalog_controls: control_id -> admin 편집/NLP 오버레이 (M2-8) ───────────
    @abstractmethod
    def load_catalog_edits(self) -> dict[str, dict[str, Any]]:
        """All catalog-overlay records keyed by control_id."""
        raise NotImplementedError

    @abstractmethod
    def save_catalog_edit(self, control_id: str, record: dict[str, Any]) -> None:
        """Upsert one catalog-overlay record (idempotent on ``control_id``)."""
        raise NotImplementedError

    @abstractmethod
    def delete_catalog_edit(self, control_id: str) -> None:
        """Remove one catalog-overlay record."""
        raise NotImplementedError

    # ── control_evidence: id -> 수기 증적 레코드 (M2-8) ─────────────────────────
    @abstractmethod
    def load_control_evidence(self) -> dict[str, dict[str, Any]]:
        """All manual evidence records keyed by id."""
        raise NotImplementedError

    @abstractmethod
    def save_control_evidence(self, evidence_id: str, record: dict[str, Any]) -> None:
        """Upsert one manual evidence record (idempotent on ``id``)."""
        raise NotImplementedError

    @abstractmethod
    def delete_control_evidence(self, evidence_id: str) -> None:
        """Remove one manual evidence record."""
        raise NotImplementedError

    # ── personal_data_flow: id -> 개인정보 처리흐름 레코드 (013) ──────────────────
    @abstractmethod
    def load_personal_data_flow(self) -> dict[str, dict[str, Any]]:
        """All personal-data-flow rows keyed by id."""
        raise NotImplementedError

    @abstractmethod
    def save_personal_data_flow(self, flow_id: str, record: dict[str, Any]) -> None:
        """Upsert one personal-data-flow row (idempotent on ``id``)."""
        raise NotImplementedError

    @abstractmethod
    def delete_personal_data_flow(self, flow_id: str) -> None:
        """Remove one personal-data-flow row."""
        raise NotImplementedError

    # ── ui_sessions: 로그인 세션 영속(M10 Phase A) ────────────────────────────
    # 비추상 기본 구현 = 프로세스 인메모리(백엔드가 세션을 영속하지 않을 때 무해).
    # Postgres 백엔드만 오버라이드해 실제 DB 영속을 제공한다(옵트인).
    def load_sessions(self) -> "dict[str, dict[str, Any]]":
        """저장된(미만료) 세션 전체 {token: record}. 기본은 인메모리."""
        return dict(getattr(self, "_mem_sessions", {}))

    def save_session(self, token: str, record: "dict[str, Any]") -> None:
        """세션 upsert(idempotent on token). 기본은 인메모리."""
        self.__dict__.setdefault("_mem_sessions", {})[token] = dict(record)

    def delete_session(self, token: str) -> None:
        """세션 1건 삭제(로그아웃/만료). 기본은 인메모리."""
        getattr(self, "_mem_sessions", {}).pop(token, None)

    def delete_expired_sessions(self, now_iso: str) -> int:
        """만료 세션 정리(삭제 건수 반환). 기본은 no-op(0)."""
        return 0


__all__ = ["StateRepository"]
