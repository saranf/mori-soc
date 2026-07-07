from __future__ import annotations

from typing import Any

from .state_base import StateRepository

try:
    import psycopg
    from psycopg.types.json import Jsonb

    PSYCOPG_AVAILABLE = True
except ImportError:  # pragma: no cover - import guard only
    psycopg = None
    Jsonb = None
    PSYCOPG_AVAILABLE = False


def _jsonb(payload):
    return Jsonb(payload or []) if Jsonb is not None else (payload or [])


class PostgresStateRepository(StateRepository):
    """PostgreSQL-backed persistence for the Phase 2 UI operational-state stores.

    Tables live in ``schema/003_phase2_ui_operational_state.sql`` (the ``ui_*``
    tables). ISO timestamp fields are stored verbatim as text so loaded state
    round-trips byte-identically with the in-memory representation.
    """

    def __init__(self, dsn: str) -> None:
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg is not installed. Install psycopg to use PostgresStateRepository.")
        self.dsn = dsn

    def _connect(self):
        return psycopg.connect(self.dsn)

    # ── user_profiles ──────────────────────────────────────────────────────────
    def load_user_profiles(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT username, display_name, department, assigned_servers, updated_at FROM ui_user_profiles")
            return {
                r[0]: {"display_name": r[1], "department": r[2],
                       "assigned_servers": list(r[3] or []), "updated_at": r[4]}
                for r in cur.fetchall()
            }

    def save_user_profile(self, username: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_user_profiles (username, display_name, department, assigned_servers, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (username) DO UPDATE SET
                    display_name = EXCLUDED.display_name, department = EXCLUDED.department,
                    assigned_servers = EXCLUDED.assigned_servers, updated_at = EXCLUDED.updated_at
                """,
                (username, record.get("display_name", ""), record.get("department", ""),
                 _jsonb(record.get("assigned_servers", [])), record.get("updated_at")),
            )

    # ── asset_owners ───────────────────────────────────────────────────────────
    def load_asset_owners(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT hostname, owner, category, importance, exception_until, "
                "exception_reason, email, team, updated_at FROM ui_asset_owners"
            )
            return {
                r[0]: {"hostname": r[0], "owner": r[1], "category": r[2], "importance": r[3],
                       "exception_until": r[4], "exception_reason": r[5], "email": r[6],
                       "team": r[7], "updated_at": r[8]}
                for r in cur.fetchall()
            }

    def save_asset_owner(self, hostname: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_asset_owners (hostname, owner, category, importance, exception_until,
                                             exception_reason, email, team, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (hostname) DO UPDATE SET
                    owner = EXCLUDED.owner, category = EXCLUDED.category, importance = EXCLUDED.importance,
                    exception_until = EXCLUDED.exception_until, exception_reason = EXCLUDED.exception_reason,
                    email = EXCLUDED.email, team = EXCLUDED.team, updated_at = EXCLUDED.updated_at
                """,
                (hostname, record.get("owner", ""), record.get("category", ""), record.get("importance", ""),
                 record.get("exception_until", ""), record.get("exception_reason", ""), record.get("email", ""),
                 record.get("team", ""), record.get("updated_at")),
            )

    def delete_asset_owner(self, hostname: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM ui_asset_owners WHERE hostname = %s", (hostname,))

    # ── asset_audit_log ────────────────────────────────────────────────────────
    def load_asset_audit_log(self) -> list[dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT log_id, hostname, field, old_value, new_value, changed_by, changed_at "
                "FROM ui_asset_audit_log ORDER BY changed_at, log_id"
            )
            return [
                {"log_id": r[0], "hostname": r[1], "field": r[2], "old_value": r[3],
                 "new_value": r[4], "changed_by": r[5], "changed_at": r[6]}
                for r in cur.fetchall()
            ]

    def append_asset_audit(self, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_asset_audit_log (log_id, hostname, field, old_value, new_value, changed_by, changed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (log_id) DO NOTHING
                """,
                (record.get("log_id"), record.get("hostname", ""), record.get("field", ""),
                 record.get("old_value", ""), record.get("new_value", ""),
                 record.get("changed_by", ""), record.get("changed_at")),
            )

    # ── vuln_actions ───────────────────────────────────────────────────────────
    def load_vuln_actions(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT vuln_id, plan_text, plan_target_date, plan_updated_by, exception_until, "
                "exception_reason, exception_updated_by, updated_at FROM ui_vuln_actions"
            )
            return {
                r[0]: {"vuln_id": r[0], "plan_text": r[1], "plan_target_date": r[2],
                       "plan_updated_by": r[3], "exception_until": r[4], "exception_reason": r[5],
                       "exception_updated_by": r[6], "updated_at": r[7]}
                for r in cur.fetchall()
            }

    def save_vuln_action(self, vuln_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_vuln_actions (vuln_id, plan_text, plan_target_date, plan_updated_by,
                                             exception_until, exception_reason, exception_updated_by, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (vuln_id) DO UPDATE SET
                    plan_text = EXCLUDED.plan_text, plan_target_date = EXCLUDED.plan_target_date,
                    plan_updated_by = EXCLUDED.plan_updated_by, exception_until = EXCLUDED.exception_until,
                    exception_reason = EXCLUDED.exception_reason, exception_updated_by = EXCLUDED.exception_updated_by,
                    updated_at = EXCLUDED.updated_at
                """,
                (vuln_id, record.get("plan_text", ""), record.get("plan_target_date", ""),
                 record.get("plan_updated_by", ""), record.get("exception_until", ""),
                 record.get("exception_reason", ""), record.get("exception_updated_by", ""),
                 record.get("updated_at")),
            )

    # ── triage_store ───────────────────────────────────────────────────────────
    def load_triage(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT alert_id, status, analyst, note, changed_by, updated_at, history FROM ui_triage_state")
            return {
                r[0]: {"status": r[1], "analyst": r[2], "note": r[3], "changed_by": r[4],
                       "updated_at": r[5], "history": list(r[6] or [])}
                for r in cur.fetchall()
            }

    def save_triage(self, alert_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_triage_state (alert_id, status, analyst, note, changed_by, updated_at, history)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (alert_id) DO UPDATE SET
                    status = EXCLUDED.status, analyst = EXCLUDED.analyst, note = EXCLUDED.note,
                    changed_by = EXCLUDED.changed_by, updated_at = EXCLUDED.updated_at, history = EXCLUDED.history
                """,
                (alert_id, record.get("status", "pending"), record.get("analyst", ""),
                 record.get("note", ""), record.get("changed_by", ""), record.get("updated_at"),
                 _jsonb(record.get("history", []))),
            )

    # ── incidents ──────────────────────────────────────────────────────────────
    def load_incidents(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT incident_id, title, status, status_updated_at, hostname, analyst, handler, "
                "alert_ids, notes, history, created_at, updated_at FROM ui_incidents"
            )
            return {
                r[0]: {"incident_id": r[0], "title": r[1], "status": r[2], "status_updated_at": r[3],
                       "hostname": r[4], "analyst": r[5], "handler": r[6], "alert_ids": list(r[7] or []),
                       "notes": list(r[8] or []), "history": list(r[9] or []),
                       "created_at": r[10], "updated_at": r[11]}
                for r in cur.fetchall()
            }

    def save_incident(self, incident_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_incidents (incident_id, title, status, status_updated_at, hostname, analyst,
                                          handler, alert_ids, notes, history, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (incident_id) DO UPDATE SET
                    title = EXCLUDED.title, status = EXCLUDED.status, status_updated_at = EXCLUDED.status_updated_at,
                    hostname = EXCLUDED.hostname, analyst = EXCLUDED.analyst, handler = EXCLUDED.handler,
                    alert_ids = EXCLUDED.alert_ids, notes = EXCLUDED.notes, history = EXCLUDED.history,
                    created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
                """,
                (incident_id, record.get("title", ""), record.get("status", "open"),
                 record.get("status_updated_at"), record.get("hostname", ""), record.get("analyst", ""),
                 record.get("handler", ""), _jsonb(record.get("alert_ids", [])),
                 _jsonb(record.get("notes", [])), _jsonb(record.get("history", [])),
                 record.get("created_at"), record.get("updated_at")),
            )

    # ── risk_register (R-2) ────────────────────────────────────────────────────
    def load_risk_register(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT vuln_id, impact, likelihood, score, level, treatment, accept_reason, "
                "accept_approver, residual_level, review_due, assessed_by, assessed_at, updated_at "
                "FROM ui_risk_register"
            )
            return {
                r[0]: {"vuln_id": r[0], "impact": r[1], "likelihood": r[2], "score": r[3],
                       "level": r[4], "treatment": r[5], "accept_reason": r[6],
                       "accept_approver": r[7], "residual_level": r[8], "review_due": r[9],
                       "assessed_by": r[10], "assessed_at": r[11], "updated_at": r[12]}
                for r in cur.fetchall()
            }

    def save_risk_assessment(self, vuln_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_risk_register (vuln_id, impact, likelihood, score, level, treatment,
                                              accept_reason, accept_approver, residual_level, review_due,
                                              assessed_by, assessed_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (vuln_id) DO UPDATE SET
                    impact = EXCLUDED.impact, likelihood = EXCLUDED.likelihood, score = EXCLUDED.score,
                    level = EXCLUDED.level, treatment = EXCLUDED.treatment,
                    accept_reason = EXCLUDED.accept_reason, accept_approver = EXCLUDED.accept_approver,
                    residual_level = EXCLUDED.residual_level, review_due = EXCLUDED.review_due,
                    assessed_by = EXCLUDED.assessed_by, assessed_at = EXCLUDED.assessed_at,
                    updated_at = EXCLUDED.updated_at
                """,
                (vuln_id, int(record.get("impact", 0) or 0), int(record.get("likelihood", 0) or 0),
                 int(record.get("score", 0) or 0), record.get("level", ""), record.get("treatment", ""),
                 record.get("accept_reason", ""), record.get("accept_approver", ""),
                 record.get("residual_level", ""), record.get("review_due", ""),
                 record.get("assessed_by", ""), record.get("assessed_at"), record.get("updated_at")),
            )

    # ── evidence_events (CSOP diff envelopes) ──────────────────────────────────
    def load_evidence_events(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, host_id, artifact_name, delta_type, cve, summary, source, envelope, received_at "
                "FROM ui_evidence_events ORDER BY received_at DESC NULLS LAST LIMIT %s",
                (max(0, int(limit)),),
            )
            return [
                {"id": r[0], "host_id": r[1], "artifact_name": r[2], "delta_type": r[3],
                 "cve": r[4], "summary": r[5], "source": r[6], "envelope": r[7] or {},
                 "received_at": r[8]}
                for r in cur.fetchall()
            ]

    def save_evidence_event(self, event_id: str, record: dict[str, Any]) -> None:
        envelope = record.get("envelope") or {}
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_evidence_events (id, host_id, artifact_name, delta_type, cve,
                                                summary, source, envelope, received_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    host_id = EXCLUDED.host_id, artifact_name = EXCLUDED.artifact_name,
                    delta_type = EXCLUDED.delta_type, cve = EXCLUDED.cve, summary = EXCLUDED.summary,
                    source = EXCLUDED.source, envelope = EXCLUDED.envelope,
                    received_at = EXCLUDED.received_at
                """,
                (event_id, record.get("host_id", ""), record.get("artifact_name", ""),
                 record.get("delta_type", ""), record.get("cve", ""), record.get("summary", ""),
                 record.get("source", "csop"),
                 Jsonb(envelope) if Jsonb is not None else envelope, record.get("received_at")),
            )


__all__ = ["PostgresStateRepository", "PSYCOPG_AVAILABLE"]
