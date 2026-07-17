from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

from .state_base import StateRepository

_log = logging.getLogger("mori_soc.state")

# migration 메타(#6): 어떤 스키마 파일이 언제·성공여부·checksum 으로 적용됐는지 기록.
# SQL 파일 내용이 바뀌면 checksum 이 달라져 드리프트를 감지할 수 있다.
_MIGRATIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    " version TEXT PRIMARY KEY,"
    " checksum TEXT NOT NULL,"
    " applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
    " success BOOLEAN NOT NULL DEFAULT true)"
)


def _schema_dir() -> Path | None:
    """Locate the ``schema/`` directory holding the DDL files.

    Honours ``MORI_SCHEMA_DIR`` if set; otherwise resolves the project root from
    this module (``.../src/mori_soc/repositories/state_postgres.py`` → parents[3]).
    Returns ``None`` if no directory is found (schema apply is then skipped).
    """
    override = os.getenv("MORI_SCHEMA_DIR", "").strip()
    if override:
        p = Path(override)
        return p if p.is_dir() else None
    cand = Path(__file__).resolve().parents[3] / "schema"
    return cand if cand.is_dir() else None

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


def _schema_fail_fast() -> bool:
    """스키마 적용 실패 시 부팅 중단 여부. 명시 설정이 우선, 없으면 운영 모드에서 기본 활성."""
    explicit = os.getenv("MORI_SCHEMA_FAIL_FAST", "").strip().lower()
    if explicit in ("1", "true", "yes", "on"):
        return True
    if explicit in ("0", "false", "no", "off"):
        return False
    # 미설정 → 운영 모드(MORI_DEMO_MODE=false)면 fail-fast, 데모면 관대.
    return os.getenv("MORI_DEMO_MODE", "").strip().lower() in ("false", "0", "no", "off")


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

    def apply_schema(self) -> None:
        """Run every ``schema/*.sql`` in order so the DB is self-healing at boot.

        Postgres' ``docker-entrypoint-initdb.d`` only runs on a *fresh* volume, so
        a pre-existing volume never receives tables added after it was created —
        the app then crashes SELECTing a missing table. Every DDL file is
        ``CREATE TABLE IF NOT EXISTS`` (idempotent), so applying them on each boot
        closes that gap safely. 각 파일은 독립 트랜잭션이라 한 파일 실패가 다른 테이블/
        데이터를 손상시키지 않는다. fail-fast(운영 기본)면 실패 시 부팅을 중단해 불완전한
        DB 상태로 서비스가 정상처럼 뜨는 것을 막는다.
        """
        schema_dir = _schema_dir()
        if schema_dir is None:
            _log.warning("[schema] no schema dir found; skipping auto-apply")
            return
        self._ensure_migrations_table()   # 기록 테이블 먼저(파일 적용 전에 존재해야 기록 가능)
        failed: list[str] = []
        for f in sorted(schema_dir.glob("*.sql")):
            sql = f.read_text(encoding="utf-8")
            if not sql.strip():
                continue
            checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            try:
                with self._connect() as conn, conn.cursor() as cur:
                    cur.execute(sql)
                self._record_migration(f.name, checksum, success=True)
                _log.info("[schema] applied %s", f.name)
            except Exception:  # noqa: BLE001 - report and continue(부팅은 계속하되 은폐 금지)
                failed.append(f.name)
                self._record_migration(f.name, checksum, success=False)
                _log.exception("[schema] FAILED %s — 해당 테이블이 없어 관련 조회가 빈 결과가 될 수 있음", f.name)
        if failed:
            _log.error("[schema] %d개 파일 적용 실패: %s (데이터가 조용히 비어 보일 수 있음)",
                       len(failed), ", ".join(failed))
            if _schema_fail_fast():
                raise RuntimeError(
                    f"[schema] 스키마 적용 실패로 부팅 중단(fail-fast): {', '.join(failed)}. "
                    "불완전한 DB 로 서비스하지 않는다. 데모라면 MORI_SCHEMA_FAIL_FAST=false 로 완화 가능."
                )

    def _ensure_migrations_table(self) -> None:
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(_MIGRATIONS_DDL)
        except Exception:  # noqa: BLE001 - 기록 실패는 스키마 적용을 막지 않는다(계측만)
            _log.exception("[schema] schema_migrations 테이블 준비 실패 — 적용 이력 미기록")

    def _record_migration(self, version: str, checksum: str, *, success: bool) -> None:
        """적용 이력 upsert + 파일 내용 변경(체크섬 드리프트) 감지 경고."""
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute("SELECT checksum FROM schema_migrations WHERE version = %s", (version,))
                row = cur.fetchone()
                if row and row[0] != checksum:
                    _log.warning("[schema] %s 체크섬 변경 감지(드리프트): 기록 %s → 현재 %s",
                                 version, row[0][:12], checksum[:12])
                cur.execute(
                    "INSERT INTO schema_migrations (version, checksum, applied_at, success) "
                    "VALUES (%s, %s, now(), %s) "
                    "ON CONFLICT (version) DO UPDATE SET checksum = EXCLUDED.checksum, "
                    "applied_at = now(), success = EXCLUDED.success",
                    (version, checksum, success))
        except Exception:  # noqa: BLE001
            _log.exception("[schema] %s 적용 이력 기록 실패", version)

    def applied_migrations(self) -> list[dict[str, Any]]:
        """적용된 마이그레이션 목록(버전·checksum·적용시각·성공여부). 없으면 빈 목록."""
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT version, checksum, applied_at, success FROM schema_migrations "
                    "ORDER BY version")
                return [{"version": r[0], "checksum": r[1],
                         "applied_at": r[2].isoformat() if r[2] else None, "success": r[3]}
                        for r in cur.fetchall()]
        except Exception:  # noqa: BLE001
            return []

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

    def delete_evidence_event(self, event_id: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM ui_evidence_events WHERE id = %s", (event_id,))

    # ── action audit log (append-only, hash-chained, #20) ──────────────────────
    def append_audit_event(self, entry: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ui_audit_log (seq, ts, username, action, detail, prev_hash, hash) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (seq) DO NOTHING",  # append-only
                (entry.get("seq"), entry.get("ts"), entry.get("username"), entry.get("action"),
                 entry.get("detail"), entry.get("prev_hash"), entry.get("hash")))

    def load_audit_events(self, limit: int = 2000) -> list[dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT seq, ts, username, action, detail, prev_hash, hash FROM ("
                " SELECT * FROM ui_audit_log ORDER BY seq DESC LIMIT %s) t ORDER BY seq ASC",
                (max(1, int(limit)),))
            return [
                {"seq": r[0], "ts": r[1].isoformat() if r[1] else None, "username": r[2],
                 "action": r[3], "detail": r[4], "prev_hash": r[5], "hash": r[6]}
                for r in cur.fetchall()
            ]

    def latest_audit_event(self) -> dict[str, Any] | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT seq, hash FROM ui_audit_log ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
        return {"seq": row[0], "hash": row[1]} if row else None

    # ── evidence_approvals: 증적 승인 스냅샷(불변, #4) ─────────────────────────
    _APPROVAL_COLS = ("approval_id", "control_id", "evidence_id", "content_hash", "version",
                      "status", "reviewer", "approver", "reviewed_at", "approved_at",
                      "pdf_sha256", "prev_approval_id", "supersede_reason", "actor", "created_at")

    def save_evidence_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        def _ts(v: Any) -> Any:
            return v or None
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ui_evidence_approvals (approval_id, control_id, evidence_id, content_hash,"
                " version, status, reviewer, approver, reviewed_at, approved_at, pdf_sha256,"
                " prev_approval_id, supersede_reason, actor, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now()) "
                "ON CONFLICT (approval_id) DO UPDATE SET status = EXCLUDED.status, "
                "supersede_reason = EXCLUDED.supersede_reason",
                (approval_id, record.get("control_id"), record.get("evidence_id"),
                 record.get("content_hash"), record.get("version"), record.get("status"),
                 record.get("reviewer"), record.get("approver"), _ts(record.get("reviewed_at")),
                 _ts(record.get("approved_at")), record.get("pdf_sha256"),
                 record.get("prev_approval_id"), record.get("supersede_reason"), record.get("actor")))

    def load_evidence_approvals(self, control_id: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            if control_id:
                cur.execute(
                    "SELECT approval_id, control_id, evidence_id, content_hash, version, status, "
                    "reviewer, approver, reviewed_at, approved_at, pdf_sha256, prev_approval_id, "
                    "supersede_reason, actor, created_at FROM ui_evidence_approvals "
                    "WHERE control_id = %s ORDER BY created_at DESC", (control_id,))
            else:
                cur.execute(
                    "SELECT approval_id, control_id, evidence_id, content_hash, version, status, "
                    "reviewer, approver, reviewed_at, approved_at, pdf_sha256, prev_approval_id, "
                    "supersede_reason, actor, created_at FROM ui_evidence_approvals "
                    "ORDER BY created_at DESC LIMIT 500")
            rows = cur.fetchall()
        out = []
        for r in rows:
            d = dict(zip(self._APPROVAL_COLS, r))
            for k in ("reviewed_at", "approved_at", "created_at"):
                if d.get(k) is not None and hasattr(d[k], "isoformat"):
                    d[k] = d[k].isoformat()
            out.append(d)
        return out

    # ── settings (org-wide key-value) ──────────────────────────────────────────
    def load_settings(self) -> dict[str, str]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT key, value FROM ui_settings")
            return {r[0]: (r[1] or "") for r in cur.fetchall()}

    def save_setting(self, key: str, value: str, updated_by: str = "") -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ui_settings (key, value, updated_by, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
                """,
                (key, value, updated_by or None),
            )

    # ── control_status (M2-7 통제 이행 상태) ────────────────────────────────────
    def load_control_status(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT control_id, status, owner, exception_reason, improvement_plan, "
                "due_date, updated_at, updated_by FROM control_status"
            )
            out: dict[str, dict[str, Any]] = {}
            for r in cur.fetchall():
                out[r[0]] = {
                    "control_id": r[0], "status": r[1], "owner": r[2] or "",
                    "exception_reason": r[3] or "", "improvement_plan": r[4] or "",
                    "due_date": r[5].isoformat() if r[5] else "",
                    "updated_at": r[6].isoformat() if r[6] else None,
                    "updated_by": r[7] or "",
                }
            return out

    def save_control_status(self, control_id: str, record: dict[str, Any]) -> None:
        due = record.get("due_date") or None
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO control_status (control_id, status, owner, exception_reason,
                                            improvement_plan, due_date, updated_at, updated_by)
                VALUES (%s, %s, %s, %s, %s, %s, now(), %s)
                ON CONFLICT (control_id) DO UPDATE SET
                    status = EXCLUDED.status, owner = EXCLUDED.owner,
                    exception_reason = EXCLUDED.exception_reason,
                    improvement_plan = EXCLUDED.improvement_plan,
                    due_date = EXCLUDED.due_date, updated_at = now(),
                    updated_by = EXCLUDED.updated_by
                """,
                (control_id, record.get("status", "미정"), record.get("owner") or None,
                 record.get("exception_reason") or None, record.get("improvement_plan") or None,
                 due, record.get("updated_by") or None),
            )

    # ── host_accounts (osquery push 인벤토리) ───────────────────────────────────
    def load_host_accounts(self) -> dict[str, list[dict[str, Any]]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT host_key, username, host_type, uid, gid, shell, home, groups, "
                "is_privileged, is_sudo, disabled, last_login, pwd_last_change, source, collected_at "
                "FROM host_accounts"
            )
            out: dict[str, list[dict[str, Any]]] = {}
            for r in cur.fetchall():
                out.setdefault(r[0], []).append({
                    "username": r[1], "host_type": r[2], "uid": r[3], "gid": r[4],
                    "shell": r[5], "home": r[6], "groups": r[7] or [],
                    "is_privileged": bool(r[8]), "is_sudo": bool(r[9]), "disabled": bool(r[10]),
                    "last_login": r[11].isoformat() if r[11] else None,
                    "pwd_last_change": r[12].isoformat() if r[12] else None,
                    "source": r[13], "collected_at": r[14].isoformat() if r[14] else None,
                })
            return out

    def save_host_accounts(self, host_key: str, accounts: list[dict[str, Any]]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM host_accounts WHERE host_key = %s", (host_key,))
            for a in accounts:
                cur.execute(
                    """
                    INSERT INTO host_accounts (host_key, username, host_type, uid, gid, shell, home,
                        groups, is_privileged, is_sudo, disabled, last_login, pwd_last_change, source, collected_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now())
                    ON CONFLICT (host_key, username) DO UPDATE SET
                        host_type=EXCLUDED.host_type, uid=EXCLUDED.uid, gid=EXCLUDED.gid,
                        shell=EXCLUDED.shell, home=EXCLUDED.home, groups=EXCLUDED.groups,
                        is_privileged=EXCLUDED.is_privileged, is_sudo=EXCLUDED.is_sudo,
                        disabled=EXCLUDED.disabled, last_login=EXCLUDED.last_login,
                        pwd_last_change=EXCLUDED.pwd_last_change, source=EXCLUDED.source, collected_at=now()
                    """,
                    (host_key, a.get("username", ""), a.get("host_type", "server"),
                     a.get("uid"), a.get("gid"), a.get("shell"), a.get("home"),
                     Jsonb(a.get("groups") or []) if Jsonb is not None else (a.get("groups") or []),
                     bool(a.get("is_privileged")), bool(a.get("is_sudo")), bool(a.get("disabled")),
                     a.get("last_login") or None, a.get("pwd_last_change") or None, a.get("source", "osquery")),
                )

    # ── account_approvals (승인 대장) ───────────────────────────────────────────
    def load_account_approvals(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, scope, host_key, username, kind, reason, approver, expires, created_at, status, requested_by "
                "FROM account_approvals"
            )
            return {r[0]: {
                "id": r[0], "scope": r[1], "host_key": r[2] or "", "username": r[3],
                "kind": r[4], "reason": r[5] or "", "approver": r[6] or "",
                "expires": r[7].isoformat() if r[7] else "",
                "created_at": r[8].isoformat() if r[8] else None,
                "status": r[9] or "approved", "requested_by": r[10] or "",
            } for r in cur.fetchall()}

    def save_account_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO account_approvals (id, scope, host_key, username, kind, reason, approver, expires, created_at, status, requested_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s, now(), %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    scope=EXCLUDED.scope, host_key=EXCLUDED.host_key, username=EXCLUDED.username,
                    kind=EXCLUDED.kind, reason=EXCLUDED.reason, approver=EXCLUDED.approver, expires=EXCLUDED.expires,
                    status=EXCLUDED.status, requested_by=EXCLUDED.requested_by
                """,
                (approval_id, record.get("scope", "global"), record.get("host_key") or None,
                 record.get("username", ""), record.get("kind", "account"),
                 record.get("reason") or None, record.get("approver") or None,
                 record.get("expires") or None,
                 record.get("status", "approved"), record.get("requested_by") or None),
            )

    def delete_account_approval(self, approval_id: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM account_approvals WHERE id = %s", (approval_id,))

    # ── catalog_controls (M2-8 편집/NLP 오버레이) ───────────────────────────────
    def load_catalog_edits(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT control_id, op, framework, version, domain, section, title_ko, title_en, "
                "intent_ko, intent_en, evidence_hint_ko, evidence_hint_en, evidence_sources, tags, "
                "status, origin, updated_at, updated_by FROM catalog_controls"
            )
            return {r[0]: {
                "control_id": r[0], "op": r[1], "framework": r[2], "version": r[3],
                "domain": r[4], "section": r[5], "title_ko": r[6], "title_en": r[7],
                "intent_ko": r[8], "intent_en": r[9], "evidence_hint_ko": r[10],
                "evidence_hint_en": r[11], "evidence_sources": r[12] or [], "tags": r[13] or [],
                "status": r[14], "origin": r[15],
                "updated_at": r[16].isoformat() if r[16] else None, "updated_by": r[17] or "",
            } for r in cur.fetchall()}

    def save_catalog_edit(self, control_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO catalog_controls (control_id, op, framework, version, domain, section,
                    title_ko, title_en, intent_ko, intent_en, evidence_hint_ko, evidence_hint_en,
                    evidence_sources, tags, status, origin, updated_at, updated_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now(), %s)
                ON CONFLICT (control_id) DO UPDATE SET
                    op=EXCLUDED.op, framework=EXCLUDED.framework, version=EXCLUDED.version,
                    domain=EXCLUDED.domain, section=EXCLUDED.section, title_ko=EXCLUDED.title_ko,
                    title_en=EXCLUDED.title_en, intent_ko=EXCLUDED.intent_ko, intent_en=EXCLUDED.intent_en,
                    evidence_hint_ko=EXCLUDED.evidence_hint_ko, evidence_hint_en=EXCLUDED.evidence_hint_en,
                    evidence_sources=EXCLUDED.evidence_sources, tags=EXCLUDED.tags, status=EXCLUDED.status,
                    origin=EXCLUDED.origin, updated_at=now(), updated_by=EXCLUDED.updated_by
                """,
                (control_id, record.get("op", "upsert"), record.get("framework", ""),
                 record.get("version", ""), record.get("domain", ""), record.get("section", ""),
                 record.get("title_ko", ""), record.get("title_en", ""), record.get("intent_ko", ""),
                 record.get("intent_en", ""), record.get("evidence_hint_ko", ""),
                 record.get("evidence_hint_en", ""),
                 Jsonb(record.get("evidence_sources") or []) if Jsonb is not None else (record.get("evidence_sources") or []),
                 Jsonb(record.get("tags") or []) if Jsonb is not None else (record.get("tags") or []),
                 record.get("status", "draft"), record.get("origin", "manual"),
                 record.get("updated_by") or None),
            )

    def delete_catalog_edit(self, control_id: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM catalog_controls WHERE control_id = %s", (control_id,))

    # ── control_evidence (M2-8 수기 증적 레코드) ─────────────────────────────────
    def load_control_evidence(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, control_id, title, body, collected_by, collected_at, reference, "
                "created_at, created_by, source FROM control_evidence"
            )
            return {r[0]: {
                "id": r[0], "control_id": r[1], "title": r[2], "body": r[3],
                "collected_by": r[4], "collected_at": r[5], "reference": r[6],
                "created_at": r[7].isoformat() if r[7] else None, "created_by": r[8] or "",
                "source": r[9] or "manual",
            } for r in cur.fetchall()}

    def save_control_evidence(self, evidence_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO control_evidence (id, control_id, title, body, collected_by,
                    collected_at, reference, source, created_at, created_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s, now(), %s)
                ON CONFLICT (id) DO UPDATE SET
                    control_id=EXCLUDED.control_id, title=EXCLUDED.title, body=EXCLUDED.body,
                    collected_by=EXCLUDED.collected_by, collected_at=EXCLUDED.collected_at,
                    reference=EXCLUDED.reference, source=EXCLUDED.source, created_by=EXCLUDED.created_by
                """,
                (evidence_id, record.get("control_id", ""), record.get("title", ""),
                 record.get("body", ""), record.get("collected_by", ""),
                 record.get("collected_at", ""), record.get("reference", ""),
                 record.get("source", "manual"), record.get("created_by") or None),
            )

    def delete_control_evidence(self, evidence_id: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM control_evidence WHERE id = %s", (evidence_id,))

    # ── personal_data_flow (개인정보 처리흐름표 — 013) ────────────────────────────
    def load_personal_data_flow(self) -> dict[str, dict[str, Any]]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, record FROM personal_data_flow")
            out: dict[str, dict[str, Any]] = {}
            for r in cur.fetchall():
                rec = r[1] if isinstance(r[1], dict) else {}
                rec.setdefault("id", r[0])
                out[r[0]] = rec
            return out

    def save_personal_data_flow(self, flow_id: str, record: dict[str, Any]) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO personal_data_flow (id, record, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT (id) DO UPDATE SET record=EXCLUDED.record, updated_at=now()
                """,
                (flow_id, Jsonb(record) if Jsonb is not None else record),
            )

    def delete_personal_data_flow(self, flow_id: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM personal_data_flow WHERE id = %s", (flow_id,))


__all__ = ["PostgresStateRepository", "PSYCOPG_AVAILABLE"]
