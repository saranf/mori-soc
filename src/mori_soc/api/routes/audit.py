"""Audit-log routes (Task J-4b12).

Registers the user-action audit log (read/append), the asset-change audit log
(read), and the **unified activity log** (read, searchable) endpoints on
``ctx.app``. The unified log aggregates every history/audit source in MORI into
one normalized, searchable feed for the admin "Audit·Logs" tab.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.routes.context import RouteContext

# action_audit_log 액션 중 인증(로그인) 계열 — 통합 로그에서 별도 분류로 표시.
_LOGIN_ACTIONS = {"LOGIN", "LOGIN_FAIL", "LOGOUT"}

# 통합 로그가 노출하는 분류(프런트 select 와 동일 토큰).
_LOG_CATEGORIES = [
    "login", "action", "asset", "vuln", "triage",
    "incident", "evidence", "account", "control_evidence",
]

# 통합 로그 열람 허용 역할.
_LOG_VIEW_ROLES = {"admin", "security", "auditor"}


def register_audit(ctx: RouteContext) -> None:
    app = ctx.app
    action_audit_log = ctx.action_audit_log
    asset_audit_log = ctx.asset_audit_log
    sessions = ctx.sessions
    _log_action = ctx.log_action

    @app.get("/admin/action-audit-log", tags=["Admin"])
    def get_action_audit_log(limit: int = 500, username: str = "") -> dict[str, Any]:
        """사용자 행동 감사 로그 조회 (최신순). ?username=xxx 로 필터 가능."""
        logs = list(reversed(action_audit_log))
        if username:
            logs = [e for e in logs if e["username"] == username]
        return {"logs": logs[:limit], "total": len(logs)}

    @app.post("/admin/action-audit-log", tags=["Admin"])
    def record_action_audit(payload: dict[str, Any], request: Any = None) -> dict[str, Any]:
        """프런트엔드에서 탭 전환·쿼리 실행 등을 기록할 때 호출."""
        token = ""
        if hasattr(request, "cookies"):
            token = request.cookies.get("mori_session", "")
        sess = sessions.get(token, {})
        uname = sess.get("username", "anonymous")
        action = str(payload.get("action", "UNKNOWN"))
        detail = str(payload.get("detail", ""))
        _log_action(uname, action, detail)
        return {"ok": True}

    @app.get("/admin/audit-log", tags=["Assets"])
    def audit_log_list(hostname: str = "", field: str = "") -> Any:
        """자산 담당자/카테고리 변경 이력 조회 (어드민 전용)."""
        result = list(reversed(asset_audit_log))  # 최신 순
        if hostname:
            result = [r for r in result if r["hostname"] == hostname]
        if field:
            result = [r for r in result if r["field"] == field]
        return {"audit_log": result, "total": len(result)}

    # ── 통합 이력 로그 (검색 가능) ────────────────────────────────────────────
    def _session_role(request: Request) -> str | None:
        token = request.cookies.get("mori_session", "") if hasattr(request, "cookies") else ""
        sess = sessions.get(token) if sessions else None
        return (sess or {}).get("role")

    def _require_log_view(request: Request) -> None:
        if ctx.auth_enabled and _session_role(request) not in _LOG_VIEW_ROLES:
            raise HTTPException(status_code=403, detail="통합 로그는 admin·security·auditor 전용입니다.")

    def _ev(ts, actor, category, action, target, detail, source) -> dict[str, Any]:
        return {
            "ts": str(ts or ""), "actor": str(actor or ""), "category": category,
            "action": str(action or ""), "target": str(target or ""),
            "detail": str(detail or ""), "source": source,
        }

    def _collect_events() -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        # 1) 사용자 행동 + 로그인/로그아웃 (인메모리 action_audit_log)
        for e in action_audit_log:
            act = str(e.get("action", ""))
            cat = "login" if act in _LOGIN_ACTIONS else "action"
            events.append(_ev(e.get("ts"), e.get("username"), cat, act, "", e.get("detail"), "action"))

        # 2) 자산/취약점 변경 이력 (vuln_* 필드는 취약점 분류로)
        for r in asset_audit_log:
            field = str(r.get("field", ""))
            cat = "vuln" if field.startswith("vuln_") else "asset"
            detail = f"{field}: {r.get('old_value') or '-'} → {r.get('new_value') or '-'}"
            events.append(_ev(r.get("changed_at"), r.get("changed_by"), cat, "변경", r.get("hostname"), detail, "asset"))

        # 3) 트리아지 상태 변경 이력 (alert 별 history[])
        for alert_id, entry in (ctx.triage_store or {}).items():
            for h in (entry.get("history") or []):
                action = f"{h.get('from_status', '')}→{h.get('to_status', '')}"
                events.append(_ev(h.get("changed_at"), h.get("changed_by"), "triage", action, alert_id, h.get("note"), "triage"))

        # 4) 인시던트 변경 이력 + 노트
        for inc in (ctx.incidents or {}).values():
            title = inc.get("title") or inc.get("incident_id") or ""
            for h in (inc.get("history") or []):
                bits = [f"{k}={v}" for k, v in h.items() if k not in ("event", "analyst", "changed_at")]
                events.append(_ev(h.get("changed_at"), h.get("analyst"), "incident", h.get("event"), title, ", ".join(bits), "incident"))
            for n in (inc.get("notes") or []):
                events.append(_ev(n.get("created_at"), n.get("analyst"), "incident", "note", title, n.get("text"), "incident"))

        # 5) 증적 이벤트 (CSOP diff + Zabbix write-back) — 영속 스토어 직접 조회
        try:
            evs = ctx.state_repo.load_evidence_events(limit=2000) if ctx.state_repo else []
        except Exception:
            evs = []
        for x in evs or []:
            if not isinstance(x, dict):
                continue
            envp = x.get("envelope") if isinstance(x.get("envelope"), dict) else {}
            events.append(_ev(
                x.get("received_at"), envp.get("requested_by"), "evidence",
                x.get("delta_type"), x.get("host_id") or x.get("cve"),
                x.get("summary"), x.get("source") or "evidence",
            ))

        # 6) 계정/sudo 승인 대장
        for a in (ctx.account_approvals or {}).values():
            target = f"{a.get('username', '')}@{a.get('host_key') or a.get('scope') or ''}"
            events.append(_ev(a.get("created_at"), a.get("approver"), "account", f"승인 {a.get('kind', '')}", target, a.get("reason"), "account"))

        # 7) 통제 증적(수기/자동 스냅샷)
        for c in (ctx.control_evidence or {}).values():
            ts = c.get("created_at") or c.get("collected_at")
            actor = c.get("created_by") or c.get("collected_by")
            events.append(_ev(ts, actor, "control_evidence", f"증적 {c.get('source', '')}", c.get("control_id"), c.get("title"), "control_evidence"))

        return events

    @app.get("/admin/logs", tags=["Admin"])
    def unified_logs(
        request: Request,
        q: str = "",
        category: str = "",
        date_from: str = "",
        date_to: str = "",
        limit: int = 1000,
    ) -> dict[str, Any]:
        """모든 이력·감사 소스를 정규화해 한 피드로 통합 조회(최신순, 검색 가능).

        - q         : 행위자/액션/대상/상세/분류/소스 전체에 대한 부분일치(대소문자 무시)
        - category  : login|action|asset|vuln|triage|incident|evidence|account|control_evidence
        - date_from : ISO date/datetime 이상 (포함)
        - date_to   : ISO date/datetime 이하 (그날 포함)
        admin·security·auditor 전용.
        """
        _require_log_view(request)
        events = _collect_events()
        if category:
            events = [e for e in events if e["category"] == category]
        if date_from:
            events = [e for e in events if e["ts"] >= date_from]
        if date_to:
            # date_to 가 날짜만이면 그날 전체 포함되도록 '~'(> 'T', 숫자) 로 상한 확장
            upper = date_to + "~"
            events = [e for e in events if e["ts"] <= upper]
        if q:
            ql = q.lower()
            events = [
                e for e in events
                if ql in f"{e['actor']} {e['action']} {e['target']} {e['detail']} {e['category']} {e['source']}".lower()
            ]
        events.sort(key=lambda e: e["ts"], reverse=True)
        total = len(events)
        return {"logs": events[: max(0, limit)], "total": total, "categories": _LOG_CATEGORIES}


__all__ = ["register_audit"]
