"""Account governance routes — server/PC local accounts × LDAP × approvals.

- ``POST /ingest/accounts``       osquery(Fleet) push of a host's local accounts (token auth)
- ``GET  /accounts/overview``     governance findings + unified account list + IP list (admin·security)
- ``GET  /accounts/host/{key}``   one host's accounts (for the server/PC detail section)
- ``GET/POST/DELETE /accounts/approvals``  approval allow-list CRUD (admin·security)
- ``GET  /accounts/overview.csv`` access-review evidence export
"""
from __future__ import annotations

import io
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext
from mori_soc.services.account_recon import reconcile, FINDING_KINDS

_PRIV_GROUPS = {"root", "wheel", "sudo", "admin", "adm", "domain admins", "administrators"}


def _norm_account(a: dict[str, Any], host_type: str) -> dict[str, Any]:
    groups = a.get("groups") or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.replace(";", ",").split(",") if g.strip()]
    gl = {str(g).strip().lower() for g in groups}
    uid = str(a.get("uid", "")).strip()
    is_sudo = bool(a.get("sudo") or a.get("is_sudo")) or bool(gl & {"sudo", "wheel", "admin"})
    is_priv = uid == "0" or is_sudo or bool(gl & _PRIV_GROUPS)
    return {
        "username": str(a.get("username", "")).strip(),
        "host_type": host_type,
        "uid": uid or None, "gid": str(a.get("gid", "")).strip() or None,
        "shell": a.get("shell") or None, "home": a.get("home") or a.get("directory") or None,
        "groups": list(groups), "is_privileged": is_priv, "is_sudo": is_sudo,
        "disabled": bool(a.get("disabled")),
        "last_login": a.get("last_login") or a.get("last_login_at") or None,
        "pwd_last_change": a.get("pwd_last_change") or a.get("password_last_set") or None,
        "source": a.get("source", "osquery"),
    }


def register_accounts_gov(ctx: RouteContext) -> None:
    app = ctx.app
    sessions = ctx.sessions
    host_accounts = ctx.host_accounts
    account_approvals = ctx.account_approvals

    def _gov_role(request: Request) -> str | None:
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return sess.get("role") if sess else None

    def _require_gov(request: Request) -> str:
        if ctx.auth_enabled and _gov_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="계정 거버넌스는 admin·security 전용입니다.")
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return (sess.get("username", "") if sess else "") or ""

    def _require_ingest(request: Request) -> None:
        token_required = os.getenv("MORI_INGEST_TOKEN", "").strip()
        if token_required:
            auth = request.headers.get("authorization", "")
            provided = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-mori-token", "").strip()
            if provided != token_required:
                raise HTTPException(status_code=401, detail="invalid ingest token")
            return
        if not (ctx.get_session_username and ctx.get_session_username(request)):
            raise HTTPException(status_code=401, detail="ingest requires token or session")

    def _directory() -> list[dict[str, Any]]:
        """LDAP/AD directory accounts from the query store (ldap_sync), if any."""
        try:
            store = ctx.get_query_service().store
        except Exception:
            return []
        out: list[dict[str, Any]] = []
        for d in getattr(store, "directory_accounts", []) or []:
            out.append({
                "username": getattr(d, "username", "") or "",
                "status": getattr(d, "status", "active") or "active",
                "is_privileged": bool(getattr(d, "is_privileged", False)),
            })
        return out

    def _ip_list() -> list[dict[str, Any]]:
        try:
            store = ctx.get_query_service().store
        except Exception:
            return []
        rows = []
        for h in getattr(store, "hosts", []) or []:
            rows.append({"hostname": h.hostname, "primary_ip": getattr(h, "primary_ip", "") or "",
                         "host_id": h.host_id, "status": getattr(h, "status", "")})
        rows.sort(key=lambda r: r["hostname"])
        return rows

    def _dormant_days() -> int:
        try:
            return max(1, int(str(ctx.settings.get("accounts_dormant_days", "90")).strip()))
        except (TypeError, ValueError):
            return 90

    # ── Ingest (osquery push) ─────────────────────────────────────────────────
    @app.post("/ingest/accounts", tags=["Sources"])
    def ingest_accounts(payload: dict[str, Any], request: Request,
                        hostname: str | None = None) -> dict[str, Any]:
        """osquery(Fleet) 로컬 계정 인벤토리 push. 한 호스트의 계정 집합을 통째로 교체.

        payload: {hostname|host_id, host_type?, accounts:[{username, uid, groups, sudo,
        last_login, pwd_last_change, disabled, shell, home}, ...]}
        """
        _require_ingest(request)
        host_key = (
            (hostname or "").strip()
            or request.headers.get("x-mori-hostname", "").strip()
            or str(payload.get("hostname", "")).strip()
            or str(payload.get("host_id", "")).strip()
        )
        if not host_key:
            raise HTTPException(status_code=400, detail="hostname (또는 host_id) 가 필요합니다.")
        host_type = str(payload.get("host_type", "server")).strip() or "server"
        raw = payload.get("accounts")
        if not isinstance(raw, list):
            raise HTTPException(status_code=400, detail="accounts 배열이 필요합니다.")
        accounts = [_norm_account(a, host_type) for a in raw if str(a.get("username", "")).strip()]
        host_accounts[host_key] = accounts
        if ctx.persist_host_accounts:
            ctx.persist_host_accounts(host_key)
        return {"ok": True, "host_key": host_key, "host_type": host_type, "count": len(accounts)}

    # ── Overview (governance) ─────────────────────────────────────────────────
    def _overview() -> dict[str, Any]:
        now = datetime.now(tz=timezone.utc)
        result = reconcile(host_accounts, _directory(), list(account_approvals.values()),
                          now=now, dormant_days=_dormant_days())
        result["ip_list"] = _ip_list()
        result["dormant_days"] = _dormant_days()
        return result

    @app.get("/accounts/overview", tags=["Accounts"])
    def accounts_overview(request: Request) -> dict[str, Any]:
        """접근권한 거버넌스 — findings + 통합 계정 목록 + IP 리스트. admin·security 전용."""
        _require_gov(request)
        return _overview()

    @app.get("/accounts/host/{host_key}", tags=["Accounts"])
    def accounts_for_host(host_key: str, request: Request) -> dict[str, Any]:
        """한 호스트의 계정(서버/PC 자산 상세 섹션용). admin·security 전용."""
        _require_gov(request)
        ov = _overview()
        rows = [a for a in ov["accounts"] if a["host_key"] == host_key]
        return {"host_key": host_key, "accounts": rows, "count": len(rows),
                "flagged": sum(1 for a in rows if a["findings"])}

    # ── Approvals allow-list ──────────────────────────────────────────────────
    @app.get("/accounts/approvals", tags=["Accounts"])
    def list_approvals(request: Request) -> dict[str, Any]:
        _require_gov(request)
        items = sorted(account_approvals.values(), key=lambda a: (a.get("username", ""), a.get("kind", "")))
        return {"approvals": items, "total": len(items)}

    @app.post("/accounts/approvals", tags=["Accounts"])
    def add_approval(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """허용 계정/sudo 승인 등록 {username, kind, scope?, host_key?, reason?, expires?}."""
        actor = _require_gov(request)
        username = str(payload.get("username", "")).strip()
        if not username:
            raise HTTPException(status_code=400, detail="username 이 필요합니다.")
        kind = str(payload.get("kind", "account")).strip()
        if kind not in ("account", "sudo"):
            raise HTTPException(status_code=400, detail="kind must be account | sudo")
        scope = str(payload.get("scope", "global")).strip() or "global"
        rec = {
            "id": str(uuid.uuid4()), "scope": scope,
            "host_key": str(payload.get("host_key", "")).strip() if scope == "host" else "",
            "username": username, "kind": kind,
            "reason": str(payload.get("reason", "")).strip(),
            "approver": actor or "unknown",
            "expires": str(payload.get("expires", "")).strip(),
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        account_approvals[rec["id"]] = rec
        if ctx.persist_account_approval:
            ctx.persist_account_approval(rec["id"])
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "ACCOUNT_APPROVAL_ADD", f"{username} ({kind}, {scope})")
        return rec

    @app.delete("/accounts/approvals/{approval_id}", tags=["Accounts"])
    def delete_approval(approval_id: str, request: Request) -> dict[str, Any]:
        actor = _require_gov(request)
        if approval_id not in account_approvals:
            raise HTTPException(status_code=404, detail="승인 항목을 찾을 수 없습니다.")
        rec = account_approvals.pop(approval_id)
        if ctx.delete_account_approval:
            ctx.delete_account_approval(approval_id)
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "ACCOUNT_APPROVAL_DELETE", f"{rec.get('username')} ({rec.get('kind')})")
        return {"ok": True, "id": approval_id}

    # ── CSV evidence export ───────────────────────────────────────────────────
    @app.get("/accounts/overview.csv", tags=["Accounts"])
    def accounts_csv(request: Request) -> Any:
        _require_gov(request)
        import csv as csv_mod
        ov = _overview()
        buf = io.StringIO()
        w = csv_mod.writer(buf)
        w.writerow(["host_key", "host_type", "username", "uid", "privileged", "sudo",
                    "in_directory", "last_login", "login_age_days", "pwd_last_change", "findings"])
        for a in ov["accounts"]:
            w.writerow([a["host_key"], a["host_type"], a["username"], a.get("uid") or "",
                        "Y" if a["is_privileged"] else "", "Y" if a["is_sudo"] else "",
                        "Y" if a["in_directory"] else "", a.get("last_login") or "",
                        a.get("login_age_days") if a.get("login_age_days") is not None else "",
                        a.get("pwd_last_change") or "", "|".join(a["findings"])])
        buf.seek(0)
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="mori-accounts-{ts}.csv"'})


__all__ = ["register_accounts_gov"]
