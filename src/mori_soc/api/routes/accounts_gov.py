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

from mori_soc.api.auth import _ALL_ROLES, parse_account_view_roles
from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext
from mori_soc.services.account_recon import FINDING_KINDS, reconcile

_PRIV_GROUPS = {"root", "wheel", "sudo", "admin", "adm", "domain admins", "administrators"}

# 계정 수집 설정(ui_settings, schema/008). admin 이 어드민 콘솔에서 조정.
_COLLECT_ENABLED_KEY = "account_collect_enabled"   # "true"(기본) | "false"
_COLLECT_SOURCE_KEY = "account_collect_source"     # "fleet"(기본) | "script"


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
        if ctx.auth_enabled and _gov_role(request) not in parse_account_view_roles(ctx.settings):
            raise HTTPException(status_code=403, detail="계정 거버넌스 열람 권한이 없습니다. (admin이 역할 조정 가능)")
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return (sess.get("username", "") if sess else "") or ""

    def _require_admin(request: Request) -> str:
        if ctx.auth_enabled and _gov_role(request) != "admin":
            raise HTTPException(status_code=403, detail="열람 역할 조정은 admin 전용입니다.")
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return (sess.get("username", "") if sess else "") or ""

    def _collection_enabled() -> bool:
        """계정 수집 마스터 스위치(admin). 미설정 시 기본 켬."""
        raw = str(ctx.settings.get(_COLLECT_ENABLED_KEY, "true")).strip().lower()
        return raw not in ("false", "0", "no", "off")

    def _collection_source() -> str:
        """수집 경로. 기본 fleet(osquery via Fleet), 대안 script(push)."""
        raw = str(ctx.settings.get(_COLLECT_SOURCE_KEY, "fleet")).strip().lower()
        return raw if raw in ("fleet", "script") else "fleet"

    def _require_ingest(request: Request) -> None:
        # 수집이 꺼져 있으면 민감한 로컬 계정 인벤토리를 아예 받지 않는다(fail-closed).
        if not _collection_enabled():
            raise HTTPException(status_code=403, detail="account collection is disabled by admin")
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
        owners = ctx.asset_owners or {}
        rows = []
        for h in getattr(store, "hosts", []) or []:
            o = owners.get(h.hostname, {}) or {}
            rows.append({"hostname": h.hostname, "primary_ip": getattr(h, "primary_ip", "") or "",
                         "host_id": h.host_id, "status": getattr(h, "status", ""),
                         "team": o.get("team", "") or "", "category": o.get("category", "") or "",
                         "importance": o.get("importance", "") or ""})
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
        # 승인 완료(approved)만 이상 검출 기준선에 반영. 대기(pending) 요청은 억제하지 않음.
        approved = [a for a in account_approvals.values() if a.get("status", "approved") == "approved"]
        result = reconcile(host_accounts, _directory(), approved,
                          now=now, dormant_days=_dormant_days())
        result["ip_list"] = _ip_list()
        result["dormant_days"] = _dormant_days()
        return result

    @app.get("/accounts/overview", tags=["Accounts"])
    def accounts_overview(request: Request) -> dict[str, Any]:
        """접근권한 거버넌스 — findings + 통합 계정 목록 + IP 리스트. admin·security 전용."""
        _require_gov(request)
        return _overview()

    @app.get("/accounts/access-trail", tags=["Accounts"])
    def accounts_access_trail(request: Request, limit: int = 30) -> dict[str, Any]:
        """접속 발자취 — 최근 로그인·sudo 기록 **미리보기**(전체 아님, 전체는 Loki/Grafana).

        Loki(보는 층)에 최근 접속기록만 질의해 '누가·언제·어디서' 표를 만든다. 계정 거버넌스와
        같은 화면에서 계정↔실제 접속을 대조. env ``MORI_LOKI_URL`` 미설정 시 available=False.
        """
        _require_gov(request)
        from mori_soc.api.payloads import grafana_explore_expr_url
        from mori_soc.services.loki_client import access_log_recent, access_selector
        n = max(1, min(int(limit or 30), 100))
        rec = access_log_recent(limit=n)
        sel = access_selector()
        return {"available": bool(rec.get("available")), "entries": rec.get("entries", []),
                "shown": len(rec.get("entries", [])), "selector": sel,
                "grafana_url": grafana_explore_expr_url(sel)}

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
            "status": "approved", "requested_by": "",  # admin·보안 직접 등록 = 즉시 승인
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

    # ── 승인 요청 워크플로우 (인프라 팝업 요청 → admin·보안 승인/거절) ─────────────
    def _require_login(request: Request) -> str:
        u = ctx.get_session_username(request) if ctx.get_session_username else None
        if ctx.auth_enabled and not u:
            raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
        return u or ""

    @app.get("/accounts/host/{host_key}/privileged", tags=["Accounts"])
    def host_privileged_accounts(host_key: str, request: Request) -> dict[str, Any]:
        """호스트의 특권/sudo 계정 + 승인 상태 (서버 팝업 승인요청용). 로그인 필요."""
        _require_login(request)
        ov = _overview()
        rows = [a for a in ov["accounts"] if a["host_key"] == host_key and a.get("is_privileged")]

        def _status_for(username: str, kind: str) -> str:
            for ap in account_approvals.values():
                if ap.get("username") != username or ap.get("kind") not in (kind, "account"):
                    continue
                if ap.get("scope") == "host" and (ap.get("host_key") or "") not in ("", host_key):
                    continue
                return ap.get("status", "approved")
            return "none"

        out = [{
            "username": a["username"], "is_sudo": bool(a.get("is_sudo")),
            "kind": "sudo" if a.get("is_sudo") else "account",
            "findings": a.get("findings", []),
            "approval_status": _status_for(a["username"], "sudo" if a.get("is_sudo") else "account"),
        } for a in rows]
        return {"host_key": host_key, "privileged": out, "count": len(out)}

    @app.post("/accounts/approval-requests", tags=["Accounts"])
    def create_approval_request(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """인프라 담당자가 서버 팝업에서 sudo/특권 계정 승인 요청 (status=pending). 로그인 필요."""
        actor = _require_login(request)
        username = str(payload.get("username", "")).strip()
        if not username:
            raise HTTPException(status_code=400, detail="username 이 필요합니다.")
        kind = str(payload.get("kind", "sudo")).strip()
        if kind not in ("account", "sudo"):
            kind = "sudo"
        host_key = str(payload.get("host_key", "")).strip()
        # 이미 대기중인 동일 요청이면 중복 생성 방지
        for ap in account_approvals.values():
            if (ap.get("status") == "pending" and ap.get("username") == username
                    and ap.get("kind") == kind and (ap.get("host_key") or "") == host_key):
                raise HTTPException(status_code=409, detail="이미 대기중인 승인 요청이 있습니다.")
        rec = {
            "id": str(uuid.uuid4()),
            "scope": "host" if host_key else "global", "host_key": host_key,
            "username": username, "kind": kind,
            "reason": str(payload.get("reason", "")).strip(),
            "approver": "", "expires": "",
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
            "status": "pending", "requested_by": actor or "unknown",
        }
        account_approvals[rec["id"]] = rec
        if ctx.persist_account_approval:
            ctx.persist_account_approval(rec["id"])
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "ACCOUNT_APPROVAL_REQUEST",
                           f"{username} ({kind}) @ {host_key or 'global'}")
        return rec

    @app.post("/accounts/approvals/{approval_id}/approve", tags=["Accounts"])
    def approve_request(approval_id: str, request: Request) -> dict[str, Any]:
        """대기 요청 승인 (admin·보안). status→approved 로 전환하면 이상 검출에서 제외."""
        actor = _require_gov(request)
        rec = account_approvals.get(approval_id)
        if not rec:
            raise HTTPException(status_code=404, detail="요청을 찾을 수 없습니다.")
        rec["status"] = "approved"
        rec["approver"] = actor or "unknown"
        if ctx.persist_account_approval:
            ctx.persist_account_approval(approval_id)
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "ACCOUNT_APPROVAL_APPROVE",
                           f"{rec.get('username')} ({rec.get('kind')})")
        return rec

    @app.post("/accounts/approvals/{approval_id}/reject", tags=["Accounts"])
    def reject_request(approval_id: str, request: Request) -> dict[str, Any]:
        """대기 요청 거절 (admin·보안). 레코드 삭제."""
        actor = _require_gov(request)
        rec = account_approvals.pop(approval_id, None)
        if not rec:
            raise HTTPException(status_code=404, detail="요청을 찾을 수 없습니다.")
        if ctx.delete_account_approval:
            ctx.delete_account_approval(approval_id)
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "ACCOUNT_APPROVAL_REJECT",
                           f"{rec.get('username')} ({rec.get('kind')})")
        return {"ok": True, "id": approval_id}

    # ── 계정 수집 설정 (admin 조정) ────────────────────────────────────────────
    # 로컬 계정 인벤토리는 민감정보라 "수집 자체"를 admin 이 끄고 켤 수 있어야 한다.
    # source: fleet(기본, osquery via Fleet) | script(Fleet 없는 호스트용 push 스크립트)
    @app.get("/accounts/collection", tags=["Accounts"])
    def get_collection_config(request: Request) -> dict[str, Any]:
        """계정 수집 on/off + 수집 경로 조회. admin 전용."""
        _require_admin(request)
        return {
            "enabled": _collection_enabled(),
            "source": _collection_source(),
            "sources": ["fleet", "script"],
        }

    @app.post("/accounts/collection", tags=["Accounts"])
    def set_collection_config(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """계정 수집 설정 {enabled: bool, source: 'fleet'|'script'}. admin 전용."""
        actor = _require_admin(request)
        if "enabled" in payload:
            ctx.settings[_COLLECT_ENABLED_KEY] = "true" if bool(payload.get("enabled")) else "false"
            if ctx.persist_setting:
                ctx.persist_setting(_COLLECT_ENABLED_KEY, actor)
        if "source" in payload:
            src = str(payload.get("source", "")).strip().lower()
            if src not in ("fleet", "script"):
                raise HTTPException(status_code=400, detail="source 는 fleet 또는 script 여야 합니다.")
            ctx.settings[_COLLECT_SOURCE_KEY] = src
            if ctx.persist_setting:
                ctx.persist_setting(_COLLECT_SOURCE_KEY, actor)
        if ctx.log_action:
            ctx.log_action(actor or "admin", "ACCOUNT_COLLECTION_SET",
                           f"enabled={_collection_enabled()} source={_collection_source()}")
        return {"enabled": _collection_enabled(), "source": _collection_source()}

    # ── 열람 역할 설정 (admin 조정) ────────────────────────────────────────────
    @app.get("/accounts/view-roles", tags=["Accounts"])
    def get_view_roles(request: Request) -> dict[str, Any]:
        """계정 거버넌스 열람 역할 조회. admin 전용."""
        _require_admin(request)
        return {"roles": parse_account_view_roles(ctx.settings),
                "all_roles": list(_ALL_ROLES), "locked": ["admin"]}

    @app.post("/accounts/view-roles", tags=["Accounts"])
    def set_view_roles(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """계정 거버넌스 열람 역할 설정 {roles:[...]}. admin 항상 포함. admin 전용."""
        actor = _require_admin(request)
        raw = payload.get("roles")
        if not isinstance(raw, list):
            raise HTTPException(status_code=400, detail="roles 배열이 필요합니다.")
        roles = [r for r in ("admin", *[str(x).strip() for x in raw]) if r in _ALL_ROLES]
        # 중복 제거(순서 유지)
        seen: set[str] = set()
        roles = [r for r in roles if not (r in seen or seen.add(r))]
        ctx.settings["account_view_roles"] = ",".join(roles)
        if ctx.persist_setting:
            ctx.persist_setting("account_view_roles", actor)
        if ctx.log_action:
            ctx.log_action(actor or "admin", "ACCOUNT_VIEW_ROLES_SET", ",".join(roles))
        return {"roles": roles}

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
