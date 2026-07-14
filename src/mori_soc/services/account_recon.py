"""Account governance reconciliation.

Cross-checks server/PC **local accounts** (osquery push) against the **LDAP/AD
directory** and the **approval allow-list**, producing access-review findings:

- ``leaver``          — local account matches a *disabled* directory account (퇴사자 잔존)
- ``orphan_priv``     — privileged local account not in the directory (미등록 특권)
- ``unapproved_sudo`` — sudo account not in the approval allow-list (미승인 sudo)
- ``dormant``         — no login within the dormancy window (휴면)

Approvals are the baseline: an account/sudo listed in the allow-list is never
flagged for orphan_priv / unapproved_sudo (its approval reason is itself evidence).
ISMS-P 2.5.1 / 2.5.5 / 2.5.6 · ISO 27001:2022 A.5.16 / A.5.18 / A.8.2.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_DISABLED_STATUSES = {"disabled", "locked", "deleted", "inactive", "expired"}
FINDING_KINDS = ("leaver", "orphan_priv", "unapproved_sudo", "dormant")

# 특권으로 보는 그룹. 로컬 계정 정규화(normalize_account)와 검출 로직이 함께 쓴다.
PRIV_GROUPS = {"root", "wheel", "sudo", "admin", "adm", "domain admins", "administrators"}


def normalize_account(a: dict[str, Any], host_type: str) -> dict[str, Any]:
    """원시 로컬 계정 → host_accounts 저장 형태로 정규화.

    수집 경로가 둘(API ``POST /ingest/accounts`` 푸시 · 워커의 Fleet osquery 폴링)이라
    양쪽이 **같은 판정**을 쓰도록 여기 한 곳에 둔다. uid 0 · sudo · 특권 그룹이면 특권.
    """
    groups = a.get("groups") or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.replace(";", ",").split(",") if g.strip()]
    gl = {str(g).strip().lower() for g in groups}
    uid = str(a.get("uid", "")).strip()
    is_sudo = bool(a.get("sudo") or a.get("is_sudo")) or bool(gl & {"sudo", "wheel", "admin"})
    is_priv = uid == "0" or is_sudo or bool(gl & PRIV_GROUPS)
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


def _age_days(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, int((now - dt).total_seconds() // 86400))
    except (TypeError, ValueError):
        return None


def reconcile(
    host_accounts: dict[str, list[dict[str, Any]]],
    directory: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    now: datetime,
    dormant_days: int = 90,
) -> dict[str, Any]:
    """Return {accounts, findings, counts, summary} for the account-governance view.

    ``directory`` items: {username, status, is_privileged}.
    ``approvals`` items: {scope('global'|'host'), host_key, username, kind('account'|'sudo')}.
    """
    dir_by_user: dict[str, dict[str, Any]] = {}
    for d in directory:
        u = str(d.get("username", "")).strip().lower()
        if u:
            dir_by_user[u] = d
    disabled_dir = {u for u, d in dir_by_user.items()
                    if str(d.get("status", "active")).lower() in _DISABLED_STATUSES}

    def _approved(username: str, host_key: str, kind: str) -> bool:
        """kind='sudo' needs a sudo approval; kind='account' accepts any approval
        (a sudo approval implies the account itself is approved to exist)."""
        un = username.strip().lower()
        for a in approvals:
            if str(a.get("username", "")).strip().lower() != un:
                continue
            if a.get("scope") == "host" and str(a.get("host_key", "")) != host_key:
                continue
            if kind == "sudo" and a.get("kind", "account") != "sudo":
                continue
            return True
        return False

    accounts: list[dict[str, Any]] = []
    counts = {k: 0 for k in FINDING_KINDS}
    findings: dict[str, list[dict[str, Any]]] = {k: [] for k in FINDING_KINDS}

    for host_key, accs in sorted(host_accounts.items()):
        for a in accs:
            username = str(a.get("username", ""))
            un = username.strip().lower()
            host_type = a.get("host_type", "server")
            is_priv = bool(a.get("is_privileged"))
            is_sudo = bool(a.get("is_sudo"))
            in_dir = un in dir_by_user
            login_age = _age_days(a.get("last_login"), now)

            tags: list[str] = []
            if un in disabled_dir:
                tags.append("leaver")
            if is_priv and not in_dir and not _approved(username, host_key, "account"):
                tags.append("orphan_priv")
            if is_sudo and not _approved(username, host_key, "sudo"):
                tags.append("unapproved_sudo")
            if login_age is not None and login_age > dormant_days:
                tags.append("dormant")

            row = {
                "host_key": host_key, "host_type": host_type, "username": username,
                "uid": a.get("uid"), "is_privileged": is_priv, "is_sudo": is_sudo,
                "disabled": bool(a.get("disabled")), "in_directory": in_dir,
                "last_login": a.get("last_login"), "login_age_days": login_age,
                "pwd_last_change": a.get("pwd_last_change"),
                "groups": a.get("groups") or [], "findings": tags,
            }
            accounts.append(row)
            for t in tags:
                counts[t] += 1
                if len(findings[t]) < 200:
                    findings[t].append({"host_key": host_key, "host_type": host_type,
                                        "username": username, "is_privileged": is_priv,
                                        "is_sudo": is_sudo, "login_age_days": login_age})

    hosts = sorted(host_accounts.keys())
    summary = {
        "hosts": len(hosts),
        "servers": len({h for h, a in host_accounts.items() for x in a if x.get("host_type") == "server"}),
        "pcs": len({h for h, a in host_accounts.items() for x in a if x.get("host_type") == "pc"}),
        "accounts": len(accounts),
        "privileged": sum(1 for a in accounts if a["is_privileged"]),
        "directory": len(dir_by_user),
        "flagged": sum(1 for a in accounts if a["findings"]),
    }
    return {"accounts": accounts, "findings": findings, "counts": counts, "summary": summary}


__all__ = ["reconcile", "FINDING_KINDS", "normalize_account", "PRIV_GROUPS"]
