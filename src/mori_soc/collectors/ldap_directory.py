"""LDAP/AD Directory Collector — accounts, group memberships, privilege bindings."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope

# Optional dependency — collector degrades gracefully when ldap3 is absent.
try:
    from ldap3 import ALL as LDAP_ALL
    from ldap3 import SUBTREE as LDAP_SUBTREE
    from ldap3 import Connection as LdapConnection
    from ldap3 import Server as LdapServer

    LDAP3_AVAILABLE = True
except ImportError:  # pragma: no cover
    LDAP3_AVAILABLE = False
    LdapServer = None  # type: ignore[assignment,misc]
    LdapConnection = None  # type: ignore[assignment,misc]
    LDAP_ALL = None
    LDAP_SUBTREE = None

# Well-known privileged group names (case-insensitive matching).
_PRIVILEGED_GROUPS: set[str] = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "server operators",
    "backup operators",
    "sudo",
    "wheel",
    "root",
}


class LdapDirectoryCollector(BaseCollector):
    """Collect user accounts, group memberships, and privilege info from LDAP/AD."""

    def __init__(
        self,
        ldap_url: str,
        bind_dn: str,
        bind_pw: str,
        base_dn: str,
        *,
        user_filter: str = "(objectClass=user)",
        group_filter: str = "(objectClass=group)",
        user_attrs: tuple[str, ...] = (
            "sAMAccountName", "cn", "displayName", "mail",
            "department", "userAccountControl", "memberOf",
            "lastLogon", "pwdLastSet", "whenCreated",
        ),
        group_attrs: tuple[str, ...] = ("cn", "member"),
        connect_timeout: int = 10,
    ) -> None:
        self._ldap_url = ldap_url
        self._bind_dn = bind_dn
        self._bind_pw = bind_pw
        self._base_dn = base_dn
        self._user_filter = user_filter
        self._group_filter = group_filter
        self._user_attrs = list(user_attrs)
        self._group_attrs = list(group_attrs)
        self._connect_timeout = connect_timeout

    @property
    def source_name(self) -> str:
        return "ldap"

    # ------------------------------------------------------------------
    # collect
    # ------------------------------------------------------------------

    def collect(self) -> Iterable[CollectorRecord]:
        if not LDAP3_AVAILABLE:
            raise RuntimeError("ldap3 package is required for LdapDirectoryCollector")

        collected_at = datetime.now(tz=timezone.utc)
        server = LdapServer(self._ldap_url, get_info=LDAP_ALL, connect_timeout=self._connect_timeout)
        conn = LdapConnection(server, self._bind_dn, self._bind_pw, auto_bind=True)

        records: list[CollectorRecord] = []

        # --- Users ---
        conn.search(self._base_dn, self._user_filter, search_scope=LDAP_SUBTREE, attributes=self._user_attrs)
        for entry in conn.entries:
            payload = self._entry_to_dict(entry)
            username = payload.get("sAMAccountName") or payload.get("cn") or str(entry.entry_dn)
            records.append(CollectorRecord(
                source=self.source_name,
                record_type="directory_account",
                observed_at=collected_at,
                external_id=username,
                host_aliases=[],
                payload=payload,
            ))

        # --- Groups ---
        conn.search(self._base_dn, self._group_filter, search_scope=LDAP_SUBTREE, attributes=self._group_attrs)
        for entry in conn.entries:
            payload = self._entry_to_dict(entry)
            group_name = payload.get("cn") or str(entry.entry_dn)
            records.append(CollectorRecord(
                source=self.source_name,
                record_type="group",
                observed_at=collected_at,
                external_id=group_name,
                host_aliases=[],
                payload=payload,
            ))

        conn.unbind()
        return records

    # ------------------------------------------------------------------
    # normalize
    # ------------------------------------------------------------------

    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        if record.record_type == "directory_account":
            yield from self._normalize_account(record)
            return
        if record.record_type == "group":
            yield from self._normalize_group(record)
            return
        raise ValueError(f"Unsupported LDAP record_type: {record.record_type}")

    # ------------------------------------------------------------------
    # private — account normalization
    # ------------------------------------------------------------------

    def _normalize_account(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        p = record.payload
        username = p.get("sAMAccountName") or p.get("cn") or record.external_id or "unknown"
        account_id = self._make_id("acct", username)

        uac = self._int_value(p.get("userAccountControl"))
        status = self._uac_to_status(uac)
        member_of = p.get("memberOf") or []
        if isinstance(member_of, str):
            member_of = [member_of]
        group_cns = [self._cn_from_dn(dn) for dn in member_of if isinstance(dn, str)]
        is_privileged = any(g.lower() in _PRIVILEGED_GROUPS for g in group_cns)

        yield NormalizedEnvelope(
            entity_type="directory_account",
            entity_id=account_id,
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"ldap:user:{username}",
            normalized={
                "account_id": account_id,
                "username": username,
                "display_name": p.get("displayName") or p.get("cn"),
                "email": p.get("mail"),
                "department": p.get("department"),
                "status": status,
                "is_privileged": is_privileged,
                "last_login_at": self._ad_timestamp(p.get("lastLogon")),
                "password_last_set": self._ad_timestamp(p.get("pwdLastSet")),
                "created_at": self._iso_timestamp(p.get("whenCreated")),
            },
            raw_payload=p,
        )

        # Emit group_membership envelopes
        for group_cn in group_cns:
            membership_id = self._make_id("gm", f"{username}|{group_cn}")
            yield NormalizedEnvelope(
                entity_type="group_membership",
                entity_id=membership_id,
                observed_at=record.observed_at,
                source=self.source_name,
                raw_ref=f"ldap:membership:{username}:{group_cn}",
                normalized={
                    "membership_id": membership_id,
                    "account_id": account_id,
                    "group_name": group_cn,
                    "source": "ldap",
                },
            )

        # Emit privilege_binding for privileged groups
        for group_cn in group_cns:
            if group_cn.lower() in _PRIVILEGED_GROUPS:
                binding_id = self._make_id("pb", f"{username}|{group_cn}")
                yield NormalizedEnvelope(
                    entity_type="privilege_binding",
                    entity_id=binding_id,
                    observed_at=record.observed_at,
                    source=self.source_name,
                    raw_ref=f"ldap:privilege:{username}:{group_cn}",
                    normalized={
                        "binding_id": binding_id,
                        "account_id": account_id,
                        "privilege_type": "group_membership",
                        "target": group_cn,
                        "granted_by": "ldap_sync",
                    },
                )

    # ------------------------------------------------------------------
    # private — group normalization (member list → account_observation)
    # ------------------------------------------------------------------

    def _normalize_group(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        p = record.payload
        group_cn = p.get("cn") or record.external_id or "unknown"
        members = p.get("member") or []
        if isinstance(members, str):
            members = [members]
        # We emit an account_observation for each member so we can track "group change" events.
        for member_dn in members:
            if not isinstance(member_dn, str):
                continue
            member_cn = self._cn_from_dn(member_dn)
            obs_id = self._make_id("ao", f"{group_cn}|{member_cn}")
            yield NormalizedEnvelope(
                entity_type="account_observation",
                entity_id=obs_id,
                observed_at=record.observed_at,
                source=self.source_name,
                raw_ref=f"ldap:group_member:{group_cn}:{member_cn}",
                normalized={
                    "observation_id": obs_id,
                    "account_id": self._make_id("acct", member_cn),
                    "observation_type": "group_sync",
                    "source": "ldap",
                    "detail": f"Member of {group_cn}",
                },
            )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _entry_to_dict(entry: Any) -> dict[str, Any]:
        """Convert ldap3 Entry to a plain dict."""
        result: dict[str, Any] = {}
        for attr_name in entry.entry_attributes:
            val = entry[attr_name].value
            if isinstance(val, list) and len(val) == 1:
                val = val[0]
            result[str(attr_name)] = val
        return result

    @staticmethod
    def _cn_from_dn(dn: str) -> str:
        """Extract CN from a Distinguished Name."""
        for part in dn.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
        return dn

    @staticmethod
    def _make_id(prefix: str, key: str) -> str:
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        return f"ldap-{prefix}-{digest}"

    @staticmethod
    def _int_value(val: Any) -> int | None:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _uac_to_status(uac: int | None) -> str:
        """Convert AD userAccountControl bitmask to AccountStatus."""
        if uac is None:
            return "active"
        if uac & 0x0002:  # ACCOUNTDISABLE
            return "disabled"
        if uac & 0x0010:  # LOCKOUT
            return "locked"
        if uac & 0x800000:  # PASSWORD_EXPIRED
            return "expired"
        return "active"

    @staticmethod
    def _ad_timestamp(val: Any) -> str | None:
        """Convert AD FILETIME (100ns since 1601) to ISO string, or return None."""
        if val is None:
            return None
        try:
            ticks = int(val)
            if ticks <= 0 or ticks >= 9_223_372_036_854_775_807:
                return None
            epoch_diff = 116_444_736_000_000_000  # 1601→1970 in 100ns
            ts = (ticks - epoch_diff) / 10_000_000
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (ValueError, TypeError, OSError):
            return None

    @staticmethod
    def _iso_timestamp(val: Any) -> str | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val.replace(tzinfo=timezone.utc).isoformat() if val.tzinfo is None else val.isoformat()
        return str(val) if val else None

