"""Zabbix write-back client (Level 1 — comment-only).

MORI 는 기본적으로 read-only 다. 이 클라이언트는 명시적으로 활성화됐을 때에만
MORI 의 triage 판단을 Zabbix problem event 에 *코멘트로만* 되돌려 쓴다.

핵심 API 는 ``event.acknowledge`` 로, action bitmask 로 동작을 조합한다.
Level 1 은 "메시지 추가" 비트(=4)만 사용한다. acknowledge / suppress /
severity change / manual close 는 운영 리스크가 커서 MVP 범위에서 제외한다.

활성화 (기본 모두 비활성):
  MORI_ZABBIX_WRITEBACK_ENABLED   true 일 때만 동작 (default false)
  MORI_ZABBIX_WRITEBACK_MODE      현재 "comment_only" 만 지원 (default comment_only)
  MORI_ZABBIX_WRITEBACK_PREFIX    코멘트 접두어 (default "[MORI]")

접속 정보는 콜렉터와 동일한 환경변수를 공유한다:
  MORI_ZABBIX_API_URL / MORI_ZABBIX_API_TOKEN /
  MORI_ZABBIX_USER / MORI_ZABBIX_PASSWORD / MORI_ZABBIX_TIMEOUT_SECONDS
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .zabbix_transport import ZabbixApiError, ZabbixTransport

# event.acknowledge action bitmask (Zabbix API reference):
#   1 close, 2 acknowledge, 4 add message, 8 change severity,
#   16 unack, 32 suppress, 64 unsuppress, ...
# Level 1 write-back only ever sets "add message".
ACK_ACTION_ADD_MESSAGE = 4

MODE_COMMENT_ONLY = "comment_only"


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ZabbixWritebackConfig:
    """Resolved write-back configuration (env-derived)."""

    enabled: bool = False
    mode: str = MODE_COMMENT_ONLY
    prefix: str = "[MORI]"
    api_url: str = ""
    token: str | None = None
    username: str | None = None
    password: str | None = None
    request_timeout: int = 10

    @classmethod
    def from_env(cls) -> "ZabbixWritebackConfig":
        return cls(
            enabled=_env_flag("MORI_ZABBIX_WRITEBACK_ENABLED", default=False),
            mode=(os.getenv("MORI_ZABBIX_WRITEBACK_MODE", MODE_COMMENT_ONLY).strip() or MODE_COMMENT_ONLY),
            prefix=(os.getenv("MORI_ZABBIX_WRITEBACK_PREFIX", "[MORI]").strip() or "[MORI]"),
            api_url=os.getenv("MORI_ZABBIX_API_URL", "").strip(),
            token=(os.getenv("MORI_ZABBIX_API_TOKEN", "").strip() or None),
            username=(os.getenv("MORI_ZABBIX_USER", "").strip() or None),
            password=(os.getenv("MORI_ZABBIX_PASSWORD", "").strip() or None),
            request_timeout=int(os.getenv("MORI_ZABBIX_TIMEOUT_SECONDS", "10")),
        )

    @property
    def has_credentials(self) -> bool:
        return bool(self.api_url and (self.token or (self.username and self.password)))

    @property
    def is_operational(self) -> bool:
        """True only when write-back should actually fire."""
        return self.enabled and self.mode == MODE_COMMENT_ONLY and self.has_credentials


class ZabbixWritebackClient:
    """Posts MORI evidence comments onto Zabbix problem events."""

    def __init__(self, transport: ZabbixTransport, *, prefix: str = "[MORI]") -> None:
        self._transport = transport
        self._prefix = prefix

    def add_comment(self, event_id: str | int, message: str) -> object:
        """Append a ``[MORI]``-prefixed message to a Zabbix problem event.

        Only *trigger* problem events can be updated (Zabbix constraint). The
        event id must be present; callers gate on this upstream.

        Raises :class:`ZabbixApiError` on transport/permission failure so the
        caller can record the failure in the MORI audit trail.
        """
        event_id_text = str(event_id).strip()
        if not event_id_text:
            raise ZabbixApiError("Zabbix eventid is required for write-back")
        text = self._decorate(message)
        return self._transport.call(
            "event.acknowledge",
            {
                "eventids": event_id_text,
                "action": ACK_ACTION_ADD_MESSAGE,
                "message": text,
            },
        )

    def _decorate(self, message: str) -> str:
        body = (message or "").strip()
        prefix = self._prefix.strip()
        if not prefix:
            return body
        if body.startswith(prefix):
            return body
        return f"{prefix} {body}".strip()


def build_zabbix_writeback_client(config: ZabbixWritebackConfig) -> ZabbixWritebackClient | None:
    """Return a ready client, or ``None`` when write-back is not operational.

    A ``None`` return is the safe default: disabled flag, unsupported mode, or
    missing credentials all resolve to read-only.
    """
    if not config.is_operational:
        return None
    transport = ZabbixTransport(
        config.api_url,
        token=config.token,
        username=config.username,
        password=config.password,
        request_timeout=config.request_timeout,
    )
    return ZabbixWritebackClient(transport, prefix=config.prefix)


__all__ = [
    "ZabbixWritebackClient",
    "ZabbixWritebackConfig",
    "build_zabbix_writeback_client",
    "ACK_ACTION_ADD_MESSAGE",
    "MODE_COMMENT_ONLY",
]
