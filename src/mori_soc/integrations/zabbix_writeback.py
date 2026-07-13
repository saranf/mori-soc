"""Zabbix write-back client (Level 1 comment-only / Level 2 ack+comment).

MORI 는 기본적으로 read-only 다. 이 클라이언트는 명시적으로 활성화됐을 때에만
MORI 의 triage 판단을 Zabbix problem event 에 되돌려 쓴다.

핵심 API 는 ``event.acknowledge`` 로, action bitmask 로 동작을 조합한다.
  * Level 1 (comment_only): "메시지 추가" 비트(=4)만.
  * Level 2 (ack_comment) : acknowledge(=2) + 메시지(=4) = 6.
  * Level 3 (suppress)    : suppress(=32)/unsuppress(=64) + 메시지, suppress_until.
severity change / manual close 는 운영 리스크가 커서 범위에서 제외한다.

활성화 (기본 모두 비활성):
  MORI_ZABBIX_WRITEBACK_ENABLED   true 일 때만 동작 (default false)
  MORI_ZABBIX_WRITEBACK_MODE      comment_only | ack_comment | suppress (default comment_only)
  MORI_ZABBIX_WRITEBACK_PREFIX    코멘트 접두어 (default "[MORI]")

모드는 상위 호환 레벨이다: ack 가능 모드(ack_comment, suppress)에서 acknowledge 는
triage 가 reviewing/resolved 로 전환될 때 일어난다(pending 은 코멘트만). triage
payload 의 ``zabbix_ack`` 로 상태와 무관하게 강제/해제 가능(프론트 버튼 확장점).
suppress/unsuppress 는 자동 트리거가 아니라 명시적 예외 승인/철회 액션으로만
호출한다(전용 엔드포인트, admin·security 전용).

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
ACK_ACTION_ACKNOWLEDGE = 2
ACK_ACTION_ADD_MESSAGE = 4
ACK_ACTION_SUPPRESS = 32
ACK_ACTION_UNSUPPRESS = 64
# 각 동작은 항상 [MORI] 메시지를 함께 남겨 감사 추적을 남긴다.
ACK_ACTION_ACK_WITH_MESSAGE = ACK_ACTION_ACKNOWLEDGE | ACK_ACTION_ADD_MESSAGE  # 6
ACK_ACTION_SUPPRESS_WITH_MESSAGE = ACK_ACTION_SUPPRESS | ACK_ACTION_ADD_MESSAGE  # 36
ACK_ACTION_UNSUPPRESS_WITH_MESSAGE = ACK_ACTION_UNSUPPRESS | ACK_ACTION_ADD_MESSAGE  # 68

# suppress_until=0 → 무기한 억제 (Zabbix 규약).
SUPPRESS_INDEFINITE = 0

MODE_COMMENT_ONLY = "comment_only"
MODE_ACK_COMMENT = "ack_comment"
MODE_SUPPRESS = "suppress"
SUPPORTED_MODES = frozenset({MODE_COMMENT_ONLY, MODE_ACK_COMMENT, MODE_SUPPRESS})
# ack 가능 모드(억제 모드는 ack 를 포함하는 상위 레벨).
ACK_MODES = frozenset({MODE_ACK_COMMENT, MODE_SUPPRESS})

# triage 상태가 이 집합으로 전환되면 ack 가능 모드에서 자동 acknowledge.
ACK_STATUSES = frozenset({"reviewing", "resolved"})


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
    dry_run: bool = False

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
            # dry-run: 활성화돼도 실제 Zabbix API 는 호출하지 않고 '무엇을 할지'만 감사 기록.
            dry_run=_env_flag("MORI_ZABBIX_WRITEBACK_DRYRUN", default=False),
        )

    @property
    def has_credentials(self) -> bool:
        return bool(self.api_url and (self.token or (self.username and self.password)))

    @property
    def is_operational(self) -> bool:
        """True only when write-back should actually fire."""
        return self.enabled and self.mode in SUPPORTED_MODES and self.has_credentials

    @property
    def is_ack_mode(self) -> bool:
        return self.mode in ACK_MODES

    @property
    def can_suppress(self) -> bool:
        """True only when suppress/unsuppress write-back is unlocked."""
        return self.enabled and self.mode == MODE_SUPPRESS and self.has_credentials

    def should_acknowledge(self, status: str, *, explicit: bool | None = None) -> bool:
        """Decide whether a triage update should acknowledge the Zabbix event.

        ``explicit`` (from a triage payload's ``zabbix_ack``) overrides the
        status-driven default when set; otherwise reviewing/resolved acknowledge
        and everything else stays comment-only. Never acknowledges outside
        ack_comment mode.
        """
        if not self.is_ack_mode:
            return False
        if explicit is not None:
            return explicit
        return status in ACK_STATUSES


class ZabbixWritebackClient:
    """Posts MORI evidence comments onto Zabbix problem events."""

    def __init__(self, transport: ZabbixTransport, *, prefix: str = "[MORI]") -> None:
        self._transport = transport
        self._prefix = prefix

    def add_comment(self, event_id: str | int, message: str) -> object:
        """Append a ``[MORI]``-prefixed message to a Zabbix problem event (Level 1).

        Only *trigger* problem events can be updated (Zabbix constraint). The
        event id must be present; callers gate on this upstream.

        Raises :class:`ZabbixApiError` on transport/permission failure so the
        caller can record the failure in the MORI audit trail.
        """
        return self._acknowledge_call(event_id, message, ACK_ACTION_ADD_MESSAGE)

    def acknowledge(self, event_id: str | int, message: str) -> object:
        """Acknowledge a Zabbix problem event and attach the [MORI] message (Level 2).

        Uses ``event.acknowledge`` with acknowledge+message bits (=6). Acknowledge
        needs read-write permission on the underlying trigger; a permission
        failure surfaces as :class:`ZabbixApiError` for the audit trail.
        """
        return self._acknowledge_call(event_id, message, ACK_ACTION_ACK_WITH_MESSAGE)

    def suppress(self, event_id: str | int, message: str, *, until: int = SUPPRESS_INDEFINITE) -> object:
        """Suppress a Zabbix problem event until *until* + attach [MORI] message (Level 3).

        ``until`` is a Unix timestamp; ``0`` (SUPPRESS_INDEFINITE) suppresses
        indefinitely. Maps a MORI risk-acceptance / maintenance-window exception
        onto Zabbix. Needs trigger read-write permission.
        """
        return self._acknowledge_call(
            event_id,
            message,
            ACK_ACTION_SUPPRESS_WITH_MESSAGE,
            extra={"suppress_until": int(until)},
        )

    def unsuppress(self, event_id: str | int, message: str) -> object:
        """Lift suppression on a Zabbix problem event + attach [MORI] message (Level 3).

        Used when a MORI exception expires or is withdrawn.
        """
        return self._acknowledge_call(event_id, message, ACK_ACTION_UNSUPPRESS_WITH_MESSAGE)

    def _acknowledge_call(
        self,
        event_id: str | int,
        message: str,
        action: int,
        *,
        extra: dict[str, object] | None = None,
    ) -> object:
        event_id_text = str(event_id).strip()
        if not event_id_text:
            raise ZabbixApiError("Zabbix eventid is required for write-back")
        text = self._decorate(message)
        params: dict[str, object] = {
            "eventids": event_id_text,
            "action": action,
            "message": text,
        }
        if extra:
            params.update(extra)
        return self._transport.call("event.acknowledge", params)

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
    "ACK_ACTION_ACKNOWLEDGE",
    "ACK_ACTION_ADD_MESSAGE",
    "ACK_ACTION_ACK_WITH_MESSAGE",
    "ACK_ACTION_SUPPRESS",
    "ACK_ACTION_UNSUPPRESS",
    "ACK_ACTION_SUPPRESS_WITH_MESSAGE",
    "ACK_ACTION_UNSUPPRESS_WITH_MESSAGE",
    "SUPPRESS_INDEFINITE",
    "MODE_COMMENT_ONLY",
    "MODE_ACK_COMMENT",
    "MODE_SUPPRESS",
    "ACK_STATUSES",
]
