"""Shared state holder for the modular route packages (Task J-4b).

``create_app`` captures ~17 in-memory stores plus a handful of helper closures
via lexical scope. To move the route handlers into domain modules we gather that
state into :class:`RouteContext`, a passive holder that ``create_app`` assembles
once. Domain routers unpack what they need via a short preamble (e.g.
``sessions = ctx.sessions``) and keep their handler bodies verbatim.

Design notes
------------
* Mutable stores (dicts / lists) are shared *by reference*: assigning the same
  object onto a ``ctx`` field means in-place mutations in any module are visible
  everywhere — identical to the original closure behaviour.
* ``admin_dashboard_preferences`` is genuinely *rebound* (not just mutated) by
  the dashboard-preferences handlers, so those handlers must write back through
  the attribute (``ctx.admin_dashboard_preferences = ...``) for the change to
  persist. ``role_permissions`` is only mutated in place.
* The helper closures (``get_query_service`` etc.) are assigned as callable
  fields rather than reimplemented, so behaviour is byte-for-byte identical to
  the originals.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mori_soc.api.auth import AuthConfig


@dataclass
class RouteContext:
    """Container for the in-memory state and helpers shared across route modules."""

    app: Any

    # ── Configuration (read-only after assembly) ──────────────────────────────
    service: Any = None
    service_factory: Any = None
    auth_config: "Optional[AuthConfig]" = None
    auth_enabled: bool = False
    insecure_defaults: list[str] = field(default_factory=list)

    # ── In-memory stores (mutated in place; shared by reference) ───────────────
    local_users: dict[str, dict[str, str]] = field(default_factory=dict)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    signup_requests: list[dict[str, Any]] = field(default_factory=list)
    action_audit_log: list[dict[str, Any]] = field(default_factory=list)
    user_tab_permissions: dict[str, list[str]] = field(default_factory=dict)
    triage_store: dict[str, dict[str, Any]] = field(default_factory=dict)
    webhooks: list[dict[str, Any]] = field(default_factory=list)
    incidents: dict[str, dict[str, Any]] = field(default_factory=dict)
    asset_owners: dict[str, dict[str, Any]] = field(default_factory=dict)
    asset_audit_log: list[dict[str, Any]] = field(default_factory=list)
    action_plans: dict[str, dict[str, Any]] = field(default_factory=dict)
    vuln_actions: dict[str, dict[str, Any]] = field(default_factory=dict)
    # risk_register: vuln_id -> 위험성 평가 레코드 (R-2)
    risk_register: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    guides: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_dashboard_prefs: dict[str, dict[str, Any]] = field(default_factory=dict)

    # ── Rebindable state (reassigned, not just mutated) ───────────────────────
    admin_dashboard_preferences: dict[str, Any] = field(default_factory=dict)
    role_permissions: dict[str, list[str]] = field(default_factory=dict)

    # ── Helper closures (assigned by create_app; see module docstring) ─────────
    log_action: Optional[Callable[..., None]] = None
    verify_credentials: Optional[Callable[[str, str], bool]] = None
    get_query_service: Optional[Callable[[], Any]] = None
    user_profile: Optional[Callable[[str], dict[str, Any]]] = None
    get_session_username: Optional[Callable[[Any], Optional[str]]] = None
    vuln_exists: Optional[Callable[[str], bool]] = None
    vuln_lookup: Optional[Callable[[str], tuple[Any, str, str]]] = None
    record_vuln_audit: Optional[Callable[..., None]] = None

    # ── Persistence write-through hooks (M2-1.0d) ─────────────────────────────
    # ``state_repo`` is the StateRepository backing the 6 operational stores.
    # The ``persist_*`` closures read the just-mutated record back out of the
    # in-memory cache and write it through; ``delete_asset_owner`` removes a row.
    # With the default in-memory backend these are observably no-ops.
    state_repo: Any = None
    persist_user_profile: Optional[Callable[[str], None]] = None
    persist_asset_owner: Optional[Callable[[str], None]] = None
    delete_asset_owner: Optional[Callable[[str], None]] = None
    persist_asset_audit: Optional[Callable[[dict[str, Any]], None]] = None
    persist_vuln_action: Optional[Callable[[str], None]] = None
    persist_triage: Optional[Callable[[str], None]] = None
    persist_incident: Optional[Callable[[str], None]] = None
    persist_risk_assessment: Optional[Callable[[str], None]] = None


__all__ = ["RouteContext"]
