"""Domain-grouped HTTP route modules (Task J-4b modularization).

``create_app`` historically registered ~58 route handlers inline, each closing
over the in-memory stores and helper closures defined in its body. To split the
handlers into focused domain modules without changing behaviour, the shared
state is collected into :class:`~mori_soc.api.routes.context.RouteContext` and
passed to per-domain ``register_*`` functions.
"""
from __future__ import annotations

from mori_soc.api.routes.context import RouteContext

__all__ = ["RouteContext"]
