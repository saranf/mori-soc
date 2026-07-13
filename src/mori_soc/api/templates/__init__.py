"""HTML page templates for the MORI SOC web UI (Task J-2 modularization).

The render functions here build the standalone HTML pages served by the FastAPI
app in :mod:`mori_soc.api.server`. They depend only on the i18n runtime helpers
(:mod:`mori_soc.api.i18n`) so they can be imported without pulling in the route
layer. The larger dashboard/console templates are moved here incrementally.
"""

from mori_soc.api.templates._common import (
    DEFAULT_UI_PAYLOAD,
    DEFAULT_USER_DASHBOARD_PREFERENCES,
    DOCS_PORTAL_URL,
    FLEET_UI_URL,
    GRAFANA_UI_URL,
    USER_DASHBOARD_ASSET_COLUMN_LABELS,
    USER_DASHBOARD_CARD_LABELS,
    USER_DASHBOARD_GUIDE_LABELS,
    USER_DASHBOARD_SECTION_LABELS,
    WAZUH_UI_URL,
    ZABBIX_UI_URL,
)
from mori_soc.api.templates.auth_pages import (
    render_login_html,
    render_signup_request_html,
)
from mori_soc.api.templates.console import render_query_console_html
from mori_soc.api.templates.dashboard import render_user_dashboard_html

__all__ = [
    'render_query_console_html', 'render_user_dashboard_html',
    'render_login_html', 'render_signup_request_html',
    'DOCS_PORTAL_URL', 'FLEET_UI_URL', 'ZABBIX_UI_URL', 'WAZUH_UI_URL', 'GRAFANA_UI_URL',
    'USER_DASHBOARD_CARD_LABELS', 'USER_DASHBOARD_SECTION_LABELS',
    'USER_DASHBOARD_ASSET_COLUMN_LABELS', 'USER_DASHBOARD_GUIDE_LABELS',
    'DEFAULT_USER_DASHBOARD_PREFERENCES', 'DEFAULT_UI_PAYLOAD',
]
