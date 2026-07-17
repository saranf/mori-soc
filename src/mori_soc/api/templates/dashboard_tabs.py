"""탭 HTML 조각 집합자 — 화면별 모듈(screens/)에서 재-export.

실제 조각은 templates/screens/<화면>.py 에 화면 단위로 분리돼 있다.
기존 import 경로(mori_soc.api.templates.dashboard_tabs) 호환을 위해 여기서 모아 노출.
"""
from mori_soc.api.templates.screens.dashboard import _TAB_DASHBOARD_HTML  # noqa: F401
from mori_soc.api.templates.screens.triage import _TAB_TRIAGE_HTML  # noqa: F401
from mori_soc.api.templates.screens.incidents import _TAB_INCIDENTS_HTML  # noqa: F401
from mori_soc.api.templates.screens.assets import _TAB_ASSETS_HTML  # noqa: F401
from mori_soc.api.templates.screens.compliance import _TAB_COMPLIANCE_HTML  # noqa: F401
from mori_soc.api.templates.screens.accounts import _TAB_ACCOUNTS_HTML  # noqa: F401
from mori_soc.api.templates.screens.guides import _TAB_GUIDES_HTML  # noqa: F401

__all__ = [
    "_TAB_DASHBOARD_HTML",
    "_TAB_TRIAGE_HTML",
    "_TAB_INCIDENTS_HTML",
    "_TAB_ASSETS_HTML",
    "_TAB_COMPLIANCE_HTML",
    "_TAB_ACCOUNTS_HTML",
    "_TAB_GUIDES_HTML",
]
