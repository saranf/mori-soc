"""공통 상수 + i18n 런타임 임포트 (MORI SOC 템플릿 페이지 모듈 공용).

templates.py 를 페이지별(console/dashboard/auth_pages)로 분리하며 추출.
"""
import json
import os

from mori_soc.api.i18n import (
    _ADMIN_I18N,
    _DASHBOARD_I18N,
    _LOGIN_I18N,
    _SIGNUP_I18N,
    _i18n_script,
    _i18n_toggle_html,
)
from mori_soc.services.intent_parser import QUERY_GUIDE_EXAMPLES

DOCS_PORTAL_URL = os.getenv("MORI_DOCS_PORTAL_URL", "http://mori.rmstudio.co.kr:37854/")
FLEET_UI_URL = os.getenv("MORI_FLEET_UI_URL", "")
ZABBIX_UI_URL = os.getenv("MORI_ZABBIX_UI_URL", "")
WAZUH_UI_URL = os.getenv("MORI_WAZUH_UI_URL", "")
GRAFANA_UI_URL = os.getenv("MORI_GRAFANA_URL", "")
USER_DASHBOARD_CARD_LABELS = {
    "total_hosts": "Total Hosts",
    "offline_hosts": "Offline Hosts",
    "alerts_24h": "High Alerts 24h",
    "critical_vulns": "Critical Vulns",
    "sources_reporting": "Sources Reporting",
    "sources_healthy": "Healthy Collectors",
    "ingested_records": "Ingested Records",
}
USER_DASHBOARD_SECTION_LABELS = {
    "security_hero": "Security Overview",
    "infra_status": "Infra Status (24h/12h)",
    "fleet_status": "PC Assets (Fleet)",
    "source_coverage": "Source Coverage",
    "latest_status": "Latest Host Status",
    "risk_summary": "Risk Summary",
    "recent_activity": "Recent Activity",
}
USER_DASHBOARD_ASSET_COLUMN_LABELS = {
    "show_importance": "중요도 컬럼",
    "show_isms_control": "ISMS-P 통제 컬럼",
    "show_iso27001_control": "ISO 27001 통제 컬럼",
}
USER_DASHBOARD_GUIDE_LABELS = {
    "zabbix_setup": "Zabbix 에이전트 설정",
    "fleet_install": "Fleet 에이전트 설치",
    "isms_criteria": "ISMS-P 심사 기준",
    "iso27001_criteria": "ISO 27001 기준",
    "ldap_setup": "LDAP 통합 설정",
    "incident_response": "인시던트 대응 절차",
    "security_policy": "보안 정책 가이드",
    "risk_methodology": "위험성 평가 기준",
}
DEFAULT_USER_DASHBOARD_PREFERENCES = {
    "cards": {
        "total_hosts": True,
        "offline_hosts": True,
        "alerts_24h": True,
        "critical_vulns": True,
        "sources_reporting": False,
        "sources_healthy": False,
        "ingested_records": False,
    },
    "sections": {
        "security_hero": True,
        "infra_status": True,
        "fleet_status": True,
        "source_coverage": False,
        "latest_status": False,
        "risk_summary": True,
        "recent_activity": False,
    },
    "asset_columns": {
        "show_importance": True,
        "show_isms_control": True,
        "show_iso27001_control": True,
    },
    "guides": {
        "zabbix_setup": True,
        "fleet_install": True,
        "isms_criteria": True,
        "iso27001_criteria": True,
        "ldap_setup": True,
        "incident_response": True,
        "security_policy": True,
        "risk_methodology": True,
    },
}


DEFAULT_UI_PAYLOAD = {
    "intent": "offline_hosts",
    "scope": {"time_range": "24h"},
    "filters": {},
}



__all__ = [
    'json',
    'os',
    '_i18n_script',
    '_i18n_toggle_html',
    '_DASHBOARD_I18N',
    '_ADMIN_I18N',
    '_LOGIN_I18N',
    '_SIGNUP_I18N',
    'QUERY_GUIDE_EXAMPLES',
    'DOCS_PORTAL_URL',
    'FLEET_UI_URL',
    'ZABBIX_UI_URL',
    'WAZUH_UI_URL',
    'GRAFANA_UI_URL',
    'USER_DASHBOARD_CARD_LABELS',
    'USER_DASHBOARD_SECTION_LABELS',
    'USER_DASHBOARD_ASSET_COLUMN_LABELS',
    'USER_DASHBOARD_GUIDE_LABELS',
    'DEFAULT_USER_DASHBOARD_PREFERENCES',
    'DEFAULT_UI_PAYLOAD',
]
