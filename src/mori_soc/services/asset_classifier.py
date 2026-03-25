"""hostname 패턴 기반 서버 자산 자동 분류.

ISMS-P 인증 심사 대비용으로, Zabbix 서버 자산에 유형·중요도·ISMS 관련 통제 항목을
자동으로 부여합니다. 일반 PC(Fleet) 자산은 분류 불필요.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ServerClassification:
    category: str          # 서버 유형 (예: 도메인 컨트롤러)
    importance: str        # 중요도: 상 / 중 / 하
    isms_control: str      # 관련 ISMS-P 통제 항목 (예: 2.5 인증 및 접근통제)
    iso27001_control: str  # 관련 ISO/IEC 27001:2022 통제 항목 (예: A.8.1)
    category_en: str       # 영문 카테고리 (CSV 용)


# (regex_pattern, category, importance, isms_control, iso27001_control, category_en)
_RULES: list[tuple[str, str, str, str, str, str]] = [
    # Domain Controller / Active Directory
    (r"^(dc|ad|ldap|kerberos|activedir)", "도메인 컨트롤러", "상",
     "2.5 인증 및 접근통제", "A.5.15 접근통제 / A.8.2 특수접근권한", "Domain Controller"),
    # Database
    (r"^(db|database|mysql|postgres|oracle|mssql|maria|mongo|redis|elasticsearch)", "데이터베이스 서버", "상",
     "2.9 데이터베이스 보안", "A.8.10 정보삭제 / A.5.12 정보분류", "Database Server"),
    # Firewall / VPN / Network
    (r"^(fw|firewall|vpn|gw|gateway|proxy|utm|ids|ips)", "네트워크 보안 장비", "상",
     "2.6 네트워크 보안", "A.8.20 네트워크 보안 / A.8.21 네트워크서비스보안", "Network Security Appliance"),
    # Web Server
    (r"^(web|www|nginx|apache|iis|cdn|lb|loadbalancer)", "웹 서버", "상",
     "2.10 시스템 및 서비스 보안", "A.8.19 운영SW설치 / A.8.23 웹필터링", "Web Server"),
    # Application / API Server
    (r"^(app|api|was|tomcat|jboss|spring|node)", "어플리케이션 서버", "중",
     "2.10 시스템 및 서비스 보안", "A.8.19 운영SW설치 / A.8.28 보안코딩", "Application Server"),
    # Mail
    (r"^(mail|smtp|exchange|postfix|dovecot)", "메일 서버", "중",
     "2.10 시스템 및 서비스 보안", "A.8.22 네트워크분리 / A.8.23 웹필터링", "Mail Server"),
    # File / Storage
    (r"^(file|nas|storage|nfs|samba|ftp|sftp)", "파일 서버", "중",
     "2.5 인증 및 접근통제", "A.5.15 접근통제 / A.8.10 정보삭제", "File Server"),
    # Backup
    (r"^(backup|bkp|bak|veeam|bacula)", "백업 서버", "중",
     "2.12 업무연속성 보안", "A.8.13 정보백업 / A.5.29 중단시정보보안", "Backup Server"),
    # Monitoring / SIEM
    (r"^(monitor|zabbix|grafana|prometheus|kibana|splunk|siem|elk|wazuh)", "모니터링 서버", "하",
     "2.11 이벤트 처리", "A.8.15 로깅 / A.8.16 모니터링활동", "Monitoring Server"),
    # Dev / Test / Staging
    (r"^(dev|test|staging|qa|sandbox|demo|lab)", "개발/테스트 서버", "하",
     "2.10 시스템 및 서비스 보안", "A.8.31 개발·운영환경분리", "Dev/Test Server"),
    # Auth / SSO
    (r"^(auth|sso|idp|keycloak|okta|radius)", "인증 서버", "상",
     "2.5 인증 및 접근통제", "A.5.15 접근통제 / A.8.3 정보접근제한", "Auth Server"),
    # DNS / NTP
    (r"^(dns|ntp|dhcp)", "인프라 서버", "중",
     "2.6 네트워크 보안", "A.8.20 네트워크보안", "Infra Server"),
    # CI/CD / Build
    (r"^(jenkins|gitlab|github|ci|build|deploy|nexus|harbor|artifactory)", "CI/CD 서버", "하",
     "2.10 시스템 및 서비스 보안", "A.8.31 개발·운영환경분리 / A.8.32 변경관리", "CI/CD Server"),
]

_DEFAULT = ServerClassification(
    category="범용 서버",
    importance="중",
    isms_control="2.10 시스템 및 서비스 보안",
    iso27001_control="A.8.19 운영SW설치",
    category_en="General Server",
)


def _importance_boost(hostname: str, base: str) -> str:
    """*-prod / *-prd suffix 가 있으면 중요도를 한 단계 올린다."""
    low = hostname.lower()
    if re.search(r"[-_](prod|prd|live|real)$", low):
        if base == "하":
            return "중"
        if base == "중":
            return "상"
    return base


def classify_server(hostname: str) -> ServerClassification:
    """hostname 을 분석해 서버 분류 정보를 반환한다.

    Parameters
    ----------
    hostname:
        Zabbix 등 모니터링에서 수집한 호스트명 (대소문자 무관).
    """
    low = hostname.lower().lstrip("server-")  # strip 'server-' prefix from host_id style names
    # strip leading 'server-' or 'pc-' style normalised prefixes
    for prefix in ("server-", "pc-"):
        if low.startswith(prefix):
            low = low[len(prefix):]

    for pattern, category, importance, isms_control, iso27001_control, category_en in _RULES:
        if re.match(pattern, low):
            boosted = _importance_boost(hostname, importance)
            return ServerClassification(
                category=category,
                importance=boosted,
                isms_control=isms_control,
                iso27001_control=iso27001_control,
                category_en=category_en,
            )
    boosted = _importance_boost(hostname, _DEFAULT.importance)
    return ServerClassification(
        category=_DEFAULT.category,
        importance=boosted,
        isms_control=_DEFAULT.isms_control,
        iso27001_control=_DEFAULT.iso27001_control,
        category_en=_DEFAULT.category_en,
    )


def classify_server_as_dict(hostname: str) -> dict[str, str]:
    c = classify_server(hostname)
    return {
        "category": c.category,
        "importance": c.importance,
        "isms_control": c.isms_control,
        "iso27001_control": c.iso27001_control,
        "category_en": c.category_en,
    }

