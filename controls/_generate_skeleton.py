#!/usr/bin/env python3
"""controls/ 전 항목 골격 생성기 (ISMS-P 2023 101 + ISO 27001:2022 Annex A 93).

Full-catalog skeleton generator. Emits one bilingual YAML per control into
``isms-p/`` and ``iso27001/``. Controls that already have a hand-authored file
are SKIPPED (deep entries with rich intent/evidence are preserved).

Skeletons are ``status: draft`` — titles/structure are v1 and should be verified
against the official standard (KISA ISMS-P 고시 / ISO/IEC 27001:2022 Annex A).

    python controls/_generate_skeleton.py            # write missing skeletons
    python controls/_generate_skeleton.py --force    # overwrite all (incl. deep)
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent

# ── ISO/IEC 27001:2022 Annex A — (id, domain, section, title_ko, title_en) ──────
_ISO_DOMAINS = {
    "A.5": "A.5 Organizational controls",
    "A.6": "A.6 People controls",
    "A.7": "A.7 Physical controls",
    "A.8": "A.8 Technological controls",
}
ISO = [
    ("A.5.1", "정보보안 정책", "Policies for information security"),
    ("A.5.2", "정보보안 역할 및 책임", "Information security roles and responsibilities"),
    ("A.5.3", "직무 분리", "Segregation of duties"),
    ("A.5.4", "경영진의 책임", "Management responsibilities"),
    ("A.5.5", "관계 당국과의 연락", "Contact with authorities"),
    ("A.5.6", "전문가 그룹과의 연락", "Contact with special interest groups"),
    ("A.5.7", "위협 인텔리전스", "Threat intelligence"),
    ("A.5.8", "프로젝트 관리에서의 정보보안", "Information security in project management"),
    ("A.5.9", "정보 및 관련 자산의 목록", "Inventory of information and other associated assets"),
    ("A.5.10", "정보 및 관련 자산의 허용 가능한 사용", "Acceptable use of information and other associated assets"),
    ("A.5.11", "자산의 반납", "Return of assets"),
    ("A.5.12", "정보의 분류", "Classification of information"),
    ("A.5.13", "정보의 레이블링", "Labelling of information"),
    ("A.5.14", "정보 전송", "Information transfer"),
    ("A.5.15", "접근통제", "Access control"),
    ("A.5.16", "식별자 관리", "Identity management"),
    ("A.5.17", "인증 정보", "Authentication information"),
    ("A.5.18", "접근 권한", "Access rights"),
    ("A.5.19", "공급자 관계에서의 정보보안", "Information security in supplier relationships"),
    ("A.5.20", "공급자 계약 내 정보보안", "Addressing information security within supplier agreements"),
    ("A.5.21", "ICT 공급망의 정보보안 관리", "Managing information security in the ICT supply chain"),
    ("A.5.22", "공급자 서비스의 모니터링·검토·변경관리", "Monitoring, review and change management of supplier services"),
    ("A.5.23", "클라우드 서비스 이용의 정보보안", "Information security for use of cloud services"),
    ("A.5.24", "정보보안 사고 관리 계획 및 준비", "Information security incident management planning and preparation"),
    ("A.5.25", "정보보안 이벤트의 평가 및 결정", "Assessment and decision on information security events"),
    ("A.5.26", "정보보안 사고 대응", "Response to information security incidents"),
    ("A.5.27", "정보보안 사고로부터의 학습", "Learning from information security incidents"),
    ("A.5.28", "증거 수집", "Collection of evidence"),
    ("A.5.29", "중단 중 정보보안", "Information security during disruption"),
    ("A.5.30", "사업연속성을 위한 ICT 준비", "ICT readiness for business continuity"),
    ("A.5.31", "법적·규제적·계약적 요구사항", "Legal, statutory, regulatory and contractual requirements"),
    ("A.5.32", "지식재산권", "Intellectual property rights"),
    ("A.5.33", "기록의 보호", "Protection of records"),
    ("A.5.34", "프라이버시 및 개인식별정보(PII) 보호", "Privacy and protection of PII"),
    ("A.5.35", "정보보안의 독립적 검토", "Independent review of information security"),
    ("A.5.36", "정보보안 정책·규칙·표준 준수", "Compliance with policies, rules and standards for information security"),
    ("A.5.37", "문서화된 운영 절차", "Documented operating procedures"),
    ("A.6.1", "채용 심사", "Screening"),
    ("A.6.2", "고용 조건", "Terms and conditions of employment"),
    ("A.6.3", "정보보안 인식제고·교육·훈련", "Information security awareness, education and training"),
    ("A.6.4", "징계 절차", "Disciplinary process"),
    ("A.6.5", "고용 종료 또는 변경 후 책임", "Responsibilities after termination or change of employment"),
    ("A.6.6", "기밀유지 또는 비밀유지 협약", "Confidentiality or non-disclosure agreements"),
    ("A.6.7", "원격 근무", "Remote working"),
    ("A.6.8", "정보보안 이벤트 보고", "Information security event reporting"),
    ("A.7.1", "물리적 보안 경계", "Physical security perimeters"),
    ("A.7.2", "물리적 출입", "Physical entry"),
    ("A.7.3", "사무실·공간·시설의 보안", "Securing offices, rooms and facilities"),
    ("A.7.4", "물리적 보안 모니터링", "Physical security monitoring"),
    ("A.7.5", "물리적·환경적 위협에 대한 보호", "Protecting against physical and environmental threats"),
    ("A.7.6", "보안 구역에서의 작업", "Working in secure areas"),
    ("A.7.7", "클리어 데스크·클리어 스크린", "Clear desk and clear screen"),
    ("A.7.8", "장비 배치 및 보호", "Equipment siting and protection"),
    ("A.7.9", "사외 자산의 보안", "Security of assets off-premises"),
    ("A.7.10", "저장 매체", "Storage media"),
    ("A.7.11", "지원 유틸리티", "Supporting utilities"),
    ("A.7.12", "케이블 보안", "Cabling security"),
    ("A.7.13", "장비 유지보수", "Equipment maintenance"),
    ("A.7.14", "장비의 안전한 폐기 또는 재사용", "Secure disposal or re-use of equipment"),
    ("A.8.1", "사용자 엔드포인트 장치", "User endpoint devices"),
    ("A.8.2", "특권 접근 권한", "Privileged access rights"),
    ("A.8.3", "정보 접근 제한", "Information access restriction"),
    ("A.8.4", "소스코드 접근", "Access to source code"),
    ("A.8.5", "안전한 인증", "Secure authentication"),
    ("A.8.6", "용량 관리", "Capacity management"),
    ("A.8.7", "멀웨어에 대한 보호", "Protection against malware"),
    ("A.8.8", "기술적 취약점 관리", "Management of technical vulnerabilities"),
    ("A.8.9", "형상 관리", "Configuration management"),
    ("A.8.10", "정보 삭제", "Information deletion"),
    ("A.8.11", "데이터 마스킹", "Data masking"),
    ("A.8.12", "데이터 유출 방지", "Data leakage prevention"),
    ("A.8.13", "정보 백업", "Information backup"),
    ("A.8.14", "정보처리시설의 이중화", "Redundancy of information processing facilities"),
    ("A.8.15", "로깅", "Logging"),
    ("A.8.16", "모니터링 활동", "Monitoring activities"),
    ("A.8.17", "시각 동기화", "Clock synchronization"),
    ("A.8.18", "특권 유틸리티 프로그램 사용", "Use of privileged utility programs"),
    ("A.8.19", "운영 시스템의 소프트웨어 설치", "Installation of software on operational systems"),
    ("A.8.20", "네트워크 보안", "Networks security"),
    ("A.8.21", "네트워크 서비스의 보안", "Security of network services"),
    ("A.8.22", "네트워크 분리", "Segregation of networks"),
    ("A.8.23", "웹 필터링", "Web filtering"),
    ("A.8.24", "암호화 사용", "Use of cryptography"),
    ("A.8.25", "안전한 개발 수명주기", "Secure development life cycle"),
    ("A.8.26", "애플리케이션 보안 요구사항", "Application security requirements"),
    ("A.8.27", "안전한 시스템 아키텍처 및 엔지니어링 원칙", "Secure system architecture and engineering principles"),
    ("A.8.28", "시큐어 코딩", "Secure coding"),
    ("A.8.29", "개발 및 인수 단계의 보안 테스트", "Security testing in development and acceptance"),
    ("A.8.30", "외주 개발", "Outsourced development"),
    ("A.8.31", "개발·테스트·운영 환경 분리", "Separation of development, test and production environments"),
    ("A.8.32", "변경 관리", "Change management"),
    ("A.8.33", "테스트 정보", "Test information"),
    ("A.8.34", "감사 테스트 중 정보시스템 보호", "Protection of information systems during audit testing"),
]

# ── ISMS-P 2023 — (id, section_title, title_ko, title_en) ───────────────────────
_ISMSP_DOMAIN = {
    "1": "1. 관리체계 수립 및 운영",
    "2": "2. 보호대책 요구사항",
    "3": "3. 개인정보 처리단계별 요구사항",
}
_ISMSP_SECTION = {
    "1.1": "1.1 관리체계 기반 마련", "1.2": "1.2 위험 관리", "1.3": "1.3 관리체계 운영",
    "1.4": "1.4 관리체계 점검 및 개선",
    "2.1": "2.1 정책, 조직, 자산 관리", "2.2": "2.2 인적 보안", "2.3": "2.3 외부자 보안",
    "2.4": "2.4 물리 보안", "2.5": "2.5 인증 및 권한관리", "2.6": "2.6 접근통제",
    "2.7": "2.7 암호화 적용", "2.8": "2.8 정보시스템 도입 및 개발 보안",
    "2.9": "2.9 시스템 및 서비스 운영관리", "2.10": "2.10 시스템 및 서비스 보안관리",
    "2.11": "2.11 사고 예방 및 대응", "2.12": "2.12 재해복구",
    "3.1": "3.1 개인정보 수집 시 보호조치", "3.2": "3.2 개인정보 보유 및 이용 시 보호조치",
    "3.3": "3.3 개인정보 제공 시 보호조치", "3.4": "3.4 개인정보 파기 시 보호조치",
    "3.5": "3.5 정보주체 권리보호",
}
ISMSP = [
    ("1.1.1", "경영진의 참여", "Management commitment"),
    ("1.1.2", "최고책임자의 지정", "Designation of the CISO/CPO"),
    ("1.1.3", "조직 구성", "Organizational structure"),
    ("1.1.4", "범위 설정", "Scope definition"),
    ("1.1.5", "정책 수립", "Policy establishment"),
    ("1.1.6", "자원 할당", "Resource allocation"),
    ("1.2.1", "정보자산 식별", "Information asset identification"),
    ("1.2.2", "현황 및 흐름분석", "Current-state and flow analysis"),
    ("1.2.3", "위험 평가", "Risk assessment"),
    ("1.2.4", "보호대책 선정", "Selection of protective measures"),
    ("1.3.1", "보호대책 구현", "Implementation of protective measures"),
    ("1.3.2", "보호대책 공유", "Sharing of protective measures"),
    ("1.3.3", "운영현황 관리", "Operational status management"),
    ("1.4.1", "법적 요구사항 준수 검토", "Legal-requirement compliance review"),
    ("1.4.2", "관리체계 점검", "Management-system review"),
    ("1.4.3", "관리체계 개선", "Management-system improvement"),
    ("2.1.1", "정책의 유지관리", "Policy maintenance"),
    ("2.1.2", "조직의 유지관리", "Organization maintenance"),
    ("2.1.3", "정보자산 관리", "Information asset management"),
    ("2.2.1", "주요 직무자 지정 및 관리", "Designation and management of key personnel"),
    ("2.2.2", "직무 분리", "Segregation of duties"),
    ("2.2.3", "보안 서약", "Security pledge"),
    ("2.2.4", "인식제고 및 교육훈련", "Awareness and training"),
    ("2.2.5", "퇴직 및 직무변경 관리", "Termination and job-change management"),
    ("2.2.6", "보안 위반 시 조치", "Actions on security violations"),
    ("2.3.1", "외부자 현황 관리", "Third-party status management"),
    ("2.3.2", "외부자 계약 시 보안", "Security in third-party contracts"),
    ("2.3.3", "외부자 보안 이행 관리", "Third-party security compliance management"),
    ("2.3.4", "외부자 계약 변경 및 만료 시 보안", "Security on third-party contract change/expiry"),
    ("2.4.1", "보호구역 지정", "Designation of protected areas"),
    ("2.4.2", "출입통제", "Physical access control"),
    ("2.4.3", "정보시스템 보호", "Information-system protection"),
    ("2.4.4", "보호설비 운영", "Operation of protective facilities"),
    ("2.4.5", "보호구역 내 작업", "Work in protected areas"),
    ("2.4.6", "반출입 기기 통제", "Control of devices brought in/out"),
    ("2.4.7", "업무환경 보안", "Work-environment security"),
    ("2.5.1", "사용자 계정 관리", "User account management"),
    ("2.5.2", "사용자 식별", "User identification"),
    ("2.5.3", "사용자 인증", "User authentication"),
    ("2.5.4", "비밀번호 관리", "Password management"),
    ("2.5.5", "특수 계정 및 권한 관리", "Privileged account and rights management"),
    ("2.5.6", "접근권한 검토", "Access-rights review"),
    ("2.6.1", "네트워크 접근", "Network access"),
    ("2.6.2", "정보시스템 접근", "Information-system access"),
    ("2.6.3", "응용프로그램 접근", "Application access"),
    ("2.6.4", "데이터베이스 접근", "Database access"),
    ("2.6.5", "무선 네트워크 접근", "Wireless-network access"),
    ("2.6.6", "원격접근 통제", "Remote-access control"),
    ("2.6.7", "인터넷 접속 통제", "Internet-access control"),
    ("2.7.1", "암호정책 적용", "Cryptography policy application"),
    ("2.7.2", "암호키 관리", "Cryptographic key management"),
    ("2.8.1", "보안 요구사항 정의", "Security-requirements definition"),
    ("2.8.2", "보안 요구사항 검토 및 시험", "Security-requirements review and testing"),
    ("2.8.3", "시험과 운영 환경 분리", "Separation of test and production environments"),
    ("2.8.4", "시험 데이터 보안", "Test-data security"),
    ("2.8.5", "소스 프로그램 관리", "Source-code management"),
    ("2.8.6", "운영환경 이관", "Migration to production"),
    ("2.9.1", "변경관리", "Change management"),
    ("2.9.2", "성능 및 장애관리", "Performance and fault management"),
    ("2.9.3", "백업 및 복구관리", "Backup and recovery management"),
    ("2.9.4", "로그 및 접속기록 관리", "Log and access-record management"),
    ("2.9.5", "로그 및 접속기록 점검", "Log and access-record review"),
    ("2.9.6", "시간 동기화", "Time synchronization"),
    ("2.9.7", "정보자산의 재사용 및 폐기", "Asset reuse and disposal"),
    ("2.10.1", "보안시스템 운영", "Security-system operation"),
    ("2.10.2", "클라우드 보안", "Cloud security"),
    ("2.10.3", "공개서버 보안", "Public-server security"),
    ("2.10.4", "전자거래 및 핀테크 보안", "E-commerce and fintech security"),
    ("2.10.5", "정보전송 보안", "Information-transfer security"),
    ("2.10.6", "업무용 단말기기 보안", "Business device (endpoint) security"),
    ("2.10.7", "보조저장매체 관리", "Removable-media management"),
    ("2.10.8", "패치관리", "Patch management"),
    ("2.10.9", "악성코드 통제", "Malware control"),
    ("2.11.1", "사고 예방 및 대응체계 구축", "Incident prevention and response framework"),
    ("2.11.2", "취약점 점검 및 조치", "Vulnerability assessment and remediation"),
    ("2.11.3", "이상행위 분석 및 모니터링", "Anomaly analysis and monitoring"),
    ("2.11.4", "사고 대응 훈련 및 개선", "Incident-response drills and improvement"),
    ("2.11.5", "사고 대응 및 복구", "Incident response and recovery"),
    ("2.12.1", "재해·재난 대비 안전조치", "Disaster/emergency safeguards"),
    ("2.12.2", "재해 복구 시험 및 개선", "Disaster-recovery testing and improvement"),
    ("3.1.1", "개인정보 수집·이용", "Collection and use of personal data"),
    ("3.1.2", "개인정보 수집 제한", "Limitation on personal-data collection"),
    ("3.1.3", "주민등록번호 처리 제한", "Restriction on resident-registration-number processing"),
    ("3.1.4", "민감정보 및 고유식별정보의 처리 제한", "Restriction on sensitive/unique-identifier processing"),
    ("3.1.5", "개인정보 간접수집", "Indirect collection of personal data"),
    ("3.1.6", "영상정보처리기기 설치·운영", "CCTV installation and operation"),
    ("3.1.7", "홍보 및 마케팅 목적 활용 시 조치", "Measures for marketing use"),
    ("3.2.1", "개인정보 현황관리", "Personal-data inventory management"),
    ("3.2.2", "개인정보 품질보장", "Personal-data quality assurance"),
    ("3.2.3", "이용자 단말기 접근 보호", "Protection of access to user devices"),
    ("3.2.4", "개인정보 목적 외 이용 및 제공", "Use/provision beyond the stated purpose"),
    ("3.2.5", "가명정보 처리", "Pseudonymized-data processing"),
    ("3.3.1", "개인정보 제3자 제공", "Provision of personal data to third parties"),
    ("3.3.2", "업무 위탁에 따른 정보주체 통지", "Notice to data subjects on outsourcing"),
    ("3.3.3", "영업의 양수 등에 따른 개인정보 이전", "Personal-data transfer on business transfer"),
    ("3.3.4", "개인정보 국외이전", "Cross-border transfer of personal data"),
    ("3.4.1", "개인정보 파기", "Destruction of personal data"),
    ("3.4.2", "처리목적 달성 후 보유 시 조치", "Measures when retained after purpose fulfilment"),
    ("3.5.1", "개인정보처리방침 공개", "Disclosure of the privacy policy"),
    ("3.5.2", "정보주체 권리보장", "Guaranteeing data-subject rights"),
    ("3.5.3", "정보주체에 대한 통지", "Notice to data subjects"),
]


def _yaml_escape(s: str) -> str:
    return s.replace('"', '\\"')


def _emit(path: pathlib.Path, fields: dict) -> None:
    lines = []
    for k, v in fields.items():
        if isinstance(v, list):
            inner = ", ".join(v)
            lines.append(f"{k}: [{inner}]")
        else:
            lines.append(f'{k}: "{_yaml_escape(str(v))}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    force = "--force" in sys.argv
    written = skipped = 0

    for cid, ko, en in ISO:
        prefix = ".".join(cid.split(".")[:2])  # 'A.5'
        path = ROOT / "iso27001" / f"{cid}.yaml"
        if path.exists() and not force:
            skipped += 1
            continue
        _emit(path, {
            "id": cid, "framework": "iso27001", "version": "2022",
            "domain": _ISO_DOMAINS[prefix], "title_ko": ko, "title_en": en,
            "evidence_sources": [], "status": "draft",
        })
        written += 1

    for cid, ko, en in ISMSP:
        parts = cid.split(".")
        dom = _ISMSP_DOMAIN[parts[0]]
        sec = _ISMSP_SECTION[f"{parts[0]}.{parts[1]}"]
        path = ROOT / "isms-p" / f"{cid}.yaml"
        if path.exists() and not force:
            skipped += 1
            continue
        _emit(path, {
            "id": cid, "framework": "isms-p", "version": "2023",
            "domain": dom, "section": sec, "title_ko": ko, "title_en": en,
            "evidence_sources": [], "status": "draft",
        })
        written += 1

    print(f"written={written}, skipped(existing)={skipped}, "
          f"total ISO={len(ISO)}, ISMS-P={len(ISMSP)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
