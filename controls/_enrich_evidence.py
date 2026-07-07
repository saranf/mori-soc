#!/usr/bin/env python3
"""draft 골격 통제에 evidence_sources + 짧은 한/영 intent 를 채워 reviewed 로 승격.

MORI 5소스(Zabbix/Wazuh/Fleet/Trivy/Loki/MORI)가 실제로 증적을 만드는 통제만 대상.
텍스트 레벨 패치(skeleton 포맷 보존): ``evidence_sources: []`` → 실제 소스,
``status: "draft"`` → ``reviewed``, 그리고 title_en 다음에 intent_ko/intent_en 삽입.
idempotent — 이미 reviewed(직접 작성한 14건)는 건드리지 않는다.

    python controls/_enrich_evidence.py     # 이후 _build_catalog_json.py 재실행
"""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent

# id -> (sources, intent_ko, intent_en)
ENRICH: dict[str, tuple[list[str], str, str]] = {
    # ── ISMS-P ──
    "1.3.3": (["mori"], "보호대책의 운영현황을 지속 점검하고 이력을 관리한다.",
              "Continuously review and record the operating status of protective measures."),
    "1.4.2": (["mori"], "관리체계가 의도대로 운영되는지 정기 점검하고 결과를 기록한다.",
              "Periodically review whether the management system operates as intended and record results."),
    "2.1.3": (["fleet", "zabbix"], "정보자산을 최신 상태로 관리하고 변경 이력을 유지한다.",
              "Keep information assets current and maintain their change history."),
    "2.9.2": (["zabbix"], "시스템 성능·장애를 모니터링하고 임계치 초과·장애를 기록·대응한다.",
              "Monitor performance/faults; record and respond to threshold breaches and outages."),
    "2.9.5": (["loki", "wazuh"], "로그·접속기록을 정기적으로 점검하여 이상 여부를 확인한다.",
              "Periodically review logs/access records to detect anomalies."),
    "2.10.1": (["wazuh"], "보안시스템(탐지·차단)의 정책과 이벤트를 운영·점검한다.",
               "Operate and review the policies and events of security systems (detection/blocking)."),
    "2.11.1": (["mori", "wazuh"], "사고 예방·대응 체계를 수립하고 탐지→대응 절차를 운영한다.",
               "Establish an incident prevention/response framework and run the detect→respond procedure."),
    "2.11.4": (["mori"], "사고 대응 훈련을 수행하고 결과를 반영해 절차를 개선한다.",
               "Conduct incident-response drills and improve procedures from the results."),
    # ── ISO 27001:2022 ──
    "A.5.24": (["mori"], "정보보안 사고 관리 계획을 수립·준비한다.",
               "Plan and prepare for information security incident management."),
    "A.5.25": (["mori", "wazuh"], "정보보안 이벤트를 평가하여 사고 여부를 결정한다.",
               "Assess information security events and decide whether they are incidents."),
    "A.5.26": (["mori"], "정해진 절차에 따라 정보보안 사고에 대응한다.",
               "Respond to information security incidents per defined procedures."),
    "A.5.27": (["mori"], "사고로부터 교훈을 도출해 통제를 개선한다.",
               "Derive lessons from incidents to strengthen controls."),
    "A.8.1": (["fleet"], "사용자 엔드포인트 장치를 보호·점검한다.",
              "Protect and check user endpoint devices."),
    "A.8.6": (["zabbix"], "자원 사용량을 모니터링하고 용량을 관리한다.",
              "Monitor resource usage and manage capacity."),
    "A.8.19": (["fleet"], "운영 시스템에 설치된 소프트웨어를 식별·통제한다.",
               "Identify and control software installed on operational systems."),
    # ── 2차 확장: 방어 가능한 기술/운영 통제 ──
    "1.3.1": (["mori"], "선정한 보호대책을 구현하고 구현 현황을 관리한다.",
              "Implement selected protective measures and track implementation status."),
    "1.4.1": (["mori"], "법적 요구사항 준수 여부를 정기 검토하고 결과를 기록한다.",
              "Periodically review legal-requirement compliance and record results."),
    "1.4.3": (["mori"], "점검 결과를 반영해 관리체계를 개선한다.",
              "Improve the management system based on review findings."),
    "2.5.6": (["mori"], "사용자 접근권한의 적정성을 정기 검토하고 이력을 남긴다.",
              "Periodically review the appropriateness of access rights and keep records."),
    "2.6.1": (["zabbix", "wazuh"], "네트워크 접근·연결 상태를 모니터링하고 이상을 탐지한다.",
              "Monitor network access/connectivity and detect anomalies."),
    "2.9.1": (["mori"], "변경을 통제 절차에 따라 승인·기록한다.",
              "Approve and record changes per the change-control procedure."),
    "2.10.3": (["trivy", "zabbix"], "공개서버의 취약점·가용성을 점검·모니터링한다.",
               "Scan and monitor public servers for vulnerabilities and availability."),
    "2.12.2": (["mori"], "재해 복구 시험을 수행하고 결과로 절차를 개선한다.",
               "Run disaster-recovery tests and improve procedures from the results."),
    "A.5.7": (["wazuh"], "위협 인텔리전스를 수집·활용해 탐지에 반영한다.",
              "Collect and use threat intelligence to inform detection."),
    "A.5.18": (["mori"], "접근 권한을 부여·검토·회수하고 이력을 관리한다.",
              "Provision, review and revoke access rights, keeping records."),
    "A.5.35": (["mori"], "정보보안에 대한 독립적 검토를 수행·기록한다.",
               "Perform and record independent reviews of information security."),
    "A.5.36": (["mori"], "정책·규칙·표준 준수를 점검하고 결과를 관리한다.",
               "Check compliance with policies, rules and standards and manage results."),
    "A.8.14": (["zabbix"], "정보처리시설의 가용성·이중화를 모니터링한다.",
               "Monitor availability and redundancy of information-processing facilities."),
    "A.8.17": (["zabbix"], "시스템 시각 동기화를 점검한다.",
               "Check clock synchronization across systems."),
    "A.8.20": (["zabbix", "wazuh"], "네트워크 보안 상태를 모니터링·점검한다.",
               "Monitor and review network security."),
    "A.8.21": (["zabbix"], "네트워크 서비스의 보안·가용성을 모니터링한다.",
               "Monitor security and availability of network services."),
    "A.8.32": (["mori"], "변경을 통제 절차에 따라 관리·기록한다.",
               "Manage and record changes per the change-control procedure."),
    "2.8.2": (["trivy"], "개발 산출물의 보안 요구사항을 검토하고 취약점 시험을 수행한다.",
              "Review security requirements and run vulnerability testing on development artifacts."),
    "A.8.29": (["trivy"], "개발·인수 단계에서 보안 테스트를 수행한다.",
               "Perform security testing during development and acceptance."),
}


def _patch(path: pathlib.Path, sources: list[str], intent_ko: str, intent_en: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if "status: \"draft\"" not in text and "status: draft" not in text:
        return False  # 이미 reviewed 이거나 대상 아님
    src_yaml = "[" + ", ".join(sources) + "]"
    lines = text.splitlines()
    out = []
    for ln in lines:
        if ln.startswith("evidence_sources:"):
            out.append(f"evidence_sources: {src_yaml}")
        elif ln.startswith("status:"):
            out.append("status: reviewed")
        else:
            out.append(ln)
        if ln.startswith("title_en:"):
            out.append(f'intent_ko: "{intent_ko}"')
            out.append(f'intent_en: "{intent_en}"')
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return True


def main() -> int:
    patched = 0
    for cid, (sources, ik, ie) in ENRICH.items():
        sub = "iso27001" if cid.startswith("A.") else "isms-p"
        path = ROOT / sub / f"{cid}.yaml"
        if not path.exists():
            print(f"  ! missing {path.name}")
            continue
        if _patch(path, sources, ik, ie):
            patched += 1
    print(f"enriched {patched}/{len(ENRICH)} controls (draft → reviewed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
