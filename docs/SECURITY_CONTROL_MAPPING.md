# Security Control Mapping

Version: v1.0

Author: Sarang Baek

Document Type: Security Control Mapping

---

## 1. Document Purpose

본 문서는 **Security Visibility Platform**이 제공하는 기능을 보안 통제(Security Controls)와 매핑한다.

Security Control Mapping은 다음 목적을 가진다.

- 보안 요구사항과 시스템 기능 연결
- 보안 운영 가시성 확보
- 조직 보안 통제 준수 지원
- 보안 감사 대응

본 문서는 **ISMS / ISO 27001 / 일반 보안 운영 기준**을 참고하여 작성되었다.

> **현행화(2026-07-08)**: 이 문서의 개념 매핑은 이제 **실제 통제 카탈로그**로 구현되어 있다.
> - 카탈로그 원본: `controls/`(ISMS-P + ISO 27001, 한·영 병기) — 총 194건(ISMS-P 101 + ISO 93)
> - 스키마: `schema/007_controls.sql`(`controls` / `control_mappings` / `control_defects`)
> - UI: **컴플라이언스 탭**의 통제 트리(도메인 → 통제 계층)
> - 이행상태 편집: `schema/009_control_status.sql`(`control_status`)로 status/owner/exception_reason/improvement_plan/due_date를 편집·영속화
>
> 아래 §2~§11의 매핑 표는 개념 수준의 요약이며, 최신·상세 매핑은 위 카탈로그를 정본으로 한다.

## 2. Security Control Categories

Security Visibility Platform은 다음 보안 통제 영역을 지원한다.

| Control Domain | 설명 |
| --- | --- |
| Asset Management | IT 자산 식별 및 관리 |
| Monitoring | 시스템 상태 모니터링 |
| Log Management | 로그 수집 및 분석 |
| Endpoint Security | 사용자 단말 보안 |
| Vulnerability Management | 취약점 관리 |
| Incident Detection | 침해 이벤트 탐지 |

## 3. Security Control Mapping

다음 표는 시스템 기능과 보안 통제 간의 매핑을 설명한다.

| Security Control | Description | Implementation |
| --- | --- | --- |
| Asset Visibility | 조직 내 IT 자산 식별 | Zabbix Host Inventory |
| Infrastructure Monitoring | 서버 상태 모니터링 | Zabbix Monitoring |
| Endpoint Visibility | 사용자 PC 상태 확인 | FleetDM |
| Log Collection | 로그 중앙 수집 | Fluent Bit + Loki |
| Log Retention | 로그 보관 정책 | Loki Storage |
| Security Event Detection | 이상 이벤트 탐지 | Wazuh |
| Alerting | 보안 이벤트 경보 | Grafana Alert |
| Vulnerability Scanning | 취약점 점검 | Trivy |
| Security Dashboard | 보안 상태 시각화 | Grafana |

## 4. Asset Management Controls

시스템은 IT 자산을 식별하고 상태를 관리한다.

### 구현 방식

- Zabbix Agent 기반 자산 등록
- 자동 Host Discovery
- Host 상태 모니터링

### 수집 정보

| 항목 | 설명 |
| --- | --- |
| Hostname | 시스템 이름 |
| IP Address | 네트워크 주소 |
| OS Version | 운영체제 버전 |
| System Status | Online / Offline |

## 5. Monitoring Controls

Monitoring Controls는 시스템 상태를 지속적으로 감시한다.

### 모니터링 대상

| 대상 | 항목 |
| --- | --- |
| Server | CPU, Memory |
| Storage | Disk Usage |
| Network | Interface Status |
| Services | Process Status |

### 구현 도구

Zabbix Monitoring System

## 6. Endpoint Security Controls

Endpoint Security Controls는 사용자 PC 보안 상태를 관리한다.

### 점검 항목

| 항목 | 설명 |
| --- | --- |
| Disk Encryption | BitLocker 활성 여부 |
| Admin Accounts | 관리자 계정 존재 여부 |
| OS Patch | OS 업데이트 상태 |
| Installed Software | 설치된 프로그램 목록 |

### 구현 도구

FleetDM (osquery 기반)

## 7. Log Management Controls

Log Management Controls는 로그를 중앙 수집하고 분석한다.

### 로그 유형

| 로그 유형 | 설명 |
| --- | --- |
| System Logs | 시스템 이벤트 |
| Security Logs | 보안 이벤트 |
| Application Logs | 애플리케이션 로그 |

### 구현 구조

Fluent Bit → Loki → Grafana

## 8. Vulnerability Management Controls

취약점 관리 통제는 시스템의 보안 취약점을 식별한다.

### 스캔 대상

| 대상 | 설명 |
| --- | --- |
| OS Packages | 운영체제 패키지 |
| Container Images | 컨테이너 이미지 |
| Application Dependencies | 라이브러리 |

### 구현 도구

Trivy Vulnerability Scanner

## 9. Incident Detection Controls

보안 이벤트 탐지는 잠재적인 침해를 탐지한다.

### 탐지 이벤트

| 이벤트 | 설명 |
| --- | --- |
| Login Failures | 로그인 실패 증가 |
| Privileged Account Creation | 관리자 계정 생성 |
| Log Deletion | 로그 삭제 시도 |
| Suspicious Commands | 의심 명령 실행 |

### 구현 도구

Wazuh Detection Engine

## 10. Security Reporting

플랫폼은 보안 상태 리포트를 생성할 수 있다.

리포트 항목

- 시스템 가용성
- 취약점 현황
- 단말 보안 준수율
- 보안 이벤트 분석

### 시각화 도구

Grafana Dashboard

## 11. Compliance Alignment

Security Visibility Platform은 다음 보안 프레임워크와 연계될 수 있다.

| Framework | 설명 |
| --- | --- |
| ISMS | 한국 정보보호 관리체계 |
| ISO 27001 | 국제 정보보안 관리 기준 |
| CIS Controls | 보안 모범 사례 |