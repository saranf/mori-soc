Version: v1.0

Author: Sarang Baek

Document Type: Functional Specification

# 1. Document Purpose

본 문서는 **Security Visibility Platform**의 기능 요구사항을 정의한다.

본 시스템은 오픈소스 기반의 보안 가시성 플랫폼으로, 다음 기능을 제공한다.

- IT 자산 상태 모니터링
- 중앙 로그 수집 및 분석
- 사용자 단말 보안 상태 점검
- 취약점 스캔 및 관리
- 이상 이벤트 경보 시스템
- 보안 현황 대시보드 및 리포팅

본 문서는 시스템 기능의 범위와 동작 방식을 정의하여 개발 및 운영 기준을 제공한다.

---

# 2. System Overview

Security Visibility Platform은 조직의 IT 환경을 중앙에서 모니터링하고 보안 상태를 분석하는 플랫폼이다.

본 시스템은 다음 영역을 통합한다.

| 영역 | 설명 |
| --- | --- |
| Infrastructure Monitoring | 서버 및 네트워크 상태 모니터링 |
| Endpoint Security | 사용자 PC 보안 상태 확인 |
| Log Management | 로그 중앙 수집 및 분석 |
| Vulnerability Management | 취약점 스캔 |
| Security Event Detection | 이상 이벤트 탐지 |
| Security Dashboard | 보안 현황 시각화 |

---

# 3. Functional Modules

시스템은 다음 기능 모듈로 구성된다.

---

# 3.1 Infrastructure Monitoring Module

## 목적

서버 및 인프라 상태를 모니터링하여 시스템 장애를 조기에 감지한다.

## 주요 기능

- 서버 온라인 상태 확인
- CPU 사용량 모니터링
- 메모리 사용량 모니터링
- 디스크 사용량 모니터링
- 서비스 상태 감시
- 로그 기반 이벤트 감지

## 주요 경보 예시

| 이벤트 | 설명 |
| --- | --- |
| Host Down | 서버 또는 PC 응답 없음 |
| High CPU Usage | CPU 사용률 90% 이상 |
| Disk Usage | 디스크 사용률 90% 이상 |
| Service Failure | 서비스 프로세스 종료 |

# 3.2 Endpoint Security Module

## 목적

사용자 PC의 보안 설정 상태를 점검한다.

## 주요 기능

- 디스크 암호화 상태 확인
- 관리자 계정 확인
- OS 버전 확인
- 설치된 소프트웨어 목록 수집
- 정책 위반 단말 식별

## 주요 보안 점검 항목

| 항목 | 설명 |
| --- | --- |
| Disk Encryption | BitLocker 활성화 여부 |
| Admin Accounts | 관리자 권한 계정 수 |
| OS Version | 최신 OS 사용 여부 |
| Unauthorized Software | 승인되지 않은 프로그램 설치 |

# 3.3 Log Management Module

## 목적

시스템 및 보안 로그를 중앙에서 수집하고 분석한다.

## 주요 기능

- 애플리케이션 로그 수집
- Windows Event 로그 수집
- 로그 검색 기능
- 로그 패턴 분석
- 로그 보관 정책 관리

## 로그 예시

- 로그인 이벤트
- 애플리케이션 오류
- 보안 이벤트

# 3.4 Vulnerability Management Module

## 목적

서버 및 컨테이너 환경의 취약점을 식별하고 관리한다.

## 주요 기능

- Container Image 취약점 스캔
- OS 패키지 취약점 스캔
- 취약점 심각도 분류
- 취약점 변화 추이 분석

## 취약점 등급

| 등급 | 설명 |
| --- | --- |
| Critical | 즉시 조치 필요 |
| High | 빠른 조치 필요 |
| Medium | 일반 위험 |
| Low | 낮은 위험 |

# 3.5 Security Event Detection Module

## 목적

보안 관련 이상 이벤트를 탐지하고 경보를 생성한다.

## 주요 탐지 이벤트

| 이벤트 | 설명 |
| --- | --- |
| Login Failure Spike | 로그인 실패 증가 |
| Admin Account Created | 관리자 계정 생성 |
| Security Log Cleared | 보안 로그 삭제 |
| Suspicious PowerShell | 의심 PowerShell 실행 |

## 경보 레벨

| Level | 설명 |
| --- | --- |
| Critical | 즉시 대응 필요 |
| High | 보안 조사 필요 |
| Medium | 정책 위반 가능 |
| Low | 정보성 이벤트 |

# 3.6 Security Dashboard Module

## 목적

보안 상태를 시각적으로 표시한다.

## 주요 대시보드

### Security Overview

- 전체 자산 수
- 온라인 상태
- 취약점 개수
- 단말 보안 준수율

### Endpoint Compliance

- 암호화 적용률
- 관리자 계정 상태
- OS 버전 분포

### Vulnerability Dashboard

- 취약점 등급 분포
- 신규 취약점 발생 추이

### Security Event Timeline

- 최근 보안 이벤트
- 경보 이력

---

# 4. Alerting System

경보 시스템은 다음 기준으로 동작한다.

| Severity | 설명 |
| --- | --- |
| P1 | Critical Incident |
| P2 | High Risk Event |
| P3 | Policy Violation |
| P4 | Informational |

경보는 다음 방식으로 전달될 수 있다.

- Email
- Slack
- Dashboard Alert

---

# 5. Reporting

시스템은 정기 보안 리포트를 생성한다.

리포트 구성

1. 자산 현황
2. 가용성 통계
3. 취약점 현황
4. 단말 보안 준수율
5. 주요 보안 이벤트
6. 개선 계획

---

# 6. Non-Functional Requirements

| 항목 | 설명 |
| --- | --- |
| Scalability | 수백 대 시스템 확장 가능 |
| Availability | 중앙 시스템 24/7 운영 |
| Security | RBAC 기반 접근 제어 |
| Log Retention | 최소 90일 로그 보관 |

---

# 7. Future Enhancements

향후 확장 기능

- 자동 대응 시스템
- AI 기반 이벤트 분석
- 멀티 테넌트 구조
- 클라우드 환경 통합