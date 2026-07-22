Version: v1.1

Author: Sarang Baek

Document Type: Functional Specification

> **개정 이력**
> - **v1.1** — 현행 제품 정합화: MORI 는 단순 "보안 가시성"을 넘어 **인증(ISMS-P/ISO 27001) 증적 층**으로 확장됨.
>   컴플라이언스·증적(3.7), 개인정보 처리흐름(3.8), 실사용 온보딩·운영 안전(3.9) 모듈 추가,
>   비기능 요구(6)에 운영 안전 부팅 게이트·세션 영속·다국어(i18n)·성능 캐시 반영, 향후 계획(7) 구체화.
> - **v1.0** — 초기 보안 가시성 플랫폼 정의(3.1~3.6).

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

# 3.7 Compliance & Evidence Module (컴플라이언스·증적)

## 목적

수집한 운영 신호를 **인증 심사(ISMS-P·ISO 27001) 증적**으로 전환한다. MORI 의 정체성 —
"보는 층"이 아니라 **증적 층**. 도구가 만든 신호 → 사람의 판단 → 통제 증적으로 잇는다.

## 주요 기능

- 통제 카탈로그(ISMS-P × ISO 27001, 194개) + 프레임워크 교차 매핑
- 통제 성숙도 집계(draft/reviewed/mapped/auto_evidence)와 진행률
- 통제별 **증적 팩 PDF/CSV**(자산 인벤토리·실증적·문서화 증적) + **전체 증적 ZIP 번들**(HMAC 서명 매니페스트)
- SoA(적용선언서) 생성, PDCA 미조치 큐, 증적 신선도·감사 표본
- 코드 보안 리뷰 인제스트(SARIF/Claude) → 2.8 개발보안 통제 증적 자동 승격, GitHub OIDC 서명 검증

# 3.8 Privacy Data-Flow Module (개인정보 처리흐름, ISMS-P 3.x)

## 목적

개인정보의 **수집 → 저장 → 이용 → 파기** 라이프사이클을 코드 스캔에서 자동 도출해
개인정보 처리흐름표(감사 제출 수준)로 렌더한다.

## 주요 기능

- 무료(Semgrep) PII 룰 스캔 → 처리흐름 후보 자동 시드 / 유료(Claude) 심층 라이프사이클
- DB 테이블·컬럼 ↔ 개인정보 항목 매칭, 제3자·국외 이전 후보 분류
- 표준 플로우차트 PDF(정보주체→수집→저장→이용→파기) + 상세표
- MORI 는 고객 코드를 저장하지 않고 **스캔 결과만** 수신(코드 CI 실행)

# 3.9 Onboarding & Operations Module (실사용 온보딩·운영)

## 목적

데모를 넘어 "내 데이터로" 실사용에 빠르게 진입하고, 실배포를 안전하게 만든다.

## 주요 기능

- **온보딩 카드**(admin 첫 화면): 첫 실행 체크리스트(5스텝, 클릭 이동)·커넥터 성숙도/연결 상태·[연결 테스트]
- 커넥터 정직 표기(실검증/부분(수신형)/준비중), 코드 스캔 원클릭 핸드오프(무료 기본)
- 데모→실전 전환 준비 패널, 오늘 채울 통제 추천, 용어 글로서리
- 운영 안전: `MORI_PROFILE=production` **부팅 게이트**(인증·강한 시크릿·HTTPS 없으면 부팅 거부, fail-closed)
- **세션 Postgres 영속**(재기동에도 로그인 유지, 다중 인스턴스 토대) — 옵트인

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
| Scalability | 수백 대 시스템 확장 가능. 세션·상태 Postgres 영속으로 다중 인스턴스 토대 마련(옵트인) |
| Availability | 중앙 시스템 24/7 운영. 재기동에도 로그인 세션 유지(`MORI_SESSION_BACKEND=postgres`) |
| Security | RBAC 기반 접근 제어. **운영 안전 부팅 게이트**(`MORI_PROFILE=production`): 인증·강한 시크릿·HTTPS 미비 시 부팅 거부(fail-closed). 증적 무결성(content hash·HMAC 서명·append-only 원장) |
| Performance | 쿼리 스냅샷 **옵트인 TTL 캐시**(`MORI_QUERY_CACHE_TTL`)로 대시보드 풀스냅샷 부하 완화 |
| i18n | UI 한/영 전환 + **산출물 언어 일치**: 증적 PDF 는 UI 언어(ko/en)를 따라 렌더(잔여 PDF는 §7 계획) |
| Log Retention | 최소 90일 로그 보관 |

---

# 7. Future Enhancements

## 진행 중 · 근시일 계획 (현행 로드맵)

- **산출물 다국어 일치(잔여)** — 증적 PDF 는 완료. 개인정보 처리흐름 PDF·리포트 PDF 의 구조 라벨 i18n 및
  SoA(ISO 관례상 영문 유지 여부 결정)까지 확장.
- **다중 인스턴스(M10 B/C)** — replay/rate-limit 캐시 공유 → 로드밸런서 뒤 수평 확장(실수요 발생 시 착수).
- **온보딩 심화** — 연결 마법사에서의 시크릿 UI 주입(암호화 저장) 및 커넥터 호환성 매트릭스.

## 장기 확장

- 자동 대응 시스템
- AI 기반 이벤트 분석
- 멀티 테넌트 구조
- 클라우드 환경 통합