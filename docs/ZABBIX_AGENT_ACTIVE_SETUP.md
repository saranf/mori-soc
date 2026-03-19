# Zabbix Agent Active 등록 가이드

## 1. 목적

이 문서는 개인 PC 또는 테스트 단말을 **Zabbix Agent Active 방식**으로
MORI SOC-lite의 Zabbix Server에 연결하는 절차를 정리합니다.

## 2. 권장 방식

권장 방식은 **Active Agent**입니다.

- 단말이 Zabbix Server로 직접 연결
- NAT/사내망 환경에서 상대적으로 구성 단순
- 서버가 단말의 `10050` 포트로 직접 들어올 필요 없음

현재 서버 공개 포트 기준:

- Zabbix Web: `http://mori.rmstudio.co.kr:18081`
- Zabbix Server: `mori.rmstudio.co.kr:10051`

## 3. 사전 조건

- 내 PC에서 `mori.rmstudio.co.kr:10051`로 outbound 연결 가능
- Zabbix Web 로그인 가능
- Host 이름을 직접 지정할 수 있음

초기 Zabbix Web 계정(초기 설치 기준):

- ID: `Admin`
- PW: `zabbix`

## 4. 서버 측 Host 생성

Zabbix Web에서 아래 순서로 등록합니다.

1. `Data collection` → `Hosts`
2. `Create host`
3. 아래 값 입력

- Host name: Agent 설정의 `Hostname`과 동일값
- Templates:
  - Windows: `Windows by Zabbix agent active`
  - Linux: `Linux by Zabbix agent active`
  - macOS: 운영 환경에 맞는 active 템플릿 또는 범용 agent 템플릿
- Host groups: 예) `Endpoints`
- Interfaces: Active 전용만 사용할 경우 필수는 아니지만 관리 편의상 추가 가능

## 5. Agent 설정 예시

저장소 예시 파일:

- `config/zabbix_agent/zabbix_agent2.active.example.conf`

핵심 설정은 아래 4개입니다.

- `Server=mori.rmstudio.co.kr`
- `ServerActive=mori.rmstudio.co.kr:10051`
- `Hostname=PC별_고유이름`
- `HostMetadata=windows|linux|macos`

예시:

```conf
Server=mori.rmstudio.co.kr
ServerActive=mori.rmstudio.co.kr:10051
Hostname=SRANG-LAPTOP
HostMetadata=windows
```

## 6. OS별 적용 포인트

### Windows

- Zabbix Agent 2 설치
- 예시 설정 파일 내용을 `zabbix_agent2.conf`에 반영
- 서비스 재시작

권장 메타데이터:

- `HostMetadata=windows`

### Linux

- 패키지로 Zabbix Agent 2 설치
- `/etc/zabbix/zabbix_agent2.conf` 수정
- 서비스 재시작

권장 메타데이터:

- `HostMetadata=linux`

### macOS

- Zabbix Agent 2 설치
- 설정 파일에 Active 항목 반영
- LaunchAgent/서비스 재시작

권장 메타데이터:

- `HostMetadata=macos`

## 7. 연결 확인 방법

Zabbix Web에서 아래를 확인합니다.

- `Monitoring` → `Hosts`
- Host 상태가 활성으로 보이는지 확인
- `Latest data`에서 CPU/Memory/Disk 항목 수집 확인

처음 데이터 반영까지는 수 분 정도 걸릴 수 있습니다.

## 8. 추천 PoC 항목

처음에는 아래 항목만 확인해도 충분합니다.

- CPU utilization
- Memory utilization
- Disk usage
- Network interface status
- Agent availability

## 9. 트러블슈팅

### 데이터가 안 들어올 때

- `Hostname`이 Zabbix Host 이름과 정확히 같은지 확인
- `ServerActive=mori.rmstudio.co.kr:10051`로 설정했는지 확인
- 단말 방화벽/사내망에서 outbound `10051/tcp` 차단이 없는지 확인
- Active 템플릿을 연결했는지 확인

### 로그인은 되는데 Host가 회색일 때

- Host 템플릿이 맞지 않거나
- Agent 서비스가 아직 재시작되지 않았거나
- Active check 대상 호스트명이 일치하지 않는 경우가 많습니다.