## Fleet macOS 등록 및 검증 기록

이 문서는 MORI SOC-lite 환경에서 **MacBook을 FleetDM에 등록하고**, 등록 이후 **Live Query / Grafana 연동까지 확인하는 절차**를 정리한 운영 메모입니다.

### 1. 현재까지 완료한 작업

- 서버 Fleet 로그인 루프 이슈를 우회하기 위해 운영 서버에서 Fleet 이미지를 `fleetdm/fleet:5056724`로 고정해 로그인 성공을 확인함
- Fleet 웹 UI 로그인 확인 완료
  - URL: `http://mori.example.com:1337/login`
- macOS에서 `fleetctl` 설치 확인 완료
  - 설치 경로: `~/.fleetctl/fleetctl`
  - 확인 버전: `fleetctl 4.82.1`
- macOS `.pkg` 설치 진행 완료
  - 설치 후 macOS에서 "Fleet Device Management Inc" 백그라운드 항목 추가 알림 확인
- 저장소의 Grafana starter dashboard를 `MORI SOC Overview` 형태로 확장함
  - 파일: `config/grafana/provisioning/dashboards/mori-overview.json`
  - 데이터소스: Loki

### 2. 전제 조건

- Fleet 서버는 현재 **HTTPS가 아닌 HTTP**로 운영 중임
- 따라서 `fleetctl package` 실행 시 `--insecure` 옵션이 필요함
- Fleet enrollment secret은 민감정보이므로 문서/채팅/커밋에 남기지 않음
- 본 대화 중 secret이 노출되었으므로 **등록 검증 후 secret 재발급 권장**

### 3. macOS 등록 절차

Fleet UI에서 아래 순서로 enrollment secret을 확인합니다.

1. `Hosts`
2. `Add hosts`
3. `macOS`
4. 표시된 enrollment secret 복사

macOS 터미널에서 `fleetctl`이 PATH로 바로 잡히지 않을 수 있으므로, 아래처럼 **직접 경로 실행**을 권장합니다.

```bash
mkdir -p ~/fleet-package
cd ~/fleet-package

~/.fleetctl/fleetctl package --type=pkg --enable-scripts --fleet-desktop \
  --fleet-url=http://mori.example.com:1337 \
  --enroll-secret='YOUR_SECRET_HERE' \
  --insecure

ls -lh *.pkg
sudo installer -pkg ./*.pkg -target /
```

정상 기대 결과:

- `.pkg` 파일이 생성됨
- macOS 설치 완료 메시지가 출력됨
- 로그인 항목/백그라운드 항목 알림이 표시될 수 있음

### 4. 1차 확인: Fleet 호스트 등록 여부

Fleet 웹 UI에서 아래를 확인합니다.

- `Hosts` 목록에 MacBook이 표시되는지
- 플랫폼이 `macOS`로 인식되는지
- 상태가 `Online` 또는 최근 체크인으로 보이는지

호스트가 바로 보이지 않으면 **1~3분 후 새로고침**하여 다시 확인합니다.

### 5. 2차 확인: Live Query 테스트

호스트가 보이면 해당 MacBook을 선택한 뒤 Live Query를 1회 실행합니다.

권장 첫 쿼리:

```sql
SELECT hostname, hardware_model, uuid
FROM system_info;
```

확인 포인트:

- 결과 테이블이 반환되는지
- `hostname`, `hardware_model`, `uuid` 값이 정상 출력되는지
- 이 단계가 성공하면 Fleet 등록 + osquery 통신이 정상일 가능성이 높음

### 6. 3차 확인: Grafana / Loki 연동 테스트

현재 Grafana에는 Loki datasource만 provision 되어 있으며, Fleet 로그는 Fluent Bit를 통해 Loki로 적재됩니다.

로그 소스:

- Fleet status: `/logs/osqueryd.status.log`
- Fleet results: `/logs/osqueryd.results.log`

Fluent Bit 라벨:

- host logs: `job="fluent-bit", source="host"`
- fleet status: `job="fleetdm", source="fleet", log_type="status"`
- fleet result: `job="fleetdm", source="fleet", log_type="result"`

Grafana Explore 확인 쿼리:

```logql
{job="fleetdm", log_type="status"}
{job="fleetdm", log_type="result"}
{job="fluent-bit"}
```

대시보드 확인 위치:

- Grafana URL: `http://mori.example.com:13000`
- Dashboard: `MORI SOC Overview`

확인 포인트:

- `Fleet status logs` 패널에 데이터가 보이는지
- Live Query 실행 후 `Fleet osquery results` 패널에 데이터가 쌓이는지
- `Security telemetry volume` 패널에 이벤트 볼륨이 표시되는지

### 7. 테스트 체크리스트

#### A. 설치/등록 테스트

- [ ] `~/.fleetctl/fleetctl --version` 동작
- [ ] `.pkg` 생성 성공
- [ ] macOS 설치 성공
- [ ] Fleet `Hosts`에 MacBook 표시

#### B. 통신 테스트

- [ ] MacBook 상태가 `Online`으로 보임
- [ ] Live Query 결과 반환
- [ ] `system_info` 결과값 확인

#### C. 시각화 테스트

- [ ] Grafana 로그인 가능
- [ ] `MORI SOC Overview` 표시
- [ ] Fleet status/result 로그 조회 가능
- [ ] Live Query 이후 result 로그 유입 확인

### 8. 문제 발생 시 확인 방법

macOS에서 에이전트 상태를 확인할 때는 아래 명령을 사용합니다.

```bash
sudo launchctl list | grep -Ei 'orbit|osquery'
log show --last 10m --style compact \
  --predicate 'process CONTAINS[c] "orbit" OR process CONTAINS[c] "osquery"'
```

증상별 점검 포인트:

- `fleetctl: command not found`
  - `~/.fleetctl/fleetctl` 직접 경로 사용
- `.pkg` 없음
  - `fleetctl package ...` 단계가 실패했는지 확인
- Fleet `Hosts`에 안 뜸
  - 1~3분 대기 후 새로고침
  - macOS 로그에서 `orbit`/`osquery` 에러 확인
- Grafana에 result 로그 안 보임
  - Live Query를 실제로 1회 이상 실행했는지 확인

### 9. 후속 권장 작업

- Fleet enrollment secret 재발급
- 저장소의 `docker-compose.yml`에도 Fleet 이미지 핀 고정 반영 여부 검토
- Grafana 대시보드에 호스트별 필터 변수 추가
- Wazuh / Zabbix 지표를 SOC Overview에 2차 통합