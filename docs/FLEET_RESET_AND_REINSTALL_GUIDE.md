# Fleet 초기화 및 macOS Host 재설치 가이드

Fleet 로그인 문제나 enrollment 꼬임이 있을 때 **전체 스택을 밀지 말고 Fleet만 선택 초기화**하는 절차입니다.

## 1. 이 문서가 다루는 범위

- Fleet UI 로그인 문제
- Fleet 전용 볼륨 초기화
- 새 관리자 계정 재생성
- macOS `fleetd` 제거 후 재설치

아래 데이터는 **초기화 시 사라질 수 있습니다.**

- Fleet 관리자 계정
- 등록된 Fleet host 목록
- enrollment secret
- Fleet policy / query / pack / 설정 일부

반대로 아래는 **건드리지 않으면 유지됩니다.**

- MORI Postgres
- Grafana
- Zabbix
- Wazuh

## 2. 절대 먼저 하면 안 되는 것

아래 명령은 Fleet만이 아니라 다른 서비스 볼륨까지 지울 수 있으니 주의합니다.

```bash
docker compose down -v
```

## 3. Fleet만 정지/제거

배포 경로에서 실행합니다. 현재 서버 기준 경로는 `/backup/rmstudio/mori` 입니다.

```bash
cd /backup/rmstudio/mori
docker compose stop fleet mysql redis fleet-init
docker compose rm -f fleet mysql redis fleet-init
docker volume ls | grep fleet
```

보통 아래와 비슷한 볼륨 이름이 보입니다.

- `..._fleet-mysql-data`
- `..._fleet-redis-data`
- `..._fleet-data`
- `..._fleet-vulndb`

## 4. Fleet DB / 세션 초기화

로그인 꼬임 해결이 목적이면 **우선 아래 2개만** 지우는 것을 권장합니다.

```bash
docker volume rm $(docker volume ls -q | grep 'fleet-mysql-data$')
docker volume rm $(docker volume ls -q | grep 'fleet-redis-data$')
```

host 재설치까지 완전히 새로 갈 때는 아래도 같이 지워도 됩니다.

```bash
docker volume rm $(docker volume ls -q | grep 'fleet-data$')
docker volume rm $(docker volume ls -q | grep 'fleet-vulndb$')
```

## 5. Fleet 다시 기동

```bash
cd /backup/rmstudio/mori
docker compose up -d mysql redis fleet-init fleet
docker compose ps mysql redis fleet
docker compose logs fleet --tail=100
```

정상 기준:

- `mysql`, `redis`, `fleet` 가 `Up` 또는 healthy
- Fleet 로그에 치명 오류가 없음
- 브라우저에서 `http://mori.rmstudio.co.kr:1337` 접속 가능

## 6. 브라우저 쪽 정리

로그인 루프였으면 서버 초기화 후에도 쿠키가 남아 있을 수 있습니다.

- Fleet 사이트 쿠키/사이트 데이터 삭제
- 또는 시크릿/프라이빗 창에서 재접속

## 7. Fleet 첫 로그인 및 새 secret 발급

초기화 후에는 예전 admin 계정이 더 이상 유효하지 않을 수 있습니다.

1. `http://mori.rmstudio.co.kr:1337` 접속
2. 초기 setup 화면이 보이면 새 관리자 계정 생성
3. 로그인 후 `Hosts -> Add hosts -> macOS` 이동
4. 새 enrollment secret 확인

## 8. macOS 기존 fleetd 제거

Fleet 공식 가이드를 참고합니다.

- 가이드: `https://fleetdm.com/guides/how-to-uninstall-fleetd`

가이드 기준 핵심 흐름은 아래와 같습니다.

1. `uninstall-fleetd-macos.sh` 다운로드
2. 실행 권한 부여
3. `sudo ./uninstall-fleetd-macos.sh` 실행

## 9. macOS 패키지 재생성 및 재설치

현재 서버는 HTTP 기준이므로 `--insecure` 옵션이 필요합니다.

```bash
mkdir -p ~/fleet-package && cd ~/fleet-package
~/.fleetctl/fleetctl package --type=pkg --enable-scripts --fleet-desktop \
  --fleet-url=http://mori.rmstudio.co.kr:1337 \
  --enroll-secret='새로_발급한_SECRET' --insecure
sudo installer -pkg ./*.pkg -target /
```

## 10. 재설치 확인

설치 후 1~3분 정도 기다린 뒤 Fleet UI에서 확인합니다.

- `Hosts` 목록에 MacBook 표시
- platform 이 `macOS`
- 상태가 `Online` 또는 최근 체크인으로 표시

가능하면 Live Query로 아래 쿼리도 1회 확인합니다.

```sql
SELECT hostname, hardware_model, uuid
FROM system_info;
```

## 11. macOS에서 안 붙을 때 확인

```bash
sudo launchctl list | grep -Ei 'orbit|osquery'
log show --last 10m --style compact \
  --predicate 'process CONTAINS[c] "orbit" OR process CONTAINS[c] "osquery"'
```

## 12. 그래도 Fleet 로그인 문제가 반복되면

이전 점검 기록상 Fleet 로그인 루프는 이미지 태그 영향 가능성이 있습니다.
DB 초기화 후에도 같은 증상이 반복되면 `docker-compose.yml` 의 Fleet 이미지를
`fleetdm/fleet:5056724` 로 pin 해서 재기동하는 우회가 필요할 수 있습니다.

## 13. 권장 순서 요약

1. Fleet 관련 서비스만 정지
2. `fleet-mysql-data`, `fleet-redis-data` 우선 초기화
3. 필요 시 `fleet-data`, `fleet-vulndb` 추가 초기화
4. Fleet 재기동
5. 브라우저 쿠키 삭제 또는 시크릿 창 접속
6. 새 관리자 계정 생성
7. 새 enrollment secret 발급
8. macOS `fleetd` 제거 후 새 패키지로 재설치
9. Fleet UI에서 host 등록과 Live Query 확인