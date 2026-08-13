# 배포 URL·도메인·포트 정리 (서버 개편 체크리스트)

서버를 개편하거나 도메인으로 이관할 때 **어떤 값이 브라우저로 나가고(운영자가 도메인으로
설정해야 함) 어떤 값이 컨테이너 내부용인지(그대로 둬도 됨)** 를 구분한다.

핵심: MORI 는 **값을 억지로 유추하지 않는다**(그럴듯하지만 틀린 링크 금지). 운영 모드
(`MORI_DEMO_MODE=false` 또는 `MORI_PROFILE=production`)에서 브라우저용 URL 이 localhost 를
가리키거나 공개주소가 비면 **온보딩 카드/`/onboarding/status`(`deployment_warnings`)에 경고**한다.

## A. 브라우저로 나가는 값 — 실서버에선 반드시 도메인으로 설정

| env | 용도 | 기본값 | 실서버 설정 |
|-----|------|--------|-------------|
| `MORI_PUBLIC_URL` | 공개 접속 주소(쿠키 Secure 자동·CSRF Origin·스캔 수신 URL·딥링크 기준) | (없음) | `https://mori.example.com` **필수** |
| `MORI_GRAFANA_URL` | Grafana 딥링크 | `http://localhost:13000` | 실제 Grafana 노출 주소(없으면 링크 숨김 권장) |
| `MORI_ZABBIX_UI_URL` | Zabbix 웹 딥링크 | (빈값→"미설정" 표기) | 실제 Zabbix UI 주소 |
| `MORI_FLEET_UI_URL` | Fleet 웹 딥링크 | (빈값→"미설정" 표기) | 실제 Fleet UI 주소 |
| `MORI_WAZUH_UI_URL` | Wazuh 대시보드 딥링크 | (빈값) | 실제 Wazuh 대시보드 주소 |
| `MORI_DOCS_PORTAL_URL` | 운영 문서 포털 링크 | `http://localhost:37854/` | 실제 문서 포털 주소(또는 비워 숨김) |

> Zabbix/Fleet/Wazuh 는 **빈값이면 "연동 URL 미설정"으로 정직하게 표기**(깨진 링크 대신).
> Grafana·Docs 는 localhost 기본값이라 **운영 모드에서 경고 대상**이다 — 실주소로 바꾸거나 비운다.
> 리버스 프록시(caddy) 뒤에서 서브패스/서브도메인으로 노출한다면 그 최종 접속 주소를 넣는다.

## B. 컨테이너 내부용 — 그대로 둬도 됨(브라우저 무관)

| env / 값 | 용도 | 비고 |
|----------|------|------|
| `MORI_DATABASE_URL` (`@soc-postgres:5432`) | 앱→DB | compose 서비스명, 내부 네트워크 |
| `MORI_ZABBIX_API_URL` (`http://zabbix-web:8080/...`) | 폴러→Zabbix API | 내부(브라우저 아님). 외부 Zabbix면 그 주소 |
| `MORI_FLEET_API_URL` / `MORI_LDAP_URL` | 폴러→소스 API | 내부/사내망 |
| `/health` `127.0.0.1:8000` (Dockerfile healthcheck) | 컨테이너 자가진단 | 내부 |
| uvicorn `0.0.0.0:8000` / api 포트 `127.0.0.1:18000->8000` | 프록시 뒤 바인딩 | edge/caddy 가 앞단 |

## C. 실서버 토폴로지(예: 관측된 배포)

```
브라우저 → edge-caddy(:80/:443, 도메인) → mori-caddy(:18443) → mori-api(127.0.0.1:18000→:8000)
                                                             ├ soc-postgres(:5432 내부)
worker/poller → zabbix-web:8080 · fleet · openldap (내부)
```
- mori-api 는 `127.0.0.1:18000` 로만 바인딩(외부 노출은 caddy 담당) — 올바름.
- 따라서 브라우저가 보는 주소는 **도메인**이고, 위 A 항목을 그 도메인 기준으로 설정해야 링크가 산다.

## D. 이관 시 점검 순서

1. `MORI_PUBLIC_URL` = 실제 https 도메인.
2. A 표의 딥링크 env 를 실제 노출 주소로(안 쓰면 빈값 → 링크 숨김).
3. `/admin` 온보딩 카드의 **배포 점검 경고**가 사라지는지 확인(운영 모드에서 localhost/미설정 감지).
4. `MORI_PROFILE=production` 이면 HTTPS 미구성 시 부팅 거부 — `MORI_BEHIND_TLS_PROXY=true`(프록시 종단) 또는 https 공개 URL.
