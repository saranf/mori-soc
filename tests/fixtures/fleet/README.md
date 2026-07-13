# Fleet API 실응답 캡처 (F0)

`collectors/fleet_api.py`(F1) 를 **추측 없이** 만들기 위해, 실제로 띄운 Fleet 서버에서 받은
응답을 그대로 저장한 것이다. 손으로 만든 샘플이 아니다.

## 어떻게 캡처했나

1. `docker compose --profile fleet up -d` — Fleet 실기동 (compose 기본값: `:1337`)
2. `POST /api/v1/setup` 으로 관리자 생성 → `POST /api/v1/fleet/login` 으로 **Bearer 토큰** 발급
3. 실제 osquery 에이전트를 **컨테이너로 enroll** (Ubuntu 20.04 / osquery 4.9.0)
   — 이 과정에만 Fleet TLS 가 필요했다(osquery 는 HTTPS 만 지원). 캡처 후 레포 기본 설정(HTTP)으로 되돌림.
4. 아래 엔드포인트 응답을 그대로 저장

| 파일 | 엔드포인트 | 내용 |
|---|---|---|
| `hosts_list.json` | `GET /api/v1/fleet/hosts` | 호스트 목록 (자산 매핑의 입력) |
| `host_detail.json` | `GET /api/v1/fleet/hosts/1` | 호스트 상세 — **`software[]` 93건 포함** |
| `software_versions.json` | `GET /api/v1/fleet/software/versions` | 소프트웨어 버전 집계(count 93) |

## F1 이 알아야 할 스키마 사실

- **자산**: `id` · `hostname` · `uuid` · `platform` · `os_version` · `osquery_version` · `primary_ip` ·
  `primary_mac` · `status`(online/offline) · `seen_time` · `cpu_type` · `memory` · `hardware_serial`
- **취약점 운반 필드**: 호스트 상세의 **`software[].vulnerabilities`** (그리고 `software[].generated_cpe`).
  소프트웨어 항목 키: `id, name, version, source, generated_cpe, vulnerabilities, display_name, ...`

## 알려진 한계 (정직하게 기록)

이 캡처에서 **`vulnerabilities` 는 전부 `null`, `generated_cpe` 는 전부 빈 문자열**이다.
Fleet 이 NVD DB(788MB)를 받아 `vulnerabilities` 크론까지 돌렸지만, 캡처에 쓴 컨테이너의
배포판(Ubuntu deb 패키지)에 대해 CVE 매칭이 붙지 않았다.

→ **CVE가 실린 취약점 fixture는 아직 없다.** F1 에서 취약점 매핑을 구현할 때는
`software[].vulnerabilities` 가 **비어 있는 경우(현재 캡처)** 를 먼저 정확히 처리하고,
CVE가 실린 케이스는 **실호스트(F3 맥북 enroll) 캡처로 fixture를 추가한 뒤** 검증한다.
스키마를 추측해서 넣지 말 것.
