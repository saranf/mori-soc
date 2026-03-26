# MORI SOC — 실시간 수집 기준표 (Collection Standards)

> **이 문서가 유일한 진실의 원천(Single Source of Truth)입니다.**
> 코드의 폴러 상수, 환경변수 기본값, UI의 stale 판단 기준은 모두 이 표에 맞춰야 합니다.
> 기준을 바꿀 때는 반드시 이 문서를 먼저 수정하고 코드를 따라 고치세요.

---

## 소스별 수집 기준표

| 항목 | Zabbix | Fleet | Wazuh | Trivy | LDAP/AD |
|------|--------|-------|-------|-------|---------|
| **수집 방식** | Polling (REST API) | Polling (REST API) | Polling (REST API) | Batch (파일/온디맨드) | Polling (LDAP) |
| **폴링 주기** | 60 s | 120 s | 60 s | 86400 s (24 h) | 3600 s (1 h) |
| **목표 레이턴시** | < 90 s | < 3 min | < 90 s | < 30 min (수동) | < 1.5 h |
| **Freshness 기준** | 5 min | 10 min | 5 min | 7 days | 4 h |
| **Max Retries** | 3 | 3 | 3 | 2 | 3 |
| **Retry Backoff** | 10 s | 15 s | 10 s | 30 s | 30 s |
| **Stale 판단 기준** | 10 min | 20 min | 10 min | 7 days | 8 h |
| **연동 상태** | ✅ 연결됨 | 🔲 미연결 (API stub) | 🔲 미연결 (파일 모드) | 🟡 수동 실행 | 🟡 옵션 (env 설정 시) |

---

## 각 항목 정의

### 수집 방식
- **Polling**: MORI 워커가 주기적으로 외부 API를 호출해 데이터를 가져옴
- **Batch**: 특정 이벤트(스캔 완료) 시점에 결과 파일을 읽어 처리
- **Webhook** (미구현): 외부 소스가 MORI에 푸시 (Phase 3 예정)

### 폴링 주기 (`poll_interval_seconds`)
워커가 한 사이클을 완료한 뒤 다음 사이클까지 대기하는 시간.
환경변수 `MORI_{SOURCE}_INTERVAL_SECONDS`로 개별 재정의 가능.

### 목표 레이턴시
이벤트가 소스에서 발생한 뒤 MORI DB에 저장될 때까지 허용하는 최대 시간.
`폴링 주기 + API 응답 시간 + 처리 시간` 합산 기준.

### Freshness 기준
`last_success_at`이 이 시간 이내이면 "신선(fresh)"으로 간주.
UI에서 초록색 배지 표시 기준.

### Max Retries (`max_retries`)
한 사이클 내에서 수집 실패 시 재시도 횟수.
모두 실패하면 `SourceSync.status = "error"` 기록.

### Retry Backoff (`retry_backoff_seconds`)
재시도 사이 대기 시간 (고정값, jitter 미적용).
네트워크 순간 오류 대응용.

### Stale 판단 기준 (`stale_threshold_seconds`)
`last_success_at`이 이 시간보다 오래된 경우 "stale(오래됨)"으로 표시.
UI에서 노란색/빨간색 경고 표시, `sources_healthy` 카운트에서 제외.

---

## 환경변수 참조

```bash
# ── 글로벌 (폴백) ──────────────────────────────────────
MORI_WORKER_INTERVAL_SECONDS=60        # 소스별 미설정 시 폴백 (기본 60)

# ── Zabbix ────────────────────────────────────────────
MORI_ENABLE_ZABBIX=true
MORI_ZABBIX_API_URL=http://zabbix-web:8080/api_jsonrpc.php
MORI_ZABBIX_API_TOKEN=                 # 또는 USER + PASSWORD
MORI_ZABBIX_INTERVAL_SECONDS=60        # 기준: 60
MORI_ZABBIX_TIMEOUT_SECONDS=10
MORI_ZABBIX_MAX_RETRIES=3             # 기준: 3
MORI_ZABBIX_RETRY_BACKOFF_SECONDS=10  # 기준: 10
MORI_ZABBIX_STALE_SECONDS=600         # 기준: 600 (10분)

# ── Fleet ─────────────────────────────────────────────
MORI_ENABLE_FLEET=false               # 미연결 — API 연동 시 true
MORI_FLEET_API_URL=http://fleet:8080
MORI_FLEET_API_TOKEN=
MORI_FLEET_INTERVAL_SECONDS=120       # 기준: 120
MORI_FLEET_TIMEOUT_SECONDS=15
MORI_FLEET_MAX_RETRIES=3             # 기준: 3
MORI_FLEET_RETRY_BACKOFF_SECONDS=15  # 기준: 15
MORI_FLEET_STALE_SECONDS=1200        # 기준: 1200 (20분)

# ── Wazuh ─────────────────────────────────────────────
MORI_ENABLE_WAZUH=false              # 미연결 — API 연동 시 true
MORI_WAZUH_API_URL=https://wazuh-manager:55000
MORI_WAZUH_API_USER=
MORI_WAZUH_API_PASSWORD=
MORI_WAZUH_INTERVAL_SECONDS=60       # 기준: 60
MORI_WAZUH_TIMEOUT_SECONDS=10
MORI_WAZUH_MAX_RETRIES=3            # 기준: 3
MORI_WAZUH_RETRY_BACKOFF_SECONDS=10 # 기준: 10
MORI_WAZUH_STALE_SECONDS=600        # 기준: 600 (10분)

# ── Trivy ─────────────────────────────────────────────
MORI_ENABLE_TRIVY=false
MORI_TRIVY_REPORT_GLOB=reports/trivy/*.json
MORI_TRIVY_INTERVAL_SECONDS=86400    # 기준: 86400 (24h)
MORI_TRIVY_MAX_RETRIES=2            # 기준: 2
MORI_TRIVY_RETRY_BACKOFF_SECONDS=30 # 기준: 30
MORI_TRIVY_STALE_SECONDS=604800     # 기준: 604800 (7일)

# ── LDAP ──────────────────────────────────────────────
MORI_ENABLE_LDAP_SYNC=false
MORI_LDAP_URL=ldap://ad.corp.local
MORI_LDAP_BIND_DN=CN=svc-mori,...
MORI_LDAP_INTERVAL_SECONDS=3600     # 기준: 3600 (1h)
MORI_LDAP_SYNC_TIMEOUT_SECONDS=10
MORI_LDAP_MAX_RETRIES=3            # 기준: 3
MORI_LDAP_RETRY_BACKOFF_SECONDS=30 # 기준: 30
MORI_LDAP_STALE_SECONDS=28800      # 기준: 28800 (8h)
```

---

## 장애 처리 흐름

```
[폴러 사이클 시작]
      │
      ▼
[수집 시도]──실패──▶[backoff 대기]──▶[재시도 (max_retries회)]
      │                                        │
      │ 성공                                  모두 실패
      ▼                                        ▼
[normalize → save]                  [SourceSync status=error 기록]
[SourceSync status=success]         [UI: 빨간 배지 + 알림]
      │
      ▼
[last_success_at 갱신]
[stale 타이머 리셋]
```

---

## 연동 로드맵

| Phase | 항목 | 목표 |
|-------|------|------|
| **현재** | Zabbix API polling | ✅ 운영 중 |
| **현재** | Trivy 파일 batch | 🟡 수동 실행 |
| **현재** | LDAP 동기화 | 🟡 env 설정 필요 |
| **Phase 3** | Fleet API polling | 🔲 REST API 연동 |
| **Phase 3** | Wazuh API polling | 🔲 REST API 연동 |
| **Phase 4** | Webhook 수신 (Fleet/Wazuh) | 🔲 Push 모드 |

