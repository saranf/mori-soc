# 접속기록 증적 — Zabbix / Loki 경로 확인 및 템플릿

> **질문(사용자)** — "접속기록 Zabbix에서 긁어와 Loki로 보고 데이터 증적자료 만들 수 있는 거 아니야? 필요하면 템플릿도."
> **결론** — **가능하다. 그리고 상당 부분 이미 깔려 있다.** 번들 스택의 `fluent-bit`가 이미 `/host/var/log/*.log`를 Loki로 적재 중이라, 인증로그(sshd/sudo/su)는 이미 Loki에 흐르고 있다. MORI는 이를 **조회해 증적화**만 하면 된다 — 포지셔닝("증적 층, 조회는 Loki에 위임")과 정확히 일치.
> **법적 근거** — 개인정보 안전성 확보조치 기준(고시 제2023-6호) **제8조**: 접속기록 **최소 1년**(고유식별·민감정보 처리 또는 5만명↑는 **2년**) 보관 + **월 1회 이상 점검**. ISMS-P **2.9.4**, ISO 27001 **A.8.15/A.8.16**.

---

## 1. 무엇이 이미 있고 무엇이 비었나

| 구성요소 | 상태 | 근거 |
|---|---|---|
| fluent-bit → Loki 로그 파이프라인 | **있음** | `config/fluent-bit/fluent-bit.conf` — `/host/var/log/*.log` → `job=fluent-bit,source=host` 로 Loki 적재 |
| Zabbix 에이전트 | **있음** | `config/zabbix_agent/zabbix_agent2.active.example.conf` |
| Zabbix API 범용 호출 플러밍 | **있음** | `collectors/zabbix_events.py:_api_call(method, params)` — 임의 메서드 호출 가능(현재는 `problem.get`/`host.get`만) |
| MORI 접속기록 **보존현황 지표** | **신규 구현** | `_source_metrics()` loki 지표를 정적 문자열 → **실 관측 기록범위 vs 목표 보존일** 배지로 교체 |
| MORI **월간 점검 워크플로** | **신규 구현** | `GET/POST /compliance/log-review` — 제8조 "월1회 점검"을 버튼→증적 레코드로 |
| Loki를 실제 쿼리하는 클라이언트 | **구현됨** | `services/loki_client.py` — `access_log_summary()` LogQL 조회, 파싱 순수함수 단위테스트 6/6 통과(`tests/test_loki_access.py`). 라이브 연결은 도커에서 검증 필요 |
| 접속기록 전용 라벨 분리 | **템플릿 제공** | `config/fluent-bit/authlog.template.conf` (job=authlog) |

---

## 2. 두 가지 경로 (권장: Loki 경로)

```
[경로 A · Loki — 권장, 포지셔닝 일치]
  호스트 /var/log/{auth.log,secure}
     └─ fluent-bit(tail+grep) ──> Loki (job=authlog)
                                     └─ (조회) Grafana/Loki = 열람 층
                                     └─ (증적) MORI LokiAccessLogCollector ─LogQL─> 보존범위·건수
                                                 └─ 월간 점검 레코드 + PDF/ZIP = 증적 층

[경로 B · Zabbix — 폐쇄망/에이전트 표준화 조직]
  호스트 /var/log/secure
     └─ Zabbix agent log[] 아이템 ──> Zabbix history
                                        └─ MORI ─history.get / auditlog.get─> 접속기록 증적
  * auditlog.get = Zabbix 관리콘솔 자체 접속기록(누가 로그인·설정변경)
```

- **경로 A(Loki)**: MORI가 Loki HTTP API(LogQL)로 접속기록의 **최古 시각·건수**만 뽑아 증적화. Loki는 "보는 층"으로 그대로 두고 MORI는 "증명하는 층" — 제품 서사와 100% 정합. 파이프라인이 이미 있어 **가장 적은 추가작업**.
- **경로 B(Zabbix)**: Loki 없이 Zabbix만 쓰는 조직용. 기존 `_api_call`에 `history.get`(로그 아이템)·`auditlog.get`(콘솔 접근) 추가로 구현. **관리콘솔 접속기록(auditlog)** 은 Zabbix만이 주는 고유 증적.

---

## 3. Loki 경로 — 수집 계약 (LogQL) · **구현됨**

`services/loki_client.py`의 `access_log_summary()`가 Loki `/loki/api/v1/query_range`를 호출.
활성화 env: `MORI_LOKI_URL`(미설정 시 라이브 조회 생략·관측추정 폴백), `MORI_LOKI_ACCESS_SELECTOR`
(기본 `{job="authlog"}`). 응답 파싱(`parse_query_range`)은 순수함수로 분리해 단위테스트됨. LogQL:

```logql
# 최근 N일 로그인 성공 건수(호스트별)
sum by (host) (count_over_time({job="authlog"} |= "Accepted password" [30d]))

# 로그인 실패(이상징후 후보)
sum by (host) (count_over_time({job="authlog"} |= "Failed password" [30d]))

# 보존 하한 검증용 — 가장 오래된 접속기록 timestamp
#   query_range 를 start=now-800d 로 넓게 던져 첫 스트림의 최소 ts 를 취함
{job="authlog"} |= "password"
```

수집 결과를 `_log_retention_status()`의 `loki` 소스 행으로 직접 주입(현재는 `store.alerts` 관측 기반 → Loki 실쿼리 기반으로 승격). 반환 계약:

```json
{ "source": "loki", "count": 12840, "oldest": "2024-09-01", "span_days": 679,
  "accepted": 12040, "failed": 800 }
```

`span_days ≥ target_days(365/730)` → 통제상세·월간점검 리포트에 **충족** 배지.

> **정직성 주의** — `span_days`는 "MORI가 관측한 기록 범위"다. Loki 자체 retention(`config/loki/config.yml`의 `retention_period`) 설정 증빙과 **병행 대조**해야 법정 보존기간 충족을 단정할 수 있다. 리포트 본문에 이 문구가 자동 포함된다.

---

## 4. 지금 동작하는 것 (이번 구현)

`compliance.py`에 반영:

1. **`_log_retention_status()`** — store의 실 관측 기록에서 소스별 최古 시각·건수·보존범위(일) 계산, 목표 보존일(기본 365 / 개인정보 처리 시 730) 대비 충족/미달 판정. `ui_settings` 키: `log_retention_target_days`, `log_retention_personal`.
2. **loki 지표 교체** — 통제 2.9.4 / A.8.15 상세 패널에 "관측 기록 범위 N일 / 목표 365일 — 충족" + 소스별 breakdown이 **라이브로** 뜬다(기존 정적 문자열 제거). 이 값은 기존 **실증적 스냅샷·PDF·ZIP**에 그대로 실린다.
3. **`GET /compliance/log-review`** — 보존현황 + 월간 점검 이력(최근 24개월) + 이번 달 수행 여부.
4. **`POST /compliance/log-review/run`** — "이번 달 접속기록 점검 수행" → 보존현황·소스별 현황·이상징후 검토란을 담은 **월간 점검 증적 레코드**를 로그 통제(2.9.4, A.8.15)에 적립(`source=log_review`). 매월 1건 쌓이면 그게 **제8조 월1회 점검 증적**. 기존 증적 PDF/ZIP 파이프라인으로 자동 export.

> **UI 증적이 남는 방식(사용자 질문에 대한 답)** — MORI는 통제마다 ①**라이브 실증적 지표**(지금 이만큼의 기록이 있다) ②**증적 레코드**(수기/자동 스냅샷/월간점검) ③**PDF·CSV·ZIP export** 3층으로 증적을 남긴다. 접속기록은 ①에 보존범위 배지가 뜨고, "월간 점검 수행" 버튼이 ②에 날짜 찍힌 점검 레코드를 적립하며, 심사 때 ③으로 통째 제출된다. 별도 화면을 새로 그릴 필요 없이 **기존 통제상세 패널에 그대로 실린다.**

5. **접속기록 커버리지 대사 (MORI다운 차별점)** — 크로스체크에 `access_record_coverage` 추가: **in-scope 서버 × 접속기록 로그 소스(Wazuh/Loki/host_log)** 를 대사해 **"접속기록 미수집 서버"** 를 가려낸다(raw 로그를 한 줄도 안 들고 "어디가 비었나"를 증명 — 안전조치 제8조 심사의 '빠짐없이 하나' 대응). 대시보드 **오늘의 작업 큐**에 `접속기록 미수집 서버` 타일로 노출(`GET /dashboard/evidence-gaps` → `gaps.access_uncovered`, KO/EN). 순수 집합 로직 `access_record_coverage_sets` 단위테스트 3/3 통과.

---

## 5. 템플릿 (제공)

| 파일 | 용도 |
|---|---|
| `config/fluent-bit/authlog.template.conf` | 인증로그를 **job=authlog** 전용 라벨로 Loki 적재(경로 A) — grep으로 로그인/권한상승만 필터 |
| `config/zabbix_agent/access-log.template.conf` | Zabbix 에이전트 `log[]` 아이템 + UserParameter(로그인 성공/실패 카운트)(경로 B) |

---

## 6. 다음 구현 순서 (권장)

1. ~~`LokiAccessLogCollector`~~ **완료** — `services/loki_client.py` + `_log_retention_status()` loki 행 승격. 남은 것은 도커 스택 라이브 연결 검증.
2. **UI 버튼** — 통제상세/컴플라이언스 탭에 "이번 달 접속기록 점검 수행"(`POST /compliance/log-review/run`) + 이력 뱃지. `dashboard.py` + `i18n.py` KO/EN.
3. **evidence-gap 신호** — `log_review_pending`(이번 달 미점검) 을 작업큐 타일 + `DEF-LOG-001` 결함으로 추가(`validate.py` 허용키 갱신).
4. **경로 B** — `zabbix_events.py`에 `auditlog.get`/`history.get` 추가(관리콘솔 접속기록).

---

## 7. 운영 가이드 — "제3자로 설정만 살짝 얹기" · UI에서 보는 법 · 로그 확인법

### 7-1. MORI가 바꾸는 것 / 안 바꾸는 것 (제3자 원칙)

| 대상 | 개입 | 내용 |
|---|---|---|
| **감시 대상 서버·앱** | **안 건드림** | MORI는 여기에 아무것도 설치·변경하지 않는다 |
| **로그 파이프라인(fluent-bit)** | **선택적 1블록** | 접속기록 전용 라벨을 원할 때만 `authlog.template.conf` 추가. 안 하면 기존 라벨 재사용(무개입) |
| **Loki** | **읽기(질의)만** + 보존설정 확인 | MORI는 LogQL 질의만. 단 **법정 보존기간 충족을 위해 Loki retention을 ≥365/730일로 명시** 권장 |
| **MORI** | env 2~3개 | `MORI_LOKI_URL` 등만 설정 |

### 7-2. "설정만 살짝" 체크리스트 (최소 개입 순서)

1. **인증로그가 이미 Loki에 오는지 확인** — 번들 fluent-bit이 `/host/var/log/*.log`를 수집 중이라 `auth.log`/`secure`가 이미 들어온다. Grafana Explore에서 `{job="fluent-bit",source="host"} |= "password"` 로 확인.
2. **라벨 선택** — (A) 깔끔히 분리: `config/fluent-bit/authlog.template.conf` 추가 → `{job="authlog"}`. (B) 무개입: 그대로 두고 MORI에 `MORI_LOKI_ACCESS_SELECTOR='{job="fluent-bit",source="host"}'` 지정.
3. **MORI env** (`.env`):
   ```
   MORI_LOKI_URL=http://loki:3100
   # (B안일 때만) MORI_LOKI_ACCESS_SELECTOR={job="fluent-bit",source="host"}
   ```
   보존 목표는 관리자 설정(ui_settings): `log_retention_target_days`(기본 365), `log_retention_personal`(개인정보 처리 시 true→730).
4. **Loki 보존기간 명시** — 현재 `config/loki/config.yml`엔 retention 미설정(= 삭제 안 됨/무한). 실운영은 compactor + `retention_period: 8760h`(365일) 또는 `17520h`(730일)로 **명시**해 "이만큼 보관한다"를 증빙 가능하게.

### 7-3. UI에서 지금 보이는 것 / 아직 없는 것 (정직)

- ✅ **자동으로 보임** — `/ui` → **Compliance 탭** → 통제 **2.9.4 / A.8.15** 클릭 → 통제상세 **"실증적 (현재)"** 영역에 **`관측 기록 범위 N일 / 목표 365일 — 충족`** 배지 + 소스별 breakdown이 뜬다(`dashboard.py:3985` evidence_live 렌더 경유, **UI 코드 변경 불필요**).
- ✅ **증적 적립도 지금 가능** — 같은 화면의 **"실증적 자동 기록"** 버튼이 이 배지를 날짜 찍힌 증적 레코드로 저장(→ CSV/PDF/ZIP export). 즉 **월간 점검을 지금은 이 버튼으로 대체 수행**할 수 있다.
- ✅ **접속 발자취(Access Trail) 패널** — `/ui` → **계정** 탭 → 계정 목록 아래 **"접속 발자취 (누가·언제·어디서)"** 카드. 최근 로그인·sudo 기록을 **미리보기(최대 30건)** 로 표(시각·계정·유형·호스트·출발IP·결과), 우상단 **"전체는 Loki에서 →"** Grafana Explore 딥링크. 계정 목록과 같은 화면에서 **계정↔실제 접속** 대조. 엔드포인트 `GET /accounts/access-trail`(계정 열람 역할), Loki 미연결 시 안내 문구로 degrade. **전체 로그는 보여주지 않고** 보는 층(Loki)에 위임.
- ⏳ **아직 없음** — 전용 **"이번 달 접속기록 점검"** 버튼. 백엔드 `POST /compliance/log-review/run`은 동작하나 UI 버튼 미연결(§6-2 잔여). 임시로는 위 "실증적 자동 기록" 버튼 사용 또는 API 직접 호출.

### 7-4. 로그를 직접 확인하는 3가지 방법

1. **Grafana Explore (사람이 보는 층)** — Grafana → Explore → Loki 데이터소스(`uid: loki`, provisioning 완료) →
   `{job="authlog"} |= "Accepted password"` (성공 로그인) / `|= "Failed password"` (실패). MORI는 호스트별 Explore 딥링크도 이미 제공(`payloads.py:_grafana_explore_url`).
2. **curl 로 MORI와 동일 질의 검증** —
   ```bash
   # 최근 접속기록 존재/최古 확인
   curl -sG 'http://loki:3100/loki/api/v1/query_range' \
     --data-urlencode 'query={job="authlog"}' \
     --data-urlencode 'direction=forward' --data-urlencode 'limit=1' | jq '.data.result[0].values[0]'
   ```
3. **MORI API (증적 층)** — `GET /compliance/log-review` → 보존현황 + 월간 점검 이력을 JSON으로. 통제상세 배지가 바로 이 계산 결과.
