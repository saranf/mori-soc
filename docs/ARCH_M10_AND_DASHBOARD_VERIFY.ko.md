# M10 세션 영속 설계 + 대시보드 숫자 검증 · 수정 계획

작성 배경: 온보딩 플랜 M10(세션 영속) 설계 + "대시보드에 나오는 숫자들이 실제로 동작하는가" 실측 검증 + 수정 계획.
검증 환경: 실행 중 docker 스택(실 postgres 백엔드), admin 세션.

---

## Part 1 — 대시보드 숫자 검증 결과 (실측)

**결론: 모든 KPI 숫자는 실데이터(store)에서 계산되어 동작한다. 하드코딩·가짜값 없음.**
`build_dashboard_payload` 등 빌더는 전부 `store.alerts/vulnerabilities/hosts/observations` 를 집계한다.

| 엔드포인트 | 값(실측) | 원천 대조 | 판정 |
|---|---|---|---|
| `/dashboard/summary` overview | total_hosts 15·crit_vulns 4·high 6·ingested 51 | DB alerts12/vulns20/hosts16/obs11 | ○ 계산 일치 |
| `/compliance/pdca` | checks 26·pass 48%·pending 21·overdue 13 | store 집계 | ○ |
| `/dashboard/evidence-gaps` | total 33 (vuln 8·overdue 13·control 13·access 11·unmapped 1) | crosscheck 와 정합 | ○ |
| `/controls/maturity` | 194 = draft129+reviewed13+mapped45+auto7 | 합계 정확 | ◎ 일관 |
| `/accounts/overview` | accounts 9·findings 4·ips 16 | host_accounts | ○ |
| `/compliance/crosscheck` | source uncovered 1·access uncovered 11 | hosts 16↔15 차이 설명 | ○ |

### 검증에서 드러난 3가지 주의점(숫자 오류 아님, 의미/구조 이슈)

1. **[MAJOR·전역] 요청당 전체 DB 풀스냅샷** — `get_query_service()` 는 프로덕션에서
   `service_factory=create_query_service_from_env` → **매 호출마다 `repository.snapshot()` 로
   DB 전체를 메모리로 로드**한다(`server.py:2077`, 34개 호출부). 데모 규모에선 13ms 로 빠르지만,
   호스트/취약점이 수천 건인 실환경에선 한 대시보드 로드가 여러 번 풀스냅샷을 유발 → 지연·부하.
   → 숫자는 "라이브·정확"하지만 **전달 비용**이 문제(리뷰의 M1 CRITICAL 과 동일 뿌리).

2. **[MINOR·국소] 호스트 카운트 의미가 화면마다 다름** — total_hosts 15 vs DB hosts 16 vs
   crosscheck uncovered 1. 원인: Trivy 이미지 아티팩트(`alpine:3.19`)·관측 없는 호스트가
   뷰마다 다르게 집계됨(`latest_host_status_view` 는 관측 기반). 오류는 아니나 "왜 숫자가 다르지?"
   혼란 유발.

3. **[MINOR·국소] 데모 데이터로 일부 KPI 가 0** — `alerts_24h=0`(경보 12건은 있으나 24h 밖·
   심각도 필터). 의미상 정확(최근 24h 고위험 없음)이나, 데모에선 "빈 값처럼" 보임. 실 Zabbix
   연결 시 자연 해소.

---

## Part 2 — M10 세션 영속 설계 (재시작 견고성 · 다중 인스턴스)

### 문제
`sessions`(로그인), `triage_store` 등 20+ 인메모리 스토어 + replay/rate-limit 캐시가 **프로세스 로컬**.
→ ① 재기동 시 전원 로그아웃 ② 다중 인스턴스 불가(LB 뒤 2대면 세션 불일치) ③ 운영 데이터 유실.
단, 운영 스토어 6종은 이미 `persist_*` 훅으로 StateRepository(Postgres)에 영속됨 — **세션은 미영속**.

### 설계 (3단계, 안전 우선 · fail-closed)

**Phase A — 세션 Postgres 영속 (핵심)**
- 새 테이블 `ui_sessions(token PK, username, role, created_at, last_seen, expires_at)` (+ 마이그레이션).
- L1 인메모리 캐시(읽기 속도) + L2 Postgres(정본). 로그인=write-through, 로그아웃=delete, 만료=TTL 정리.
- `build_session_auth_middleware`·`/auth/login`·`/auth/logout` 를 스토어 경유로.
- **플래그 `MORI_SESSION_BACKEND=memory|postgres`(기본 memory)** — 기존 배포 무영향, 옵트인 전환.
- 안전: postgres 백엔드인데 DB 불가 시 **fail-closed**(인증 실패, 무인증 통과 금지). 롤아웃 전 충분한 테스트.

**Phase B — replay/rate-limit 캐시 공유**
- `_INGEST_REPLAY_SEEN`(ingest replay)·로그인 실패 카운터 → Postgres/Redis. 단일 인스턴스는 현행 유지 가능(후순위).

**Phase C — 다중 인스턴스**
- A·B 완료 후 mori-api 2+대 LB. 세션·캐시가 공유되므로 수평 확장 가능.

### 위험(모리다움)
auth 코어 변경 → **잘못하면 전원 잠금**. 반드시 플래그 뒤 점진 롤아웃 + `test_secure_boot` 확장.
Redis 도입은 스택 확장(코어 단순성 원칙과 상충) → **Postgres 우선**, Redis 는 진짜 필요할 때만.

---

## Part 3 — 수정 계획 (우선순위)

| # | 항목 | 유형 | 상태 |
|---|---|---|---|
| F1 | **옵트인 TTL 스냅샷 캐시** — `MORI_QUERY_CACHE_TTL>0` 이면 대시보드 버스트의 풀스냅샷 흡수(기본 0=현행) | 성능 | ✅ 구현(`e4f3daf`, `api/query_cache.py`) |
| F2 | 폴링용 짧은 TTL 캐시 | 성능 | ✅ F1 로 통합(동일 메커니즘) |
| F3 | 호스트 vs 아티팩트 분류 단일화 | 정합성 | ▶ 보류 — 대시보드는 이미 아티팩트 제외해 15를 정확히 표시(원시 테이블 16과의 차이는 비교 시 혼란뿐, 사용자 화면 오류 아님). 가치 낮아 후순위 |
| F4 | M10 Phase A(세션 Postgres) — 플래그 옵트인 | 견고성 | ✅ 구현(`b423101`, `ui_sessions`+`PersistentSessionDict`). 로그아웃 Request 주입 버그도 수정 |

**M10 잔여:** Phase B(replay/rate-limit 공유)·C(다중 인스턴스)는 **실제로 다중 인스턴스를 띄울 때** 착수
(코어 단순성 원칙 — 필요 전 선제 구축 금지). 단일 인스턴스에선 현행으로 충분.

**결론:** 추천 플랜의 고가치 항목(F1·F4)은 모두 안전(옵트인·무영향·검증)하게 반영됨.
남은 F3 은 마진, M10 B/C 는 수요 발생 시 별도 에픽.
