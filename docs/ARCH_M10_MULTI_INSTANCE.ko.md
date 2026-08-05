# M10 B/C — 다중 인스턴스 설계 (R7)

목표: mori-api 를 로드밸런서 뒤 2+대로 수평 확장. **세션(M10-A)은 이미 Postgres 영속**이므로,
남은 것은 **프로세스 로컬 캐시 3종의 공유**다. 원칙(모리다움): 단일 인스턴스 단순성을 해치지
않도록 **전부 옵트인**(기본 memory=현행), 실제 다중 인스턴스 수요가 있을 때 켠다.

## 공유해야 할 프로세스 로컬 상태

| 상태 | 위치 | 다중 인스턴스 시 문제 | 심각도 | Phase |
|------|------|----------------------|--------|-------|
| **OIDC ingest replay** (`_INGEST_REPLAY_SEEN`) | `routes/sources.py` | 인스턴스 A 에서 본 jti 를 B 가 몰라 **재전송 스캔이 통과**(증적 중복·오집계) | **높음(보안)** | B |
| 세션(`sessions`) | `session_store.py` | — (M10-A 로 이미 Postgres 공유) | 완료 | A ✅ |
| 로그인 실패 카운터 | `auth.py` | 인스턴스별 개별 카운트 → 잠금이 느슨해짐(무차별 방어 약화) | 중 | B |
| Rate limit 카운터 | `ratelimit.py` | 인스턴스별 개별 한도 → 전체 한도가 N배로 느슨 | 중 | B |

## Phase B — 공유 캐시(Postgres 우선, Redis 는 진짜 필요할 때만)

**공용 KV 테이블 하나로 3종을 모두 처리**(신규 의존성 없이 코어 단순 유지):

```sql
-- schema/0NN_shared_kv.sql
CREATE TABLE IF NOT EXISTS shared_kv (
    ns          TEXT NOT NULL,           -- 'replay' | 'login_fail' | 'ratelimit'
    k           TEXT NOT NULL,           -- jti / (user|ip) / (ip|route)
    v           BIGINT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ,
    PRIMARY KEY (ns, k)
);
CREATE INDEX IF NOT EXISTS idx_shared_kv_expires ON shared_kv (expires_at);
```

- StateRepository 에 원자적 메서드: `kv_seen_once(ns,k,ttl)->bool`(replay: INSERT … ON CONFLICT DO NOTHING → 삽입되면 최초),
  `kv_incr(ns,k,ttl)->int`(카운터), `kv_get`, `kv_cleanup(now)`.
- replay: `_is_replayed` 를 `kv_seen_once('replay', jti, window)` 로 — **원자적**이라 경합에도 정확.
- login_fail·ratelimit: `kv_incr` 로 카운트, 만료는 expires_at.
- **옵트인 플래그** `MORI_SHARED_STATE_BACKEND=memory|postgres`(기본 memory). memory 면 현행 인메모리 그대로.
- **가용성**: DB 순단 시 replay 는 fail-open(중복 위험 < 서비스 중단) 대신 **fail-closed 옵션** 제공,
  ratelimit 는 fail-open(막지 않음). 정책은 플래그로.

## Phase C — 로드밸런서 롤아웃

1. Phase A(세션)+B(공유 캐시) 켠 상태로 mori-api replica=2.
2. LB(예: caddy/nginx)는 세션이 공유되므로 **sticky 불필요**(라운드로빈 가능).
3. 헬스체크 `/health/ready` 로 무중단 롤링.
4. `shared_kv` 정리 잡(주기 `kv_cleanup`) — worker 에 추가.

## 테스트 계획

- `kv_seen_once` 동시성: 같은 jti 를 2스레드가 호출 → 하나만 True.
- replay: postgres 백엔드에서 2번째 동일 jti ingest → duplicate 응답.
- 회귀: memory 백엔드(기본)에서 현행 동작 불변.
- E2E: replica=2 compose 프로필로 로그인→다른 인스턴스에서 세션 유지·replay 차단.

## 착수 판단(모리다움)

**지금 구현하지 않는다** — 단일 인스턴스로 충분한 현재, 위 복잡도는 순비용. **실제 수평 확장
수요(부하·가용성 SLA)가 생기면** 이 설계대로 Phase B(공용 KV) → C(LB) 순으로 옵트인 도입한다.
가장 먼저 켤 것은 **replay 공유(보안)**.
