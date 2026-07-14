# 백업 · 복구 · 재해복구 런북

MORI 의 모든 운영 상태는 PostgreSQL 한 곳에 write-through 로 영속화된다(담당자·감사로그·위험성
평가·Triage 이력·인시던트·사용자 프로필·통제 증적/이행상태·카탈로그 편집·code_review 소스·개인정보
흐름·계정 거버넌스). 따라서 **PostgreSQL 논리 덤프 하나가 곧 전체 백업**이다.

## 무엇이 백업되고, 무엇이 안 되나

- 백업됨: `soc-postgres` 의 `mori_soc` DB 전체(위 상태 + 스키마). `pg_dump` custom format.
- 백업 안 됨(별도 보관 필요):
  - `.env`(DB 비밀번호·`MORI_INGEST_TOKEN`·`ANTHROPIC_API_KEY`·LDAP/Zabbix 자격증명 등) — 시크릿
    저장소나 안전한 오프라인 매체에 **별도** 보관. 절대 덤프와 같은 위치에 평문으로 두지 말 것.
  - 산출물 파일(PDF·CSV·SVG·ZIP)은 요청 시 메모리에서 생성되므로 저장 대상이 아니다.
  - 번들 스택(Zabbix/Wazuh/Fleet) 자체 데이터는 각 스택의 볼륨/백업 절차를 따른다(MORI 범위 밖).

## 정기 백업

```bash
./scripts/mori-backup.sh                     # backups/mori-soc-YYYYMMDD-HHMMSS.dump 생성
BACKUP_DIR=/var/backups/mori ./scripts/mori-backup.sh   # 저장 경로 지정
```

- cron 예(매일 03:00, 14일 보관):
  ```cron
  0 3 * * * cd /opt/mori && BACKUP_DIR=/var/backups/mori ./scripts/mori-backup.sh \
    && find /var/backups/mori -name 'mori-soc-*.dump' -mtime +14 -delete
  ```
- **오프사이트 복제**: 덤프를 다른 호스트/오브젝트 스토리지로 복사한다(단일 디스크 장애 대비).
  가능하면 변경 불가 저장(예: object lock)에 두어 랜섬웨어·실수 삭제에 대비한다.

## 복구

```bash
docker compose up -d soc-postgres            # DB 만 먼저 기동
./scripts/mori-restore.sh backups/mori-soc-YYYYMMDD-HHMMSS.dump   # 확인 프롬프트 → yes
docker compose up -d --build mori-api mori-worker                 # 앱 기동(스키마 자동 재적용)
curl -s http://127.0.0.1:${MORI_API_PORT:-18000}/health           # {"status":"ok"} 확인
```

복구는 기존 객체를 `--clean --if-exists` 로 지우고 재생성한다. 실행 전 현재 데이터가 있으면
`./scripts/mori-backup.sh` 로 먼저 안전 백업을 만든다.

## 재해복구(서버 통째 분실)

빈 서버에서 처음부터 복구하는 순서:

1. 코드: `git clone` (또는 배포 경로에서 `git pull`).
2. 설정: 안전 보관한 `.env` 를 프로젝트 루트에 복원(시크릿 포함).
3. DB 기동: `docker compose up -d soc-postgres`.
4. 데이터: 최신 덤프로 `./scripts/mori-restore.sh <dump>`.
5. 앱 기동: `docker compose up -d --build mori-api mori-worker` (필요 시 `--profile` 로 번들 스택).
6. 검증(아래 완료 기준).

## 완료 기준(복구 검증)

빈 서버 기준으로 다음이 성립해야 복구 성공으로 본다:

```
빈 서버 → .env 복원 → soc-postgres 기동 → mori-restore → mori-api 기동
  → /health 가 {"status":"ok"}
  → 로그인 성공(운영 계정)
  → 자산 담당자 · Triage 이력 · 위험성 평가 · 통제 증적이 복구 전과 동일하게 조회됨
```

자동 검증은 `tests/test_migration_e2e.py`(fresh install + 재적용 무손실)와
`tests/test_state_persistence.py`(재기동 후 6개 store 잔존)가 CI 에서 상시 보증한다.
운영 복구 리허설은 위 수동 절차를 스테이징에서 분기마다 1회 수행할 것을 권장한다.

## 업그레이드와 롤백

스키마는 앱 부팅마다 idempotent 재적용되고(`docs/DEPLOYMENT.md` §주의), 각 파일의 적용 이력은
`schema_migrations`(버전·checksum)에 남는다. 스키마는 **전진(forward)만** 자동화돼 있고 자동
다운그레이드는 없다. 따라서 업그레이드는 **백업 우선 + 이미지 태그 고정**으로 되돌릴 수 있게 한다.

### 업그레이드 절차(롤백 가능하게)

1. **백업 먼저**: `./scripts/mori-backup.sh` — 업그레이드 직전 상태를 dump 로 남긴다.
2. **현재 이미지 태그 기록**: `docker compose images mori-api` (되돌릴 지점).
3. 코드 갱신: `git pull` (또는 태그 체크아웃).
4. 재빌드·기동: `docker compose up -d --build mori-api mori-worker`.
5. 검증: `/health` 가 ok, `GET /admin/schema-migrations` 로 새 마이그레이션이 success 인지,
   핵심 화면(자산·Triage·위험·증적)이 정상인지 확인.

### 롤백 절차(업그레이드가 잘못됐을 때)

1. 코드/이미지를 **이전 태그로 되돌린다**: `git checkout <이전 태그>` → `docker compose up -d --build mori-api`.
   - 스키마는 append-only(`CREATE TABLE IF NOT EXISTS`)라 새로 추가된 테이블/컬럼이 남아 있어도
     구버전 앱은 자기 것만 쓰므로 대개 그대로 동작한다.
2. 데이터까지 되돌려야 하면(예: 마이그레이션이 데이터를 변형) **업그레이드 전 dump 로 복구**:
   `./scripts/mori-restore.sh <업그레이드전.dump>` → `docker compose restart mori-api`.
3. 다운타임: 복구는 DB 재적재 시간(수 초~수십 초) 동안 API 를 재시작한다. 무중단이 필요하면
   스테이징에서 리허설 후 저부하 시간대에 수행한다.

> 파괴적(destructive) 마이그레이션(컬럼 삭제·타입 변경 등)은 현재 스키마 규칙(IF NOT EXISTS)
> 밖이다. 그런 변경을 도입할 때는 **백업 필수 + 롤백 불가**임을 릴리스 노트에 명시한다.
