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
  0 3 * * * cd /backup/rmstudio/mori && BACKUP_DIR=/var/backups/mori ./scripts/mori-backup.sh \
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

## 업그레이드와의 관계

스키마는 앱 부팅마다 idempotent 재적용된다(`docs/DEPLOYMENT.md` §주의). 업그레이드가 잘못돼도
데이터는 보존되지만, **업그레이드 전 반드시 위 백업을 만들어** 이미지 롤백 시 함께 복원할 수 있게
한다(이전 이미지 태그로 되돌린 뒤 필요 시 덤프 복원).
