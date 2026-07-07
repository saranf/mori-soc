# Trivy 활용 가이드

## 1. 목적

이 문서는 MORI SOC-lite 저장소에서 Trivy를 이용해
파일시스템 및 컨테이너 이미지 취약점을 점검하는 방법을 정리합니다.

## 2. 현재 구성

현재 `docker-compose.yml`에는 아래 서비스가 포함되어 있습니다.

- 서비스명: `trivy`
- 실행 프로필: `scanner`
- 기본 모드: 파일시스템 스캔

직접 실행 시 기본 명령:

```bash
docker compose --profile scanner run --rm trivy
```

## 3. 추천 실행 스크립트

저장소에는 아래 보조 스크립트를 추가했습니다.

- `scripts/trivy-fs-scan.sh`: 저장소 내부 경로 스캔
- `scripts/trivy-image-scan.sh`: 이미지 레퍼런스 스캔

리포트는 자동으로 아래 경로에 저장됩니다.

- `reports/trivy/`

## 4. 파일시스템 스캔

저장소 전체 스캔:

```bash
./scripts/trivy-fs-scan.sh .
```

특정 경로만 스캔:

```bash
./scripts/trivy-fs-scan.sh config
./scripts/trivy-fs-scan.sh .github
```

심각도 범위 조정 예시:

```bash
TRIVY_SEVERITY=CRITICAL,HIGH ./scripts/trivy-fs-scan.sh .
```

## 5. 이미지 스캔

Grafana 이미지 스캔:

```bash
./scripts/trivy-image-scan.sh grafana/grafana-oss:11.5.2
```

Zabbix Web 이미지 스캔:

```bash
./scripts/trivy-image-scan.sh zabbix/zabbix-web-nginx-pgsql:alpine-7.4-latest
```

## 6. 출력 형식

기본 출력 형식은 `table`입니다.

JSON 형식 예시:

```bash
TRIVY_FORMAT=json ./scripts/trivy-fs-scan.sh .
```

## 7. 운영 권장 방식

PoC 단계에서는 아래 순서를 권장합니다.

1. 저장소 전체 파일시스템 스캔
2. 운영 예정 이미지 개별 스캔
3. `CRITICAL`, `HIGH` 우선 정리
4. 이후 CI 또는 cron에 연결

## 7.5 MORI 원격 인제스트 (push)

원격 호스트/CI/CSOP 에이전트가 스캔 결과를 MORI로 직접 push할 수 있습니다. 인증은
`MORI_INGEST_TOKEN`(mori-api env) 이며 `Authorization: Bearer <토큰>` 또는
`X-MORI-Token` 헤더를 사용합니다. 토큰 미설정 시 로그인 세션이 필요합니다(자동화 불가).

### 원본 Trivy 리포트 → `POST /ingest/trivy`

```bash
# 호스트 매핑: ?hostname= / X-MORI-Hostname / 본문 hostname 중 하나로 실제 호스트에 연결.
# (미지정 시 ArtifactName 에서 파생 → 이미지 스캔이 Zabbix/Fleet 호스트와 안 묶임)
curl -X POST "https://mori.example.com/ingest/trivy?hostname=server-db01" \
  -H "Authorization: Bearer $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' \
  --data @trivy-report.json
# → {"ok":true,"records_collected":N,"entities_saved":M,"host_id":"server-db01"}
```

MORI가 리포트를 자체 정규화·적재합니다(라이브 조회는 postgres 백엔드 필요).

### 조치 전/후 증적 → `POST /ingest/evidence`

`/ingest/trivy` 는 원본 리포트만 받아 정규화하므로 `delta_type`(new/fixed/reopened) 이나
조치 전/후 증적은 담지 못합니다. CSOP diff envelope 은 이 엔드포인트로 push합니다.

```bash
# 단건 또는 {"events":[…]} 배열. payload 원형은 JSONB 로 보존, 조회용 키만 추출.
curl -X POST "https://mori.example.com/ingest/evidence" \
  -H "X-MORI-Token: $MORI_INGEST_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"server-db01","delta_type":"fixed","cve":"CVE-2024-9","summary":"openssl 패치"}'
# → {"ok":true,"saved":1,"ids":["evi-…"]}
```

적재된 증적은 `ui_evidence_events` 테이블(`schema/006`)에 보관되며, **admin·security** 롤만
`GET /evidence?host=…&delta=…&limit=…` 로 최신순 조회할 수 있습니다(위험성 평가와 동일 가시성).

## 8. 해석 기준

- `CRITICAL`: 우선 조치 대상
- `HIGH`: 운영 배포 전 검토 권장
- `MEDIUM`: 일정에 맞춰 순차 개선

## 9. 한계 및 주의

- 이미지 스캔은 이미지 레퍼런스 기준으로 수행합니다.
- 파일시스템 스캔은 현재 저장소에 존재하는 의존성/매니페스트 기준입니다.
- 결과 해석 시 실제 배포 환경의 베이스 이미지 버전과 함께 확인해야 합니다.