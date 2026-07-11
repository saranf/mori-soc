# Zabbix community-templates 제안 — Linux access records (접속기록)

> 대상 저장소: **zabbix/community-templates** (별도 repo, PR로 제출)
> 참고 선례: 사용자의 기존 PR **#745** (`Operating_Systems/template_linux_security_baseline/7.4/`, security/audit baseline)
> 이 제안은 그 baseline의 **접속기록(access record) 확장**이다.

---

## 1. 무엇을 템플릿화했나 (Zabbix에서 가능한 것만)

접속기록에서 **Zabbix로 templatize 가능한 것 = OS 레벨 인증로그 수집**(sshd 로그인·sudo). 각 서버에 이미 있는 Zabbix agent가 `log[]` active 아이템으로 auth log를 tail → **누가·언제·어디서 로그인했나**를 Zabbix가 각 서버에서 수집.

**템플릿화 안 되는 것(경계, 정직):**
- **애플리케이션 "수행업무" 접속기록**(개인정보처리시스템에서 어떤 정보주체 정보를 처리했나) → 앱/DB 감사로그 영역, 템플릿 불가.
- **Zabbix 관리콘솔 접속기록** → 서버 측 `auditlog.get` **API**, 템플릿이 아니라 코드 수집.
- **장기보관·위·변조 방지** → Zabbix history가 아니라 로그 저장소(Loki/SIEM) 몫.

## 2. 제출 파일

```
Operating_Systems/template_linux_access_records/7.4/template_linux_access_records.yaml
```

- 형식 **YAML**, Zabbix **7.4** (PR #745와 동일 컨벤션: `template_` 접두어, 버전 하위폴더, 보안 태그 `class=security`).
- 템플릿: `Linux access records by Zabbix agent active`.
- **매크로**(튜너블): `{$ACCESSLOG.PATH}`(/var/log/secure ↔ auth.log), `{$ACCESSLOG.ACCEPTED/FAILED/SUDO.REGEX}`, `{$ACCESSLOG.FAILED.WINDOW}`(5m), `{$ACCESSLOG.FAILED.MAX}`(10).
- **아이템**(Zabbix agent active, value type **Log**): accepted logins · failed logins · sudo commands.
- **트리거**: `count(failed, {WINDOW}) > {MAX}` → 브루트포스 의심(Warning, `class=security`, `source=linux-access-records`).

## 3. 왜 커뮤니티에 유용한가 (실제 필요)

- 감사·컴플라이언스(ISMS-P 2.9.4 / ISO 27001 A.8.15 / PIPA 접속기록 의무)에서 **"각 서버의 로그인 기록"**은 흔한 필수 증적인데, 순수 Zabbix로 이걸 표준화한 공개 템플릿이 드묾.
- 이미 Zabbix를 쓰는 조직은 **새 로그 파이프라인(Promtail/Loki) 없이** 에이전트 설정만으로 접속기록 수집·브루트포스 탐지를 얻음.
- #745 security baseline과 **짝**을 이뤄 "가용성/자원 + 접속기록"의 audit baseline 세트가 됨.

## 4. 제출 전 반드시 검증 (정직성)

이 YAML은 **구조·컨벤션 기준으로 작성한 초안이며, 실제 Zabbix 7.4에서 import 검증을 아직 안 했다.** 제출 전:

1. Zabbix 7.4 UI → *Data collection → Templates → Import* 로 이 YAML을 임포트해 **파싱·UUID·키 검증**(UUID 충돌 시 재생성).
2. 테스트 호스트에 **Zabbix agent(active)** + `ServerActive` 설정, `zabbix` 사용자가 `{$ACCESSLOG.PATH}` **읽기 권한** 확인.
3. 실제 로그인/실패/sudo 발생시켜 3개 아이템에 Log 값 수집 + 브루트포스 트리거 발화 확인.
4. community-templates **CONTRIBUTING** 가이드(폴더 구조·README·스크린샷 요건) 준수 후 PR.

## 5. 제출 절차 (요약)

```bash
# community-templates 포크에서
mkdir -p Operating_Systems/template_linux_access_records/7.4
cp template_linux_access_records.yaml Operating_Systems/template_linux_access_records/7.4/
# 가이드 요건: README.md(개요·매크로·요구사항) + 필요 시 스크린샷 추가
git checkout -b template-linux-access-records
git add Operating_Systems/template_linux_access_records
git commit -m "Add Linux access records template (auth log, Zabbix agent active) for 7.4"
git push origin template-linux-access-records
# → PR: base zabbix/community-templates:main
```

## 6. MORI 연결

이 템플릿(경로 B: Zabbix 수집)은 **MORI의 접속기록 증적 층과 짝**이다 — Zabbix history에 쌓인 접속기록을 MORI가 `history.get`으로 읽어(다음 개발 후보) 보존현황·월간점검·접속 발자취·커버리지 대사 증적으로 승격할 수 있다. Loki 경로(현재 구현)와 택일/병행.
