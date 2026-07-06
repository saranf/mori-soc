# Zabbix 커뮤니티 템플릿 PR 제출 가이드

`config/zabbix/templates/mori_linux_security_baseline.yaml` 를 **Zabbix 공식 커뮤니티
템플릿 저장소**([github.com/zabbix/community-templates](https://github.com/zabbix/community-templates))
에 PR로 제출하는 절차입니다. 이 템플릿은 `configuration.import` round-trip 검증(`true`)을
통과한 **Zabbix 7.4 공식 포맷**이라 그대로 제출 가능합니다.

## 0. 제출 전 체크리스트 (커뮤니티 요건)

- [x] **버전 명시**: `zabbix_export.version: '7.4'`
- [x] **벤더 종속 제거**: 트리거 링크는 하드코딩이 아니라 `{$MORI.URL}` 매크로(기본 빈값)
- [x] **임계값 매크로화**: `{$MORI.DISK.PUSED.MAX}` 등 사용자 매크로 + 기본값
- [x] **LLD**: 마운트 파일시스템 자동 발견(정적 경로 하드코딩 아님)
- [x] **태그**: `class`, `source`, `component` (필터링 표준)
- [x] **import 검증**: `configuration.import` = `true`
- [ ] 스크린샷(선택): Latest data / Problems 예시

## 1. 저장소 포크 & 브랜치

```bash
# github.com/zabbix/community-templates 를 웹에서 Fork 후
git clone git@github.com:<your-user>/community-templates.git
cd community-templates
git checkout -b add-mori-linux-security-baseline
```

## 2. 파일 배치

커뮤니티 저장소는 카테고리 폴더 구조입니다. OS 계열이므로:

```
Operating_Systems/MORI_Linux_Security_Baseline/
├── mori_linux_security_baseline.yaml   # ← config/zabbix/templates/ 의 것 복사
└── README.md                            # ← 아래 템플릿 사용
```

```bash
mkdir -p "Operating_Systems/MORI_Linux_Security_Baseline"
cp <mori-repo>/config/zabbix/templates/mori_linux_security_baseline.yaml \
   "Operating_Systems/MORI_Linux_Security_Baseline/"
```

## 3. 폴더 README.md (커뮤니티 형식 — 그대로 복붙)

````markdown
# MORI Linux Security Baseline

## Overview

A lightweight baseline template for Linux endpoints monitored by **Zabbix agent 2**.
It surfaces disk / CPU / memory / agent-availability problems intended to be consumed
as **audit evidence** (originally built for the MORI SOC platform, but vendor-neutral).

## Requirements

- Zabbix 7.4 or newer
- Zabbix agent 2 on the monitored host

## Macros used

| Name | Description | Default |
|---|---|---|
| `{$MORI.DISK.PUSED.MAX}` | Filesystem used-space trigger threshold, % (context-aware per `{#FSNAME}`) | `85` |
| `{$MORI.CPU.LOAD.MAX}` | CPU load (1m avg) trigger threshold | `4` |
| `{$MORI.MEM.PAVAIL.MIN}` | Minimum available memory, % | `10` |
| `{$MORI.AGENT.NODATA}` | Agent no-data window | `5m` |
| `{$MORI.URL}` | Optional URL attached to triggers (leave empty for none) | *(empty)* |

## Discovery rules

- **Mounted filesystem discovery** (`vfs.fs.discovery`) → per-mount used-% item + trigger.

## Items

- CPU: load average (1m) — `system.cpu.load[all,avg1]`
- Memory: available, in % — `vm.memory.size[pavailable]`
- Zabbix agent availability — `agent.ping`
- FS {#FSNAME}: space used, in % — `vfs.fs.size[{#FSNAME},pused]` (prototype)

## Triggers

| Name | Severity |
|---|---|
| FS {#FSNAME}: space usage is high | High |
| CPU load is too high (avg 5m) | Average |
| Available memory is low | High |
| Zabbix agent is not responding | High |

## Tags

`class=security`, `source=mori`, `component={storage,cpu,memory,agent}`

## Author

<your-name> — <your-github>
````

## 4. 커밋 & PR

```bash
git add Operating_Systems/MORI_Linux_Security_Baseline
git commit -m "Add MORI Linux Security Baseline template (Zabbix 7.4)"
git push origin add-mori-linux-security-baseline
```

- GitHub에서 **Compare & pull request** → base: `zabbix/community-templates:main`.
- PR 본문에 Overview / 요건 체크리스트 / (선택)스크린샷 첨부.
- 리뷰에서 카테고리 폴더명·README 형식 지적이 있으면 맞춰 수정.

## 5. 참고

- 템플릿 재생성/수정은 MORI 저장소의 `./scripts/mori-zabbix-template.sh` 로 하고,
  `--export` 로 YAML 을 다시 뽑아 커뮤니티 폴더에 복사하세요.
- MORI 내부 배포에는 `{$MORI.URL}` 을 MORI Alert Triage 주소로 설정하면 트리거에서
  바로 이동 링크가 붙습니다(커뮤니티 배포본은 빈값 유지).
