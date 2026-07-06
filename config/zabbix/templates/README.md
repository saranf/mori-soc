# MORI Zabbix Templates

Zabbix 공식 export 포맷(YAML)으로 저장한 MORI 표준 템플릿입니다. Zabbix Web
(**Data collection → Templates → Import**) 또는 API(`configuration.import`)로 그대로
가져올 수 있고, Zabbix 커뮤니티 템플릿 저장소 제출 형식과 동일합니다.

## `mori_linux_security_baseline.yaml` — MORI Linux Security Baseline

Zabbix Agent 2가 붙은 Linux 엔드포인트에서 감사/보안 관점 problem을 만들어
MORI Alert Triage로 흘려보내는 베이스라인 템플릿.

| 항목 | 키 | 트리거 (기본 임계, 매크로) | 심각도 |
|---|---|---|---|
| **FS 자동 발견 (LLD)** | `vfs.fs.discovery` → `vfs.fs.size[{#FSNAME},pused]` | 마운트별 `> {$MORI.DISK.PUSED.MAX:"{#FSNAME}"}` (85) | High |
| CPU load (1m) | `system.cpu.load[all,avg1]` | `avg(5m) > {$MORI.CPU.LOAD.MAX}` (4) | Average |
| Memory available % | `vm.memory.size[pavailable]` | `< {$MORI.MEM.PAVAIL.MIN}` (10) | High |
| Agent availability | `agent.ping` | `nodata({$MORI.AGENT.NODATA})` (5m) | High |

> 디스크는 **LLD(Low-Level Discovery)** 로 마운트된 모든 파일시스템을 자동 발견해 마운트별 트리거를 생성합니다. 컨텍스트 매크로 `{$MORI.DISK.PUSED.MAX:"{#FSNAME}"}` 로 특정 마운트만 임계값을 다르게 줄 수 있습니다.

- **매크로**로 임계값 파라미터화 → 호스트/템플릿 레벨에서 재정의.
- **`{$MORI.URL}`** (기본 빈값): 값을 넣으면 각 트리거에 MORI Alert Triage 딥링크가 붙습니다.
- 태그: `class=security`, `source=mori`, `component=<storage|cpu|memory|agent>`.

### 사용

```bash
# 생성/수정은 API 스크립트로
./scripts/mori-zabbix-template.sh            # 생성
./scripts/mori-zabbix-template.sh --export   # 이 YAML 재생성(stdout)
./scripts/mori-zabbix-template.sh --delete    # 삭제

# 또는 Zabbix Web 에서 이 YAML 을 Import
```

> 검증: `configuration.import` round-trip이 `true` — 실제 import 가능한 유효 템플릿(Zabbix 7.4).
