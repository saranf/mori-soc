#!/usr/bin/env bash
# ============================================================================
# MORI SOC — Zabbix community-templates PR 준비 자동화
#
# 대상 레포: https://github.com/zabbix/community-templates
# 올릴 것  : config/zabbix/templates/mori_linux_security_baseline.yaml + README.md
#
# 이 스크립트가 하는 일 (mechanical 부분 자동화):
#   1) 포크 클론 안에 카테고리 폴더 생성
#   2) 템플릿 YAML 복사 + 커뮤니티 형식 README.md 생성
#   3) 새 브랜치 + git add + commit (로컬)
#   4) push / PR 오픈 명령 출력 (gh 있으면 PR 초안까지)
#
# 사용:
#   # (A) 이미 포크를 클론해 뒀다면:
#   ./scripts/mori-community-pr.sh /path/to/community-templates
#
#   # (B) 포크 URL 로 새로 클론:
#   ./scripts/mori-community-pr.sh --clone git@github.com:<you>/community-templates.git
#
# env:
#   MORI_PR_AUTHOR   README/PR 서명 (기본: git user.name)
#   MORI_PR_CATEGORY 카테고리 폴더 (기본: "Operating Systems" — 실제 레포 구조에 맞게 조정)
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_YAML="$REPO_ROOT/config/zabbix/templates/mori_linux_security_baseline.yaml"
# 커뮤니티 레포 컨벤션: 카테고리/폴더는 언더스코어 (예: Operating_Systems/Linux)
TPL_LEAF="${MORI_PR_LEAF:-MORI_Linux_Security_Baseline}"
CATEGORY="${MORI_PR_CATEGORY:-Operating_Systems}"
BRANCH="add-mori-linux-security-baseline"
AUTHOR="${MORI_PR_AUTHOR:-$(git config user.name 2>/dev/null || echo 'your-name')}"

err(){ printf "\033[31m✖\033[0m %s\n" "$*" >&2; }
ok(){  printf "\033[32m✅\033[0m %s\n" "$*"; }
log(){ printf "\033[36m▶\033[0m %s\n" "$*"; }

[ -f "$SRC_YAML" ] || { err "템플릿 YAML 없음: $SRC_YAML  (먼저 ./scripts/mori-zabbix-template.sh --export 로 생성)"; exit 1; }

# ── 포크 위치 결정 ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--clone" ]; then
  [ -n "${2:-}" ] || { err "--clone <fork-git-url> 형식으로 URL 지정"; exit 2; }
  FORK_DIR="$REPO_ROOT/community-templates-fork"
  log "포크 클론 → $FORK_DIR"
  [ -d "$FORK_DIR/.git" ] || git clone "$2" "$FORK_DIR"
else
  FORK_DIR="${1:-}"
  [ -n "$FORK_DIR" ] || { err "사용법: $0 <포크클론경로>  또는  $0 --clone <fork-url>"; exit 2; }
fi
[ -d "$FORK_DIR/.git" ] || { err "git 저장소가 아님: $FORK_DIR"; exit 2; }

cd "$FORK_DIR"
# community-templates 포크가 맞는지 가벼운 확인
if ! git remote -v | grep -qi "community-templates"; then
  err "이 저장소의 remote 가 community-templates 가 아닌 듯합니다. zabbix/community-templates 포크를 사용하세요."
  echo "   현재 remote:"; git remote -v | sed 's/^/     /'
  exit 2
fi

DEST_DIR="$FORK_DIR/$CATEGORY/$TPL_LEAF"
log "카테고리 폴더: $CATEGORY/$TPL_LEAF"
mkdir -p "$DEST_DIR"

# ── 1) YAML 복사 ─────────────────────────────────────────────────────────────
cp "$SRC_YAML" "$DEST_DIR/mori_linux_security_baseline.yaml"
ok "템플릿 YAML 복사"

# ── 2) 커뮤니티 형식 README 생성 ─────────────────────────────────────────────
cat > "$DEST_DIR/README.md" <<README
# MORI Linux Security Baseline

## Overview

A lightweight security/audit baseline template for Linux endpoints monitored by
**Zabbix agent 2**. It surfaces disk / CPU / memory / agent-availability problems
so they can be consumed as audit evidence. Vendor-neutral: the only vendor-specific
piece (a trigger URL) is a macro that defaults to empty.

## Requirements

- Zabbix 7.4 or newer
- Zabbix agent 2 on the monitored host

## Macros used

| Name | Description | Default |
|---|---|---|
| \`{\$MORI.DISK.PUSED.MAX}\` | Filesystem used-space trigger threshold, % (context-aware per \`{#FSNAME}\`) | \`85\` |
| \`{\$MORI.CPU.LOAD.MAX}\` | CPU load (1m avg) trigger threshold | \`4\` |
| \`{\$MORI.MEM.PAVAIL.MIN}\` | Minimum available memory, % | \`10\` |
| \`{\$MORI.AGENT.NODATA}\` | Agent no-data window | \`5m\` |
| \`{\$MORI.URL}\` | Optional URL attached to triggers (leave empty for none) | *(empty)* |

## Discovery rules

- **Mounted filesystem discovery** (\`vfs.fs.discovery\`) → per-mount used-% item + trigger.

## Items

- CPU: load average (1m) — \`system.cpu.load[all,avg1]\`
- Memory: available, in % — \`vm.memory.size[pavailable]\`
- Zabbix agent availability — \`agent.ping\`
- FS {#FSNAME}: space used, in % — \`vfs.fs.size[{#FSNAME},pused]\` (prototype)

## Triggers

| Name | Severity |
|---|---|
| FS {#FSNAME}: space usage is high | High |
| CPU load is too high (avg 5m) | Average |
| Available memory is low | High |
| Zabbix agent is not responding | High |

## Tags

\`class=security\`, \`source=mori\`, \`component={storage,cpu,memory,agent}\`

## Author

$AUTHOR
README
ok "커뮤니티 README.md 생성"

# ── 3) 브랜치 + 커밋 ─────────────────────────────────────────────────────────
git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH"
git add "$CATEGORY/$TPL_LEAF"
git commit -q -m "Add MORI Linux Security Baseline template (Zabbix 7.4)" || log "커밋할 변경 없음(이미 커밋됨?)"
ok "브랜치 '$BRANCH' 에 커밋 완료"

# ── 4) PR 본문 파일 + 안내 ───────────────────────────────────────────────────
PR_BODY="$FORK_DIR/PR_BODY.md"
cat > "$PR_BODY" <<'BODY'
## Add: MORI Linux Security Baseline (Zabbix 7.4)

A vendor-neutral security/audit baseline for Linux endpoints (Zabbix agent 2).

**Highlights**
- Filesystem LLD (per-mount used-% items & triggers)
- Static CPU load / available memory / agent availability triggers
- All thresholds parameterized via user macros (context-aware for filesystems)
- Trigger URL is a macro (`{$MORI.URL}`, empty by default) — no vendor lock-in
- Tags: class=security, source=mori, component=…
- Validated: `configuration.import` round-trip returns `true` on Zabbix 7.4

**Files** (see PR diff)
- `<category>/MORI_Linux_Security_Baseline/mori_linux_security_baseline.yaml`
- `<category>/MORI_Linux_Security_Baseline/README.md`
BODY

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "준비 완료 — 남은 것은 push + PR 오픈"
echo "  1) push:   (cd \"$FORK_DIR\" && git push -u origin $BRANCH)"
if command -v gh >/dev/null 2>&1; then
echo "  2) PR:     (cd \"$FORK_DIR\" && gh pr create --repo zabbix/community-templates \\"
echo "               --base main --head <you>:$BRANCH \\"
echo "               --title 'Add MORI Linux Security Baseline template (Zabbix 7.4)' \\"
echo "               --body-file PR_BODY.md)"
else
echo "  2) PR:     github.com/zabbix/community-templates → 'Compare & pull request'"
echo "             base: zabbix/community-templates:main ← head: <you>:$BRANCH"
echo "             제목/본문: $PR_BODY 내용 사용"
fi
echo ""
echo "  ⚠️  카테고리 폴더명(\"$CATEGORY\")은 실제 레포 구조와 다를 수 있습니다."
echo "      community-templates 최상위 폴더 목록을 확인하고 다르면"
echo "      MORI_PR_CATEGORY=\"<정확한폴더>\" 로 다시 실행하세요."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
