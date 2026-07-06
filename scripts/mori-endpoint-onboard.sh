#!/usr/bin/env bash
# ============================================================================
# MORI SOC — 엔드포인트 온보딩 번들 (Zabbix Agent 2 + Trivy 동시 설치)
#
# 대상 Linux 서버 1대를 MORI 관측 대상으로 만드는 원커맨드 스크립트:
#   1) Zabbix Agent 2 설치 + MORI Zabbix Server 로 Active 연결 설정
#   2) Trivy 설치 + 파일시스템 취약점 스캔 → JSON 리포트 생성
#
# 사용 (대상 서버에서 sudo 로):
#   MORI_ZABBIX_SERVER=mori.example.com \
#   MORI_HOSTNAME=my-web-01 \
#   sudo -E ./scripts/mori-endpoint-onboard.sh
#
# 옵션 env:
#   MORI_ZABBIX_SERVER   (필수) MORI Zabbix Server 호스트/IP (Agent 가 접속, :10051)
#   MORI_HOSTNAME        (필수) 이 서버의 Zabbix Host name (Web 등록 시 동일값)
#   MORI_TRIVY_OUTDIR    (선택) Trivy JSON 출력 폴더 (기본: ./reports/trivy)
#   MORI_SKIP_TRIVY=1    (선택) Trivy 설치/스캔 건너뛰기
#   MORI_SKIP_ZABBIX=1   (선택) Zabbix Agent 설치 건너뛰기
# ============================================================================
set -euo pipefail

ZBX_SERVER="${MORI_ZABBIX_SERVER:-}"
HOSTNAME_VAL="${MORI_HOSTNAME:-$(hostname)}"
TRIVY_OUTDIR="${MORI_TRIVY_OUTDIR:-./reports/trivy}"

log() { printf '\033[36m▶\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m✅\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m⚠️ \033[0m %s\n' "$*"; }

# ── OS/패키지 매니저 감지 ────────────────────────────────────────────────────
PKG=""
if command -v apt-get >/dev/null 2>&1;   then PKG="apt"
elif command -v dnf >/dev/null 2>&1;      then PKG="dnf"
elif command -v yum >/dev/null 2>&1;      then PKG="yum"
elif command -v brew >/dev/null 2>&1;     then PKG="brew"
else warn "지원되는 패키지 매니저(apt/dnf/yum/brew)를 못 찾음"; fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 MORI Endpoint Onboard  (pkg=${PKG:-unknown}, host=${HOSTNAME_VAL})"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1) Zabbix Agent 2 ───────────────────────────────────────────────────────
if [ "${MORI_SKIP_ZABBIX:-0}" != "1" ]; then
  if [ -z "$ZBX_SERVER" ]; then
    warn "MORI_ZABBIX_SERVER 미지정 → Zabbix Agent 설정 스킵 (설치만). 나중에 conf 의 ServerActive 수정 필요."
  fi
  log "Zabbix Agent 2 설치..."
  case "$PKG" in
    apt)
      . /etc/os-release 2>/dev/null || true
      REL="${VERSION_ID:-24.04}"; DIST="${ID:-ubuntu}"
      TMPDEB="/tmp/zabbix-release.deb"
      curl -fsSL "https://repo.zabbix.com/zabbix/7.4/release/${DIST}/pool/main/z/zabbix-release/zabbix-release_latest_7.4+${DIST}${REL}_all.deb" -o "$TMPDEB" \
        && dpkg -i "$TMPDEB" && apt-get update -y && apt-get install -y zabbix-agent2 \
        || warn "Zabbix repo 설치 실패 — 배포판 버전 확인 후 수동 설치 필요"
      ;;
    dnf|yum)
      rpm -Uvh "https://repo.zabbix.com/zabbix/7.4/release/rhel/9/noarch/zabbix-release-latest-7.4.el9.noarch.rpm" || true
      "$PKG" install -y zabbix-agent2 || warn "zabbix-agent2 설치 실패"
      ;;
    brew) brew install zabbix || warn "brew zabbix 설치 실패" ;;
    *) warn "Zabbix Agent 자동 설치 불가 — 수동 설치 필요" ;;
  esac

  CONF="/etc/zabbix/zabbix_agent2.conf"
  [ -f "$CONF" ] || CONF="$(brew --prefix 2>/dev/null)/etc/zabbix/zabbix_agent2.conf"
  if [ -f "$CONF" ] && [ -n "$ZBX_SERVER" ]; then
    log "에이전트 설정 ($CONF)"
    sed -i.bak -E "s|^#?[[:space:]]*Server=.*|Server=${ZBX_SERVER}|" "$CONF" || true
    sed -i -E "s|^#?[[:space:]]*ServerActive=.*|ServerActive=${ZBX_SERVER}:10051|" "$CONF" || true
    sed -i -E "s|^#?[[:space:]]*Hostname=.*|Hostname=${HOSTNAME_VAL}|" "$CONF" || true
    grep -q "^ServerActive=" "$CONF" || echo "ServerActive=${ZBX_SERVER}:10051" >> "$CONF"
    grep -q "^Hostname=" "$CONF" || echo "Hostname=${HOSTNAME_VAL}" >> "$CONF"
    systemctl enable --now zabbix-agent2 2>/dev/null || true
    systemctl restart zabbix-agent2 2>/dev/null || true
    ok "Zabbix Agent 2 설정 완료 → ServerActive=${ZBX_SERVER}:10051, Hostname=${HOSTNAME_VAL}"
  fi
fi

# ── 2) Trivy ────────────────────────────────────────────────────────────────
if [ "${MORI_SKIP_TRIVY:-0}" != "1" ]; then
  log "Trivy 설치..."
  if ! command -v trivy >/dev/null 2>&1; then
    case "$PKG" in
      apt)
        curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || true
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
        apt-get update -y && apt-get install -y trivy || warn "trivy apt 설치 실패"
        ;;
      dnf|yum)
        cat > /etc/yum.repos.d/trivy.repo <<'REPO'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=0
enabled=1
REPO
        "$PKG" install -y trivy || warn "trivy 설치 실패"
        ;;
      brew) brew install trivy || warn "brew trivy 설치 실패" ;;
      *)
        # 폴백: 공식 설치 스크립트
        curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || warn "trivy 설치 스크립트 실패"
        ;;
    esac
  fi

  if command -v trivy >/dev/null 2>&1; then
    mkdir -p "$TRIVY_OUTDIR"
    OUT="${TRIVY_OUTDIR}/trivy-${HOSTNAME_VAL}-$(date +%Y%m%d).json"
    log "Trivy 파일시스템 스캔 → $OUT (수 분 소요)"
    trivy filesystem --scanners vuln --format json --output "$OUT" / 2>/dev/null \
      || trivy rootfs --format json --output "$OUT" / 2>/dev/null \
      || warn "Trivy 스캔 실패"
    [ -f "$OUT" ] && ok "Trivy 리포트 생성: $OUT"
  fi
fi

# ── 안내 ────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "온보딩 완료 — 다음 단계"
echo "  1) Zabbix Web(:18081) → Data collection → Hosts → Create host"
echo "     - Host name: ${HOSTNAME_VAL}  (에이전트 Hostname 과 동일)"
echo "     - Templates: 'MORI Linux Security Baseline' 연결 (./scripts/mori-zabbix-template.sh 로 생성)"
echo "  2) 임계 초과 시 problem 발생 → mori-worker 30초 폴링 → MORI 🚨 Alert Triage"
echo "  3) Trivy 리포트를 MORI 로 전달:"
echo "     - MORI 호스트에서 실행했다면 이미 ${TRIVY_OUTDIR} 에 있음 (MORI_TRIVY_REPORT_GLOB=reports/trivy/*.json)"
echo "     - 원격이면 scp: scp ${OUT:-<report>} <mori>:<MORI_repo>/reports/trivy/"
echo "  자세히: docs/ZABBIX_AGENT_ACTIVE_SETUP.md · docs/TRIVY_USAGE.md"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
