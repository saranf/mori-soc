#!/usr/bin/env bash
# ============================================================================
# MORI SOC — 엔드포인트 온보딩 번들 (Zabbix Agent 2 + Fleet 에이전트 + Trivy)
#
# 대상 Linux 서버 1대를 MORI 관측 대상으로 만드는 원커맨드 스크립트.
#   1) Zabbix Agent 2 설치 + MORI Zabbix Server 로 Active 연결 설정
#   2) Fleet 에이전트(fleetd/osquery) 설치 + Fleet 서버로 등록
#   3) Trivy 설치 + 파일시스템 취약점 스캔 → JSON 리포트 (+ MORI 자동 배송)
#
# 사용 (대상 서버, root/sudo):
#   sudo -E MORI_ZABBIX_SERVER=mori.example.com MORI_HOSTNAME=my-web-01 \
#        MORI_FLEET_URL=https://fleet.example.com:1337 MORI_FLEET_SECRET=<enroll-secret> \
#        bash mori-endpoint-onboard.sh
#
# curl 로 바로 (다운로드→확인→실행 권장):
#   curl -fsSL https://raw.githubusercontent.com/saranf/mori-soc/main/scripts/mori-endpoint-onboard.sh -o mori-onboard.sh
#   sudo -E MORI_ZABBIX_SERVER=... MORI_HOSTNAME=... bash mori-onboard.sh
#
# 옵션:
#   -h, --help     도움말
#   --check        사전 점검만(설치 안 함): OS/패키지매니저, root, Zabbix 연결
#   --skip-zabbix  Zabbix Agent 건너뛰기        (env: MORI_SKIP_ZABBIX=1)
#   --skip-fleet   Fleet 에이전트 건너뛰기       (env: MORI_SKIP_FLEET=1)
#   --skip-trivy   Trivy 건너뛰기               (env: MORI_SKIP_TRIVY=1)
#
# env:
#   MORI_ZABBIX_SERVER  (Zabbix용) MORI Zabbix Server 호스트/IP (Agent 접속, :10051)
#   MORI_HOSTNAME       (권장) 이 서버의 Zabbix Host name (기본: `hostname`)
#   MORI_ZABBIX_PORT    (선택) Zabbix Server 포트 (기본 10051)
#   MORI_FLEET_URL      (Fleet용) Fleet 서버 URL (예: https://fleet.example.com:1337)
#   MORI_FLEET_SECRET   (Fleet용) Fleet enroll secret
#   MORI_TRIVY_OUTDIR   (선택) Trivy JSON 출력 폴더 (기본: ./reports/trivy)
#   MORI_INGEST_URL     (선택) 설정 시 Trivy 리포트를 MORI 로 HTTP push (POST /ingest/trivy)
#   MORI_INGEST_TOKEN   (선택) 인제스트 토큰(서버의 MORI_INGEST_TOKEN 과 동일)
# ============================================================================
set -euo pipefail

ZBX_SERVER="${MORI_ZABBIX_SERVER:-}"
ZBX_PORT="${MORI_ZABBIX_PORT:-10051}"
HOSTNAME_VAL="${MORI_HOSTNAME:-$(hostname)}"
TRIVY_OUTDIR="${MORI_TRIVY_OUTDIR:-./reports/trivy}"
FLEET_URL="${MORI_FLEET_URL:-}"
FLEET_SECRET="${MORI_FLEET_SECRET:-}"
SKIP_ZABBIX="${MORI_SKIP_ZABBIX:-0}"
SKIP_FLEET="${MORI_SKIP_FLEET:-0}"
SKIP_TRIVY="${MORI_SKIP_TRIVY:-0}"
CHECK_ONLY=0

# ── 인자 파싱 ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --check) CHECK_ONLY=1 ;;
    --skip-zabbix) SKIP_ZABBIX=1 ;;
    --skip-fleet) SKIP_FLEET=1 ;;
    --skip-trivy) SKIP_TRIVY=1 ;;
    *) echo "알 수 없는 옵션: $1 (--help 참고)"; exit 2 ;;
  esac
  shift
done

c_cyan="\033[36m"; c_grn="\033[32m"; c_yel="\033[33m"; c_red="\033[31m"; c_rst="\033[0m"
log()  { printf "${c_cyan}▶${c_rst} %s\n" "$*"; }
ok()   { printf "${c_grn}✅${c_rst} %s\n" "$*"; }
warn() { printf "${c_yel}⚠️ ${c_rst} %s\n" "$*"; }
err()  { printf "${c_red}✖${c_rst} %s\n" "$*"; }

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ── OS/패키지 매니저 감지 ────────────────────────────────────────────────────
PKG=""
if command -v apt-get >/dev/null 2>&1;   then PKG="apt"
elif command -v dnf >/dev/null 2>&1;      then PKG="dnf"
elif command -v yum >/dev/null 2>&1;      then PKG="yum"
elif command -v brew >/dev/null 2>&1;     then PKG="brew"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 MORI Endpoint Onboard  (Zabbix Agent + Fleet + Trivy)"
echo "   host=${HOSTNAME_VAL}  pkg=${PKG:-unknown}"
echo "   zabbix=${ZBX_SERVER:-<skip>}:${ZBX_PORT}   fleet=${FLEET_URL:-<skip>}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 사전 점검 ────────────────────────────────────────────────────────────────
PRECHECK_OK=1
log "사전 점검..."
[ -n "$PKG" ] && ok "패키지 매니저: $PKG" || { err "지원 패키지 매니저 없음(apt/dnf/yum/brew)"; PRECHECK_OK=0; }
if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
  err "root 아님 + sudo 없음 — 설치 불가"; PRECHECK_OK=0
else ok "권한: $([ "$(id -u)" -eq 0 ] && echo root || echo 'sudo 사용')"; fi

# Zabbix Server 연결 확인 (bash /dev/tcp 우선, 없으면 nc)
if [ -n "$ZBX_SERVER" ]; then
  if (exec 3<>"/dev/tcp/${ZBX_SERVER}/${ZBX_PORT}") 2>/dev/null; then
    ok "Zabbix Server 연결 가능: ${ZBX_SERVER}:${ZBX_PORT}"; exec 3>&- 2>/dev/null || true
  elif command -v nc >/dev/null 2>&1 && nc -z -w3 "$ZBX_SERVER" "$ZBX_PORT" 2>/dev/null; then
    ok "Zabbix Server 연결 가능(nc): ${ZBX_SERVER}:${ZBX_PORT}"
  else
    warn "Zabbix Server(${ZBX_SERVER}:${ZBX_PORT}) 연결 실패 — 방화벽/주소 확인. (설치는 계속)"
  fi
else
  warn "MORI_ZABBIX_SERVER 미지정 — Agent 설정 스킵(설치만). 나중에 conf ServerActive 수정 필요."
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  [ "$PRECHECK_OK" -eq 1 ] && ok "사전 점검 통과 (--check)" || err "사전 점검 실패 (--check)"
  exit $((1 - PRECHECK_OK))
fi
[ "$PRECHECK_OK" -eq 1 ] || { err "사전 점검 실패 — 중단"; exit 1; }

# ── 1) Zabbix Agent 2 ───────────────────────────────────────────────────────
if [ "$SKIP_ZABBIX" != "1" ]; then
  if command -v zabbix_agent2 >/dev/null 2>&1; then
    ok "Zabbix Agent 2 이미 설치됨 — 설정만 갱신"
  else
    log "Zabbix Agent 2 설치..."
    case "$PKG" in
      apt)
        . /etc/os-release 2>/dev/null || true
        DIST="${ID:-ubuntu}"; REL="${VERSION_ID:-24.04}"
        curl -fsSL "https://repo.zabbix.com/zabbix/7.4/release/${DIST}/pool/main/z/zabbix-release/zabbix-release_latest_7.4+${DIST}${REL}_all.deb" -o /tmp/zabbix-release.deb \
          && $SUDO dpkg -i /tmp/zabbix-release.deb && $SUDO apt-get update -y && $SUDO apt-get install -y zabbix-agent2 \
          || warn "Zabbix repo/agent 설치 실패 — 배포판 버전 확인 후 수동 설치"
        ;;
      dnf|yum)
        $SUDO rpm -Uvh "https://repo.zabbix.com/zabbix/7.4/release/rhel/9/noarch/zabbix-release-latest-7.4.el9.noarch.rpm" || true
        $SUDO "$PKG" install -y zabbix-agent2 || warn "zabbix-agent2 설치 실패"
        ;;
      brew) brew install zabbix || warn "brew zabbix 설치 실패" ;;
    esac
  fi

  CONF="/etc/zabbix/zabbix_agent2.conf"
  [ -f "$CONF" ] || CONF="$(brew --prefix 2>/dev/null)/etc/zabbix/zabbix_agent2.conf"
  if [ -f "$CONF" ] && [ -n "$ZBX_SERVER" ]; then
    log "에이전트 설정: $CONF"
    $SUDO sed -i.bak -E "s|^#?[[:space:]]*Server=.*|Server=${ZBX_SERVER}|" "$CONF" || true
    $SUDO sed -i -E "s|^#?[[:space:]]*ServerActive=.*|ServerActive=${ZBX_SERVER}:${ZBX_PORT}|" "$CONF" || true
    $SUDO sed -i -E "s|^#?[[:space:]]*Hostname=.*|Hostname=${HOSTNAME_VAL}|" "$CONF" || true
    grep -q "^ServerActive=" "$CONF" || echo "ServerActive=${ZBX_SERVER}:${ZBX_PORT}" | $SUDO tee -a "$CONF" >/dev/null
    grep -q "^Hostname=" "$CONF"     || echo "Hostname=${HOSTNAME_VAL}" | $SUDO tee -a "$CONF" >/dev/null
    $SUDO systemctl enable --now zabbix-agent2 2>/dev/null || true
    $SUDO systemctl restart zabbix-agent2 2>/dev/null || true
    # 검증
    if systemctl is-active --quiet zabbix-agent2 2>/dev/null; then
      ok "Zabbix Agent 2 실행 중 → ServerActive=${ZBX_SERVER}:${ZBX_PORT}, Hostname=${HOSTNAME_VAL}"
    else
      warn "zabbix-agent2 서비스 미기동 — 'systemctl status zabbix-agent2' 및 /var/log/zabbix/zabbix_agent2.log 확인"
    fi
    command -v zabbix_agent2 >/dev/null 2>&1 && zabbix_agent2 -V 2>/dev/null | head -1 || true
  fi
fi

# ── 2) Fleet 에이전트 (fleetd/osquery) ──────────────────────────────────────
install_fleetctl() {
  command -v fleetctl >/dev/null 2>&1 && return 0
  if command -v npm >/dev/null 2>&1; then
    $SUDO npm install -g fleetctl >/dev/null 2>&1 && command -v fleetctl >/dev/null 2>&1 && return 0
  fi
  # 폴백: GitHub 최신 릴리스에서 fleetctl(linux) 바이너리 다운로드
  local url
  url=$(curl -fsSL https://api.github.com/repos/fleetdm/fleet/releases/latest 2>/dev/null \
        | grep -oE 'https://[^"]*fleetctl_[^"]*_linux\.tar\.gz' | head -1)
  [ -n "$url" ] || return 1
  curl -fsSL "$url" -o /tmp/fleetctl.tar.gz 2>/dev/null && tar -xzf /tmp/fleetctl.tar.gz -C /tmp 2>/dev/null \
    && $SUDO install -m 0755 "$(find /tmp -name fleetctl -type f 2>/dev/null | head -1)" /usr/local/bin/fleetctl 2>/dev/null \
    && command -v fleetctl >/dev/null 2>&1
}

if [ "$SKIP_FLEET" != "1" ]; then
  if command -v orbit >/dev/null 2>&1 || systemctl is-active --quiet orbit 2>/dev/null; then
    ok "Fleet 에이전트(orbit) 이미 설치됨"
  elif [ -z "$FLEET_URL" ] || [ -z "$FLEET_SECRET" ]; then
    warn "MORI_FLEET_URL / MORI_FLEET_SECRET 미지정 — Fleet 에이전트 스킵 (Fleet UI→Add hosts 참고)"
  else
    log "Fleet 에이전트(fleetd) 설치..."
    if install_fleetctl; then
      case "$PKG" in apt) FTYPE=deb ;; dnf|yum) FTYPE=rpm ;; brew) FTYPE=pkg ;; *) FTYPE=deb ;; esac
      log "fleetctl package 생성 (type=$FTYPE)..."
      ( cd /tmp && fleetctl package --type="$FTYPE" --fleet-url="$FLEET_URL" --enroll-secret="$FLEET_SECRET" >/dev/null 2>&1 ) || warn "fleetctl package 생성 실패(인터넷/버전 확인)"
      PKGFILE=$(ls -t /tmp/fleet-osquery*."$FTYPE" 2>/dev/null | head -1)
      if [ -n "${PKGFILE:-}" ]; then
        case "$PKG" in
          apt) $SUDO dpkg -i "$PKGFILE" 2>/dev/null || $SUDO apt-get -f install -y ;;
          dnf|yum) $SUDO "$PKG" install -y "$PKGFILE" ;;
          *) $SUDO installer -pkg "$PKGFILE" -target / 2>/dev/null || warn "패키지 설치 수동 필요: $PKGFILE" ;;
        esac
        if systemctl is-active --quiet orbit 2>/dev/null; then
          ok "Fleet 에이전트(orbit) 실행 중 → $FLEET_URL"
        else
          warn "orbit 서비스 확인 필요 — 'systemctl status orbit'"
        fi
      else
        warn "설치 패키지 생성 실패 — Fleet UI→Add hosts 의 명령을 사용하거나 수동 설치"
      fi
    else
      warn "fleetctl 설치 실패 — 'npm i -g fleetctl' 또는 fleetctl 바이너리 수동 설치 필요"
    fi
  fi
fi

# ── 3) Trivy ────────────────────────────────────────────────────────────────
OUT=""
if [ "$SKIP_TRIVY" != "1" ]; then
  if command -v trivy >/dev/null 2>&1; then
    ok "Trivy 이미 설치됨 ($(trivy --version 2>/dev/null | head -1))"
  else
    log "Trivy 설치..."
    case "$PKG" in
      apt)
        curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null || true
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | $SUDO tee /etc/apt/sources.list.d/trivy.list >/dev/null
        $SUDO apt-get update -y && $SUDO apt-get install -y trivy || warn "trivy 설치 실패"
        ;;
      dnf|yum)
        printf '[trivy]\nname=Trivy\nbaseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/\ngpgcheck=0\nenabled=1\n' | $SUDO tee /etc/yum.repos.d/trivy.repo >/dev/null
        $SUDO "$PKG" install -y trivy || warn "trivy 설치 실패"
        ;;
      brew) brew install trivy || warn "brew trivy 설치 실패" ;;
      *) curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b /usr/local/bin || warn "trivy 설치 스크립트 실패" ;;
    esac
  fi

  if command -v trivy >/dev/null 2>&1; then
    mkdir -p "$TRIVY_OUTDIR"
    OUT="${TRIVY_OUTDIR}/trivy-${HOSTNAME_VAL}-$(date +%Y%m%d).json"
    log "Trivy 파일시스템 스캔 → $OUT (수 분 소요)"
    trivy filesystem --scanners vuln --format json --output "$OUT" / 2>/dev/null \
      || trivy rootfs --format json --output "$OUT" / 2>/dev/null \
      || warn "Trivy 스캔 실패"
    if [ -f "$OUT" ]; then
      N=$(grep -o '"VulnerabilityID"' "$OUT" 2>/dev/null | wc -l | tr -d ' ')
      ok "Trivy 리포트 생성: $OUT (취약점 항목 ~${N}건)"
      # 자동 배송: MORI_INGEST_URL 지정 시 HTTP 로 MORI 에 push (원격→MORI)
      if [ -n "${MORI_INGEST_URL:-}" ]; then
        log "MORI 로 Trivy 리포트 전송 → ${MORI_INGEST_URL%/}/ingest/trivy"
        AUTH=(); [ -n "${MORI_INGEST_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer ${MORI_INGEST_TOKEN}")
        code=$(curl -s -o /tmp/mori_ingest_resp -w "%{http_code}" -X POST "${MORI_INGEST_URL%/}/ingest/trivy" \
          -H "Content-Type: application/json" "${AUTH[@]}" --data-binary "@$OUT" 2>/dev/null || echo 000)
        if [ "$code" = "200" ]; then ok "MORI 인제스트 성공: $(cat /tmp/mori_ingest_resp 2>/dev/null)"
        else warn "MORI 인제스트 실패(HTTP $code) — MORI_INGEST_URL/토큰 확인 또는 수동 scp"; fi
      fi
    fi
  fi
fi

# ── 안내 ────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "온보딩 완료 — 다음 단계"
echo "  1) Zabbix Web(:18081) → Data collection → Hosts → Create host"
echo "     - Host name: ${HOSTNAME_VAL}   (에이전트 Hostname 과 동일)"
echo "     - Templates: 'MORI Linux Security Baseline' 연결"
echo "       (생성: ./scripts/mori-zabbix-template.sh  또는 YAML import:"
echo "        config/zabbix/templates/mori_linux_security_baseline.yaml)"
echo "  2) 임계 초과 → problem → mori-worker 30초 폴링 → MORI 🚨 Alert Triage"
if [ "$SKIP_FLEET" != "1" ] && [ -n "$FLEET_URL" ]; then
echo "  2b) Fleet UI(:1337) → Hosts 에 '${HOSTNAME_VAL}' online 확인 → 자산 식별/osquery"
fi
if [ -n "$OUT" ]; then
echo "  3) Trivy 리포트 → MORI:"
echo "     - MORI 호스트에서 실행: 이미 ${TRIVY_OUTDIR} 에 있음 (MORI_TRIVY_REPORT_GLOB=reports/trivy/*.json)"
echo "     - 원격: scp ${OUT} <mori>:<repo>/reports/trivy/"
fi
echo "  docs: ZABBIX_AGENT_ACTIVE_SETUP.md · TRIVY_USAGE.md"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
