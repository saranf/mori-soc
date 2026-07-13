#!/usr/bin/env bash
# ============================================================================
# MORI SOC — 로컬 계정 수집 → POST /ingest/accounts
#
# Fleet(osquery) 이 깔린 호스트는 MORI 가 Fleet 에서 계정을 가져오므로 이 스크립트가
# 필요 없다. 이 스크립트는 **Fleet 이 없는 서버**용 보조 경로다.
# osquery 가 있으면 osquery 를, 없으면 /etc/passwd·group·sudoers·lastlog 를 파싱한다.
#
# 사용:
#   export MORI_INGEST_URL=https://mori.example.com
#   export MORI_INGEST_TOKEN=<서버 .env 의 MORI_INGEST_TOKEN>
#   sudo -E bash mori-collect-accounts.sh            # 1회 수집
#   sudo -E bash mori-collect-accounts.sh --cron     # 1회 수집 + 매일 03:20 cron 등록
#   sudo -E bash mori-collect-accounts.sh --dry-run  # 전송 안 하고 payload 만 출력
#
# env:
#   MORI_INGEST_URL    (필수) MORI 베이스 URL
#   MORI_INGEST_TOKEN  (필수) 인제스트 토큰
#   MORI_HOSTNAME      (선택) 자산 매칭용 호스트명 (기본: hostname)
#   MORI_HOST_TYPE     (선택) server | pc  (기본: server)
#
# 참고: 호스트별 계정 집합을 **통째로 교체**하므로 주기 실행 시 항상 최신 상태가 된다.
# ============================================================================
set -euo pipefail

INGEST_URL="${MORI_INGEST_URL:-}"
INGEST_TOKEN="${MORI_INGEST_TOKEN:-}"
HOSTNAME_VAL="${MORI_HOSTNAME:-$(hostname)}"
HOST_TYPE="${MORI_HOST_TYPE:-server}"
DO_CRON=0
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --cron) DO_CRON=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "알 수 없는 옵션: $arg (--help)"; exit 2 ;;
  esac
done

if [ "$DRY_RUN" -eq 0 ]; then
  [ -n "$INGEST_URL" ]   || { echo "MORI_INGEST_URL 미설정 — 중단"; exit 1; }
  [ -n "$INGEST_TOKEN" ] || { echo "MORI_INGEST_TOKEN 미설정 — 중단"; exit 1; }
fi

# ── 계정 수집 → JSON accounts 배열 ──────────────────────────────────────────
# osquery 가 있으면 그걸 쓰고(그룹·sudo 판정이 정확), 없으면 표준 파일을 파싱한다.
collect_accounts_json() {
  if command -v osqueryi >/dev/null 2>&1; then
    osqueryi --json "
      SELECT u.username, u.uid, u.gid, u.shell, u.directory AS home
      FROM users u WHERE u.username NOT LIKE '\_%';" 2>/dev/null \
      | python3 -c '
import json,sys,subprocess
rows=json.load(sys.stdin)
def groups_of(u):
    try:
        return subprocess.run(["id","-nG",u],capture_output=True,text=True,timeout=5).stdout.split()
    except Exception:
        return []
out=[]
for r in rows:
    g=groups_of(r.get("username",""))
    out.append({**r,"groups":g,"sudo":bool({"sudo","wheel","admin"} & {x.lower() for x in g})})
print(json.dumps(out,ensure_ascii=False))'
  else
    python3 - <<'PY'
import json, subprocess, pwd, grp, os

def last_login(u):
    try:
        out = subprocess.run(["lastlog","-u",u],capture_output=True,text=True,timeout=5).stdout.splitlines()
        if len(out) > 1 and "Never" not in out[1]:
            return " ".join(out[1].split()[3:])
    except Exception:
        pass
    return None

def sudoers_users():
    users = set()
    for path in ("/etc/sudoers", *(os.path.join("/etc/sudoers.d", f)
                                   for f in (os.listdir("/etc/sudoers.d") if os.path.isdir("/etc/sudoers.d") else []))):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("Defaults"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and "ALL" in line and not parts[0].startswith("%"):
                        users.add(parts[0])
        except OSError:
            continue
    return users

sudo_direct = sudoers_users()
all_groups = grp.getgrall()          # 한 번만 읽어 재사용
accounts = {}                        # username → account (중복 엔트리 제거)
for p in pwd.getpwall():
    if p.pw_name.startswith("_") or p.pw_name in accounts:
        continue
    try:
        groups = [g.gr_name for g in all_groups if p.pw_name in g.gr_mem]
        primary = grp.getgrgid(p.pw_gid).gr_name
        if primary not in groups:
            groups.append(primary)
    except Exception:
        groups = []
    groups = sorted(set(groups))     # 그룹 중복 제거
    gl = {g.lower() for g in groups}
    is_sudo = bool(gl & {"sudo", "wheel", "admin"}) or p.pw_name in sudo_direct
    # nologin/false 셸이면 비활성으로 본다
    disabled = any(s in (p.pw_shell or "") for s in ("nologin", "/false"))
    accounts[p.pw_name] = {
        "username": p.pw_name, "uid": str(p.pw_uid), "gid": str(p.pw_gid),
        "shell": p.pw_shell, "home": p.pw_dir, "groups": groups,
        "sudo": is_sudo, "disabled": disabled, "last_login": last_login(p.pw_name),
    }
print(json.dumps(sorted(accounts.values(), key=lambda a: a["username"]), ensure_ascii=False))
PY
  fi
}

ACCOUNTS_JSON="$(collect_accounts_json)"
PAYLOAD="$(python3 -c '
import json,sys
accounts=json.loads(sys.argv[1]); host=sys.argv[2]; htype=sys.argv[3]
print(json.dumps({"hostname":host,"host_type":htype,"accounts":accounts},ensure_ascii=False))' \
  "$ACCOUNTS_JSON" "$HOSTNAME_VAL" "$HOST_TYPE")"

COUNT="$(python3 -c 'import json,sys;print(len(json.loads(sys.argv[1])["accounts"]))' "$PAYLOAD")"
echo "수집: ${COUNT} 계정 (host=${HOSTNAME_VAL}, type=${HOST_TYPE})"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "$PAYLOAD"
  exit 0
fi

# ── MORI 로 전송 ────────────────────────────────────────────────────────────
HTTP_CODE="$(printf '%s' "$PAYLOAD" | curl -s -o /tmp/mori-acct-resp.json -w '%{http_code}' \
  -X POST "${INGEST_URL%/}/ingest/accounts?hostname=$(printf '%s' "$HOSTNAME_VAL" | sed 's/ /%20/g')" \
  -H "Authorization: Bearer ${INGEST_TOKEN}" \
  -H 'Content-Type: application/json' --data-binary @-)"

if [ "$HTTP_CODE" = "200" ]; then
  echo "MORI 전송 성공: $(cat /tmp/mori-acct-resp.json)"
elif [ "$HTTP_CODE" = "403" ]; then
  echo "전송 거부(403) — 어드민 콘솔에서 '계정 수집'이 꺼져 있습니다." >&2; exit 1
else
  echo "전송 실패(${HTTP_CODE}): $(cat /tmp/mori-acct-resp.json 2>/dev/null)" >&2; exit 1
fi

# ── cron 등록 (매일 03:20) ──────────────────────────────────────────────────
if [ "$DO_CRON" -eq 1 ]; then
  SELF="$(readlink -f "$0")"
  CRON_LINE="20 3 * * * MORI_INGEST_URL='${INGEST_URL}' MORI_INGEST_TOKEN='${INGEST_TOKEN}' MORI_HOSTNAME='${HOSTNAME_VAL}' MORI_HOST_TYPE='${HOST_TYPE}' bash ${SELF} >/dev/null 2>&1"
  ( crontab -l 2>/dev/null | grep -v 'mori-collect-accounts.sh' ; echo "$CRON_LINE" ) | crontab -
  echo "cron 등록 완료 — 매일 03:20 자동 수집 (crontab -l 로 확인)"
fi
