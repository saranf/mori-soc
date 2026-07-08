#!/usr/bin/env bash
# ============================================================================
# MORI SOC — LDAP 사용자 추가 헬퍼
#
# 번들 OpenLDAP(또는 기존 LDAP)에 로그인 계정을 하나 추가한다. 이 계정은 같은
# LDAP을 바라보는 모든 서비스(MORI / Grafana / Zabbix / Fleet)에서 로그인된다.
#
# 사용 (기본: 번들 openldap 컨테이너에 docker compose exec 로 추가):
#   ./scripts/mori-ldap-adduser.sh -u hong -n "홍길동" -p 'InitPassw0rd!' -m hong@corp.com
#
# 기존(외부) LDAP 서버에 추가:
#   ./scripts/mori-ldap-adduser.sh -u hong -n "홍길동" -p 'pw' \
#       --host ldap://ldap.corp.com:389 \
#       --admin-dn 'cn=admin,dc=corp,dc=com' --admin-pw '***' \
#       --base 'ou=users,dc=corp,dc=com'
#
# 옵션:
#   -u  uid(로그인 아이디, 필수)   -n  cn(표시 이름)   -p  초기 비밀번호(필수)
#   -m  mail(이메일)              --base  사용자 OU DN (기본 ou=users,dc=mori,dc=local)
#   --host  ldap URL             --admin-dn / --admin-pw  바인드 계정
#   --container  openldap 컨테이너명(기본 mori-soc-openldap-1)
# ============================================================================
set -euo pipefail

UID_=""; CN=""; PW=""; MAIL=""
BASE="${MORI_LDAP_BASE_DN:-ou=users,dc=mori,dc=local}"
HOST="${MORI_LDAP_URL:-ldap://localhost:389}"
ADMIN_DN="${MORI_LDAP_BIND_DN:-cn=admin,dc=mori,dc=local}"
ADMIN_PW="${MORI_LDAP_BIND_PW:-${LDAP_ADMIN_PASSWORD:-admin}}"
CONTAINER="${MORI_LDAP_CONTAINER:-mori-soc-openldap-1}"
USE_CONTAINER=1   # 기본은 번들 컨테이너 내부에서 ldapadd 실행

while [ $# -gt 0 ]; do
  case "$1" in
    -u) UID_="$2"; shift 2;;
    -n) CN="$2"; shift 2;;
    -p) PW="$2"; shift 2;;
    -m) MAIL="$2"; shift 2;;
    --base) BASE="$2"; shift 2;;
    --host) HOST="$2"; USE_CONTAINER=0; shift 2;;
    --admin-dn) ADMIN_DN="$2"; shift 2;;
    --admin-pw) ADMIN_PW="$2"; shift 2;;
    --container) CONTAINER="$2"; shift 2;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown option: $1" >&2; exit 1;;
  esac
done

[ -n "$UID_" ] && [ -n "$PW" ] || { echo "❌ -u(uid) 와 -p(password) 는 필수입니다. --help 참고." >&2; exit 1; }
CN="${CN:-$UID_}"

# 부모 도메인 DN 은 base 에서 ou=... 를 떼어 유추 (ou=users,dc=mori,dc=local → dc=mori,dc=local)
PARENT_DN="${BASE#*,}"
OU_NAME="$(echo "$BASE" | sed -E 's/^ou=([^,]+),.*/\1/')"

LDIF_OU="dn: ${BASE}
objectClass: organizationalUnit
ou: ${OU_NAME}
"
LDIF_USER="dn: uid=${UID_},${BASE}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: ${CN}
sn: ${CN}
uid: ${UID_}
userPassword: ${PW}
${MAIL:+mail: ${MAIL}}
"

run_ldapadd() {  # $1 = ldif text ; 실패해도(이미 존재 등) 계속하려면 tolerant=1
  local ldif="$1" tolerant="${2:-0}" out rc
  if [ "$USE_CONTAINER" = "1" ]; then
    out="$(printf '%s' "$ldif" | docker exec -i "$CONTAINER" \
      ldapadd -x -H ldap://localhost:389 -D "$ADMIN_DN" -w "$ADMIN_PW" 2>&1)" && rc=0 || rc=$?
  else
    out="$(printf '%s' "$ldif" | ldapadd -x -H "$HOST" -D "$ADMIN_DN" -w "$ADMIN_PW" 2>&1)" && rc=0 || rc=$?
  fi
  if [ $rc -ne 0 ]; then
    if [ "$tolerant" = "1" ] && echo "$out" | grep -qi "Already exists"; then return 0; fi
    echo "$out" >&2; return $rc
  fi
}

echo "→ 사용자 OU 확인/생성: ${BASE}"
run_ldapadd "$LDIF_OU" 1 || true

echo "→ 사용자 추가: uid=${UID_},${BASE}"
run_ldapadd "$LDIF_USER" 0

echo "✅ 완료 — 이제 이 계정으로 MORI(및 같은 LDAP을 보는 Grafana/Zabbix/Fleet)에 로그인할 수 있습니다."
echo "   로그인 아이디: ${UID_}"
