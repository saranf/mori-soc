#!/usr/bin/env bash
# MORI SOC — Zabbix 실전 시나리오 데모용 problem 생성/삭제
#
# 목적: "Zabbix problem → MORI worker 수집 → Alert Triage → Incident → 증적 export"
#       파이프라인을 시연하기 위해, Zabbix 서버 호스트에 항상-참 데모 트리거를 만들어
#       실제 problem 이벤트를 발생시킨다. mori-worker 가 30초 주기로 수집한다.
#
# 사용:
#   ./scripts/mori-zabbix-demo-problem.sh          # 데모 트리거 생성(problem 발생)
#   ./scripts/mori-zabbix-demo-problem.sh --delete  # 데모 트리거 삭제(problem 해소)
#
# 요구: docker compose 스택 실행 중(zabbix-web + mori-worker). Zabbix API 자격증명은
#       mori-worker 컨테이너의 MORI_ZABBIX_* 환경변수를 재사용한다.
set -euo pipefail

WORKER="${MORI_WORKER_CONTAINER:-mori-soc-mori-worker-1}"
ACTION="${1:-create}"

docker exec -i -e MORI_DEMO_ACTION="$ACTION" "$WORKER" python - <<'PY'
import os, json, time, urllib.request

URL = os.environ["MORI_ZABBIX_API_URL"]
USER = os.getenv("MORI_ZABBIX_USER", "Admin")
PW = os.getenv("MORI_ZABBIX_PASSWORD", "zabbix")
ACTION = os.getenv("MORI_DEMO_ACTION", "create")
DESC = "MORI DEMO: 디스크 사용률 임계 초과 (시나리오 점검)"

_token = None

def rpc(method, params):
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json-rpc"}
    if _token and method != "user.login":
        headers["Authorization"] = "Bearer " + _token  # Zabbix 6.4+/7.x
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=headers)
    return json.loads(urllib.request.urlopen(req, timeout=10).read().decode())

# 로그인 (7.x throttle 대응 백오프 + username/user 호환)
for attempt in range(6):
    resp = rpc("user.login", {"username": USER, "password": PW})
    if "result" not in resp:
        resp = rpc("user.login", {"user": USER, "password": PW})
    if "result" in resp:
        _token = resp["result"]
        break
    time.sleep(10)
else:
    raise SystemExit("Zabbix 로그인 실패 (throttle? 잠시 후 재시도)")

# 기존 데모 트리거 조회
existing = rpc("trigger.get", {"filter": {"description": DESC}, "output": ["triggerid"]}).get("result", [])

if ACTION == "--delete":
    if existing:
        rpc("trigger.delete", [t["triggerid"] for t in existing])
        print("🧹 데모 트리거 삭제:", [t["triggerid"] for t in existing])
    else:
        print("삭제할 데모 트리거 없음")
    raise SystemExit

if existing:
    print("이미 데모 트리거 존재:", [t["triggerid"] for t in existing], "→ 재사용")
    raise SystemExit

# 숫자형(uint) 아이템에 항상-참 트리거 생성 → 즉시 problem
hosts = rpc("host.get", {"output": ["hostid", "host"]})["result"]
key = None
for h in hosts:
    items = rpc("item.get", {"hostids": h["hostid"], "output": ["key_", "lastvalue", "value_type"],
                             "filter": {"status": 0, "value_type": 3}, "limit": 50})["result"]
    for it in items:
        if str(it.get("lastvalue")) not in ("None", "") and "packages" not in it["key_"]:
            key = (h["host"], it["key_"]); break
    if key:
        break
if not key:
    raise SystemExit("숫자형 아이템을 찾지 못함")

host, item_key = key
# Zabbix→MORI 역방향 링크: 트리거 url 을 MORI Alert Triage 로 설정하면
# Zabbix problem 컨텍스트 메뉴에서 MORI 로 이동할 수 있다(양방향 URL 연결).
mori_url = os.getenv("MORI_PUBLIC_URL", "http://localhost:18000/ui")
trigger_params = {"description": DESC, "priority": "4",
                  "expression": "last(/%s/%s)>=0" % (host, item_key),
                  "url": mori_url, "url_name": "MORI Alert Triage"}
res = rpc("trigger.create", trigger_params)
print("✅ 데모 트리거 생성:", res.get("result", res.get("error")))
print("   → mori-worker 가 30초 내 수집하여 Alert Triage 에 노출합니다.")
print("   → 확인: /ui → 🚨 Alert Triage 탭 (source=zabbix, 'MORI DEMO ...')")
PY
