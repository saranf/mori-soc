#!/usr/bin/env bash
# MORI SOC — Zabbix 템플릿 생성/삭제
#
# "MORI Linux Security Baseline" 템플릿을 Zabbix API 로 생성한다. 이 템플릿을 호스트에
# 붙이면 감사/보안 관점에서 MORI Alert Triage 로 흘러들 만한 problem 을 만든다:
#   - 디스크 사용률 임계 초과 (vfs.fs.size[/,pused])
#   - CPU load 과다 (system.cpu.load)
#   - 메모리 여유 부족 (vm.memory.size[pavailable])
#   - 에이전트 응답 없음 (agent.ping / nodata)
#
# 사용:
#   ./scripts/mori-zabbix-template.sh            # 템플릿+아이템+트리거 생성
#   ./scripts/mori-zabbix-template.sh --delete   # 템플릿 삭제
#
# 요구: docker compose 스택 실행 중(zabbix-web). 자격증명은 mori-worker 의 MORI_ZABBIX_* 재사용.
set -euo pipefail
WORKER="${MORI_WORKER_CONTAINER:-mori-soc-mori-worker-1}"
ACTION="${1:-create}"

docker exec -i -e MORI_TPL_ACTION="$ACTION" "$WORKER" python - <<'PY'
import os, json, time, urllib.request

URL = os.environ["MORI_ZABBIX_API_URL"]
USER = os.getenv("MORI_ZABBIX_USER", "Admin")
PW = os.getenv("MORI_ZABBIX_PASSWORD", "zabbix")
ACTION = os.getenv("MORI_TPL_ACTION", "create")
TPL_NAME = "MORI Linux Security Baseline"
GRP_NAME = "Templates/MORI"
_token = None

def rpc(method, params):
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json-rpc"}
    if _token and method != "user.login":
        headers["Authorization"] = "Bearer " + _token
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=headers)
    return json.loads(urllib.request.urlopen(req, timeout=15).read().decode())

for _ in range(6):
    r = rpc("user.login", {"username": USER, "password": PW})
    if "result" not in r:
        r = rpc("user.login", {"user": USER, "password": PW})
    if "result" in r:
        _token = r["result"]; break
    time.sleep(10)
else:
    raise SystemExit("Zabbix 로그인 실패 (throttle? 잠시 후 재시도)")

existing = rpc("template.get", {"filter": {"host": TPL_NAME}, "output": ["templateid"]}).get("result", [])

if ACTION == "--delete":
    if existing:
        rpc("template.delete", [t["templateid"] for t in existing])
        print("🧹 템플릿 삭제:", TPL_NAME)
    else:
        print("삭제할 템플릿 없음")
    raise SystemExit

if existing:
    print("이미 템플릿 존재:", TPL_NAME, "→ 재사용 (수정하려면 --delete 후 재생성)")
    raise SystemExit

# 1) 템플릿 그룹 확보
grp = rpc("templategroup.get", {"filter": {"name": GRP_NAME}, "output": ["groupid"]}).get("result", [])
gid = grp[0]["groupid"] if grp else rpc("templategroup.create", {"name": GRP_NAME})["result"]["groupids"][0]

# 2) 템플릿 생성
tid = rpc("template.create", {"host": TPL_NAME, "groups": [{"groupid": gid}]})["result"]["templateids"][0]
print("✅ 템플릿 생성:", TPL_NAME, "(id", tid + ")")

# 3) 아이템 (Zabbix agent 키) — value_type: 0=float, 3=unsigned
items = [
    ("Root FS used %", "vfs.fs.size[/,pused]", 0, "%"),
    ("CPU load (1m avg)", "system.cpu.load[all,avg1]", 0, ""),
    ("Memory available %", "vm.memory.size[pavailable]", 0, "%"),
    ("Zabbix agent ping", "agent.ping", 3, ""),
]
item_ids = {}
for name, key, vt, unit in items:
    r = rpc("item.create", {"name": name, "key_": key, "hostid": tid, "type": 0,  # 0=Zabbix agent
                            "value_type": vt, "units": unit, "delay": "60s"})
    item_ids[key] = r["result"]["itemids"][0]
print("✅ 아이템", len(item_ids), "개 생성")

# 4) 트리거 (보안/감사 관점 problem)
triggers = [
    ("MORI: {HOST.NAME} 디스크 사용률 85% 초과", "last(/%s/vfs.fs.size[/,pused])>85" % TPL_NAME, "4"),
    ("MORI: {HOST.NAME} CPU load 과다 (5m avg > 4)", "avg(/%s/system.cpu.load[all,avg1],5m)>4" % TPL_NAME, "3"),
    ("MORI: {HOST.NAME} 메모리 여유 10% 미만", "last(/%s/vm.memory.size[pavailable])<10" % TPL_NAME, "4"),
    ("MORI: {HOST.NAME} Zabbix agent 응답 없음(5m)", "nodata(/%s/agent.ping,5m)=1" % TPL_NAME, "4"),
]
for desc, expr, prio in triggers:
    rpc("trigger.create", {"description": desc, "expression": expr, "priority": prio,
                           "url": os.getenv("MORI_PUBLIC_URL", "http://localhost:18000/ui"),
                           "url_name": "MORI Alert Triage"})
print("✅ 트리거", len(triggers), "개 생성 (disk/cpu/mem/agent)")
print("   → Zabbix Web: Data collection → Hosts → 대상 호스트 → Templates 에서 '%s' 연결" % TPL_NAME)
print("   → 임계 초과 시 problem 발생 → mori-worker 수집 → MORI Alert Triage")
PY
