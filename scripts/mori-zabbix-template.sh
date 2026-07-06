#!/usr/bin/env bash
# MORI SOC — Zabbix 템플릿 생성 / 삭제 / 내보내기(export)
#
# "MORI Linux Security Baseline" 템플릿을 Zabbix API 로 만든다. 임계값은 사용자
# 매크로로 파라미터화하고, 아이템/트리거에 태그를 달아 Zabbix 커뮤니티 템플릿
# 표준에 맞춘다. --export 로 공식 import 포맷(YAML)을 얻어 저장소에 커밋할 수 있다.
#
# 사용:
#   ./scripts/mori-zabbix-template.sh            # 생성 (매크로/태그 포함)
#   ./scripts/mori-zabbix-template.sh --export   # 공식 YAML export → stdout
#   ./scripts/mori-zabbix-template.sh --delete    # 삭제
#
# 요구: docker compose 스택 실행 중(zabbix-web). 자격증명은 mori-worker MORI_ZABBIX_* 재사용.
set -euo pipefail
WORKER="${MORI_WORKER_CONTAINER:-mori-soc-mori-worker-1}"
ACTION="${1:-create}"

docker exec -i -e MORI_TPL_ACTION="$ACTION" "$WORKER" python - <<'PY'
import os, json, time, urllib.request

URL = os.environ["MORI_ZABBIX_API_URL"]
USER = os.getenv("MORI_ZABBIX_USER", "Admin")
PW = os.getenv("MORI_ZABBIX_PASSWORD", "zabbix")
ACTION = os.getenv("MORI_TPL_ACTION", "create")
TPL = "MORI Linux Security Baseline"
GRP = "Templates/MORI"
_token = None

def rpc(method, params):
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json-rpc"}
    if _token and method != "user.login":
        headers["Authorization"] = "Bearer " + _token
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=headers)
    return json.loads(urllib.request.urlopen(req, timeout=20).read().decode())

for _ in range(6):
    r = rpc("user.login", {"username": USER, "password": PW})
    if "result" not in r:
        r = rpc("user.login", {"user": USER, "password": PW})
    if "result" in r:
        _token = r["result"]; break
    time.sleep(10)
else:
    raise SystemExit("Zabbix 로그인 실패 (throttle? 잠시 후 재시도)")

existing = rpc("template.get", {"filter": {"host": TPL}, "output": ["templateid"]}).get("result", [])

# ── export: 공식 import 포맷(YAML) ─────────────────────────────────────────
if ACTION == "--export":
    if not existing:
        raise SystemExit("템플릿이 없음 — 먼저 생성하세요")
    out = rpc("configuration.export", {"format": "yaml",
              "options": {"templates": [existing[0]["templateid"]]}})
    # export 결과는 문자열(YAML) — 그대로 stdout 으로 (스크립트에서 파일로 리다이렉트)
    print(out["result"], end="")
    raise SystemExit

# ── delete ──────────────────────────────────────────────────────────────────
if ACTION == "--delete":
    if existing:
        rpc("template.delete", [t["templateid"] for t in existing])
        print("🧹 템플릿 삭제:", TPL)
    else:
        print("삭제할 템플릿 없음")
    raise SystemExit

# ── create ──────────────────────────────────────────────────────────────────
if existing:
    print("이미 템플릿 존재:", TPL, "→ 재사용 (수정하려면 --delete 후 재생성)")
    raise SystemExit

grp = rpc("templategroup.get", {"filter": {"name": GRP}, "output": ["groupid"]}).get("result", [])
gid = grp[0]["groupid"] if grp else rpc("templategroup.create", {"name": GRP})["result"]["groupids"][0]

# 임계값 = 사용자 매크로(운영자가 호스트/템플릿 레벨에서 재정의 가능)
macros = [
    {"macro": "{$MORI.DISK.PUSED.MAX}", "value": "85", "description": "루트 FS 사용률 임계(%)"},
    {"macro": "{$MORI.CPU.LOAD.MAX}", "value": "4", "description": "CPU load(1m avg) 임계"},
    {"macro": "{$MORI.MEM.PAVAIL.MIN}", "value": "10", "description": "가용 메모리 최소(%)"},
    {"macro": "{$MORI.AGENT.NODATA}", "value": "5m", "description": "agent 무응답 판정 시간"},
    {"macro": "{$MORI.URL}", "value": "", "description": "트리거 링크 대상(MORI Alert Triage URL). 비우면 링크 없음"},
]
tid = rpc("template.create", {
    "host": TPL, "name": TPL, "groups": [{"groupid": gid}], "macros": macros,
    "description": "MORI SOC baseline for Linux endpoints. Surfaces disk/CPU/memory/agent "
                   "problems into MORI Alert Triage (ISMS-P / ISO 27001 audit evidence).",
})["result"]["templateids"][0]
print("✅ 템플릿 생성:", TPL, "(id", tid + ") + 매크로", len(macros))

TAGS = lambda extra: [{"tag": "class", "value": "security"},
                      {"tag": "source", "value": "mori"}] + extra
items = [
    ("Root FS: space used, in %", "vfs.fs.size[/,pused]", 0, "%", [{"tag": "component", "value": "storage"}]),
    ("CPU: load average (1m)", "system.cpu.load[all,avg1]", 0, "", [{"tag": "component", "value": "cpu"}]),
    ("Memory: available, in %", "vm.memory.size[pavailable]", 0, "%", [{"tag": "component", "value": "memory"}]),
    ("Zabbix agent availability", "agent.ping", 3, "", [{"tag": "component", "value": "agent"}]),
]
for name, key, vt, unit, tg in items:
    rpc("item.create", {"name": name, "key_": key, "hostid": tid, "type": 0,
                        "value_type": vt, "units": unit, "delay": "60s", "tags": TAGS(tg)})
print("✅ 아이템", len(items), "개 (태그 포함)")

MORI_URL = "{$MORI.URL}"  # 매크로 — 호스트/템플릿 레벨에서 MORI Triage URL 지정(비우면 링크 없음)
triggers = [
    ("Root FS space usage is high (>{$MORI.DISK.PUSED.MAX}%)",
     "last(/%s/vfs.fs.size[/,pused])>{$MORI.DISK.PUSED.MAX}" % TPL, "4", "storage"),
    ("CPU load is too high (avg 5m >{$MORI.CPU.LOAD.MAX})",
     "avg(/%s/system.cpu.load[all,avg1],5m)>{$MORI.CPU.LOAD.MAX}" % TPL, "3", "cpu"),
    ("Available memory is low (<{$MORI.MEM.PAVAIL.MIN}%)",
     "last(/%s/vm.memory.size[pavailable])<{$MORI.MEM.PAVAIL.MIN}" % TPL, "4", "memory"),
    ("Zabbix agent is not responding ({$MORI.AGENT.NODATA})",
     "nodata(/%s/agent.ping,{$MORI.AGENT.NODATA})=1" % TPL, "4", "agent"),
]
for desc, expr, prio, comp in triggers:
    rpc("trigger.create", {"description": desc, "expression": expr, "priority": prio,
                           "url": MORI_URL, "url_name": "MORI Alert Triage",
                           "tags": TAGS([{"tag": "component", "value": comp}])})
print("✅ 트리거", len(triggers), "개 (매크로 임계 + 태그)")
print("   export: ./scripts/mori-zabbix-template.sh --export > config/zabbix/templates/mori_linux_security_baseline.yaml")
PY
