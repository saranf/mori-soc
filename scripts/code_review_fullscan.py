#!/usr/bin/env python3
"""전체 레포 AI 보안 리뷰 → MORI (기존 코드 스캔용, PR diff 아님).

claude-code-security-review 액션은 PR diff만 리뷰한다. "지금 있는 코드 전체"를
감사(ISMS-P 2.8 / ISO A.8.25·28)하려면 이 스크립트를 고객 레포 CI(GitHub Actions)에서
돌린다 — 레포 소스를 모아 Claude에 보안 리뷰를 요청하고, findings 를 MORI
``/ingest/code-review`` 로 push 한다. **스캔은 CI에서 돌고 MORI 는 코드를 만지지 않는다.**

의존성: 표준 라이브러리만(urllib/json). GitHub 러너 python3 에서 그대로 실행.
환경변수: ANTHROPIC_API_KEY(필수) · MORI_INGEST_URL(필수) · MORI_INGEST_TOKEN 또는
MORI_OIDC_TOKEN(인증) · CLAUDE_MODEL · GITHUB_REPOSITORY · GITHUB_SHA · GITHUB_RUN_ID.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

# 소스 코드로 볼 확장자(로직 취약점 리뷰 대상). 문서/락파일/바이너리는 제외.
CODE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".php", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".cs", ".rs", ".kt", ".scala", ".swift", ".sh", ".bash",
    ".sql", ".tf", ".yaml", ".yml", ".tpl",
}
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__",
    ".next", ".nuxt", "target", "bin", "obj", ".terraform", "migrations", "backups",
}
PER_FILE_MAX = 60_000          # 파일당 상한(대형 생성물 제외)
DEFAULT_TOTAL_MAX = 5_000_000  # 전체 수집 안전상한(폭주 방지) — 실 분할은 아래 배치가 담당
# 파일이 많으면 한 번의 Claude 호출이 컨텍스트 한도를 넘는다 → 배치로 쪼개 여러 번 호출한다
# (토큰을 더 쓰더라도 파일을 조용히 버리지 않는다). 배치 예산·개수는 env 로 조정 가능.
BATCH_MAX = int(os.getenv("MORI_SCAN_BATCH_MAX", "140000"))   # 호출당 전송 문자 예산
MAX_BATCHES = int(os.getenv("MORI_SCAN_MAX_BATCHES", "20"))   # 호출 횟수 상한(비용 방어)

def collect_files(root: str, *, total_max: int = DEFAULT_TOTAL_MAX,
                  exts: set[str] = CODE_EXTS, skip_dirs: set[str] = SKIP_DIRS) -> tuple[list[tuple[str, str]], bool]:
    """(상대경로, 내용) 목록과 truncated 여부를 반환. total_max 초과분은 자른다(무음 아님)."""
    out: list[tuple[str, str]] = []
    total = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in skip_dirs and not d.startswith(".")]
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1].lower()
            if ext not in exts:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                if os.path.getsize(full) > PER_FILE_MAX:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if total + len(text) > total_max:
                truncated = True
                continue
            out.append((rel, text))
            total += len(text)
    return out, truncated


def chunk_files(files: list[tuple[str, str]], batch_max: int = BATCH_MAX) -> list[list[tuple[str, str]]]:
    """파일 목록을 호출당 문자 예산(batch_max)으로 배치 분할. 한 파일이 예산보다 커도 자체 배치로 보낸다."""
    batches: list[list[tuple[str, str]]] = []
    cur: list[tuple[str, str]] = []
    size = 0
    for rel, text in files:
        if cur and size + len(text) > batch_max:
            batches.append(cur)
            cur, size = [], 0
        cur.append((rel, text))
        size += len(text)
    if cur:
        batches.append(cur)
    return batches


def merge_flow(acc: dict, new: dict) -> dict:
    """배치별 개인정보 흐름 결과를 병합 — 항목(item) 단위로 store/collect/use/dispose 를 합친다."""
    if not isinstance(new, dict) or not new:
        return acc
    items: dict[str, dict] = {i["item"]: dict(i) for i in (acc.get("items") or [])
                             if isinstance(i, dict) and i.get("item")}
    for it in new.get("items") or []:
        if not isinstance(it, dict) or not it.get("item"):
            continue
        name = it["item"]
        if name in items:
            cur = items[name]
            for k in ("collect", "store", "use", "dispose"):
                cur[k] = list(dict.fromkeys((cur.get(k) or []) + (it.get(k) or [])))
            for k in ("encryption", "table", "category", "third_party", "overseas"):
                if not cur.get(k) and it.get(k):
                    cur[k] = it[k]
        else:
            items[name] = dict(it)
    merged_items = list(items.values())
    gaps = list(dict.fromkeys((acc.get("gaps") or []) + (new.get("gaps") or [])))
    tables = {i.get("table") for i in merged_items if i.get("table")}
    enc = next((i.get("encryption") for i in merged_items if i.get("encryption")), "미확인")
    return {"items": merged_items, "gaps": gaps,
            "summary": {"items": len(merged_items), "tables": len(tables), "encryption": enc}}


def call_claude(api_key: str, model: str, prompt: str, *, max_tokens: int = 4096) -> str:
    body = json.dumps({
        "model": model, "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body,
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 (fixed host)
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:  # 400 등 — 실제 사유(모델/길이)를 노출
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:600]
        except Exception:
            detail = getattr(exc, "reason", "")
        raise RuntimeError(f"Anthropic API {exc.code}: {detail}") from exc
    chunks = [c.get("text", "") for c in data.get("content", []) if c.get("type") == "text"]
    return "".join(chunks)


def _with_scheme(base: str) -> str:
    """MORI_INGEST_URL 에 스킴이 없으면 https:// 를 붙인다(unknown url type 방지)."""
    b = (base or "").strip()
    return b if "://" in b else "https://" + b


def post_to_mori(base_url: str, findings: list[dict], *, repo: str, commit: str, run_id: str,
                 token: str = "", oidc: str = "") -> int:
    url = _with_scheme(base_url).rstrip("/") + f"/ingest/code-review?repo={repo}&commit={commit}&run_id={run_id}"
    body = json.dumps({"findings": findings}).encode("utf-8")
    headers = {"content-type": "application/json"}
    if oidc:
        headers["x-mori-oidc"] = oidc
    elif token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        return resp.status


def post_flow_to_mori(base_url: str, flow: dict, *, repo: str, commit: str, run_id: str,
                      token: str = "", oidc: str = "") -> int:
    url = _with_scheme(base_url).rstrip("/") + f"/ingest/privacy-flow?repo={repo}&commit={commit}&run_id={run_id}"
    body = json.dumps(flow, ensure_ascii=False).encode("utf-8")
    headers = {"content-type": "application/json"}
    if oidc:
        headers["x-mori-oidc"] = oidc
    elif token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        return resp.status


# ── 한 번의 Claude 호출로 보안 findings + 개인정보 라이프사이클을 함께 뽑는다 ──
# 파일을 두 번 보내던 낭비를 없애 컨텍스트 여유↑·비용↓·잘림↓. findings 스코프에
# '평문 PII 저장·약한 해시·PII 로깅·과수집·마스킹 누락' 을 넣어 개인정보-보안까지 잡는다.
COMBINED_PROMPT = """\
You are a senior application security AND privacy auditor. Read the EXISTING repository source below
and return ONE JSON object with two parts. No prose, JSON only.

"findings": real, actionable issues with exact file+line — classic security (injection, broken authz,
hardcoded secrets, crypto misuse, SSRF, path traversal, deserialization) AND privacy-security
(sensitive PII stored in PLAINTEXT / missing encryption-at-rest, weak password hashing, PII written to
logs, over-collection, missing output masking). Be precise, avoid false positives. None => [].

"privacy": the personal-data lifecycle (collect->store->use->dispose) with real code evidence
(files, API routes, DB tables/columns, encryption, masking functions, disposal paths).

Output EXACTLY this JSON shape:
{"findings":[{"file":"path","line":N,"severity":"HIGH|MEDIUM|LOW","category":"snake_case","description":"...","recommendation":"..."}],
 "privacy":{"items":[{"item":"이메일","category":"일반|고유식별|비밀|금융","collect":["회원가입 signup/page.tsx"],
   "store":["User.emailEnc","User.emailHash (블라인드 인덱스)"],"encryption":"AES-256-GCM + HMAC",
   "use":["로그인 findByEmail()","마스킹 maskEmail()"],"dispose":["탈퇴 withdrawUser()","만료 purgeExpired()"],
   "third_party":"","overseas":"","table":"User"}],
  "gaps":["파기 흐름 개선 필요 지점"],"summary":{"items":N,"tables":N,"encryption":"대표 암호화"}}}

--- SOURCE ---
"""


def build_combined_prompt(files: list[tuple[str, str]]) -> str:
    parts = [COMBINED_PROMPT]
    for rel, text in files:
        parts.append(f"\n===== FILE: {rel} =====\n")
        for i, line in enumerate(text.splitlines(), start=1):
            parts.append(f"{i}: {line}\n")
    return "".join(parts)


def parse_combined(text: str) -> tuple[list[dict], dict]:
    """통합 응답에서 (정규화된 findings, privacy dict) 를 관대하게 추출."""
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.split("```", 2)[1] if "```" in t[3:] else t
        t = t[t.find("{"):]
    i, j = t.find("{"), t.rfind("}")
    obj: dict = {}
    if i >= 0 and j > i:
        try:
            obj = json.loads(t[i:j + 1])
        except Exception:
            obj = {}
    findings: list[dict] = []
    for f in (obj.get("findings") if isinstance(obj, dict) else None) or []:
        if isinstance(f, dict):
            findings.append({
                "file": f.get("file") or f.get("path"), "line": f.get("line"),
                "severity": f.get("severity") or f.get("level") or "medium",
                "category": f.get("category") or f.get("rule_id") or "security",
                "description": f.get("description") or f.get("message") or f.get("title") or "",
                "recommendation": f.get("recommendation"),
            })
    privacy = obj.get("privacy") if isinstance(obj, dict) else {}
    return findings, (privacy if isinstance(privacy, dict) else {})


def main() -> int:
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    mori_url = os.getenv("MORI_INGEST_URL", "").strip()
    if not api_key:
        print("ANTHROPIC_API_KEY 미설정 — 중단", file=sys.stderr)
        return 1
    if not mori_url:
        print("MORI_INGEST_URL 미설정 — 스킵")
        return 0
    model = os.getenv("CLAUDE_MODEL", "").strip() or "claude-sonnet-5"
    files, truncated = collect_files(os.getenv("SCAN_ROOT", "."))
    batches = chunk_files(files)
    if len(batches) > MAX_BATCHES:
        print(f"경고: 배치 {len(batches)}개 > 상한 {MAX_BATCHES} — 초과 배치는 스킵합니다 "
              f"(MORI_SCAN_MAX_BATCHES 로 상향 가능).", file=sys.stderr)
        batches = batches[:MAX_BATCHES]
        truncated = True
    print(f"수집: {len(files)} 파일 → {len(batches)} 배치"
          + (" (일부 잘림)" if truncated else ""))
    findings: list[dict] = []
    flow: dict = {}
    for bi, batch in enumerate(batches, 1):
        prompt = build_combined_prompt(batch)
        print(f"Claude 호출 {bi}/{len(batches)}(보안+개인정보): 모델={model}, "
              f"{len(batch)}파일 ≈{len(prompt):,}자")
        try:
            fds, fl = parse_combined(call_claude(api_key, model, prompt, max_tokens=16000))
        except Exception as exc:
            print(f"배치 {bi} Claude 리뷰 실패(계속): {exc}", file=sys.stderr)
            msg = str(exc).lower()
            if "model" in msg:
                print("힌트: CLAUDE_MODEL 을 계정 지원 모델 id로(예: claude-sonnet-4-5).", file=sys.stderr)
            elif "long" in msg or "max" in msg or "token" in msg:
                print("힌트: 배치가 큽니다 — MORI_SCAN_BATCH_MAX 를 낮추세요.", file=sys.stderr)
            continue   # 한 배치 실패가 전체를 무너뜨리지 않음(부분 성공 정직 보고)
        findings += fds
        flow = merge_flow(flow, fl)
    print(f"findings: {len(findings)}건 · 개인정보 {len(flow.get('items') or [])}항목 "
          f"(모델 {model}, {len(batches)} 배치)")

    repo, commit, run_id = (os.getenv("GITHUB_REPOSITORY", ""), os.getenv("GITHUB_SHA", ""),
                            os.getenv("GITHUB_RUN_ID", ""))
    token, oidc = os.getenv("MORI_INGEST_TOKEN", "").strip(), os.getenv("MORI_OIDC_TOKEN", "").strip()
    try:
        print(f"MORI push status: {post_to_mori(mori_url, findings, repo=repo, commit=commit, run_id=run_id, token=token, oidc=oidc)}")
    except Exception as exc:
        print(f"MORI push 실패(비차단): {exc}", file=sys.stderr)
    if flow.get("items"):
        try:
            st = post_flow_to_mori(mori_url, flow, repo=repo, commit=commit, run_id=run_id, token=token, oidc=oidc)
            print(f"개인정보 흐름 {len(flow['items'])}항목 push status: {st}")
        except Exception as exc:
            print(f"개인정보 흐름 전송 실패(비차단): {exc}", file=sys.stderr)
    return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
