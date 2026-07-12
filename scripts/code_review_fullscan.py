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
PER_FILE_MAX = 60_000        # 파일당 상한(대형 생성물 제외)
DEFAULT_TOTAL_MAX = 120_000  # 1회 전송 총량 상한(토큰·비용·400 방지)

_SCHEMA_HINT = (
    'Return ONLY JSON: {"findings":[{"file":"path","line":N,"severity":"HIGH|MEDIUM|LOW",'
    '"category":"snake_case_type","description":"...","recommendation":"..."}]}. '
    "Empty findings => {\"findings\":[]}. No prose."
)


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


def build_prompt(files: list[tuple[str, str]]) -> str:
    """수집한 파일들로 보안 리뷰 프롬프트를 만든다(파일마다 경로·번호 매긴 라인)."""
    parts = [
        "You are a senior application security auditor. Review the following EXISTING source "
        "files for security vulnerabilities (injection, authz, secrets, crypto misuse, SSRF, "
        "path traversal, deserialization, etc.). Report real, actionable issues with the exact "
        "file and line. Be precise; avoid false positives.",
        _SCHEMA_HINT,
        "",
    ]
    for rel, text in files:
        parts.append(f"===== FILE: {rel} =====")
        for i, line in enumerate(text.splitlines(), start=1):
            parts.append(f"{i}: {line}")
        parts.append("")
    return "\n".join(parts)


def parse_findings(text: str) -> list[dict]:
    """Claude 응답 텍스트에서 findings 배열을 관대하게 추출·정규화한다."""
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1] if "```" in raw[3:] else raw
        raw = raw[len("json"):].strip() if raw.lower().startswith("json") else raw
    obj = None
    try:
        obj = json.loads(raw)
    except Exception:
        start, end = raw.find("{"), raw.rfind("}")
        if start != -1 and end > start:
            try:
                obj = json.loads(raw[start:end + 1])
            except Exception:
                obj = None
    findings = (obj or {}).get("findings") if isinstance(obj, dict) else None
    if not isinstance(findings, list):
        return []
    norm: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        norm.append({
            "file": f.get("file") or f.get("path"),
            "line": f.get("line"),
            "severity": f.get("severity") or f.get("level") or "medium",
            "category": f.get("category") or f.get("rule_id") or "security",
            "description": f.get("description") or f.get("message") or f.get("title") or "",
            "recommendation": f.get("recommendation"),
        })
    return norm


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


FLOW_PROMPT = """\
아래 저장소 소스를 읽고 **개인정보 처리 라이프사이클(수집→저장→이용→파기)**을 JSON 으로만 출력하세요.
각 개인정보 항목별로, 실제 코드 근거(소스 파일·API 라우트·Prisma 테이블/컬럼·암복호화·마스킹 함수·파기 경로)를 담습니다.
설명 없이 아래 스키마의 JSON 객체 하나만 출력:
{"items":[{"item":"이메일","category":"일반|고유식별|비밀|금융",
  "collect":["회원가입 signup/page.tsx","POST /api/auth/signup"],
  "store":["User.emailEnc","User.emailHash (블라인드 인덱스)"],"encryption":"AES-256-GCM + HMAC",
  "use":["로그인 findByEmail()","마스킹 maskEmail()"],
  "dispose":["탈퇴 withdrawUser()","만료 purgeExpired()"],
  "third_party":"제3자 제공 대상(없으면 생략)","overseas":"국외이전(없으면 생략)","table":"User"}],
 "gaps":["파기 흐름 개선 필요 지점(있으면)"],
 "summary":{"items":항목수,"tables":테이블수,"encryption":"대표 암호화"}}

--- 소스 ---
"""


def build_flow_prompt(files: list[tuple[str, str]]) -> str:
    parts = [FLOW_PROMPT]
    for path, content in files:
        parts.append(f"\n### {path}\n{content}")
    return "".join(parts)


def parse_flow(text: str) -> dict:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```", 2)[1] if "```" in t[3:] else t
        t = t[t.find("{"):]
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j < 0:
        return {}
    try:
        d = json.loads(t[i:j + 1])
        return d if isinstance(d, dict) and isinstance(d.get("items"), list) else {}
    except Exception:
        return {}


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
    print(f"수집: {len(files)} 파일" + (" (일부 잘림 — SCAN 총량 상한)" if truncated else ""))
    if not files:
        print("스캔할 소스 파일 없음 — 0건으로 기록")
        findings: list[dict] = []
    else:
        prompt = build_prompt(files)
        print(f"Claude 호출: 모델={model}, 프롬프트≈{len(prompt):,}자")
        try:
            findings = parse_findings(call_claude(api_key, model, prompt))
        except Exception as exc:
            print(f"Claude 리뷰 실패: {exc}", file=sys.stderr)
            msg = str(exc).lower()
            if "model" in msg:
                print("힌트: CLAUDE_MODEL 을 계정에서 지원하는 모델 id로 지정하세요 "
                      "(예: claude-sonnet-4-5, 워크플로 env CLAUDE_MODEL).", file=sys.stderr)
            elif "long" in msg or "max" in msg or "token" in msg:
                print("힌트: 프롬프트가 큽니다 — DEFAULT_TOTAL_MAX 를 더 낮추세요.", file=sys.stderr)
            return 1
    print(f"findings: {len(findings)}건 (모델 {model})")
    try:
        status = post_to_mori(
            mori_url, findings,
            repo=os.getenv("GITHUB_REPOSITORY", ""), commit=os.getenv("GITHUB_SHA", ""),
            run_id=os.getenv("GITHUB_RUN_ID", ""),
            token=os.getenv("MORI_INGEST_TOKEN", "").strip(),
            oidc=os.getenv("MORI_OIDC_TOKEN", "").strip(),
        )
        print(f"MORI push status: {status}")
    except Exception as exc:
        print(f"MORI push 실패(비차단): {exc}", file=sys.stderr)

    # ── 개인정보 라이프사이클(완벽 경로) — Claude 로 구조화 흐름을 만들어 MORI 에 전송 ──
    if files:
        try:
            flow = parse_flow(call_claude(api_key, model, build_flow_prompt(files), max_tokens=8192))
            if flow.get("items"):
                st = post_flow_to_mori(
                    mori_url, flow, repo=os.getenv("GITHUB_REPOSITORY", ""),
                    commit=os.getenv("GITHUB_SHA", ""), run_id=os.getenv("GITHUB_RUN_ID", ""),
                    token=os.getenv("MORI_INGEST_TOKEN", "").strip(),
                    oidc=os.getenv("MORI_OIDC_TOKEN", "").strip())
                print(f"개인정보 흐름 {len(flow['items'])}항목 push status: {st}")
        except Exception as exc:
            print(f"개인정보 흐름 생성 실패(비차단): {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
