#!/usr/bin/env python3
"""무료 개인정보 라이프사이클 파서 — 고객 CI 에서 API 키 없이 실행(순수 stdlib).

Prisma 스키마 + 코드 관례(*Enc·*Hash·mask*·erase/withdraw/purge)를 읽어
'개인정보 수집→저장→이용→파기' 구조화 JSON 을 만들고 MORI 로 POST 한다.
AI(유료 fullscan)와 같은 /ingest/privacy-flow 스키마를 쓰므로 MORI 렌더는 동일.
관례를 따르는 앱(암호화 컬럼 *Enc, 블라인드 인덱스 *Hash, mask 함수 등)에서 잘 동작한다.

env: MORI_INGEST_URL(필수) · MORI_INGEST_TOKEN | MORI_OIDC_TOKEN(인증) ·
     GITHUB_REPOSITORY · GITHUB_SHA · GITHUB_RUN_ID.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

# (정규식, 항목, 분류) — 필드/컬럼 이름으로 PII 항목 추정.
FIELD_MAP: list[tuple[str, str, str]] = [
    (r"email|이메일", "이메일", "일반"),
    (r"phone|mobile|tel(?![a-z])|휴대폰|전화", "휴대폰", "일반"),
    (r"rrn|resident|jumin|ssn|주민", "주민등록번호", "고유식별"),
    (r"passwo?r?d|passwd|pwd", "비밀번호", "비밀"),
    (r"card", "카드번호", "금융"),
    (r"account|bank", "계좌번호", "금융"),
    (r"gender|sex|성별", "성별", "일반"),
    (r"birth|dob|생년", "생년월일", "일반"),
    (r"addr|address|주소|배송", "주소", "일반"),
    (r"recipient|holder|(full)?name|이름|성명", "이름", "일반"),
    (r"\bip\b|ipaddr", "접속기록(IP)", "일반"),
]
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "coverage", "vendor", ".venv"}
CODE_EXT = {".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rb", ".sql", ".prisma"}


def _classify(name: str) -> tuple[str, str] | None:
    low = name.lower()
    for rx, item, cat in FIELD_MAP:
        if re.search(rx, low):
            return item, cat
    return None


def _encryption(field: str) -> str:
    f = field.lower()
    if "passwordhash" in f or (("password" in f or "pwd" in f) and "hash" in f):
        return "bcrypt 단방향"
    if f.endswith("hash") or "hash" in f:
        return "HMAC 블라인드 인덱스"
    if f.endswith("enc") or "enc" in f:
        return "AES-256-GCM"
    return ""


def parse_prisma(root: Path) -> dict[str, dict]:
    """prisma schema → {item: {store:set, tables:set, enc:set, category}}."""
    acc: dict[str, dict] = {}
    for sp in list(root.rglob("*.prisma")):
        if any(p in SKIP_DIRS for p in sp.parts):
            continue
        text = sp.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"model\s+([A-Za-z_]\w*)\s*\{(.*?)\}", text, re.S):
            table, body = m.group(1), m.group(2)
            for fm in re.finditer(r"^\s*([A-Za-z_]\w*)\s+\w", body, re.M):
                field = fm.group(1)
                cl = _classify(field)
                if not cl:
                    continue
                item, cat = cl
                a = acc.setdefault(item, {"store": set(), "tables": set(), "enc": set(), "category": cat})
                a["store"].add(f"{table}.{field}")
                a["tables"].add(table)
                enc = _encryption(field)
                if enc:
                    a["enc"].add(enc)
    return acc


def scan_conventions(root: Path) -> dict[str, list[str]]:
    """mask 함수·수집 페이지·파기 라우트를 전역 수집(항목별 매칭은 이름으로)."""
    hits = {"mask": [], "collect": [], "dispose": [], "provide": []}
    for fp in root.rglob("*"):
        if fp.is_dir() or fp.suffix not in CODE_EXT or any(p in SKIP_DIRS for p in fp.parts):
            continue
        rel = str(fp.relative_to(root))
        low = rel.lower()
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for mm in re.finditer(r"\bmask([A-Za-z]+)\s*\(", text):
            hits["mask"].append((mm.group(1), rel))
        if re.search(r"signup|sign-up|register|checkout|mypage|/form|profile", low):
            hits["collect"].append(rel)
        if re.search(r"erase|withdraw|purge|/destroy|deletion|파기|탈퇴", low + " " + text[:400].lower()):
            hits["dispose"].append(rel)
        if re.search(r"provision|provide|3rd|배송사|deliver", low + " " + text[:400].lower()):
            hits["provide"].append(rel)
    return hits


def build_flow(root: Path) -> dict:
    items = parse_prisma(root)
    conv = scan_conventions(root)
    out_items = []
    for item, a in items.items():
        # 이용: 이 항목 이름과 매칭되는 mask 함수
        cl = None
        use = []
        for fn, rel in conv["mask"]:
            if _classify(fn) and _classify(fn)[0] == item:
                use.append(f"마스킹 mask{fn}()")
        # 파기: 파기 관련 파일에서 항목/컬럼 언급
        dispose = sorted({p for p in conv["dispose"]})[:4]
        collect = sorted({p for p in conv["collect"]})[:5]
        out_items.append({
            "item": item,
            "category": a["category"],
            "collect": collect,
            "store": sorted(a["store"]),
            "encryption": " + ".join(sorted(a["enc"])),
            "use": sorted(set(use)),
            "dispose": [f"파기 경로: {p}" for p in dispose],
            "table": sorted(a["tables"])[0] if a["tables"] else "",
        })
    tables = sorted({t for a in items.values() for t in a["tables"]})
    encs = sorted({e for a in items.values() for e in a["enc"]})
    gaps = []
    if "비밀번호" in items and not conv["dispose"]:
        gaps.append("비밀번호 등 파기 경로(erase/withdraw/purge)가 코드에서 발견되지 않음 — 파기 절차 점검 필요")
    return {"items": out_items, "gaps": gaps,
            "summary": {"items": len(out_items), "tables": len(tables),
                        "encryption": encs[0] if encs else "미확인"}}


def post_to_mori(base: str, flow: dict, *, repo: str, commit: str, run_id: str,
                 token: str = "", oidc: str = "") -> int:
    url = base.rstrip("/") + f"/ingest/privacy-flow?repo={repo}&commit={commit}&run_id={run_id}"
    data = json.dumps(flow, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("X-MORI-Token", token)
    if oidc:
        req.add_header("X-MORI-OIDC", oidc)
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        print("MORI:", resp.status, resp.read(200).decode("utf-8", "ignore"))
        return resp.status


def main() -> int:
    root = Path(os.getenv("SCAN_ROOT", ".")).resolve()
    flow = build_flow(root)
    print(f"parsed items={flow['summary']['items']} tables={flow['summary']['tables']}", file=sys.stderr)
    base = os.getenv("MORI_INGEST_URL", "").strip()
    if not base:
        print(json.dumps(flow, ensure_ascii=False, indent=2))
        return 0
    post_to_mori(base, flow, repo=os.getenv("GITHUB_REPOSITORY", ""),
                 commit=os.getenv("GITHUB_SHA", ""), run_id=os.getenv("GITHUB_RUN_ID", ""),
                 token=os.getenv("MORI_INGEST_TOKEN", "").strip(), oidc=os.getenv("MORI_OIDC_TOKEN", "").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
