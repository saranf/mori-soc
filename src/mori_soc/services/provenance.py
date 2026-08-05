"""증적 출처·신뢰수준 표시(provenance) — 모리다움의 뿌리.

MORI 의 `signal → decision → evidence` 에서 signal 이 **어디서** 왔는지(코드/실제 API/규칙/
AI/사람/정책)를 명시해 "왜 믿을 수 있는가"를 심사위원·담당자에게 설명한다. 법적 확정이 아니라
근거의 출처를 붙이는 것뿐이다(사람 검토 전제).

출처 태그(신뢰 강한 순의 뜻이 아니라 '종류'):
  CODE   코드에서 직접 확인(리터럴·필드·스니펫)
  API    실제 운영 API 수집(Zabbix·Fleet·Wazuh·Trivy)
  RULE   규칙 기반 판단(Semgrep 룰·휴리스틱)
  AI     AI 추론(Claude fullscan 등) — 후보 제안
  HUMAN  담당자가 확인·입력
  POLICY 정책·처리방침 문서 근거
"""
from __future__ import annotations

from typing import Any

PROVENANCE = ("CODE", "API", "RULE", "AI", "HUMAN", "POLICY")
_VALID = set(PROVENANCE)

# 사람이 아닌 자동 액터(created_by 로 HUMAN 을 판별할 때 제외).
_AUTOMATED_ACTORS = {"code_review", "ai_fullscan", "privacy_flow", "system", "", "unknown"}

# source -> 기본 출처 태그
_SOURCE_TAGS: dict[str, tuple[str, ...]] = {
    "code_review": ("CODE",),
    "code_review_scan": ("CODE",),
    "privacy_flow": ("CODE", "RULE"),
    "pii_scan": ("CODE", "RULE"),
    "ai_flow": ("AI",),
    "manual": ("HUMAN",),
    "zabbix": ("API",),
    "fleet": ("API",),
    "wazuh": ("API",),
    "trivy": ("API",),
    "zabbix_writeback": ("API", "HUMAN"),
}


def tags_for_source(source: str | None, *, tool: str | None = None,
                    created_by: str | None = None) -> list[str]:
    """source(+선택적 tool·created_by)에서 출처 태그 목록을 도출."""
    src = str(source or "").strip().lower()
    # code_review 는 스캐너 종류로 더 정밀하게: Semgrep=규칙+코드, Claude=AI.
    if src in ("code_review", "code_review_scan") and tool:
        t = str(tool).lower()
        if "claude" in t or "ai" in t or "유료" in t:
            return ["AI"]
        if "semgrep" in t or "무료" in t or "sarif" in t:
            return ["RULE", "CODE"]
    tags = list(_SOURCE_TAGS.get(src, ()))
    if tags:
        return tags
    # 알 수 없는 source 인데 사람이 만든 것이면 HUMAN.
    if created_by and str(created_by).strip().lower() not in _AUTOMATED_ACTORS:
        return ["HUMAN"]
    return []


def scan_input_signature(repo: str | None, commit: str | None, tool: str | None,
                         scanner: str | None, ruleset: str | None, model: str | None) -> str:
    """스캔 재현성 식별자(#2) — 동일 입력이면 동일 signature. commit·scanner·ruleset·model·tool."""
    from mori_soc.services.hashing import short_id
    return short_id(repo, commit, tool, scanner, ruleset, model)


def findings_content_hash(findings: "list[dict[str, Any]] | None") -> str:
    """이 스캔이 산출한 findings **집합의 내용 해시**(R4 — 그 시점 결과의 tamper-evident 앵커).

    scan_input_signature 가 '입력 동일'을 식별한다면, 이 값은 '출력(결과) 동일'을 식별한다.
    AI 비결정으로 같은 입력이어도 결과가 다르면 이 해시가 달라져, **각 실행 결과가 불변으로 고정**된다
    (감사관은 '이 스캔이 이 시점에 정확히 이 findings 를 냈다'를 위·변조 없이 확인).
    순서 무관(정렬 후 해시)·핵심 필드만(rule·file·line·severity·message) 정규화.
    """
    from mori_soc.services.hashing import canonical_json, sha256_hex
    norm: list[dict[str, Any]] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        norm.append({
            "rule": str(f.get("rule_id") or f.get("ruleId") or f.get("category") or ""),
            "file": str(f.get("file") or f.get("path") or ""),
            "line": str(f.get("line") if f.get("line") is not None else ""),
            "severity": str(f.get("severity") or f.get("level") or ""),
            "msg": str(f.get("message") or f.get("title") or ""),
        })
    norm.sort(key=lambda d: (d["file"], d["line"], d["rule"], d["msg"]))
    return "sha256:" + sha256_hex(canonical_json({"count": len(norm), "items": norm}, compact=True))


def build_provenance_detail(rec: dict[str, Any], tags: list[str]) -> dict[str, Any]:
    """provenance 를 **배지가 아니라 근거 객체**로(리뷰 #16).

    태그별로 신뢰 근거를 구조화한다 — AI: provider·model·prompt_version·input_hash / CODE·RULE:
    repo·commit·path·line·scanner·rule / API: integration·endpoint·collected_at·raw_payload_hash /
    POLICY: document·version·section·approved_at. + review_status(사람 검토 여부).
    없는 필드는 빈 값(단정 안 함). rec.envelope._provenance 를 우선 참조한다.
    """
    env = rec.get("envelope") if isinstance(rec.get("envelope"), dict) else {}
    prov = env.get("_provenance") if isinstance(env.get("_provenance"), dict) else {}
    human = "HUMAN" in tags or str(rec.get("review_status") or "") == "confirmed"
    detail: dict[str, Any] = {
        "tags": tags, "primary": tags[0] if tags else "",
        "review_status": "reviewed" if human else "unreviewed",
    }
    if "CODE" in tags or "RULE" in tags:
        detail["code"] = {
            "repo": prov.get("repo") or rec.get("repo") or "",
            "commit": prov.get("commit") or rec.get("commit") or "",
            "path": rec.get("file") or rec.get("path") or "",
            "line": rec.get("line"),
            "scanner": env.get("scanner") or rec.get("scanner") or "",
            "rule": rec.get("rule_id") or rec.get("rule") or "",
        }
    if "AI" in tags:
        detail["ai"] = {
            "provider": env.get("provider") or "Anthropic",
            "model": env.get("model") or rec.get("model") or "",
            "prompt_version": env.get("prompt_version") or env.get("ruleset") or "",
            "input_hash": env.get("input_signature") or rec.get("input_signature") or "",
        }
    if "API" in tags:
        detail["api"] = {
            "integration": rec.get("source") or "",
            "endpoint": env.get("endpoint") or "",
            "collected_at": rec.get("collected_at") or rec.get("generated_at") or "",
            "raw_payload_hash": prov.get("raw_payload_hash") or "",
        }
    if "POLICY" in tags:
        detail["policy"] = {
            "document": rec.get("policy_document") or "",
            "version": rec.get("policy_version") or "",
            "section": rec.get("policy_section") or "",
            "approved_at": rec.get("policy_approved_at") or "",
        }
    return detail


def attach_provenance(rec: dict[str, Any]) -> dict[str, Any]:
    """레코드에 provenance 태그 + 근거 객체(provenance_detail)를 붙인다(제자리 수정).

    envelope.tool 이 있으면(스캔 도구) 그것으로 code_review 를 정밀 분류한다.
    """
    existing = rec.get("provenance")
    if isinstance(existing, list) and existing and all(t in _VALID for t in existing):
        tags = existing
    else:
        tool = None
        env = rec.get("envelope")
        if isinstance(env, dict):
            prov = env.get("_provenance") if isinstance(env.get("_provenance"), dict) else {}
            tool = env.get("tool") or (prov or {}).get("tool")
        tags = tags_for_source(rec.get("source"), tool=tool, created_by=rec.get("created_by"))
        rec["provenance"] = tags
    rec["provenance_detail"] = build_provenance_detail(rec, tags)
    return rec
