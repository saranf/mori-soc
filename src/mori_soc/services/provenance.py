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
    import hashlib
    seed = "|".join(str(x or "") for x in (repo, commit, tool, scanner, ruleset, model))
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]


def attach_provenance(rec: dict[str, Any]) -> dict[str, Any]:
    """레코드에 provenance 태그를 붙인다(이미 유효하게 있으면 존중, 제자리 수정).

    envelope.tool 이 있으면(스캔 도구) 그것으로 code_review 를 정밀 분류한다.
    """
    existing = rec.get("provenance")
    if isinstance(existing, list) and existing and all(t in _VALID for t in existing):
        return rec
    tool = None
    env = rec.get("envelope")
    if isinstance(env, dict):
        prov = env.get("_provenance") if isinstance(env.get("_provenance"), dict) else {}
        tool = env.get("tool") or (prov or {}).get("tool")
    rec["provenance"] = tags_for_source(rec.get("source"), tool=tool, created_by=rec.get("created_by"))
    return rec
