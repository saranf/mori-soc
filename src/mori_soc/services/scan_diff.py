"""스캔 간 diff와 변경 사유 귀속(#3) — MORI 가 가장 잘하는 차별점.

두 스캔의 findings 를 비교해 신규/제거를 뽑고, 재현성 입력(commit·ruleset·model·tool) 차이로
**변경 원인**(코드 변경 / 룰셋 변경 / AI·도구 변경)을 귀속한다. 입력이 완전히 같은데(같은
input_signature) 결과가 다르면 '비결정성'으로 표시 — 감사 신뢰에 중요한 신호.
"""
from __future__ import annotations

from typing import Any


def finding_key(f: dict[str, Any]) -> str:
    """finding 안정 식별자 — file|line|rule. 같은 결함을 스캔 간 동일하게 매칭."""
    rule = f.get("rule_id") or f.get("ruleId") or f.get("rule") or f.get("category") or ""
    return f"{f.get('file') or f.get('path') or ''}|{f.get('line') if f.get('line') is not None else ''}|{rule}"


def diff_findings(prev: list[dict[str, Any]], cur: list[dict[str, Any]]) -> dict[str, Any]:
    """이전→현재 findings diff. 신규·제거 목록 + 개수."""
    pk = {finding_key(f): f for f in prev}
    ck = {finding_key(f): f for f in cur}
    new = [ck[k] for k in ck if k not in pk]
    removed = [pk[k] for k in pk if k not in ck]
    return {"new": new, "removed": removed,
            "new_count": len(new), "removed_count": len(removed),
            "unchanged_count": sum(1 for k in ck if k in pk)}


def attribute_change(prev_env: dict[str, Any], cur_env: dict[str, Any]) -> list[str]:
    """재현성 입력 차이로 변경 원인 귀속. 빈 목록이면 '동일 입력'."""
    causes: list[str] = []

    def _n(env: dict[str, Any], k: str) -> str:
        return str(env.get(k) or "")

    if _n(prev_env, "commit") != _n(cur_env, "commit"):
        causes.append("code")
    if _n(prev_env, "ruleset") != _n(cur_env, "ruleset"):
        causes.append("ruleset")
    if _n(prev_env, "model") != _n(cur_env, "model") or _n(prev_env, "tool") != _n(cur_env, "tool"):
        causes.append("ai")
    return causes


def summarize_diff(prev_env: dict[str, Any], cur_env: dict[str, Any],
                   prev_findings: list[dict[str, Any]], cur_findings: list[dict[str, Any]]) -> dict[str, Any]:
    """두 스캔의 완전한 비교 결과 — 원인·diff·비결정성 판정 포함."""
    d = diff_findings(prev_findings, cur_findings)
    causes = attribute_change(prev_env, cur_env)
    changed = d["new_count"] > 0 or d["removed_count"] > 0
    # 입력이 같은데(같은 signature) 결과가 다르면 비결정성 — 감사 신뢰상 경고.
    same_input = not causes
    nondeterministic = bool(same_input and changed)
    return {
        "prev": {k: prev_env.get(k) for k in ("commit", "scanner", "ruleset", "model", "tool", "input_signature")},
        "cur": {k: cur_env.get(k) for k in ("commit", "scanner", "ruleset", "model", "tool", "input_signature")},
        "diff": d,
        "causes": causes,               # ["code","ruleset","ai"] 부분집합, 빈값=동일 입력
        "changed": changed,
        "same_input": same_input,
        "nondeterministic": nondeterministic,
    }
