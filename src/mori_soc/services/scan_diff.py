"""스캔 간 diff와 변경 사유 귀속(#3) — MORI 가 가장 잘하는 차별점.

두 스캔의 findings 를 비교해 신규/제거를 뽑고, 재현성 입력(commit·ruleset·model·tool) 차이로
**변경 원인**(코드 변경 / 룰셋 변경 / AI·도구 변경)을 귀속한다. 입력이 완전히 같은데(같은
input_signature) 결과가 다르면 '비결정성'으로 표시 — 감사 신뢰에 중요한 신호.
"""
import re
from typing import Any


def _rule(f: dict[str, Any]) -> str:
    return str(f.get("rule_id") or f.get("ruleId") or f.get("rule") or f.get("category") or "")


def _semantic_fingerprint(f: dict[str, Any]) -> str:
    """finding 의 **줄 번호에 의존하지 않는** 의미 지문(리뷰 #18).

    명시 심볼(symbol/sink/function/normalized)이 있으면 그걸, 없으면 메시지에서 숫자·경로를
    지운 정규화 문자열을 쓴다. PII 맥락은 data_type/table/column 을 덧붙인다.
    """
    for k in ("symbol", "sink", "function", "normalized"):
        if f.get(k):
            return str(f[k]).strip().lower()[:120]
    msg = str(f.get("message") or f.get("msg") or "")
    msg = re.sub(r"[/\\][\w./\\-]+", "PATH", msg)   # 경로 → PATH
    msg = re.sub(r"\d+", "#", msg)                    # 숫자 → #(줄·컬럼 흔들림 제거)
    ctx = str(f.get("data_type") or f.get("table") or f.get("column") or "")
    return (msg.strip().lower()[:120] + ("|" + ctx if ctx else "")).strip()


def finding_key(f: dict[str, Any]) -> str:
    """(하위호환) file|line|rule. 신규 코드는 finding_identity(줄 독립)를 쓴다."""
    line = f.get("line") if f.get("line") is not None else ""
    return f"{f.get('file') or f.get('path') or ''}|{line}|{_rule(f)}"


def finding_identity(f: dict[str, Any]) -> str:
    """**줄 독립** 안정 식별자 — file|rule|semantic_fingerprint. 코드 한 줄 삽입에도 유지된다."""
    return f"{f.get('file') or f.get('path') or ''}|{_rule(f)}|{_semantic_fingerprint(f)}"


def diff_findings(prev: list[dict[str, Any]], cur: list[dict[str, Any]]) -> dict[str, Any]:
    """이전→현재 findings diff(리뷰 #18) — 줄 독립 identity 로 매칭해 상태를 세분한다.

    added(신규)·removed(제거)·moved(줄만 이동)·modified(심각도/내용 변경)·unchanged.
    new/removed/new_count 등은 하위호환 유지(new = added).
    """
    pk = {finding_identity(f): f for f in prev}
    ck = {finding_identity(f): f for f in cur}
    added = [ck[k] for k in ck if k not in pk]
    removed = [pk[k] for k in pk if k not in ck]
    moved: list[dict[str, Any]] = []
    modified: list[dict[str, Any]] = []
    unchanged = 0
    for k in ck:
        if k not in pk:
            continue
        a, b = pk[k], ck[k]
        line_changed = str(a.get("line")) != str(b.get("line"))
        sev_changed = str(a.get("severity") or "") != str(b.get("severity") or "")
        if sev_changed:
            modified.append({**b, "prev_severity": a.get("severity"),
                             "change": "severity_changed"})
        elif line_changed:
            moved.append({**b, "prev_line": a.get("line")})
        else:
            unchanged += 1
    return {"new": added, "removed": removed, "moved": moved, "modified": modified,
            "new_count": len(added), "removed_count": len(removed),
            "moved_count": len(moved), "modified_count": len(modified),
            "unchanged_count": unchanged}


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
    # 의미 있는 변화 = 신규·제거·심각도변경(줄만 이동한 moved 는 양성 이동이라 제외).
    changed = d["new_count"] > 0 or d["removed_count"] > 0 or d["modified_count"] > 0
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
