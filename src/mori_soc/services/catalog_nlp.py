"""자연어 법령/고시 텍스트 → 통제 카탈로그 초안 변환 (M2-8, 하이브리드).

admin이 CISA·개인정보보호법·고시 등 규정 텍스트를 붙여넣으면 통제 레코드 초안으로
변환한다. ``MORI_ANTHROPIC_API_KEY`` (또는 ``ANTHROPIC_API_KEY``) 가 설정돼 있으면
Claude API로 정확히 구조화하고, 없으면 오프라인 휴리스틱 파서로 초안을 만든다. 어느
쪽이든 결과는 ``status='draft'``, ``origin='nlp'`` 로 저장되어 admin이 검토·수정한다.

외부 전송 주의: Claude 경로는 붙여넣은 텍스트를 Anthropic으로 보낸다(공개 법령이면
통상 무방하나 민감 텍스트는 오프라인 경로만 쓰도록 키를 비워 둘 것).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

# 조항 머리 패턴: "제5조", "5.", "5.1.2", "A.8.8", "Article 7", "(1)", "1)"
_CLAUSE_RE = re.compile(
    r"^\s*(?:"
    r"제\s*\d+\s*조(?:의\s*\d+)?"          # 제5조 / 제5조의2
    r"|Article\s+\d+"                       # Article 7
    r"|[A-Z]\.\d+(?:\.\d+)*"               # A.8.8
    r"|\d+(?:\.\d+)+"                       # 5.1.2
    r"|\d+[.)]"                             # 5.  / 5)
    r"|\(\d+\)"                             # (1)
    r")\s*",
    re.IGNORECASE,
)


def _clause_head(line: str) -> str | None:
    m = _CLAUSE_RE.match(line)
    if not m:
        return None
    return m.group(0).strip()


def _slug_id(head: str, prefix: str, idx: int) -> str:
    """조항 머리에서 안정적인 control id 를 만든다."""
    cleaned = re.sub(r"[제조의\s()]", "", head).strip(".")
    cleaned = re.sub(r"Article", "art", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"[^A-Za-z0-9.\-]", "", cleaned)
    return f"{prefix}-{cleaned}" if cleaned else f"{prefix}-{idx:03d}"


def _heuristic(text: str, framework: str, prefix: str) -> list[dict[str, Any]]:
    """조항 머리/문단 기반 오프라인 초안 생성."""
    lines = [ln.rstrip() for ln in text.replace("\r", "").split("\n")]
    controls: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    idx = 0

    def _flush() -> None:
        if cur and (cur["title_ko"] or cur["intent_ko"]):
            controls.append(cur)

    for ln in lines:
        if not ln.strip():
            continue
        head = _clause_head(ln)
        if head is not None:
            _flush()
            idx += 1
            title = ln[len(head):].strip(" .·:-—") or ln.strip()
            cur = {
                "id": _slug_id(head, prefix, idx),
                "framework": framework, "title_ko": title[:120], "title_en": "",
                "intent_ko": "", "intent_en": "", "evidence_hint_ko": "",
                "evidence_sources": [], "tags": ["nlp", head], "status": "draft", "origin": "nlp",
            }
        elif cur is not None:
            cur["intent_ko"] = (cur["intent_ko"] + " " + ln.strip()).strip()[:2000]
        else:
            # 조항 머리 없이 시작 → 문단을 통제로
            idx += 1
            cur = {
                "id": f"{prefix}-{idx:03d}", "framework": framework,
                "title_ko": ln.strip()[:120], "title_en": "", "intent_ko": ln.strip()[:2000],
                "intent_en": "", "evidence_hint_ko": "", "evidence_sources": [],
                "tags": ["nlp"], "status": "draft", "origin": "nlp",
            }
    _flush()
    return controls


_SYSTEM = (
    "You convert regulatory/standard text into a compliance control catalog. "
    "Return ONLY a JSON array (no prose). Each item: "
    '{"id": short stable id, "title_ko": Korean title, "title_en": English title, '
    '"intent_ko": Korean intent 1-3 sentences, "intent_en": English intent, '
    '"evidence_hint_ko": what evidence proves compliance (Korean), '
    '"tags": [keywords]}. Split the text into discrete, atomic controls. '
    "Prefer the clause/article number as the id when present."
)


def _via_claude(text: str, framework: str, prefix: str, api_key: str) -> list[dict[str, Any]]:
    """Claude API로 구조화(실패 시 예외 → 호출부가 휴리스틱으로 폴백)."""
    import httpx

    model = os.getenv("MORI_NLP_MODEL", "claude-haiku-4-5-20251001").strip() or "claude-haiku-4-5-20251001"
    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json={
            "model": model, "max_tokens": 4096, "system": _SYSTEM,
            "messages": [{"role": "user", "content": f"Framework hint: {framework}\n\n{text[:20000]}"}],
        },
        timeout=60.0,
    )
    resp.raise_for_status()
    blocks = resp.json().get("content", [])
    raw = "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
    # JSON 배열만 추출(코드펜스/서문 방어)
    start, end = raw.find("["), raw.rfind("]")
    if start == -1 or end == -1:
        raise ValueError("no JSON array in model output")
    items = json.loads(raw[start:end + 1])
    out: list[dict[str, Any]] = []
    for i, it in enumerate(items, 1):
        if not isinstance(it, dict):
            continue
        cid = str(it.get("id") or "").strip() or f"{prefix}-{i:03d}"
        if not cid.startswith(prefix):
            cid = f"{prefix}-{cid}"
        title = str(it.get("title_ko") or it.get("title_en") or "").strip()
        if not title:
            continue
        out.append({
            "id": cid[:80], "framework": framework, "title_ko": title[:120],
            "title_en": str(it.get("title_en") or "")[:160],
            "intent_ko": str(it.get("intent_ko") or "")[:2000],
            "intent_en": str(it.get("intent_en") or "")[:2000],
            "evidence_hint_ko": str(it.get("evidence_hint_ko") or "")[:800],
            "evidence_sources": [],
            "tags": [str(t)[:40] for t in (it.get("tags") or [])][:8] + ["nlp"],
            "status": "draft", "origin": "nlp",
        })
    if not out:
        raise ValueError("model returned no usable controls")
    return out


def parse_regulation_text(text: str, framework: str = "custom",
                          id_prefix: str = "REG",
                          api_key: str | None = None) -> dict[str, Any]:
    """규정 텍스트 → 통제 초안 목록. 반환: {controls, method, count}.

    ``method`` 는 'claude' | 'heuristic' — 어느 경로로 만들었는지 UI에 표시.
    ``api_key`` 를 주면 그 키를 우선 사용(어드민 저장 키 등), 없으면 환경변수
    ``MORI_ANTHROPIC_API_KEY``/``ANTHROPIC_API_KEY`` 를 읽는다. 키가 없으면 휴리스틱.
    """
    text = (text or "").strip()
    prefix = re.sub(r"[^A-Za-z0-9]", "", (id_prefix or "REG")).upper()[:12] or "REG"
    if not text:
        return {"controls": [], "method": "none", "count": 0}
    api_key = (api_key or "").strip() or (
        os.getenv("MORI_ANTHROPIC_API_KEY", "") or os.getenv("ANTHROPIC_API_KEY", "")).strip()
    if api_key:
        try:
            controls = _via_claude(text, framework, prefix, api_key)
            return {"controls": controls, "method": "claude", "count": len(controls)}
        except Exception:
            pass  # 어떤 실패든 오프라인 폴백
    controls = _heuristic(text, framework, prefix)
    return {"controls": controls, "method": "heuristic", "count": len(controls)}


__all__ = ["parse_regulation_text"]
