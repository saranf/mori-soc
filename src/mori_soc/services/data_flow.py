"""개인정보 처리흐름표/흐름도 서비스 — ISMS-P 3.x 증적.

MORI 는 코드를 읽지 않는다("증적 층"). 스캔(고객 CI Semgrep)이 보낸 findings 중
PII/secret 성격을 골라 흐름표 "후보 행"으로 시드하고, 담당자가 저장위치·목적·
보관·파기를 채운다. 흐름표는 수집→저장→이용→파기 흐름도(SVG)로 렌더되고 3.x
통제 증적으로 승격된다. 이 모듈은 순수 함수만 담는다(저장은 state_repo).
"""
from __future__ import annotations

import html
import re
from typing import Any

# 개인정보 처리 단계(흐름도 열 순서) — ISMS-P 3.1 수집 → 저장 → 3.2 이용/제공 → 3.4 파기.
STAGES = ("수집", "저장", "이용", "파기")

# 흐름표 한 행의 필드(빈 값 허용 — 담당자가 점진적으로 채움).
FLOW_FIELDS = (
    "item", "subject", "collection_source", "storage_location", "storage_table",
    "purpose", "retention", "destruction", "third_party", "overseas", "note",
)

# finding 이 PII/개인정보·비밀정보 성격인지 판별하는 신호(rule_id/category/message).
_PII_SIGNAL = re.compile(
    r"pii|personal|privacy|gdpr|secret|credential|password|passwd|token|api[_-]?key|"
    r"private[_-]?key|email|phone|ssn|resident|jumin|주민|이메일|전화|비밀|개인정보|여권|계좌|카드",
    re.IGNORECASE,
)

# 규칙/메시지에서 항목(이메일/전화/주민번호…)을 대략 추론 — 시드 초기값 채우기용.
_ITEM_HINTS = (
    ("email", "이메일"), ("이메일", "이메일"), ("phone", "전화번호"), ("전화", "전화번호"),
    ("ssn", "주민등록번호"), ("rrn", "주민등록번호"), ("resident", "주민등록번호"), ("jumin", "주민등록번호"), ("주민", "주민등록번호"),
    ("passport", "여권번호"), ("여권", "여권번호"), ("account", "계좌번호"), ("계좌", "계좌번호"),
    ("card", "카드번호"), ("카드", "카드번호"), ("password", "비밀번호"), ("비밀", "비밀번호"),
    ("token", "인증토큰/시크릿"), ("secret", "인증토큰/시크릿"), ("credential", "자격증명"),
    ("api", "API 키"), ("key", "키/시크릿"),
)


def is_pii_finding(finding: dict[str, Any]) -> bool:
    """finding(raw_payload) 이 개인정보/비밀정보 관련인지."""
    hay = " ".join(str(finding.get(k) or "") for k in ("rule_id", "ruleId", "category", "rule", "title", "message", "description"))
    return bool(_PII_SIGNAL.search(hay))


def infer_item(finding: dict[str, Any]) -> str:
    """finding 에서 개인정보 항목을 대략 추론(없으면 빈 문자열)."""
    hay = " ".join(str(finding.get(k) or "") for k in ("rule_id", "category", "title", "message", "description")).lower()
    hits: list[str] = []
    for needle, label in _ITEM_HINTS:
        if needle in hay and label not in hits:
            hits.append(label)
    return ", ".join(hits[:3])


def seed_rows_from_findings(findings: list[dict[str, Any]], *, repo: str = "",
                            existing_keys: set[str] | None = None) -> list[dict[str, Any]]:
    """PII findings → 흐름표 후보 행(부분 채움). storage_table 에 파일:라인을 넣어 위치 단서 제공.

    중복 시드 방지를 위해 (repo|file|rule) 키로 걸러낸다(existing_keys).
    """
    existing_keys = existing_keys or set()
    out: list[dict[str, Any]] = []
    for f in findings:
        if not is_pii_finding(f):
            continue
        file_ = str(f.get("file") or f.get("path") or "")
        line = f.get("line")
        rule = str(f.get("rule_id") or f.get("category") or f.get("rule") or "")
        key = f"{repo}|{file_}|{rule}"
        if key in existing_keys:
            continue
        existing_keys.add(key)
        loc = f"{file_}:{line}" if file_ and line is not None else file_
        out.append({
            "item": infer_item(f),
            "subject": "",
            "collection_source": "",
            "storage_location": repo or "",
            "storage_table": loc,        # 코드 위치 단서(담당자가 실제 테이블로 교체)
            "purpose": "",
            "retention": "",
            "destruction": "",
            "third_party": "",
            "overseas": "",
            "note": f"[PII 스캔 시드] {rule}".strip(),
            "source": "pii_scan",
            "repo": repo or "",
            "file": file_,
            "rule": rule,
        })
    return out


def _esc(v: Any) -> str:
    return html.escape(str(v or ""))


def render_data_flow_svg(rows: list[dict[str, Any]]) -> str:
    """흐름표 → 개인정보 처리흐름도(SVG). 행마다 수집→저장→이용→파기 레인 + 화살표.

    새 라이브러리 없이 문자열로 SVG 생성(무의존성 원칙). 저장위치/테이블은 저장 단계에
    표기해 "데이터가 어디에 저장되는지"를 시각화한다.
    """
    col_w, gap, row_h, pad_top, pad_left = 190, 46, 74, 64, 150
    n = max(len(rows), 1)
    width = pad_left + len(STAGES) * col_w + (len(STAGES) - 1) * gap + 30
    height = pad_top + n * (row_h + 18) + 30
    # 팔레트 6색만: 파(#2563eb)·초(#16a34a)·노(#ca8a04)·빨(#dc2626), 배경 흰(#fff), 텍스트 검(#111827).
    stage_stroke = {"수집": "#2563eb", "저장": "#16a34a", "이용": "#ca8a04", "파기": "#dc2626"}

    def cell_text(stage: str, r: dict[str, Any]) -> str:
        if stage == "수집":
            return _esc(r.get("collection_source")) or "—"
        if stage == "저장":
            loc = _esc(r.get("storage_location"))
            tbl = _esc(r.get("storage_table"))
            return (loc + ("<br/>" + tbl if tbl else "")) or "—"
        if stage == "이용":
            return _esc(r.get("purpose")) or "—"
        return (_esc(r.get("destruction")) or _esc(r.get("retention")) or "—")

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
                 f'width="100%" style="max-width:{width}px;font-family:system-ui,sans-serif">')
    parts.append('<defs><marker id="arw" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
                 '<path d="M0,0 L8,4 L0,8 Z" fill="#111827"/></marker></defs>')
    # 단계 헤더 — 흰 배경 + 단계색 테두리/글자(팔레트 준수)
    for i, st in enumerate(STAGES):
        x = pad_left + i * (col_w + gap)
        parts.append(f'<rect x="{x}" y="24" width="{col_w}" height="30" rx="6" '
                     f'fill="#ffffff" stroke="{stage_stroke[st]}" stroke-width="1.2"/>')
        parts.append(f'<text x="{x + col_w/2}" y="44" text-anchor="middle" font-size="14" '
                     f'font-weight="700" fill="{stage_stroke[st]}">{st}</text>')
    # 행(항목별 레인)
    for ri, r in enumerate(rows):
        y = pad_top + ri * (row_h + 18)
        item = _esc(r.get("item")) or "(항목 미기재)"
        subj = _esc(r.get("subject"))
        label = item + (f" · {subj}" if subj else "")
        parts.append(f'<text x="12" y="{y + row_h/2}" font-size="12" font-weight="600" fill="#111827">{label}</text>')
        for i, st in enumerate(STAGES):
            x = pad_left + i * (col_w + gap)
            parts.append(f'<rect x="{x}" y="{y}" width="{col_w}" height="{row_h}" rx="8" '
                         f'fill="#ffffff" stroke="{stage_stroke[st]}" stroke-width="1.2"/>')
            # 셀 내용(<br/> → tspan 2줄)
            txt = cell_text(st, r)
            lines = txt.split("<br/>")[:2]
            for li, ln in enumerate(lines):
                ln = (ln[:26] + "…") if len(ln) > 27 else ln
                parts.append(f'<text x="{x + col_w/2}" y="{y + 30 + li*18}" text-anchor="middle" '
                             f'font-size="11" fill="#111827">{ln}</text>')
            if i < len(STAGES) - 1:
                ax = x + col_w
                parts.append(f'<line x1="{ax}" y1="{y + row_h/2}" x2="{ax + gap - 6}" y2="{y + row_h/2}" '
                             f'stroke="#111827" stroke-width="1.6" marker-end="url(#arw)"/>')
        # 제3자/국외 배지
        extra = []
        if str(r.get("third_party") or "").strip() and str(r.get("third_party")).strip() not in ("없음", "-", "n/a"):
            extra.append("제3자제공")
        if str(r.get("overseas") or "").strip() and str(r.get("overseas")).strip() not in ("없음", "-", "n/a"):
            extra.append("국외이전")
        if extra:
            parts.append(f'<text x="{width - 16}" y="{y + row_h/2}" text-anchor="end" font-size="10" '
                         f'fill="#dc2626">{" · ".join(extra)}</text>')
    if not rows:
        parts.append(f'<text x="{width/2}" y="{pad_top + 30}" text-anchor="middle" font-size="13" '
                     f'fill="#111827">흐름표가 비어 있습니다 — 행을 추가하거나 PII 스캔으로 시드하세요.</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_data_flow_pdf(rows: list[dict[str, Any]], *, generated_at: str = "") -> bytes:
    """개인정보 처리흐름표 PDF(감사관 제출용). reportlab 필요. 팔레트 6색만.

    가로 A4에 항목별 수집→저장→이용→파기 + 제3자/국외 표. control_evidence PDF 와
    같은 한글 폰트 파이프라인을 재사용한다(무의존성 원칙 밖 — reportlab 은 프로젝트 공통).
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("reportlab not installed; PDF output unavailable") from exc
    import io

    from mori_soc.services.reports import _get_pdf_font

    font = _get_pdf_font()
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("pdf_h1", parent=styles["Title"], fontName=font, fontSize=15, leading=19, spaceAfter=3,
                        textColor=colors.HexColor("#111827"))
    meta = ParagraphStyle("pdf_meta", parent=styles["Normal"], fontName=font, fontSize=8.5, leading=12,
                          textColor=colors.HexColor("#111827"))
    cell = ParagraphStyle("pdf_cell", parent=styles["Normal"], fontName=font, fontSize=8, leading=10.5,
                          textColor=colors.HexColor("#111827"))

    def esc(s: Any) -> str:
        return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    headers = ["개인정보 항목", "정보주체", "수집경로", "저장위치", "테이블·컬럼",
               "이용목적", "보관·파기", "제3자·국외"]
    data = [[Paragraph(f"<b>{esc(h)}</b>", cell) for h in headers]]
    for r in rows:
        keep = "보관: " + str(r.get("retention") or "-") + " / 파기: " + str(r.get("destruction") or "-")
        share = "제3자: " + str(r.get("third_party") or "없음") + " / 국외: " + str(r.get("overseas") or "없음")
        data.append([Paragraph(esc(v), cell) for v in (
            r.get("item"), r.get("subject"), r.get("collection_source"),
            r.get("storage_location"), r.get("storage_table"), r.get("purpose"), keep, share)])

    widths = [34 * mm, 22 * mm, 32 * mm, 30 * mm, 40 * mm, 38 * mm, 40 * mm, 44 * mm]
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),   # 검 헤더
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),                  # 흰 글자
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),   # 뉴트럴 그리드
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))

    buf = io.BytesIO()
    docp = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                             topMargin=14 * mm, bottomMargin=12 * mm, title="MORI 개인정보 처리흐름표")
    story: list[Any] = [Paragraph("개인정보 처리흐름표 (ISMS-P 3.1·3.2·3.4)", h1)]
    sub = f"항목 {len(rows)}건 · 수집→저장→이용→파기"
    if generated_at:
        sub += f" · 생성 {esc(generated_at)}"
    story += [Paragraph(sub, meta), Spacer(1, 6)]
    story.append(table if rows else Paragraph("흐름표가 비어 있습니다.", meta))
    docp.build(story)
    return buf.getvalue()


__all__ = ["STAGES", "FLOW_FIELDS", "is_pii_finding", "infer_item",
           "seed_rows_from_findings", "render_data_flow_svg", "render_data_flow_pdf"]
