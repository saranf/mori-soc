"""SoA — ISO/IEC 27001 적용선언서 (Statement of Applicability, clause 6.1.3 d) 생성.

MORI다움: 새 데이터를 만들지 않고 **이미 있는 것**(카탈로그 iso27001 통제 + control_status
런타임 이행상태/해당없음/사유)만 조립해 심사 필수 산출물 SoA를 낸다. reports.py 의 한글
폰트·PDF 패턴을 재사용한다. 색은 팔레트(흰/검/노/빨/초/파)만 쓴다.
"""
from __future__ import annotations

import csv
import io
from typing import Any

# control_status.status(한글) → SoA 이행상태 라벨(영문)
_IMPL_EN = {
    "이행": "Implemented", "부분이행": "Partially implemented",
    "미이행": "Not implemented", "미정": "Planned", "해당없음": "N/A",
}
_NOT_APPLICABLE = "해당없음"

_BLACK = "#191f28"


def build_soa_rows(catalog: dict[str, Any],
                   control_status: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """ISO 27001 통제별 SoA 행 목록(A.5.1 순 정렬).

    적용여부: status == '해당없음' → 제외(applicable False), 그 외 → 포함(True).
    근거: 제외면 exception_reason(왜 제외), 포함이면 exception_reason 또는 intent(왜 채택).
    """
    status_map = control_status or {}
    rows: list[dict[str, Any]] = []
    for c in catalog.get("controls", []):
        if c.get("framework") != "iso27001":
            continue
        cid = c.get("id", "")
        st = status_map.get(cid, {}) or {}
        raw = str(st.get("status", "") or "").strip()
        applicable = raw != _NOT_APPLICABLE
        reason = str(st.get("exception_reason", "") or "").strip()
        if not applicable:
            justification = reason or "Not applicable to the scope."
        else:
            justification = reason or c.get("intent_en") or c.get("intent_ko") or "Adopted as a baseline control."
        rows.append({
            "id": cid,
            "title": c.get("title_en") or c.get("title_ko") or "",
            "applicable": applicable,
            "impl_status": _IMPL_EN.get(raw, "Planned" if applicable else "N/A"),
            "justification": justification,
            "owner": str(st.get("owner", "") or ""),
            "evidence_sources": c.get("evidence_sources") or [],
            "reviewed": c.get("status") == "reviewed",
        })
    rows.sort(key=lambda r: _sortkey(r["id"]))
    return rows


def soa_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(rows),
        "applicable": sum(1 for r in rows if r["applicable"]),
        "excluded": sum(1 for r in rows if not r["applicable"]),
        "implemented": sum(1 for r in rows if r["impl_status"] == "Implemented"),
        "evidence_wired": sum(1 for r in rows if r["evidence_sources"]),
    }


def soa_to_csv(rows: list[dict[str, Any]]) -> str:
    """SoA CSV (BOM 없이; 라우트에서 BOM 부착)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Control", "Title", "Applicable", "Implementation", "Justification",
                "Owner", "Evidence sources", "Reviewed"])
    for r in rows:
        w.writerow([
            r["id"], r["title"], "Yes" if r["applicable"] else "No", r["impl_status"],
            r["justification"], r["owner"], ", ".join(r["evidence_sources"]),
            "reviewed" if r["reviewed"] else "draft",
        ])
    return buf.getvalue()


def soa_to_pdf(rows: list[dict[str, Any]], summary: dict[str, int] | None = None) -> bytes:
    """SoA PDF (ISO 27001 적용선언서). reports._get_pdf_font 재사용, 팔레트 색만."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    from mori_soc.services.pdf import get_pdf_font as _get_pdf_font
    from mori_soc.services.pdf import pdf_table

    font = _get_pdf_font()
    styles = getSampleStyleSheet()
    black = colors.HexColor(_BLACK)
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontName=font, fontSize=15, leading=19,
                        spaceAfter=2, textColor=black)
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=font, fontSize=9, leading=12,
                          textColor=black)
    summary = summary or soa_summary(rows)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title="ISO 27001 Statement of Applicability")
    story: list[Any] = [
        Paragraph("적용선언서 · Statement of Applicability (ISO/IEC 27001 Annex A)", h1),
        Paragraph(f"통제 {summary['total']} · 적용 {summary['applicable']} · 제외 {summary['excluded']} · "
                  f"이행 {summary['implemented']} · 증적연결 {summary['evidence_wired']}", body),
        Spacer(1, 6),
    ]
    header = ["Control", "Title", "Appl.", "Implementation", "Justification"]
    table_rows = [[r["id"], r["title"], "Yes" if r["applicable"] else "No",
                   r["impl_status"], r["justification"]] for r in rows]
    story.append(pdf_table(header, table_rows, [16 * mm, 42 * mm, 12 * mm, 30 * mm, 82 * mm], font=font))
    doc.build(story)
    return buf.getvalue()


def _sortkey(cid: str):
    parts = cid.replace("A.", "").split(".")
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    return out
