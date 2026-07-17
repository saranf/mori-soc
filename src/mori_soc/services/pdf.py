"""공유 PDF 렌더 프리미티브 — 한글 폰트 등록 + 팔레트 테이블(정리·제품화 C5).

증적 PDF(control_catalog)·SoA(soa)·개인정보 흐름표(data_flow)·리포트(reports)가 각자 폰트 등록·
Table 스타일을 재정의하던 것을 여기 한 곳으로 모은다(공통화). 팔레트 6색만 사용.
reports.py 는 하위호환용으로 이 모듈을 re-export 한다.
"""
from __future__ import annotations

from typing import Any

# 시스템 한글 폰트 후보(순서대로 탐색, 실패 시 Helvetica).
KOREAN_FONT_CANDIDATES = (
    ("NanumGothic", "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),
    ("NanumGothic", "/usr/share/fonts/nanum/NanumGothic.ttf"),
    ("NotoSansCJK", "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
    ("AppleSDGothicNeo", "/System/Library/Fonts/AppleSDGothicNeo.ttc"),
)

_pdf_font_name: str | None = None


def get_pdf_font() -> str:
    """ReportLab 에 한글 폰트를 등록(최초 1회)하고 폰트명을 반환. 실패 시 Helvetica."""
    global _pdf_font_name
    if _pdf_font_name is not None:
        return _pdf_font_name
    try:
        import os as _os

        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        for name, path in KOREAN_FONT_CANDIDATES:
            if _os.path.exists(path):
                try:
                    pdfmetrics.registerFont(TTFont(name, path))
                    _pdf_font_name = name
                    return name
                except Exception:
                    continue
    except ImportError:
        pass
    _pdf_font_name = "Helvetica"
    return _pdf_font_name


def pdf_table(headers: list[Any], rows: list[list[Any]], col_widths: list[float],
              *, font: str | None = None):
    """공유 PDF 테이블 flowable — 팔레트(검정 텍스트·중립 그리드)만.

    headers/rows 는 원시값(자동 escape + Paragraph). reportlab Table 반환.
    """
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, Table, TableStyle
    f = font or get_pdf_font()
    black = colors.HexColor("#111827")
    cell = ParagraphStyle("pdfcell", parent=getSampleStyleSheet()["Normal"], fontName=f,
                          fontSize=8, leading=10.5, textColor=black)

    def _esc(x: Any) -> str:
        return str(x if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    data = [[Paragraph(f"<b>{_esc(h)}</b>", cell) for h in headers]]
    data += [[Paragraph(_esc(x), cell) for x in r] for r in rows]
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), f),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (-1, -1), black),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


__all__ = ["KOREAN_FONT_CANDIDATES", "get_pdf_font", "pdf_table"]
