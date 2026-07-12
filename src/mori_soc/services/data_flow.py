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
    ("gender", "성별"), ("성별", "성별"),
    ("birth", "생년월일"), ("dob", "생년월일"), ("생년월일", "생년월일"),
    ("address", "주소"), ("주소", "주소"), ("배송지", "주소"),
    ("full_name", "이름"), ("fullname", "이름"), ("성명", "이름"), ("고객명", "이름"), ("이름", "이름"),
)

# 어드민이 러프하게 늘릴 수 있는 PII 필드 기본셋 — (semgrep pattern-regex, 항목 라벨).
# 스캔이 리터럴 값뿐 아니라 필드/스키마 식별자까지 잡도록(이름·성별·생년월일·주소 등).
DEFAULT_PII_FIELDS: tuple[tuple[str, str], ...] = (
    (r"(?i)\bemail\b|이메일", "이메일"),
    (r"(?i)\b(phone|mobile|tel)\b|휴대폰|전화번호", "전화번호"),
    (r"(?i)\b(resident_?reg_?num|residentnumber|rrn|ssn|jumin)\b|주민등록번호", "주민등록번호"),
    (r"(?i)\b(card_?number|creditcard)\b|카드번호", "카드번호"),
    (r"(?i)\b(account_?number|bank_?account)\b|계좌번호", "계좌번호"),
    (r"(?i)\b(birth_?date|birthday|dob)\b|생년월일", "생년월일"),
    (r"(?i)\bgender\b|성별", "성별"),
    (r"(?i)\b(address|shipping_?address)\b|주소|배송지", "주소"),
    (r"(?i)\bpassport\b|여권", "여권번호"),
    (r"(?i)\b(full_?name)\b|성명|고객명", "이름"),
)


def is_pii_finding(finding: dict[str, Any]) -> bool:
    """finding(raw_payload) 이 개인정보/비밀정보 관련인지."""
    hay = " ".join(str(finding.get(k) or "") for k in ("rule_id", "ruleId", "category", "rule", "title", "message", "description"))
    return bool(_PII_SIGNAL.search(hay))


def infer_item(finding: dict[str, Any]) -> str:
    """finding 에서 개인정보 항목을 대략 추론(없으면 빈 문자열). 스니펫의 필드명도 반영."""
    hay = " ".join(str(finding.get(k) or "") for k in ("rule_id", "category", "title", "message", "description", "snippet")).lower()
    hits: list[str] = []
    for needle, label in _ITEM_HINTS:
        if needle in hay and label not in hits:
            hits.append(label)
    return ", ".join(hits[:3])


# 파일 경로로 개인정보 처리 단계를 추정 — MORI 는 코드를 안 읽으니 경로 단서로 best-effort.
_COLLECT_HINTS = ("signup", "sign-up", "sign_up", "register", "registration", "join", "login",
                  "sign-in", "signin", "/form", "checkout", "contact", "subscribe", "apply",
                  "onboard", "survey", "profile", "mypage", "account", "input", "enroll", "order")
_STORE_HINTS = ("seed", "migration", "migrate", "schema", "prisma", "/model", "entity", "repository",
                "dao", ".sql", "/db/", "database", "fixtures", "/store", "insert")
_USE_HINTS = ("/api/", "route", "handler", "service", "controller", "usecase", "use-case", "process",
              "send", "mailer", "sms", "notif", "export", "report", "analytic", "payment", "/lib/")
_DISPOSE_HINTS = ("erase", "/destroy", "purge", "withdraw", "탈퇴", "파기", "deletion", "expire")


# 스니펫/메시지에서 DB 테이블·모델명을 뽑는다 — Prisma·SQL·TypeORM·Sequelize 흔한 패턴.
_TABLE_PATTERNS = (
    re.compile(r"\bmodel\s+([A-Za-z_]\w*)", re.I),                 # Prisma: model User {
    re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?[\"'`\[]?([A-Za-z_]\w*)", re.I),  # SQL
    re.compile(r"@Entity\([^)]*\)\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_]\w*)", re.I),  # TypeORM
    re.compile(r"table\s*[:=]\s*[\"'`]([A-Za-z_]\w*)", re.I),      # sequelize/knex tableName
    re.compile(r"@Table\([^)]*name\s*[:=]\s*[\"'`]([A-Za-z_]\w*)", re.I),
)


def infer_table(finding: dict[str, Any]) -> str:
    """finding 스니펫/메시지에서 DB 테이블(모델)명을 추정. 없으면 빈 문자열."""
    hay = " ".join(str(finding.get(k) or "") for k in ("snippet", "message", "description", "title"))
    for pat in _TABLE_PATTERNS:
        m = pat.search(hay)
        if m:
            return m.group(1)
    return ""


def infer_stage(file_path: str) -> str | None:
    """파일 경로로 처리 단계(수집/저장/이용/파기)를 추정. 불명확하면 None."""
    p = (file_path or "").lower()
    if not p:
        return None
    if any(h in p for h in _DISPOSE_HINTS):
        return "파기"
    if any(h in p for h in _STORE_HINTS):
        return "저장"
    if any(h in p for h in _COLLECT_HINTS):
        return "수집"
    if any(h in p for h in _USE_HINTS):
        return "이용"
    return None


def seed_rows_from_findings(findings: list[dict[str, Any]], *, repo: str = "",
                            existing_keys: set[str] | None = None) -> list[dict[str, Any]]:
    """PII findings → 흐름표 후보 행. 파일 경로로 단계(수집/저장/이용)를 추정해 해당 칸에 코드 위치.

    signup·checkout·form → 수집 / prisma·seed·schema·sql → 저장 / api·service → 이용.
    불명확하면 저장(코드에 존재). 중복 시드 방지는 (repo|file|rule) 키로.
    """
    existing_keys = existing_keys or set()
    out: list[dict[str, Any]] = []
    for f in findings:
        if not is_pii_finding(f):
            continue
        file_ = str(f.get("file") or f.get("path") or "")
        line = f.get("line")
        rule = str(f.get("rule_id") or f.get("category") or f.get("rule") or "")
        table = infer_table(f)
        key = f"{repo}|{file_}|{rule}|{table}"  # 같은 파일 내 여러 테이블 구분
        if key in existing_keys:
            continue
        existing_keys.add(key)
        loc = f"{file_}:{line}" if file_ and line is not None else file_
        stage = infer_stage(file_)
        # 저장위치 = DB 테이블(추출되면) / 아니면 파일 위치. repo 이름은 넣지 않는다(사용자 요청).
        store_loc = (f"{table} 테이블" if table else "") if stage in (None, "저장") else ""
        store_tbl = (f"{table} ({loc})" if table else loc) if stage in (None, "저장") else ""
        out.append({
            "item": infer_item(f),
            "subject": "",
            # 추정 단계에 코드 위치를 넣는다 — 수집 지점도 채워지도록.
            "collection_source": loc if stage == "수집" else "",
            "storage_location": store_loc,
            "storage_table": store_tbl,
            "purpose": loc if stage == "이용" else "",
            "retention": "",
            "destruction": loc if stage == "파기" else "",
            "third_party": "",
            "overseas": "",
            "note": f"[PII 스캔 시드] {rule} · {loc} · 추정단계 {stage or '저장'}".strip(),
            "source": "pii_scan",
            "stage": stage or "저장",
            "repo": repo or "",
            "file": file_,
            "rule": rule,
            "table": table,
        })
    return out


# 항상 포함되는 리터럴 값 룰(한국형) — 실제 PII 값 하드코딩 탐지.
_LITERAL_RULES = (
    ("korean-pii-rrn", "WARNING", "주민등록번호로 보이는 값이 하드코딩됨 (개인정보)",
     r"\b\d{6}[-\s]?[1-4]\d{6}\b"),
    ("korean-pii-phone", "INFO", "휴대폰번호로 보이는 값이 하드코딩됨 (개인정보)",
     r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b"),
    ("korean-pii-card", "WARNING", "카드번호로 보이는 값이 하드코딩됨 (개인정보)",
     r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b"),
)

# DB 테이블/모델 블록 안의 PII — 스니펫에 'model X {'·'CREATE TABLE X' 를 담아
# MORI 가 저장 테이블명을 뽑도록. (저장 단계 행의 '저장위치=테이블' 근거)
_PII_FIELD_ALT = r"(email|phone|mobile|tel|gender|birth|dob|resident|rrn|ssn|jumin|card|account|passport|address|이메일|휴대폰|전화|성별|생년월일|주민|카드|계좌|여권|주소|배송지)"
_TABLE_RULES = (
    ("pii-prisma-model", "INFO", "Prisma 모델(DB 테이블)에 개인정보 필드",
     r"(?is)model\s+[A-Za-z_]\w*\s*\{[^}]*?\b" + _PII_FIELD_ALT + r"\b[^}]*?\}"),
    ("pii-sql-table", "INFO", "SQL 테이블 정의에 개인정보 컬럼",
     r"(?is)create\s+table[^;(]*\([^;]*?\b" + _PII_FIELD_ALT + r"\b[^;]*?\)"),
)


def build_pii_semgrep_rules(custom_terms: list[dict[str, str]] | None = None) -> str:
    """스캔용 Semgrep 룰(YAML) — 리터럴 값 + PII 필드명 기본셋 + 어드민 커스텀 기준.

    custom_terms: [{"term": "배송지|shippingAddr", "item": "주소"}, ...] (term=정규식, item=라벨).
    필드/커스텀 룰의 message 에 항목 라벨을 넣어 MORI 가 infer_item 으로 항목을 잡는다.
    """
    def _q(rx: str) -> str:
        # YAML single-quoted scalar — 내부 홑따옴표만 이스케이프.
        return "'" + str(rx).replace("'", "''") + "'"

    lines = ["rules:"]
    for rid, sev, msg, rx in (*_LITERAL_RULES, *_TABLE_RULES):
        lines += [f"  - id: {rid}", "    languages: [generic]", f"    severity: {sev}",
                  f'    message: "{msg}"', "    patterns:", f"      - pattern-regex: {_q(rx)}"]
    for i, (rx, item) in enumerate(DEFAULT_PII_FIELDS):
        lines += [f"  - id: pii-field-{i}", "    languages: [generic]", "    severity: INFO",
                  f'    message: "{item}(개인정보) 항목이 코드에 사용됨"', "    patterns:",
                  f"      - pattern-regex: {_q(rx)}"]
    for i, ct in enumerate(custom_terms or []):
        term = str((ct or {}).get("term") or "").strip()
        item = str((ct or {}).get("item") or "개인정보").strip() or "개인정보"
        if not term:
            continue
        lines += [f"  - id: pii-custom-{i}", "    languages: [generic]", "    severity: INFO",
                  f'    message: "{item}(개인정보·어드민 기준) 항목이 코드에 사용됨"', "    patterns:",
                  f"      - pattern-regex: {_q(term)}"]
    return "\n".join(lines) + "\n"


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
        from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("reportlab not installed; PDF output unavailable") from exc
    import io

    from mori_soc.services.reports import _get_pdf_font

    BLACK, WHITE, NEUTRAL = colors.HexColor("#111827"), colors.white, colors.HexColor("#e5e7eb")
    BLUE, GREEN, YELLOW, RED = (colors.HexColor("#2563eb"), colors.HexColor("#16a34a"),
                               colors.HexColor("#ca8a04"), colors.HexColor("#dc2626"))
    STAGE_COLOR = {"수집": BLUE, "저장": GREEN, "이용": YELLOW, "파기": RED}

    font = _get_pdf_font()
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("pdf_h1", parent=styles["Title"], fontName=font, fontSize=15, leading=19,
                        spaceAfter=2, textColor=BLACK)
    meta = ParagraphStyle("pdf_meta", parent=styles["Normal"], fontName=font, fontSize=8.5, leading=12, textColor=BLACK)
    h2 = ParagraphStyle("pdf_h2", parent=styles["Heading2"], fontName=font, fontSize=11, leading=14,
                        spaceBefore=10, spaceAfter=4, textColor=BLACK)
    body = ParagraphStyle("pdf_body", parent=styles["Normal"], fontName=font, fontSize=9, leading=13, textColor=BLACK)
    cell = ParagraphStyle("pdf_cell", parent=styles["Normal"], fontName=font, fontSize=8, leading=10.5, textColor=BLACK)
    hcell = ParagraphStyle("pdf_hcell", parent=cell, textColor=WHITE)  # 헤더는 흰 글자(검 배경 위)

    def esc(s: Any) -> str:
        return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def val(s: Any) -> str:
        return esc(s) if str(s or "").strip() else "—"

    # ── 수집→저장→이용→파기 흐름도(그림) — 팔레트 테두리 박스 + 화살표 ──────────────
    def _flow_drawing(width: float) -> "Drawing":
        h, bw, bh, gap = 46, 90, 30, 26
        d = Drawing(width, h)
        n = len(STAGES)
        total = n * bw + (n - 1) * gap
        x0 = (width - total) / 2
        for i, st in enumerate(STAGES):
            x = x0 + i * (bw + gap)
            col = STAGE_COLOR[st]
            d.add(Rect(x, 8, bw, bh, rx=6, ry=6, strokeColor=col, strokeWidth=1.3, fillColor=WHITE))
            d.add(String(x + bw / 2, 18, st, fontName=font, fontSize=12, fillColor=col, textAnchor="middle"))
            if i < n - 1:
                ax = x + bw
                d.add(Line(ax, 23, ax + gap - 4, 23, strokeColor=BLACK, strokeWidth=1.2))
                d.add(Polygon([ax + gap - 4, 23, ax + gap - 10, 20, ax + gap - 10, 26], fillColor=BLACK, strokeColor=BLACK))
        return d

    # ── 상세 표(헤더 흰 글자) ──────────────────────────────────────────────────
    headers = ["개인정보 항목", "정보주체", "수집경로", "저장위치", "테이블·컬럼(코드위치)",
               "이용목적", "보관·파기", "제3자·국외"]
    data = [[Paragraph(f"<b>{esc(h)}</b>", hcell) for h in headers]]
    for r in rows:
        keep = f"보관: {val(r.get('retention'))} / 파기: {val(r.get('destruction'))}"
        share = f"제3자: {esc(r.get('third_party') or '없음')} / 국외: {esc(r.get('overseas') or '없음')}"
        data.append([Paragraph(v, cell) for v in (
            val(r.get("item")), val(r.get("subject")), val(r.get("collection_source")),
            val(r.get("storage_location")), val(r.get("storage_table")), val(r.get("purpose")), keep, share)])
    widths = [30 * mm, 20 * mm, 30 * mm, 30 * mm, 44 * mm, 34 * mm, 42 * mm, 40 * mm]
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), BLACK), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.4, NEUTRAL), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))

    # ── 요약 ───────────────────────────────────────────────────────────────────
    items = sorted({str(r.get("item") or "").strip() for r in rows if r.get("item")})
    stores = sorted({str(r.get("storage_location") or "").strip() for r in rows if r.get("storage_location")})
    n_third = sum(1 for r in rows if str(r.get("third_party") or "").strip() not in ("", "없음", "-", "n/a"))
    n_over = sum(1 for r in rows if str(r.get("overseas") or "").strip() not in ("", "없음", "-", "n/a"))
    n_seed = sum(1 for r in rows if r.get("source") == "pii_scan")

    buf = io.BytesIO()
    docp = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                             topMargin=13 * mm, bottomMargin=12 * mm, title="MORI 개인정보 처리흐름표")
    content_w = landscape(A4)[0] - 24 * mm
    story: list[Any] = [Paragraph("개인정보 처리흐름표 (ISMS-P 3.1 수집 · 3.2 이용/제공 · 3.4 파기)", h1)]
    sub = f"항목 {len(rows)}건" + (f" · 생성 {esc(generated_at)}" if generated_at else "") + " · MORI 코드 리뷰 파이프라인"
    story.append(Paragraph(sub, meta))
    story.append(Paragraph(
        "이 문서는 개인정보 항목이 <b>수집 → 저장 → 이용 → 파기</b> 각 단계에서 어떻게 처리·저장되는지 기록한 "
        "ISMS-P 개인정보 처리단계 필수 증적입니다. '테이블·컬럼(코드위치)' 열에 <b>src/…:라인</b> 형태로 표시된 항목은 "
        "코드 스캔(Semgrep, 고객 CI)에서 자동 발견된 개인정보 처리 지점이며, 저장위치·이용목적·보관/파기는 담당자가 확정합니다. "
        "MORI 는 코드를 저장하지 않고 스캔 결과만 받습니다.", body))
    story += [Spacer(1, 8), _flow_drawing(content_w), Spacer(1, 4)]
    story.append(Paragraph("요약", h2))
    story.append(Paragraph(
        f"· 개인정보 항목({len(items)}종): {esc(', '.join(items)) or '—'}<br/>"
        f"· 저장위치({len(stores)}곳): {esc(', '.join(stores)) or '—'}<br/>"
        f"· 제3자 제공: {n_third}건 · 국외 이전: {n_over}건 · 스캔 자동발견 행: {n_seed}건", body))
    story.append(Paragraph("처리흐름 상세", h2))
    story.append(table if rows else Paragraph("흐름표가 비어 있습니다 — 스캔에서 개인정보가 발견되지 않았거나 행이 미작성 상태입니다.", body))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "용어 · '—' 는 담당자 미작성(추가 확정 필요). 단계: 수집(3.1)=개인정보를 받는 지점 / 저장(3.2)=보관 위치(DB·테이블·파일) / "
        "이용(3.2)=사용 목적 / 파기(3.4)=보관기간 경과·목적 달성 후 삭제. '제3자·국외' 표시는 해당 항목의 외부 제공·국외 이전 여부.",
        ParagraphStyle("pdf_note", parent=cell, textColor=BLACK)))
    docp.build(story)
    return buf.getvalue()


__all__ = ["STAGES", "FLOW_FIELDS", "DEFAULT_PII_FIELDS", "is_pii_finding", "infer_item", "infer_stage",
           "seed_rows_from_findings", "build_pii_semgrep_rules", "render_data_flow_svg", "render_data_flow_pdf"]
