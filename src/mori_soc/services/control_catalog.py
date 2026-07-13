"""통제 카탈로그(Phase 2) 로더 + 트리/커버리지 빌더 + DB 싱크.

정본은 ``controls/*.yaml``, 런타임은 패키지 내부 JSON 아티팩트
(``mori_soc/data/controls_catalog.json``, ``controls/_build_catalog_json.py`` 생성)를
stdlib json 으로 읽는다 — 이미지에 PyYAML 이 없어도 동작.

- :func:`load_catalog` — JSON 로드(캐시)
- :func:`build_tree` — framework→domain→section→controls 트리 + 커버리지(lite/full)
- :func:`sync_catalog_to_db` — schema/007 테이블로 upsert(기동 시 최선노력 호출)
"""
from __future__ import annotations

import io
import json
import pathlib
from datetime import datetime, timezone
from typing import Any

_DATA_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "controls_catalog.json"

# lite = MORI 코어 + Zabbix + Trivy / full = + Wazuh·Fleet·Loki (README 로드맵 기준)
_LITE_SOURCES = {"zabbix", "trivy", "mori"}
_FULL_SOURCES = {"zabbix", "trivy", "mori", "wazuh", "fleet", "loki"}

_cache: dict[str, Any] | None = None


def load_catalog() -> dict[str, Any]:
    """카탈로그 JSON 을 로드(프로세스 캐시). 파일이 없으면 빈 카탈로그."""
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _cache = {"meta": {}, "controls": [], "mappings": [], "defects": []}
    return _cache


# M2-8: 정본 카탈로그 편집 필드(오버레이 upsert 레코드가 base 통제를 덮어쓰는 키들).
_OVERLAY_FIELDS = (
    "framework", "version", "domain", "section", "title_ko", "title_en",
    "intent_ko", "intent_en", "evidence_hint_ko", "evidence_hint_en",
    "evidence_sources", "tags", "status",
)


def merge_edits(catalog: dict[str, Any], edits: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    """base 카탈로그 위에 admin 편집/NLP 오버레이(``edits``)를 병합한 새 카탈로그.

    op='delete' 는 base 통제를 숨기고, op='upsert' 는 기존 통제를 덮어쓰거나 새 통제를
    추가한다. base(``controls/*.yaml``)는 건드리지 않아 재싱크에도 오버레이가 유지된다.
    """
    if not edits:
        return catalog
    base = list(catalog.get("controls", []))
    by_id = {c.get("id"): c for c in base}
    deleted: set[str] = set()
    for cid, e in edits.items():
        if not cid:
            continue
        if e.get("op") == "delete":
            deleted.add(cid)
            continue
        merged = dict(by_id.get(cid, {}))
        merged["id"] = cid
        for f in _OVERLAY_FIELDS:
            if f in e and e.get(f) not in (None, ""):
                merged[f] = e.get(f)
        merged.setdefault("framework", "custom")
        merged["_origin"] = e.get("origin", "manual")
        merged["_edited"] = True
        by_id[cid] = merged
    controls = [c for cid, c in by_id.items() if cid not in deleted]
    return {**catalog, "controls": controls}


def _coverage(controls: list[dict], sources: set[str]) -> dict[str, Any]:
    total = len(controls)
    covered = sum(1 for c in controls if set(c.get("evidence_sources") or []) & sources)
    pct = round(covered / total * 100, 1) if total else 0.0
    return {"total": total, "covered": covered, "pct": pct}


# 통제 성숙도(#46) — 194개를 수기 라벨링하지 않고 기존 신호에서 도출한다.
# 오름차순: draft(미검토) < reviewed(검토됨) < mapped(교차프레임워크 매핑) < auto_evidence(MORI 자동증적).
_MATURITY_ORDER = ("draft", "reviewed", "mapped", "auto_evidence")


def mapped_control_ids(catalog: dict[str, Any]) -> set[str]:
    """cross-framework 매핑에 등장하는 통제 id 집합(isms_p + iso27001)."""
    ids: set[str] = set()
    for m in catalog.get("mappings", []) or []:
        if m.get("isms_p"):
            ids.add(str(m["isms_p"]))
        for x in m.get("iso27001", []) or []:
            ids.add(str(x))
    return ids


def control_maturity_level(control: dict[str, Any], mapped_ids: set[str], auto_ids: set[str]) -> str:
    """한 통제의 성숙도 레벨을 '달성한 최고 신호'로 도출.

    auto_evidence(MORI 자동증적 대상)는 검토 상태와 무관하게 최상위 — 실제로 증적이
    자동 수집되는 상태가 가장 성숙하기 때문. 그 아래로 mapped > reviewed > draft.
    """
    cid = str(control.get("id"))
    if cid in auto_ids:
        return "auto_evidence"
    if str(control.get("status")) != "reviewed":
        return "draft"
    if cid in mapped_ids:
        return "mapped"
    return "reviewed"


def maturity_summary(auto_ids: set[str] | None = None,
                     catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    """레벨별 통제 수 + 각 통제의 레벨. auto_ids = MORI 자동증적 통제 id 집합."""
    cat = catalog or load_catalog()
    mapped = mapped_control_ids(cat)
    auto = set(auto_ids or ())
    controls = cat.get("controls", []) or []
    per: list[dict[str, str]] = []
    counts = dict.fromkeys(_MATURITY_ORDER, 0)
    for c in controls:
        lvl = control_maturity_level(c, mapped, auto)
        counts[lvl] += 1
        per.append({"id": str(c.get("id")), "maturity": lvl})
    return {"order": list(_MATURITY_ORDER), "levels": counts,
            "total": len(controls), "controls": per}


def build_tree(catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    """UI용 트리 + 커버리지 요약을 만든다."""
    cat = catalog or load_catalog()
    controls = cat.get("controls", [])

    frameworks: dict[str, dict[str, Any]] = {}
    for c in controls:
        fw = c.get("framework", "?")
        dom = c.get("domain", "") or "(기타)"
        sec = c.get("section", "") or dom
        fnode = frameworks.setdefault(fw, {"framework": fw, "domains": {}})
        dnode = fnode["domains"].setdefault(dom, {"domain": dom, "sections": {}})
        snode = dnode["sections"].setdefault(sec, {"section": sec, "controls": []})
        snode["controls"].append({
            "id": c.get("id"),
            "title_ko": c.get("title_ko", ""),
            "title_en": c.get("title_en", ""),
            "evidence_sources": c.get("evidence_sources") or [],
            "status": c.get("status", "draft"),
            "mapped": bool(c.get("evidence_sources")),
        })

    # dict → 정렬된 list
    def _sort_key(cid: str):
        parts = []
        for p in str(cid).replace("A.", "").split("."):
            parts.append(int(p) if p.isdigit() else p)
        return parts

    # 알려진 프레임워크 먼저, 그 외(custom·법령 임포트 등)는 뒤에 알파벳순으로.
    known = ("isms-p", "iso27001")
    ordered = [fw for fw in known if fw in frameworks] + sorted(
        fw for fw in frameworks if fw not in known)
    tree = []
    for fw in ordered:
        fnode = frameworks[fw]
        domains = []
        for dnode in fnode["domains"].values():
            sections = []
            for snode in dnode["sections"].values():
                snode["controls"].sort(key=lambda x: _sort_key(x["id"]))
                sections.append(snode)
            domains.append({"domain": dnode["domain"], "sections": sections})
        tree.append({"framework": fw, "domains": domains})

    # 카탈로그 검토 진척도(정직성): reviewed vs draft. 커버리지 %는 reviewed+증적 연결
    # 통제만 집계되지만, 전체 194 중 몇 %가 실제 검토됐는지를 별도로 노출한다.
    total = len(controls)
    reviewed = sum(1 for c in controls if str(c.get("status", "draft")) == "reviewed")
    return {
        "meta": cat.get("meta", {}),
        "coverage": {
            "lite": _coverage(controls, _LITE_SOURCES),
            "full": _coverage(controls, _FULL_SOURCES),
            "review": {
                "reviewed": reviewed,
                "draft": total - reviewed,
                "total": total,
                "pct": round(reviewed / total * 100, 1) if total else 0.0,
            },
        },
        "tree": tree,
    }


# 증적 소스 → UI 라벨/딥링크 탭
_SOURCE_META: dict[str, dict[str, str]] = {
    "trivy": {"ko": "Trivy 취약점", "en": "Trivy vulnerabilities", "tab": "compliance"},
    "zabbix": {"ko": "Zabbix 경보·자산", "en": "Zabbix alerts & assets", "tab": "triage"},
    "wazuh": {"ko": "Wazuh 탐지", "en": "Wazuh detections", "tab": "triage"},
    "fleet": {"ko": "Fleet 자산", "en": "Fleet assets", "tab": "assets"},
    "loki": {"ko": "Loki 로그", "en": "Loki logs", "tab": "assets"},
    "mori": {"ko": "MORI 운영 기록", "en": "MORI operational records", "tab": "incidents"},
}


def build_control_detail(control_id: str, gaps: dict[str, Any] | None = None,
                         metrics: dict[str, Any] | None = None,
                         catalog: dict[str, Any] | None = None,
                         evidence_records: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    """한 통제의 증적 상세 — 통제 + 크로스매핑 + 관련 결함 + **라이브 실증적** + **수기 증적**.

    evidence mapper: 통제를 그 증적 소스·매핑·심사 결함으로 연결하고, ``metrics``
    (소스별 실데이터 집계)를 붙여 "매핑됨"을 넘어 "지금 이만큼의 실증적이 있다"를
    보여준다. 결함의 ``mori_signal`` 은 대시보드 evidence-gaps 카운트(gaps)와 이어붙인다.
    ``catalog`` 를 주면(오버레이 병합본) 그것을, 아니면 base 카탈로그를 쓴다.
    ``evidence_records`` 는 이 통제에 문서화된 수기 증적 목록.
    """
    cat = catalog or load_catalog()
    control = next((c for c in cat.get("controls", []) if c.get("id") == control_id), None)
    if control is None:
        return None

    metrics = metrics or {}
    evidence_live: list[dict[str, Any]] = []
    for s in control.get("evidence_sources") or []:
        meta = _SOURCE_META.get(s, {})
        m = metrics.get(s) or {}
        evidence_live.append({
            "source": s, "label_ko": meta.get("ko", s), "label_en": meta.get("en", s),
            "tab": meta.get("tab", ""),
            "summary_ko": m.get("summary_ko", ""), "summary_en": m.get("summary_en", ""),
            "count": m.get("count"),
            "breakdown": m.get("breakdown") or [], "more": m.get("more", 0),
        })

    mapped: list[dict[str, Any]] = []
    by_id = {c.get("id"): c for c in cat.get("controls", [])}
    for m in cat.get("mappings", []):
        peers: list[str] = []
        if m.get("isms_p") == control_id:
            peers = list(m.get("iso27001") or [])
        elif control_id in (m.get("iso27001") or []):
            peers = [m.get("isms_p")]
        for pid in peers:
            peer = by_id.get(pid, {})
            mapped.append({
                "id": pid, "title_ko": peer.get("title_ko", ""), "title_en": peer.get("title_en", ""),
                "relation": m.get("relation", "related"),
                "note_ko": m.get("note_ko", ""), "note_en": m.get("note_en", ""),
            })

    gap_map = (gaps or {})
    defects: list[dict[str, Any]] = []
    for d in cat.get("defects", []):
        if control_id in (d.get("controls") or []):
            sig = d.get("mori_signal", "")
            defects.append({**d, "gap_count": gap_map.get(sig) if sig else None})

    manual = sorted(evidence_records or [],
                    key=lambda r: str(r.get("collected_at") or r.get("created_at") or ""), reverse=True)
    return {"control": control, "mapped_to": mapped, "defects": defects,
            "evidence_live": evidence_live, "evidence_records": manual,
            "generated_at": datetime.now(tz=timezone.utc).isoformat()}


def control_evidence_pdf(control_id: str, gaps: dict[str, Any] | None = None,
                         metrics: dict[str, Any] | None = None,
                         catalog: dict[str, Any] | None = None,
                         evidence_records: list[dict[str, Any]] | None = None) -> bytes | None:
    """통제 증적 팩 PDF (reportlab). 통제 미존재 시 None."""
    detail = build_control_detail(control_id, gaps=gaps, metrics=metrics,
                                  catalog=catalog, evidence_records=evidence_records)
    if detail is None:
        return None
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("reportlab not installed; PDF output unavailable") from exc
    from mori_soc.services.reports import _get_pdf_font

    c = detail["control"]
    font = _get_pdf_font()
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontName=font, fontSize=16, leading=20, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName=font, fontSize=12, leading=16, spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=font, fontSize=9.5, leading=14)
    small = ParagraphStyle("small", parent=styles["Normal"], fontName=font, fontSize=8, leading=11, textColor=colors.grey)

    def esc(s: Any) -> str:
        return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=14 * mm, title=f"MORI Evidence Pack {c.get('id')}")
    story: list[Any] = []
    fw = "ISMS-P 2023" if c.get("framework") == "isms-p" else "ISO 27001:2022"
    story.append(Paragraph(f"[{esc(c.get('id'))}] {esc(c.get('title_ko'))}", h1))
    story.append(Paragraph(f"{esc(c.get('title_en'))} · {fw}", small))
    meta = " · ".join(x for x in [esc(c.get("domain")), esc(c.get("section")), f"status: {esc(c.get('status'))}"] if x)
    story.append(Paragraph(meta, small))

    if c.get("intent_ko") or c.get("intent_en"):
        story.append(Paragraph("취지 / Intent", h2))
        if c.get("intent_ko"):
            story.append(Paragraph(esc(c.get("intent_ko")), body))
        if c.get("intent_en"):
            story.append(Paragraph(esc(c.get("intent_en")), small))

    story.append(Paragraph("증적 소스 / Evidence sources", h2))
    srcs = ", ".join(c.get("evidence_sources") or []) or "— (미연결 / not wired)"
    story.append(Paragraph(esc(srcs), body))
    if c.get("evidence_hint_ko"):
        story.append(Paragraph(esc(c.get("evidence_hint_ko")), body))
    if c.get("evidence_hint_en"):
        story.append(Paragraph(esc(c.get("evidence_hint_en")), small))

    if detail.get("evidence_live"):
        story.append(Paragraph("실증적 (현재) / Live evidence", h2))
        for e in detail["evidence_live"]:
            s = e.get("summary_ko") or "— (수집 데이터 없음)"
            story.append(Paragraph(f"• {esc(e.get('label_ko'))}: {esc(s)}", body))
            for row in (e.get("breakdown") or [])[:8]:
                story.append(Paragraph(f"&nbsp;&nbsp;&nbsp;&nbsp;- {esc(row.get('label'))}: {esc(row.get('value'))}", small))
            if e.get("more"):
                story.append(Paragraph(f"&nbsp;&nbsp;&nbsp;&nbsp;… +{esc(e.get('more'))}", small))

    if detail.get("evidence_records"):
        story.append(Paragraph("수기 증적 / Documented evidence", h2))
        for r in detail["evidence_records"]:
            head = " · ".join(x for x in [esc(r.get("title")), esc(r.get("collected_at")),
                                          esc(r.get("collected_by"))] if x)
            story.append(Paragraph(f"• {head}", body))
            if r.get("body"):
                story.append(Paragraph(esc(r.get("body")), small))
            if r.get("reference"):
                story.append(Paragraph(f"↳ {esc(r.get('reference'))}", small))

    if detail["mapped_to"]:
        story.append(Paragraph("크로스매핑 / Cross-mapping", h2))
        rows = [["ID", "Title", "Relation"]]
        for m in detail["mapped_to"]:
            rows.append([esc(m["id"]), esc(m.get("title_ko") or m.get("title_en")), esc(m["relation"])])
        t = Table(rows, colWidths=[30 * mm, 110 * mm, 30 * mm])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    if detail["defects"]:
        story.append(Paragraph("관련 심사 결함 / Related defects", h2))
        for d in detail["defects"]:
            gc = d.get("gap_count")
            gc_txt = f"  · 현재 증적 공백: {gc}건" if isinstance(gc, int) else ""
            story.append(Paragraph(f"• [{esc(d.get('severity'))}] {esc(d.get('title_ko'))}{esc(gc_txt)}", body))
            if d.get("fix_ko"):
                story.append(Paragraph(f"↳ 시정: {esc(d.get('fix_ko'))}", small))

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(f"생성 {esc(detail['generated_at'][:19])} · MORI SOC 통제 증적 팩 (draft catalog v1 — 공식 고시 대비 검증 필요)", small))
    doc.build(story)
    return buf.getvalue()


def control_evidence_csv(control_id: str, gaps: dict[str, Any] | None = None,
                         metrics: dict[str, Any] | None = None,
                         catalog: dict[str, Any] | None = None,
                         evidence_records: list[dict[str, Any]] | None = None) -> str | None:
    """통제 증적 팩 CSV(라이브 증적 + 수기 증적 합본). 통제 미존재 시 None."""
    detail = build_control_detail(control_id, gaps=gaps, metrics=metrics,
                                  catalog=catalog, evidence_records=evidence_records)
    if detail is None:
        return None
    import csv as csv_mod
    c = detail["control"]
    buf = io.StringIO()
    w = csv_mod.writer(buf)
    w.writerow(["control_id", "title_ko", "title_en", "framework", "kind", "label",
                "detail", "collected_by", "collected_at", "reference"])
    cid, tko, ten = c.get("id", ""), c.get("title_ko", ""), c.get("title_en", "")
    fw = c.get("framework", "")
    for e in detail.get("evidence_live", []):
        w.writerow([cid, tko, ten, fw, "live", e.get("label_ko") or e.get("source", ""),
                    e.get("summary_ko") or "", "", "", ""])
        for row in e.get("breakdown", []) or []:
            w.writerow([cid, tko, ten, fw, "live-detail", row.get("label", ""),
                        row.get("value", ""), "", "", ""])
    for r in detail.get("evidence_records", []):
        kind = "auto" if r.get("source") == "auto" else "manual"
        w.writerow([cid, tko, ten, fw, kind, r.get("title", ""), r.get("body", ""),
                    r.get("collected_by", ""), r.get("collected_at", ""), r.get("reference", "")])
    for m in detail.get("mapped_to", []):
        w.writerow([cid, tko, ten, fw, "mapping", m.get("id", ""),
                    m.get("title_ko") or m.get("title_en") or "", "", "", m.get("relation", "")])
    return buf.getvalue()


# ── 증적 문서 (evidence document) — 통제 팩이 아니라 '증적'만 예쁘게 ──────────────
# doc 구조: {control:{id,title_ko,title_en,framework,intent_ko}, status, generated_at,
#           collector, inventory:[{hostname,ip,status,source}], live:[{label,summary}],
#           records:[{collected_at,kind,title,collected_by,reference,body}]}

def evidence_document_csv(doc: dict[str, Any]) -> str:
    """증적 문서 CSV — 자산 인벤토리 표 + 문서화된 증적 표(엑셀에서 두 표로 읽힘)."""
    import csv as csv_mod
    c = doc.get("control", {})
    buf = io.StringIO()
    w = csv_mod.writer(buf)
    w.writerow(["# 통제", c.get("id", ""), c.get("title_ko", "")])
    w.writerow(["# 프레임워크", c.get("framework", ""), f"이행상태: {doc.get('status', '')}"])
    w.writerow(["# 생성", (doc.get("generated_at") or "")[:19], f"수집자: {doc.get('collector', '')}"])
    w.writerow([])
    w.writerow(["[자산 인벤토리]"])
    w.writerow(["호스트명", "IP", "상태", "소스"])
    for h in doc.get("inventory", []):
        w.writerow([h.get("hostname", ""), h.get("ip", ""), h.get("status", ""), h.get("source", "")])
    if not doc.get("inventory"):
        w.writerow(["(수집된 자산 없음)"])
    if doc.get("live"):
        w.writerow([])
        w.writerow(["[기타 실증적]"])
        w.writerow(["소스", "요약"])
        for e in doc["live"]:
            w.writerow([e.get("label", ""), e.get("summary", "")])
    w.writerow([])
    w.writerow(["[문서화된 증적]"])
    w.writerow(["일자", "유형", "제목", "수집자", "참조", "내용"])
    for r in doc.get("records", []):
        w.writerow([r.get("collected_at", ""), r.get("kind", ""), r.get("title", ""),
                    r.get("collected_by", ""), r.get("reference", ""), r.get("body", "")])
    if not doc.get("records"):
        w.writerow(["(문서화된 증적 없음)"])
    return buf.getvalue()


def evidence_document_pdf(doc: dict[str, Any]) -> bytes:
    """증적 문서 PDF — 자산 인벤토리·문서화 증적을 표로 깔끔하게. reportlab 필요."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("reportlab not installed; PDF output unavailable") from exc
    from mori_soc.services.reports import _get_pdf_font

    c = doc.get("control", {})
    font = _get_pdf_font()
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontName=font, fontSize=15, leading=19, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName=font, fontSize=11.5, leading=15, spaceBefore=12, spaceAfter=5)
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=font, fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=styles["Normal"], fontName=font, fontSize=8, leading=11, textColor=colors.grey)
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontName=font, fontSize=8.5, leading=11)

    def esc(s: Any) -> str:
        return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _table(headers: list[str], rows: list[list[Any]], widths: list[float]) -> Table:
        # 공유 헬퍼로 위임 — 팔레트(검정·중립) 통일, 중복 스타일 제거.
        from mori_soc.services.reports import pdf_table
        return pdf_table(headers, rows, widths, font=font)

    buf = io.BytesIO()
    docp = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                             topMargin=16 * mm, bottomMargin=14 * mm,
                             title=f"MORI Evidence {c.get('id')}")
    fw = "ISMS-P 2023" if c.get("framework") == "isms-p" else ("ISO 27001:2022" if c.get("framework") == "iso27001" else str(c.get("framework", "")))
    story: list[Any] = []
    story.append(Paragraph(f"증적 문서 · [{esc(c.get('id'))}] {esc(c.get('title_ko'))}", h1))
    sub = " · ".join(x for x in [esc(c.get("title_en")), fw] if x)
    story.append(Paragraph(sub, small))
    meta = " · ".join(x for x in [f"생성 {esc((doc.get('generated_at') or '')[:19])}",
             f"수집자 {esc(doc.get('collector'))}" if doc.get("collector") else "",
             f"이행상태 {esc(doc.get('status'))}"] if x)
    story.append(Paragraph(meta, small))
    if c.get("intent_ko"):
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(esc(c.get("intent_ko")), body))

    story.append(Paragraph("자산 인벤토리 (실증적)", h2))
    inv = doc.get("inventory", [])
    if inv:
        rows = [[h.get("hostname", ""), h.get("ip", ""), h.get("status", ""), h.get("source", "")] for h in inv]
        story.append(_table(["호스트명", "IP", "상태", "소스"], rows,
                            [70 * mm, 40 * mm, 30 * mm, 28 * mm]))
        story.append(Paragraph(f"총 {len(inv)}건 · 수집 시점 자동 현행화 자산", small))
    else:
        story.append(Paragraph("(수집된 자산 인벤토리 없음)", small))

    if doc.get("live"):
        story.append(Paragraph("기타 실증적", h2))
        for e in doc["live"]:
            story.append(Paragraph(f"• [{esc(e.get('label'))}] {esc(e.get('summary'))}", body))

    story.append(Paragraph("문서화된 증적", h2))
    recs = doc.get("records", [])
    if recs:
        rows = [[r.get("collected_at", ""), r.get("kind", ""), r.get("title", ""),
                 r.get("collected_by", ""), r.get("reference", "")] for r in recs]
        story.append(_table(["일자", "유형", "제목", "수집자", "참조"], rows,
                            [22 * mm, 16 * mm, 66 * mm, 24 * mm, 40 * mm]))
    else:
        story.append(Paragraph("(문서화된 증적 없음)", small))

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("MORI SOC 증적 문서 — 감사 대응 증적", small))
    docp.build(story)
    return buf.getvalue()


def sync_catalog_to_db(dsn: str) -> dict[str, int]:
    """카탈로그를 schema/007 테이블로 upsert. psycopg 필요. 반환: 반영 건수."""
    import psycopg
    from psycopg.types.json import Jsonb

    cat = load_catalog()
    controls = cat.get("controls", [])
    mappings = cat.get("mappings", [])
    defects = cat.get("defects", [])

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        for c in controls:
            cur.execute(
                """
                INSERT INTO controls (framework, id, version, domain, section, title_ko, title_en,
                    intent_ko, intent_en, evidence_hint_ko, evidence_hint_en, evidence_sources,
                    mori_intents, tags, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (framework, id) DO UPDATE SET
                    version=EXCLUDED.version, domain=EXCLUDED.domain, section=EXCLUDED.section,
                    title_ko=EXCLUDED.title_ko, title_en=EXCLUDED.title_en,
                    intent_ko=EXCLUDED.intent_ko, intent_en=EXCLUDED.intent_en,
                    evidence_hint_ko=EXCLUDED.evidence_hint_ko, evidence_hint_en=EXCLUDED.evidence_hint_en,
                    evidence_sources=EXCLUDED.evidence_sources, mori_intents=EXCLUDED.mori_intents,
                    tags=EXCLUDED.tags, status=EXCLUDED.status
                """,
                (c.get("framework", ""), c.get("id", ""), c.get("version", ""), c.get("domain", ""),
                 c.get("section", ""), c.get("title_ko", ""), c.get("title_en", ""),
                 c.get("intent_ko", ""), c.get("intent_en", ""), c.get("evidence_hint_ko", ""),
                 c.get("evidence_hint_en", ""), Jsonb(c.get("evidence_sources") or []),
                 Jsonb(c.get("mori_intents") or []), Jsonb(c.get("tags") or []), c.get("status", "draft")),
            )
        for m in mappings:
            for iso in m.get("iso27001", []) or []:
                cur.execute(
                    """
                    INSERT INTO control_mappings (isms_p_id, iso27001_id, relation, note_ko, note_en)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (isms_p_id, iso27001_id) DO UPDATE SET
                        relation=EXCLUDED.relation, note_ko=EXCLUDED.note_ko, note_en=EXCLUDED.note_en
                    """,
                    (m.get("isms_p", ""), iso, m.get("relation", "related"),
                     m.get("note_ko", ""), m.get("note_en", "")),
                )
        for d in defects:
            cur.execute(
                """
                INSERT INTO control_defects (id, controls, title_ko, title_en, symptom_ko, symptom_en,
                    evidence_gap_ko, evidence_gap_en, mori_signal, fix_ko, fix_en, severity)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO UPDATE SET
                    controls=EXCLUDED.controls, title_ko=EXCLUDED.title_ko, title_en=EXCLUDED.title_en,
                    symptom_ko=EXCLUDED.symptom_ko, symptom_en=EXCLUDED.symptom_en,
                    evidence_gap_ko=EXCLUDED.evidence_gap_ko, evidence_gap_en=EXCLUDED.evidence_gap_en,
                    mori_signal=EXCLUDED.mori_signal, fix_ko=EXCLUDED.fix_ko, fix_en=EXCLUDED.fix_en,
                    severity=EXCLUDED.severity
                """,
                (d.get("id", ""), Jsonb(d.get("controls") or []), d.get("title_ko", ""),
                 d.get("title_en", ""), d.get("symptom_ko", ""), d.get("symptom_en", ""),
                 d.get("evidence_gap_ko", ""), d.get("evidence_gap_en", ""), d.get("mori_signal", ""),
                 d.get("fix_ko", ""), d.get("fix_en", ""), d.get("severity", "")),
            )
    return {"controls": len(controls), "mappings": len(mappings), "defects": len(defects)}


__all__ = ["load_catalog", "merge_edits", "build_tree", "build_control_detail",
           "control_evidence_pdf", "control_evidence_csv",
           "evidence_document_pdf", "evidence_document_csv", "sync_catalog_to_db"]
