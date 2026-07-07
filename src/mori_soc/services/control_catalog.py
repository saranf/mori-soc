"""통제 카탈로그(Phase 2) 로더 + 트리/커버리지 빌더 + DB 싱크.

정본은 ``controls/*.yaml``, 런타임은 패키지 내부 JSON 아티팩트
(``mori_soc/data/controls_catalog.json``, ``controls/_build_catalog_json.py`` 생성)를
stdlib json 으로 읽는다 — 이미지에 PyYAML 이 없어도 동작.

- :func:`load_catalog` — JSON 로드(캐시)
- :func:`build_tree` — framework→domain→section→controls 트리 + 커버리지(lite/full)
- :func:`sync_catalog_to_db` — schema/007 테이블로 upsert(기동 시 최선노력 호출)
"""
from __future__ import annotations

import json
import pathlib
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


def _coverage(controls: list[dict], sources: set[str]) -> dict[str, Any]:
    total = len(controls)
    covered = sum(1 for c in controls if set(c.get("evidence_sources") or []) & sources)
    pct = round(covered / total * 100, 1) if total else 0.0
    return {"total": total, "covered": covered, "pct": pct}


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

    tree = []
    for fw in ("isms-p", "iso27001"):
        if fw not in frameworks:
            continue
        fnode = frameworks[fw]
        domains = []
        for dnode in fnode["domains"].values():
            sections = []
            for snode in dnode["sections"].values():
                snode["controls"].sort(key=lambda x: _sort_key(x["id"]))
                sections.append(snode)
            domains.append({"domain": dnode["domain"], "sections": sections})
        tree.append({"framework": fw, "domains": domains})

    return {
        "meta": cat.get("meta", {}),
        "coverage": {
            "lite": _coverage(controls, _LITE_SOURCES),
            "full": _coverage(controls, _FULL_SOURCES),
        },
        "tree": tree,
    }


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


__all__ = ["load_catalog", "build_tree", "sync_catalog_to_db"]
