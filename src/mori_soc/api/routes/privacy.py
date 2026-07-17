"""개인정보 처리흐름표/흐름도 라우트 — ISMS-P 3.x 개인정보 증적.

흐름표 CRUD + PII 스캔 시드 + 흐름도(SVG) + CSV + 3.x 통제 증적 승격.
개인정보는 민감하므로 모든 엔드포인트 admin·security 전용(역할 가시성 정책).
MORI 는 코드를 읽지 않는다 — 시드는 스캔 findings(고객 CI)에서만 온다.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from mori_soc.api.routes.context import RouteContext
from mori_soc.services.csv_export import csv_streaming_response
from mori_soc.services.data_flow import (
    DEFAULT_PII_FIELDS,
    FLOW_FIELDS,
    STAGES,
    build_file_overview,
    build_isms3x_manifest,
    build_pii_semgrep_rules,
    build_processing_tasks,
    classify_external_recipients,
    compare_policy_to_flow,
    render_data_flow_overview_svg,
    render_data_flow_pdf,
    render_data_flow_svg,
    render_data_flow_swimlane_svg,
    seed_rows_from_findings,
)

_PII_TERMS_SETTING = "privacy_pii_terms"  # settings 에 JSON 으로 어드민 커스텀 기준 보관

# 흐름표가 증적을 대는 개인정보 통제(3.1 수집·3.2 이용/제공·3.4 파기).
PRIVACY_FLOW_CONTROL_IDS = ("3.1.1", "3.2.1", "3.4.1")


def register_privacy(ctx: RouteContext) -> None:
    app = ctx.app
    sessions = ctx.sessions
    get_query_service = ctx.get_query_service

    def _require_privacy_role(request: Request) -> str:
        if not ctx.auth_enabled:
            return "admin"
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        role = sess.get("role") if sess else None
        if role not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="개인정보 처리흐름은 admin·security 전용입니다.")
        return role

    def _sorted_rows() -> list[dict[str, Any]]:
        rows = list((ctx.personal_data_flow or {}).values())
        rows.sort(key=lambda r: (str(r.get("item") or "~"), str(r.get("created_at") or "")))
        return rows

    def _user(request: Request) -> str:
        return (ctx.get_session_username(request) if ctx.get_session_username else "") or ""

    def _custom_terms() -> list[dict[str, str]]:
        raw = (ctx.settings or {}).get(_PII_TERMS_SETTING, "")
        try:
            data = json.loads(raw) if raw else []
            return [{"term": str(t.get("term", "")), "item": str(t.get("item", ""))}
                    for t in data if isinstance(t, dict) and str(t.get("term", "")).strip()]
        except Exception:
            return []

    def _flow_meta() -> dict[str, Any]:
        raw = (ctx.settings or {}).get("privacy_flow_meta", "")
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    # ── 목록 ─────────────────────────────────────────────────────────────────
    @app.get("/privacy/data-flow", tags=["Privacy"])
    def list_data_flow(request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        rows = _sorted_rows()
        ai = any(r.get("source") == "ai_flow" for r in rows)
        return {"rows": rows, "stages": list(STAGES), "fields": list(FLOW_FIELDS),
                "meta": _flow_meta() if ai else {}}

    # ── 전체 리셋(읽기전용 증적 초기화 — 재스캔으로 재생성) ─────────────────────────
    @app.post("/privacy/data-flow/reset", tags=["Privacy"])
    def reset_data_flow(request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        ids = list(ctx.personal_data_flow.keys())
        for fid in ids:
            ctx.personal_data_flow.pop(fid, None)
            if ctx.delete_personal_data_flow:
                ctx.delete_personal_data_flow(fid)
        if ctx.log_action:
            ctx.log_action(_user(request), "PRIVACY_FLOW_RESET", f"{len(ids)} rows cleared")
        return {"ok": True, "cleared": len(ids)}

    def _flow_opts() -> dict[str, bool]:
        raw = (ctx.settings or {}).get("privacy_flow_opts", "")
        try:
            d = json.loads(raw) if raw else {}
        except Exception:
            d = {}
        return {"route_match": bool(d.get("route_match")), "orm_extra": bool(d.get("orm_extra"))}

    # ── 무료 개인정보 흐름 파서(스크립트) 서빙 — 워크플로가 fetch 해서 실행(파일 1개 유지) ──
    @app.get("/privacy/flow-scanner.py", tags=["Privacy"], response_class=Response)
    def flow_scanner_py() -> Response:
        from pathlib import Path as _Path
        content = ""
        for cand in (_Path(__file__).resolve().parents[4] / "scripts" / "privacy_flow_scan.py",
                     _Path.cwd() / "scripts" / "privacy_flow_scan.py"):
            try:
                content = cand.read_text(encoding="utf-8")
                break
            except OSError:
                continue
        # 어드민 옵트인 옵션을 스크립트에 주입(라우트 매칭·추가 ORM 파싱).
        opts = _flow_opts()
        content = re.sub(r"^_OPTS = \{.*\}  # MORI-INJECT-OPTS$",
                         f"_OPTS = {json.dumps(opts)}  # MORI-INJECT-OPTS",
                         content, count=1, flags=re.M)
        return Response(content=content, media_type="text/x-python; charset=utf-8")

    # ── 어드민 파서 옵션(옵트인 고급 분석) ────────────────────────────────────────
    @app.get("/privacy/flow-opts", tags=["Privacy"])
    def get_flow_opts(request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        return _flow_opts()

    @app.put("/privacy/flow-opts", tags=["Privacy"])
    def put_flow_opts(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        opts = {"route_match": bool(payload.get("route_match")), "orm_extra": bool(payload.get("orm_extra"))}
        ctx.settings["privacy_flow_opts"] = json.dumps(opts)
        if ctx.persist_setting:
            ctx.persist_setting("privacy_flow_opts", _user(request))
        return {"ok": True, **opts}

    # ── 스캔용 PII 룰(YAML) — 기본셋 + 어드민 커스텀 기준. 워크플로가 스캔 때 가져감 ──
    @app.get("/privacy/pii-rules.yml", tags=["Privacy"], response_class=Response)
    def pii_rules_yml() -> Response:
        """고객 CI Semgrep 이 --config 로 가져가는 룰. 민감정보 아님(공개 GET)."""
        return Response(content=build_pii_semgrep_rules(_custom_terms()),
                        media_type="text/yaml; charset=utf-8")

    # ── 어드민 PII 기준(기본 노출 + 커스텀 편집) ─────────────────────────────────
    @app.get("/privacy/pii-criteria", tags=["Privacy"])
    def get_pii_criteria(request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        return {"defaults": [{"pattern": rx, "item": item} for rx, item in DEFAULT_PII_FIELDS],
                "custom": _custom_terms()}

    @app.put("/privacy/pii-criteria", tags=["Privacy"])
    def put_pii_criteria(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        raw = payload.get("custom") or []
        terms = [{"term": str((t or {}).get("term", "")).strip(), "item": str((t or {}).get("item", "")).strip() or "개인정보"}
                 for t in raw if isinstance(t, dict) and str((t or {}).get("term", "")).strip()][:200]
        ctx.settings[_PII_TERMS_SETTING] = json.dumps(terms, ensure_ascii=False)
        if ctx.persist_setting:
            ctx.persist_setting(_PII_TERMS_SETTING, _user(request))
        if ctx.log_action:
            ctx.log_action(_user(request), "PRIVACY_PII_CRITERIA", f"{len(terms)} custom terms")
        return {"ok": True, "custom": terms}

    # ── 추가 ─────────────────────────────────────────────────────────────────
    @app.post("/privacy/data-flow", tags=["Privacy"])
    def add_data_flow(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        now = datetime.now(tz=timezone.utc).isoformat()
        rec: dict[str, Any] = {k: str(payload.get(k, "") or "").strip() for k in FLOW_FIELDS}
        if not rec.get("item"):
            raise HTTPException(status_code=400, detail="item(개인정보 항목)은 필수입니다.")
        rec.update({"id": "pdf-" + uuid.uuid4().hex[:12], "source": "manual",
                    "created_at": now, "created_by": _user(request), "updated_at": now})
        ctx.personal_data_flow[rec["id"]] = rec
        if ctx.persist_personal_data_flow:
            ctx.persist_personal_data_flow(rec["id"])
        if ctx.log_action:
            ctx.log_action(_user(request), "PRIVACY_FLOW_ADD", rec.get("item", ""))
        return rec

    # ── 수정 ─────────────────────────────────────────────────────────────────
    @app.put("/privacy/data-flow/{flow_id}", tags=["Privacy"])
    def update_data_flow(flow_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        rec = ctx.personal_data_flow.get(flow_id)
        if not rec:
            raise HTTPException(status_code=404, detail="흐름 행을 찾을 수 없습니다.")
        for k in FLOW_FIELDS:
            if k in payload:
                rec[k] = str(payload.get(k, "") or "").strip()
        rec["updated_at"] = datetime.now(tz=timezone.utc).isoformat()
        ctx.personal_data_flow[flow_id] = rec
        if ctx.persist_personal_data_flow:
            ctx.persist_personal_data_flow(flow_id)
        return rec

    # ── 담당자 확인(#9) — 흐름별 담당자 지정 + 사람 확정을 감사 증적으로 고정 ────────────────
    @app.post("/privacy/data-flow/{flow_id}/review", tags=["Privacy"])
    def review_data_flow(flow_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """흐름 행에 담당자를 지정하고 확정/재검토한다.

        action=confirm → review_status=confirmed·reviewed_by·reviewed_at 기록(사람 판단 증적).
        action=reopen  → 다시 pending(자동 후보)로. assignee만 바꾸려면 action 생략.
        """
        _require_privacy_role(request)
        rec = ctx.personal_data_flow.get(flow_id)
        if not rec:
            raise HTTPException(status_code=404, detail="흐름 행을 찾을 수 없습니다.")
        if "assignee" in payload:
            rec["assignee"] = str(payload.get("assignee", "") or "").strip()[:120]
        action = str(payload.get("action", "") or "").strip()
        now = datetime.now(tz=timezone.utc).isoformat()
        if action == "confirm":
            rec["review_status"] = "confirmed"
            rec["reviewed_by"] = _user(request)
            rec["reviewed_at"] = now
        elif action == "reopen":
            rec["review_status"] = "pending"
            rec["reviewed_by"] = ""
            rec["reviewed_at"] = ""
        rec["updated_at"] = now
        ctx.personal_data_flow[flow_id] = rec
        if ctx.persist_personal_data_flow:
            ctx.persist_personal_data_flow(flow_id)
        if ctx.log_action and action:
            ctx.log_action(_user(request), f"PRIVACY_FLOW_{action.upper()}",
                           f"{rec.get('item','')} → {rec.get('assignee','')}")
        return rec

    # ── 삭제 ─────────────────────────────────────────────────────────────────
    @app.delete("/privacy/data-flow/{flow_id}", tags=["Privacy"])
    def delete_data_flow(flow_id: str, request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        if flow_id not in ctx.personal_data_flow:
            raise HTTPException(status_code=404, detail="흐름 행을 찾을 수 없습니다.")
        ctx.personal_data_flow.pop(flow_id, None)
        if ctx.delete_personal_data_flow:
            ctx.delete_personal_data_flow(flow_id)
        return {"ok": True, "id": flow_id}

    # ── PII 스캔 시드 — code_review findings 중 개인정보/비밀정보를 후보 행으로 ──────
    @app.post("/privacy/data-flow/seed-from-scan", tags=["Privacy"])
    def seed_from_scan(request: Request, repo: str | None = None) -> dict[str, Any]:
        _require_privacy_role(request)
        if get_query_service is None:
            raise HTTPException(status_code=503, detail="query service unavailable")
        want_repo = (repo or "").strip()
        findings: list[dict[str, Any]] = []
        for a in get_query_service().store.alerts:
            if a.source != "code_review":
                continue
            rp = a.raw_payload or {}
            prov = rp.get("_provenance") or {}
            r_repo = str(prov.get("repo") or "")
            if want_repo and r_repo != want_repo:
                continue
            rp = dict(rp)
            rp.setdefault("_repo", r_repo)
            findings.append(rp)
        # ingest 자동시드와 동일한 결정적 id 로 upsert → 재분류 반영, 중복 없음.
        now = datetime.now(tz=timezone.utc).isoformat()
        added = 0
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            by_repo.setdefault(str(f.get("_repo") or want_repo or ""), []).append(f)
        for rp_repo, fs in by_repo.items():
            for row in seed_rows_from_findings(fs, repo=rp_repo):
                fid = "pdf-" + hashlib.sha1(
                    f"{rp_repo}|{row.get('file','')}|{row.get('line','')}|{row.get('item','')}|{row.get('table','')}".encode("utf-8")).hexdigest()[:12]
                row.update({"id": fid, "created_at": now, "created_by": _user(request), "updated_at": now})
                ctx.personal_data_flow[fid] = row
                if ctx.persist_personal_data_flow:
                    ctx.persist_personal_data_flow(fid)
                added += 1
        if ctx.log_action:
            ctx.log_action(_user(request), "PRIVACY_FLOW_SEED", f"{added} rows from scan")
        return {"ok": True, "seeded": added, "scanned_findings": len(findings)}

    # ── 흐름도(SVG) ────────────────────────────────────────────────────────────
    @app.get("/privacy/data-flow.svg", tags=["Privacy"])
    def data_flow_svg(request: Request) -> Response:
        _require_privacy_role(request)
        svg = render_data_flow_svg(_sorted_rows())
        return Response(content=svg, media_type="image/svg+xml")

    # ── 상세 흐름도(스윔레인, 출발점=정보주체) ──────────────────────────────────────
    @app.get("/privacy/data-flow-swimlane.svg", tags=["Privacy"])
    def data_flow_swimlane_svg(request: Request) -> Response:
        _require_privacy_role(request)
        svg = render_data_flow_swimlane_svg(_sorted_rows())
        return Response(content=svg, media_type="image/svg+xml")

    # ── 총괄 흐름도(생명주기×조직: 업무·정보주체·담당자·시스템DB·연계기관) — 레퍼런스 ① ──
    @app.get("/privacy/data-flow-overview.svg", tags=["Privacy"])
    def data_flow_overview_svg(request: Request) -> Response:
        _require_privacy_role(request)
        svg = render_data_flow_overview_svg(_sorted_rows())
        return Response(content=svg, media_type="image/svg+xml")

    # ── CSV(공통 openCsvPreview 용) ────────────────────────────────────────────
    @app.get("/privacy/data-flow.csv", tags=["Privacy"])
    def data_flow_csv(request: Request) -> StreamingResponse:
        _require_privacy_role(request)
        header_map = {
            "item": "개인정보 항목", "category": "구분", "subject": "정보주체", "collection_source": "수집경로",
            "storage_location": "저장위치", "storage_table": "테이블/컬럼(또는 코드위치)",
            "purpose": "이용목적", "retention": "보관기간", "destruction": "파기",
            "third_party": "제3자제공", "overseas": "국외이전", "source": "출처", "note": "비고",
        }
        return csv_streaming_response(_sorted_rows(), header_map, "mori-personal-data-flow")

    # ── 개인정보 파일 개요 CSV(레퍼런스 ③: 파일명·정보주체수·필수/선택·제3자·목적) ──────
    @app.get("/privacy/data-file-overview.csv", tags=["Privacy"])
    def data_file_overview_csv(request: Request) -> StreamingResponse:
        _require_privacy_role(request)
        header_map = {
            "file_name": "파일명(테이블/업무)", "subject_count": "정보주체 수",
            "required_items": "개인정보 항목(필수)", "optional_items": "개인정보 항목(선택)",
            "third_party": "제3자 제공", "purpose": "처리 목적",
        }
        return csv_streaming_response(build_file_overview(_sorted_rows()), header_map,
                                      "mori-personal-data-file-overview")

    # ── 개인정보 처리업무 자동 그룹화(#6) — 스캔 결과를 처리업무 단위 초안으로 ────────────
    @app.get("/privacy/processing-tasks", tags=["Privacy"])
    def list_processing_tasks(request: Request) -> dict[str, Any]:
        """흐름 행을 처리업무 단위로 자동 묶은 초안(모리다움 — 후보 제공, 담당자 확정)."""
        _require_privacy_role(request)
        return {"tasks": build_processing_tasks(_sorted_rows())}

    @app.get("/privacy/processing-tasks.csv", tags=["Privacy"])
    def processing_tasks_csv(request: Request) -> StreamingResponse:
        _require_privacy_role(request)
        header_map = {
            "task": "처리업무", "subjects": "정보주체", "items": "개인정보 항목",
            "system": "시스템/저장", "collect_code": "수집 근거(코드)",
            "dispose_code": "파기 근거(코드)", "purpose": "이용 목적",
            "controls": "관련 통제", "confirm_status": "확인 상태",
        }
        return csv_streaming_response(build_processing_tasks(_sorted_rows()), header_map,
                                      "mori-personal-data-processing-tasks")

    # ── 외부 수신자 구분(#7) — 위탁·제3자 제공·국외이전 후보(담당자 확인 필요) ──────────
    @app.get("/privacy/external-recipients", tags=["Privacy"])
    def list_external_recipients(request: Request) -> dict[str, Any]:
        """코드·설정상 외부 전송 후보를 위탁/제3자/국외이전으로 구분(법적 확정 아님)."""
        _require_privacy_role(request)
        return {"recipients": classify_external_recipients(_sorted_rows())}

    @app.get("/privacy/external-recipients.csv", tags=["Privacy"])
    def external_recipients_csv(request: Request) -> StreamingResponse:
        _require_privacy_role(request)
        header_map = {
            "recipient": "외부 수신자", "candidate_types": "후보 구분", "items": "개인정보 항목",
            "purpose": "목적", "overseas": "국외(리전/국가)", "basis": "근거", "confirm": "확인",
        }
        return csv_streaming_response(classify_external_recipients(_sorted_rows()), header_map,
                                      "mori-personal-data-external-recipients")

    # ── 처리방침 vs 코드 불일치 탐지(#8) — 문서 주장과 기술 현실 비교 ─────────────────────
    _POLICY_SETTING = "privacy_declared_policy"

    def _declared_policy() -> dict[str, Any]:
        raw = (ctx.settings or {}).get(_POLICY_SETTING, "")
        try:
            d = json.loads(raw) if raw else {}
        except Exception:
            d = {}
        return {"items": list(d.get("items") or []), "retention": str(d.get("retention") or "")}

    @app.get("/privacy/policy-compare", tags=["Privacy"])
    def get_policy_compare(request: Request) -> dict[str, Any]:
        """저장된 처리방침 주장과 현재 흐름표(코드·DB) 비교 결과."""
        _require_privacy_role(request)
        pol = _declared_policy()
        diff = compare_policy_to_flow(pol["items"], pol["retention"], _sorted_rows())
        return {"policy": pol, "diff": diff}

    @app.put("/privacy/policy-compare", tags=["Privacy"])
    def put_policy_compare(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """처리방침 주장(수집항목·보유기간)을 저장하고 즉시 비교. MORI는 문서를 관리하지 않는다."""
        _require_privacy_role(request)
        raw_items = payload.get("items") or []
        if isinstance(raw_items, str):
            raw_items = [s.strip() for s in re.split(r"[,\n·]", raw_items)]
        items = [str(i).strip() for i in raw_items if str(i).strip()][:500]
        retention = str(payload.get("retention", "") or "").strip()[:200]
        pol = {"items": items, "retention": retention}
        ctx.settings[_POLICY_SETTING] = json.dumps(pol, ensure_ascii=False)
        if ctx.persist_setting:
            ctx.persist_setting(_POLICY_SETTING, _user(request))
        if ctx.log_action:
            ctx.log_action(_user(request), "PRIVACY_POLICY_DECLARE", f"{len(items)} items")
        diff = compare_policy_to_flow(items, retention, _sorted_rows())
        return {"policy": pol, "diff": diff}

    # ── ISMS-P 3.x 증적 패키지(#10) — 개인정보 증적을 하나의 감사 패키지로 조립 ────────────
    @app.get("/privacy/isms-3x-package", tags=["Privacy"])
    def isms3x_package_manifest(request: Request) -> dict[str, Any]:
        """3.x 개인정보 증적 매니페스트(통제별 근거 유무·산출물 목록·검토/대조 요약)."""
        _require_privacy_role(request)
        now = datetime.now(tz=timezone.utc).isoformat()
        return build_isms3x_manifest(_sorted_rows(), _declared_policy(), generated_at=now)

    @app.get("/privacy/isms-3x-package.zip", tags=["Privacy"])
    def isms3x_package_zip(request: Request) -> Response:
        """3.x 증적을 ZIP(manifest.json + 흐름표·처리업무·외부수신자·파일개요 CSV + 흐름표 PDF)로."""
        import io
        import zipfile

        from mori_soc.services.csv_export import render_csv
        from mori_soc.services.data_flow import render_data_flow_pdf
        _require_privacy_role(request)
        rows = _sorted_rows()
        now = datetime.now(tz=timezone.utc).isoformat()
        manifest = build_isms3x_manifest(rows, _declared_policy(), generated_at=now)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            zf.writestr("data-flow.csv", render_csv(rows, {
                k: k for k in ("item", "subject", "collection_source", "storage_location",
                               "purpose", "retention", "destruction", "third_party", "overseas")}))
            zf.writestr("processing-tasks.csv", render_csv(build_processing_tasks(rows), {
                "task": "처리업무", "subjects": "정보주체", "items": "개인정보 항목",
                "system": "시스템/저장", "collect_code": "수집 근거", "dispose_code": "파기 근거",
                "purpose": "이용 목적", "controls": "관련 통제", "confirm_status": "확인 상태"}))
            zf.writestr("external-recipients.csv", render_csv(classify_external_recipients(rows), {
                "recipient": "외부 수신자", "candidate_types": "후보 구분", "items": "개인정보 항목",
                "purpose": "목적", "overseas": "국외", "confirm": "확인"}))
            zf.writestr("file-overview.csv", render_csv(build_file_overview(rows), {
                "file_name": "파일명", "subject_count": "정보주체 수", "required_items": "필수 항목",
                "optional_items": "선택 항목", "third_party": "제3자", "purpose": "목적"}))
            try:
                pdf = render_data_flow_pdf(rows, generated_at=now)
                if pdf:
                    zf.writestr("data-flow.pdf", pdf)
            except Exception:
                pass  # reportlab 미설치 등 — CSV·매니페스트만으로도 유효한 패키지.
        headers = {"Content-Disposition": 'attachment; filename="mori-isms-3x-evidence-package.zip"'}
        return Response(content=buf.getvalue(), media_type="application/zip", headers=headers)

    # ── DB 컬럼 ↔ 개인정보 항목 매칭 CSV(어느 컬럼에 어떤 정보) ─────────────────────────
    @app.get("/privacy/data-tables.csv", tags=["Privacy"])
    def data_tables_csv(request: Request) -> StreamingResponse:
        from mori_soc.services.data_flow import build_column_item_map
        _require_privacy_role(request)
        header_map = {"table": "DB 테이블", "column": "컬럼", "item": "개인정보 항목"}
        return csv_streaming_response(build_column_item_map(_sorted_rows()), header_map,
                                      "mori-personal-data-columns")

    # ── 흐름표 PDF(감사관 제출용) ──────────────────────────────────────────────
    @app.get("/privacy/data-flow.pdf", tags=["Privacy"])
    def data_flow_pdf(request: Request) -> Response:
        _require_privacy_role(request)
        meta = _flow_meta()
        try:
            pdf = render_data_flow_pdf(_sorted_rows(),
                                       generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"),
                                       gaps=meta.get("gaps") or [], summary=meta.get("summary") or {})
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return Response(content=pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="mori-personal-data-flow-{ts}.pdf"'})

    # ── 3.x 통제 증적 승격 ─────────────────────────────────────────────────────
    @app.post("/privacy/data-flow/promote-evidence", tags=["Privacy"])
    def promote_evidence(request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        rows = _sorted_rows()
        if not rows:
            raise HTTPException(status_code=400, detail="흐름표가 비어 있어 승격할 증적이 없습니다.")
        now = datetime.now(tz=timezone.utc).isoformat()
        collected_at = now[:10]
        items = [str(r.get("item") or "?") for r in rows]
        stores = sorted({str(r.get("storage_location") or "").strip() for r in rows if r.get("storage_location")})
        overseas = [r for r in rows if str(r.get("overseas") or "").strip() not in ("", "없음", "-", "n/a")]
        third = [r for r in rows if str(r.get("third_party") or "").strip() not in ("", "없음", "-", "n/a")]
        title = f"개인정보 처리흐름표 — 항목 {len(rows)}건 · 저장위치 {len(stores)}곳"
        body = (f"개인정보 항목: {', '.join(items[:12])}{' 외' if len(items) > 12 else ''}"
                f" · 저장위치: {', '.join(stores[:8]) or '미기재'}"
                f" · 제3자제공 {len(third)}건 · 국외이전 {len(overseas)}건"
                f" · 수집→저장→이용→파기 흐름도 첨부(/privacy/data-flow.svg)")
        from mori_soc.services.evidence import stamp_evidence
        promoted = 0
        for cid in PRIVACY_FLOW_CONTROL_IDS:
            ev_id = "pdf-ev-" + hashlib.sha1(f"privacy-flow|{cid}".encode("utf-8")).hexdigest()[:16]
            rec = {"id": ev_id, "control_id": cid, "title": title, "body": body,
                   "collected_by": "MORI 개인정보 흐름표", "collected_at": collected_at,
                   "reference": "/privacy/data-flow.svg", "source": "privacy_flow",
                   "source_event_id": ev_id,
                   "created_at": now, "created_by": _user(request) or "privacy_flow"}
            stamp_evidence(rec)   # content_hash·version·generated_at (#21)
            try:
                ctx.control_evidence[ev_id] = rec
                if ctx.persist_control_evidence:
                    ctx.persist_control_evidence(ev_id)
                promoted += 1
            except Exception:
                pass
        if ctx.log_action:
            ctx.log_action(_user(request), "PRIVACY_FLOW_PROMOTE", f"{promoted} controls")
        return {"ok": True, "evidence_promoted": promoted, "controls": list(PRIVACY_FLOW_CONTROL_IDS)}
