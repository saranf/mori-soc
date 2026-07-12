"""개인정보 처리흐름표/흐름도 라우트 — ISMS-P 3.x 개인정보 증적.

흐름표 CRUD + PII 스캔 시드 + 흐름도(SVG) + CSV + 3.x 통제 증적 승격.
개인정보는 민감하므로 모든 엔드포인트 admin·security 전용(역할 가시성 정책).
MORI 는 코드를 읽지 않는다 — 시드는 스캔 findings(고객 CI)에서만 온다.
"""
from __future__ import annotations

import csv as csv_mod
import hashlib
import io
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from mori_soc.api.routes.context import RouteContext
from mori_soc.services.data_flow import (
    FLOW_FIELDS,
    STAGES,
    render_data_flow_pdf,
    render_data_flow_svg,
    seed_rows_from_findings,
)

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

    # ── 목록 ─────────────────────────────────────────────────────────────────
    @app.get("/privacy/data-flow", tags=["Privacy"])
    def list_data_flow(request: Request) -> dict[str, Any]:
        _require_privacy_role(request)
        return {"rows": _sorted_rows(), "stages": list(STAGES), "fields": list(FLOW_FIELDS)}

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
        # 이미 있는 시드 키(repo|file|rule)로 중복 방지
        existing = {f"{r.get('repo','')}|{r.get('file','')}|{r.get('rule','')}"
                    for r in ctx.personal_data_flow.values() if r.get("source") == "pii_scan"}
        # repo 별로 나눠 시드(각 finding 의 _repo 사용)
        now = datetime.now(tz=timezone.utc).isoformat()
        added = 0
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            by_repo.setdefault(str(f.get("_repo") or want_repo or ""), []).append(f)
        for rp_repo, fs in by_repo.items():
            for row in seed_rows_from_findings(fs, repo=rp_repo, existing_keys=existing):
                row.update({"id": "pdf-" + uuid.uuid4().hex[:12], "created_at": now,
                            "created_by": _user(request), "updated_at": now})
                ctx.personal_data_flow[row["id"]] = row
                if ctx.persist_personal_data_flow:
                    ctx.persist_personal_data_flow(row["id"])
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

    # ── CSV(공통 openCsvPreview 용) ────────────────────────────────────────────
    @app.get("/privacy/data-flow.csv", tags=["Privacy"])
    def data_flow_csv(request: Request) -> StreamingResponse:
        _require_privacy_role(request)
        header_map = {
            "item": "개인정보 항목", "subject": "정보주체", "collection_source": "수집경로",
            "storage_location": "저장위치", "storage_table": "테이블/컬럼(또는 코드위치)",
            "purpose": "이용목적", "retention": "보관기간", "destruction": "파기",
            "third_party": "제3자제공", "overseas": "국외이전", "source": "출처", "note": "비고",
        }
        buf = io.StringIO()
        writer = csv_mod.DictWriter(buf, fieldnames=list(header_map.keys()), extrasaction="ignore")
        writer.writerow(header_map)
        writer.writerows(_sorted_rows())
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="mori-personal-data-flow-{ts}.csv"'},
        )

    # ── 흐름표 PDF(감사관 제출용) ──────────────────────────────────────────────
    @app.get("/privacy/data-flow.pdf", tags=["Privacy"])
    def data_flow_pdf(request: Request) -> Response:
        _require_privacy_role(request)
        try:
            pdf = render_data_flow_pdf(_sorted_rows(),
                                       generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"))
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
        promoted = 0
        for cid in PRIVACY_FLOW_CONTROL_IDS:
            ev_id = "pdf-ev-" + hashlib.sha1(f"privacy-flow|{cid}".encode("utf-8")).hexdigest()[:16]
            rec = {"id": ev_id, "control_id": cid, "title": title, "body": body,
                   "collected_by": "MORI 개인정보 흐름표", "collected_at": collected_at,
                   "reference": "/privacy/data-flow.svg", "source": "privacy_flow",
                   "created_at": now, "created_by": _user(request) or "privacy_flow"}
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
