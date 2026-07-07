"""Compliance routes (Task J-4b8).

Registers the PDCA / crosscheck / evidence-report endpoints on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures; only the
unpacking preamble (binding shared stores + the ``get_query_service`` helper from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from mori_soc.services.reports import (
    REPORT_TYPES,
    build_risk_register_report,
    generate_report,
    report_to_csv,
    report_to_pdf,
)
from mori_soc.api.payloads import build_crosscheck_payload, build_pdca_payload
from mori_soc.api.routes.context import RouteContext


def register_compliance(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    vuln_actions = ctx.vuln_actions
    triage_store = ctx.triage_store
    sessions = ctx.sessions

    def _evidence_role(request: Request) -> str | None:
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return sess.get("role") if sess else None

    @app.get("/compliance/pdca", tags=["Compliance"])
    def compliance_pdca_summary() -> dict[str, Any]:
        """Compliance PDCA 대시보드 요약 데이터."""
        try:
            return build_pdca_payload(
                get_query_service(),
                vuln_actions=vuln_actions,
                alert_triage=triage_store,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"compliance pdca unavailable: {exc}") from exc

    @app.get("/dashboard/evidence-gaps", tags=["Compliance"])
    def dashboard_evidence_gaps(request: Request) -> dict[str, Any]:
        """'오늘의 작업 큐' — 증적으로 이어지지 않은 미조치 항목 카운트.

        MORI 의 '증적 층' 정체성을 대시보드에 노출한다. 위험성 평가와 동일하게
        admin·security 롤 전용(인프라·헬프데스크는 조치 현황만). PDCA 집계
        (build_pdca_payload)를 재사용하고, 예외 만료 임박은 vuln_actions 에서 계산.
        """
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="evidence gaps require admin or security role")
        try:
            pdca = build_pdca_payload(get_query_service(), vuln_actions=vuln_actions, alert_triage=triage_store)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"evidence gaps unavailable: {exc}") from exc

        now = datetime.now(tz=timezone.utc)
        soon = now + timedelta(days=7)
        expiring = 0
        for action in vuln_actions.values():
            raw = str(action.get("exception_until", "")).strip()
            if not raw:
                continue
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if now <= dt <= soon:
                expiring += 1

        # 자산 대사(reconciliation): 어떤 소스에서도 관측 안 된 자산 = 관리 이탈/미매핑.
        # Fleet 자산 식별(1.2.1)·자산 현행화(2.1.3) 증적의 핵심 공백 신호.
        unmapped = 0
        try:
            cross = build_crosscheck_payload(get_query_service())
            for chk in cross.get("checks", []) or []:
                if chk.get("id") == "source_coverage":
                    unmapped = int(chk.get("uncovered_hosts", 0) or 0)
                    break
        except Exception:
            unmapped = 0

        src = pdca.get("pending_sources", {}) or {}
        gaps = {
            "vuln_pending": int(src.get("trivy", 0) or 0),
            "exceptions_expiring": expiring,
            "untriaged_alerts": int(src.get("alert", 0) or 0),
            "overdue": int(pdca.get("overdue_count", 0) or 0),
            "control_pending": int(src.get("control_check", 0) or 0),
            "unmapped_assets": unmapped,
        }
        return {"generated_at": pdca.get("generated_at"), "gaps": gaps,
                "total": gaps["vuln_pending"] + gaps["untriaged_alerts"] + gaps["control_pending"] + unmapped}

    @app.get("/compliance/pdca/pending.csv", tags=["Compliance"])
    def compliance_pdca_pending_csv() -> Any:
        """미조치 / 기한 초과 항목(PDCA Do 단계)을 CSV로 다운로드."""
        try:
            payload = build_pdca_payload(
                get_query_service(),
                vuln_actions=vuln_actions,
                alert_triage=triage_store,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"compliance pdca unavailable: {exc}") from exc
        import io, csv as csv_mod
        buf = io.StringIO()
        header_map = {
            "source": "출처",
            "control_id": "통제ID",
            "entity_type": "대상유형",
            "entity_id": "대상",
            "status": "상태",
            "owner": "담당자",
            "checked_at": "점검일시",
            "remediation_due_at": "조치기한",
            "overdue": "기한초과",
            "note": "비고",
        }
        fieldnames = list(header_map.keys())
        writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writerow(header_map)
        for item in payload.get("pending_remediations", []):
            row = {k: item.get(k, "") for k in fieldnames}
            row["overdue"] = "Y" if item.get("overdue") else "N"
            writer.writerow(row)
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="mori-pdca-pending-{timestamp}.csv"'},
        )

    @app.get("/compliance/crosscheck", tags=["Compliance"])
    def compliance_crosscheck() -> dict[str, Any]:
        """소스 간 교차 검증 데이터."""
        try:
            return build_crosscheck_payload(get_query_service())
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"crosscheck unavailable: {exc}") from exc

    # ── Compliance Reports (증적 Export) ────────────────────────────────────
    @app.get("/compliance/reports", tags=["Compliance"])
    def compliance_reports_list() -> dict[str, Any]:
        """사용 가능한 증적 리포트 타입 목록."""
        labels = {
            "asset_inspection": "자산 점검 리포트",
            "account_privilege": "계정/권한 점검 리포트",
            "log_collection_status": "로그 수집 상태 리포트",
            "vulnerability_assessment": "취약점 점검 리포트",
            "risk_register": "위험성 평가 대장",
            "monthly_operations": "월간 운영 리포트",
        }
        return {
            "report_types": [
                {
                    "id": rt,
                    "label": labels.get(rt, rt),
                    "url_json": f"/compliance/reports/{rt}",
                    "url_csv": f"/compliance/reports/{rt}?format=csv",
                    "url_pdf": f"/compliance/reports/{rt}?format=pdf",
                }
                for rt in REPORT_TYPES
            ]
        }

    @app.get("/compliance/reports/{report_type}", tags=["Compliance"])
    def compliance_report_get(report_type: str, format: str = "json") -> Any:
        """증적 리포트 생성. format=json|csv|pdf"""
        if report_type not in REPORT_TYPES:
            raise HTTPException(status_code=400, detail=f"Unknown report type: {report_type}. Valid: {', '.join(REPORT_TYPES)}")
        try:
            if report_type == "risk_register":
                # 위험 대장은 store 밖 risk_register + asset_owners 를 함께 사용
                report = build_risk_register_report(
                    get_query_service(), ctx.risk_register, ctx.asset_owners,
                )
            else:
                report = generate_report(report_type, get_query_service())
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"report generation failed: {exc}") from exc
        if format == "csv":
            csv_content = "\ufeff" + report_to_csv(report)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"mori-{report_type.replace('_', '-')}-{timestamp}.csv"
            return StreamingResponse(
                iter([csv_content]),
                media_type="text/csv; charset=utf-8-sig",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        if format == "pdf":
            try:
                pdf_bytes = report_to_pdf(report)
            except RuntimeError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"PDF rendering failed: {exc}") from exc
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"mori-{report_type.replace('_', '-')}-{timestamp}.pdf"
            return StreamingResponse(
                iter([pdf_bytes]),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        return report


__all__ = ["register_compliance"]
