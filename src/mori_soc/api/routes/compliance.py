"""Compliance routes (Task J-4b8).

Registers the PDCA / crosscheck / evidence-report endpoints on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures; only the
unpacking preamble (binding shared stores + the ``get_query_service`` helper from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

import logging
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import StreamingResponse

from mori_soc.api.payloads import build_crosscheck_payload, build_pdca_payload
from mori_soc.api.routes.context import RouteContext
from mori_soc.services.reports import (
    REPORT_TYPES,
    build_risk_register_report,
    generate_report,
    report_to_csv,
    report_to_pdf,
)

logger = logging.getLogger("mori_soc.api.compliance")

# M2-7: 통제 이행 상태 허용값 (ISMS-P 자율점검 관점)
_CONTROL_STATUSES = {"미정", "이행", "부분이행", "미이행", "해당없음"}

# M2-8: 법령 NLP 임포트용 Claude API 키를 어드민이 저장하는 ui_settings 키.
# env(MORI_ANTHROPIC_API_KEY/ANTHROPIC_API_KEY) 가 있으면 그게 우선한다.
ANTHROPIC_KEY_SETTING = "anthropic_api_key"


def register_compliance(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    vuln_actions = ctx.vuln_actions
    asset_owners = ctx.asset_owners
    triage_store = ctx.triage_store
    sessions = ctx.sessions

    def _evidence_role(request: Request) -> str | None:
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return sess.get("role") if sess else None

    def _require_ev(request: Request) -> None:
        """admin·security 전용 자원 공통 게이트. 미충족 시 403."""
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="admin 또는 security 권한이 필요합니다.")

    def _persist_evidence(rec: dict[str, Any]) -> dict[str, Any]:
        """증적 레코드 저장 공통 보일러플레이트(메모리+영속) + provenance 스탬프(#21)."""
        from mori_soc.services.evidence import stamp_evidence
        stamp_evidence(rec)   # content_hash·version·generated_at
        ctx.control_evidence[rec["id"]] = rec
        if ctx.persist_control_evidence:
            ctx.persist_control_evidence(rec["id"])
        return rec

    def _require_catalog_admin(request: Request) -> str:
        """카탈로그 정본 편집(추가/수정/삭제·NLP 임포트)은 admin 전용."""
        if ctx.auth_enabled and _evidence_role(request) != "admin":
            raise HTTPException(status_code=403, detail="카탈로그 편집은 admin 전용입니다.")
        user = ""
        if ctx.get_session_username:
            user = ctx.get_session_username(request) or ""
        return user or "admin"

    def _merged_catalog() -> dict[str, Any]:
        """base 카탈로그 + admin/NLP 오버레이 병합본."""
        from mori_soc.services.control_catalog import load_catalog, merge_edits
        return merge_edits(load_catalog(), ctx.catalog_edits or {})

    def _evidence_for(control_id: str) -> list[dict[str, Any]]:
        return [r for r in (ctx.control_evidence or {}).values() if r.get("control_id") == control_id]

    def _evidence_document(control_id: str, user: str, host_lists: dict | None = None,
                           metrics: dict | None = None,
                           catalog: dict | None = None) -> dict[str, Any] | None:
        """다운로드용 '증적 문서' 구조 — 통제 팩이 아니라 증적(자산 인벤토리 + 문서화 증적)만.

        fleet/zabbix 는 실제 호스트 인벤토리 표로, 그 외 소스는 짧은 요약으로. 수기·자동 증적
        레코드는 일자·유형·제목·수집자·참조 표로. (매핑·결함은 증적이 아니라 제외)
        ``host_lists``/``metrics``/``catalog`` 를 주면 재계산 생략(ZIP 일괄 생성용).
        """
        cat = catalog or _merged_catalog()
        control = next((c for c in cat.get("controls", []) if c.get("id") == control_id), None)
        if control is None:
            return None
        srcs = control.get("evidence_sources") or []
        if host_lists is None:
            host_lists = _evidence_host_lists()
        inventory: list[dict[str, str]] = []
        for src in ("fleet", "zabbix"):
            if src in srcs:
                for r in host_lists.get(src, []):
                    inventory.append({"hostname": r.get("hostname", ""), "ip": r.get("ip", ""),
                                      "status": r.get("status", ""), "source": src})
        if metrics is None:
            metrics = _source_metrics(limit=200)
        live: list[dict[str, str]] = []
        for src in srcs:
            if src in ("fleet", "zabbix"):
                continue  # 이미 인벤토리 표로 나옴
            summ = (metrics.get(src) or {}).get("summary_ko") or ""
            if summ:
                live.append({"label": src, "summary": summ})
        records = []
        for r in sorted(_evidence_for(control_id),
                        key=lambda x: str(x.get("collected_at") or x.get("created_at") or ""), reverse=True):
            records.append({"collected_at": r.get("collected_at", ""),
                            "kind": "자동" if r.get("source") == "auto" else "수기",
                            "title": r.get("title", ""), "collected_by": r.get("collected_by", ""),
                            "reference": r.get("reference", ""), "body": r.get("body", "")})
        return {
            "control": {"id": control.get("id"), "title_ko": control.get("title_ko", ""),
                        "title_en": control.get("title_en", ""), "framework": control.get("framework", ""),
                        "intent_ko": control.get("intent_ko", "")},
            "status": ctx.control_status.get(control_id, {}).get("status") or "미정",
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "collector": user or "", "inventory": inventory, "live": live, "records": records,
        }

    def _control_status_default(control_id: str) -> dict[str, Any]:
        return {
            "control_id": control_id, "status": "미정", "owner": "",
            "exception_reason": "", "improvement_plan": "", "due_date": "",
            "updated_at": None, "updated_by": "",
        }

    def _parse_date(value: Any) -> "date | None":
        try:
            return date.fromisoformat(str(value)[:10])
        except (TypeError, ValueError):
            return None

    @app.get("/dashboard/host-remediation/{hostname}", tags=["Compliance"])
    def host_remediation(hostname: str) -> dict[str, Any]:
        """'내 담당 서버' 상세창용 — 한 호스트의 미조치 항목을 3버킷으로 분류.

        예외 만료 / 조치기한 초과 / 기타 위험. 심사관이 서버 더블클릭 → 조치현황을
        바로 볼 수 있도록 통제·분류 컬럼 대신 '지금 뭘 해야 하나'를 요약한다.
        활성 예외(만료 전)는 수용된 것으로 보고 미조치에서 제외한다.
        """
        store_ = get_query_service().store
        host = next((h for h in store_.hosts if h.hostname == hostname), None)
        if host is None:
            host = next((h for h in store_.hosts if h.host_id == hostname), None)
        if host is None:
            raise HTTPException(status_code=404, detail=f"host not found: {hostname}")
        today = datetime.now(tz=timezone.utc).date()
        owner = asset_owners.get(host.hostname, {}) or {}
        buckets: dict[str, list[dict[str, Any]]] = {
            "exception_expired": [], "overdue": [], "other": [],
        }
        for v in store_.vulnerabilities:
            if v.host_id != host.host_id or v.resolved_at is not None:
                continue
            if getattr(v, "severity", "info") not in ("critical", "high"):
                continue
            action = vuln_actions.get(v.vuln_id, {}) or {}
            exc_raw = str(action.get("exception_until", "") or owner.get("exception_until", "") or "")
            exc_until = _parse_date(exc_raw)
            plan_due = _parse_date(action.get("plan_target_date", ""))
            item = {
                "kind": "vuln", "id": v.vuln_id, "label": getattr(v, "cve", None) or v.vuln_id,
                "severity": getattr(v, "severity", "info"),
                "exception_until": exc_raw, "plan_target_date": str(action.get("plan_target_date", "") or ""),
            }
            if exc_until is not None and exc_until < today:
                buckets["exception_expired"].append(item)
            elif exc_until is not None and exc_until >= today:
                continue  # 활성 예외 → 수용됨, 미조치 아님
            elif plan_due is not None and plan_due < today:
                buckets["overdue"].append(item)
            else:
                buckets["other"].append(item)
        for a in store_.alerts:
            if a.host_id != host.host_id or a.resolved_at is not None:
                continue
            if getattr(a, "severity", "info") not in ("critical", "high"):
                continue
            buckets["other"].append({
                "kind": "alert", "id": a.alert_id,
                "label": getattr(a, "rule_name", None) or (a.message or "")[:60],
                "severity": getattr(a, "severity", "info"),
                "exception_until": "", "plan_target_date": "",
            })
        out = {k: {"count": len(v), "items": v[:20]} for k, v in buckets.items()}
        return {
            "hostname": host.hostname,
            "buckets": out,
            "total": sum(len(v) for v in buckets.values()),
        }

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
        _require_ev(request)
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
        access_uncovered = 0
        try:
            cross = build_crosscheck_payload(get_query_service())
            for chk in cross.get("checks", []) or []:
                if chk.get("id") == "source_coverage":
                    unmapped = int(chk.get("uncovered_hosts", 0) or 0)
                elif chk.get("id") == "access_record_coverage":
                    access_uncovered = int(chk.get("uncovered_hosts", 0) or 0)
        except Exception:
            unmapped = access_uncovered = 0

        src = pdca.get("pending_sources", {}) or {}
        gaps = {
            "vuln_pending": int(src.get("trivy", 0) or 0),
            "exceptions_expiring": expiring,
            "untriaged_alerts": int(src.get("alert", 0) or 0),
            "code_review_pending": int(src.get("code_review", 0) or 0),
            "overdue": int(pdca.get("overdue_count", 0) or 0),
            "control_pending": int(src.get("control_check", 0) or 0),
            "unmapped_assets": unmapped,
            "access_uncovered": access_uncovered,
        }
        return {"generated_at": pdca.get("generated_at"), "gaps": gaps,
                "total": gaps["vuln_pending"] + gaps["untriaged_alerts"] + gaps["code_review_pending"]
                + gaps["control_pending"] + unmapped + access_uncovered}

    @app.get("/controls/tree", tags=["Compliance"])
    def controls_tree(request: Request) -> dict[str, Any]:
        """통제 카탈로그(ISMS-P × ISO) 트리 + lite/full 커버리지. admin·security 전용.

        정본 controls/*.yaml → 패키지 JSON 아티팩트를 읽어 framework→domain→section→
        controls 트리와 증적 소스 커버리지(lite/full)를 반환한다(한/영 병기).
        """
        _require_ev(request)
        # 장기 무재기동 서버도 일정 스냅샷이 돌도록 열람 시 도래 여부 확인(최선노력).
        _maybe_run_scheduled_snapshot()
        from mori_soc.services.control_catalog import build_tree
        try:
            # M2-8: base + admin/NLP 오버레이 병합본으로 트리 구성.
            data = build_tree(_merged_catalog())
            # M2-7: 통제별 런타임 이행 상태(control_status)를 트리에 병기 → 화면에서 상태 뱃지/편집.
            data["status_map"] = {cid: dict(rec) for cid, rec in ctx.control_status.items()}
            data["can_edit"] = (not ctx.auth_enabled) or (_evidence_role(request) == "admin")
            return data
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"control catalog unavailable: {exc}") from exc

    def _control_evidence_state(control_id: str) -> tuple[bool, str]:
        """통제 증적 '집합'의 존재 여부 + aggregate content_hash. 증적이 하나라도 바뀌면 해시가 달라진다."""
        import hashlib as _h
        recs = [v for v in ctx.control_evidence.values() if str(v.get("control_id")) == control_id]
        if not recs:
            return False, ""
        parts = sorted(str(r.get("content_hash") or r.get("id") or "") for r in recs)
        return True, _h.sha1("|".join(parts).encode("utf-8")).hexdigest()

    def _current_approval_status(approvals: list[dict[str, Any]],
                                 current_hash: str = "") -> tuple[str, dict[str, Any] | None]:
        """현재 상태·현재 레코드. 증적 내용(content_hash)이 최신 승인본과 다르면 새 버전(draft)."""
        if not approvals:
            return "draft", None
        latest = approvals[0]  # created_at DESC
        # 증적 내용이 바뀌었으면 승인본은 그대로 두고 새 버전 검토 사이클을 시작한다.
        if current_hash and str(latest.get("content_hash") or "") != current_hash:
            return "draft", latest
        st = str(latest.get("status") or "draft")
        if st == "superseded":
            return "draft", latest
        return st, latest

    @app.get("/controls/evidence/{control_id}/approvals", tags=["Compliance"])
    def evidence_approvals_list(control_id: str, request: Request) -> dict[str, Any]:
        """통제 증적의 승인 버전 이력(#4). 과거 승인본은 불변으로 보존된다. admin·security."""
        _require_ev(request)
        repo = ctx.state_repo
        approvals = repo.load_evidence_approvals(control_id) if repo is not None else []
        _, cur_hash = _control_evidence_state(control_id)
        status, current = _current_approval_status(approvals, cur_hash)
        return {"control_id": control_id, "current_status": status,
                "current": current, "approvals": approvals}

    @app.get("/controls/evidence-freshness", tags=["Compliance"])
    def evidence_freshness_all(request: Request) -> dict[str, Any]:
        """통제별 증적 신선도·데이터 품질(#11) — 자동 증적의 신뢰 품질 상태.

        증적이 있는 통제마다 최신 수집 시각·경과일·stale 여부·담당자 검토(승인) 신선도를 계산해
        '초록 Compliant' 대신 no_evidence/evidence_stale/review_required/human_verified 로 구분한다.
        """
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from mori_soc.services.evidence_freshness import compute_freshness
        _require_ev(request)
        now_iso = _dt.now(tz=_tz.utc).isoformat()
        repo = ctx.state_repo
        by_control: dict[str, list[dict[str, Any]]] = {}
        for rec in (ctx.control_evidence or {}).values():
            cid = str(rec.get("control_id") or "")
            if cid:
                by_control.setdefault(cid, []).append(rec)

        out: list[dict[str, Any]] = []
        for cid, recs in sorted(by_control.items()):
            approvals = repo.load_evidence_approvals(cid) if repo is not None else []
            _, cur_hash = _control_evidence_state(cid)
            status, current = _current_approval_status(approvals, cur_hash)
            fr = compute_freshness(recs, now_iso, approval=current, approval_status=status)
            fr["control_id"] = cid
            out.append(fr)
        # 신뢰 품질이 낮은(=검토·갱신 필요한) 것부터 노출.
        order = {"evidence_stale": 0, "review_required": 1, "evidence_available": 2,
                 "human_verified": 3, "no_evidence": 4}
        out.sort(key=lambda r: (order.get(r["status"], 9), -(r["age_days"] or 0)))
        return {"generated_at": now_iso, "controls": out}

    @app.post("/controls/audit-sample", tags=["Compliance"])
    def audit_sample(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """위험 기반 감사 표본 추출(#13) — 모집단에서 결정적 표본 + 감사 패키지 메타.

        body: population(list[dict]) · control_id? · period? · risk_field? · high_cap? · sample_rate?
        · order_field?. 전체 내부감사 모듈이 아니라 표본 추출만(모리다움). 결정적(재현 가능).
        """
        from mori_soc.services.sampling import risk_based_sample
        _require_ev(request)
        pop = payload.get("population")
        if not isinstance(pop, list):
            raise HTTPException(status_code=400, detail="population(list)이 필요합니다.")
        res = risk_based_sample(
            [p for p in pop if isinstance(p, dict)],
            risk_field=str(payload.get("risk_field", "risk")),
            high_cap=int(payload.get("high_cap", 20)),
            sample_rate=float(payload.get("sample_rate", 0.1)),
            order_field=str(payload.get("order_field", "id")),
            expected_population=(int(payload["expected_population"])
                                 if str(payload.get("expected_population", "")).strip() not in ("", "None")
                                 else None),
        )
        res["control_id"] = str(payload.get("control_id", "") or "")
        res["period"] = str(payload.get("period", "") or "")
        return res

    @app.post("/controls/audit-sample.zip", tags=["Compliance"])
    def audit_sample_zip(payload: dict[str, Any], request: Request) -> Any:
        """감사 표본 패키지 ZIP(manifest.json + sample.csv)."""
        import io
        import json as _json
        import zipfile

        from fastapi.responses import Response as _Response

        from mori_soc.services.csv_export import render_csv
        from mori_soc.services.sampling import risk_based_sample
        _require_ev(request)
        pop = payload.get("population")
        if not isinstance(pop, list):
            raise HTTPException(status_code=400, detail="population(list)이 필요합니다.")
        res = risk_based_sample(
            [p for p in pop if isinstance(p, dict)],
            risk_field=str(payload.get("risk_field", "risk")),
            high_cap=int(payload.get("high_cap", 20)),
            sample_rate=float(payload.get("sample_rate", 0.1)),
            order_field=str(payload.get("order_field", "id")),
            expected_population=(int(payload["expected_population"])
                                 if str(payload.get("expected_population", "")).strip() not in ("", "None")
                                 else None),
        )
        res["control_id"] = str(payload.get("control_id", "") or "")
        res["period"] = str(payload.get("period", "") or "")
        from mori_soc.services.evidence_bundle import (
            signing_config_from_env,
            write_bundle_with_manifest,
        )
        sample = res.pop("sample", [])
        cols: list[str] = []
        for item in sample:
            for kk in item:
                if kk not in cols:
                    cols.append(kk)
        files = {
            "manifest.json": _json.dumps(res, ensure_ascii=False, indent=2).encode("utf-8"),
            "sample.csv": render_csv(sample, {c: c for c in cols}).encode("utf-8"),
        }
        secret, key_id = signing_config_from_env()
        now2 = datetime.now(tz=timezone.utc).isoformat()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            write_bundle_with_manifest(zf, files, generated_at=now2, secret=secret, key_id=key_id,
                                       extra={"bundle": "audit-sample", "control_id": res["control_id"]})
        fname = "mori-audit-sample" + (f"-{res['control_id']}" if res["control_id"] else "") + ".zip"
        return _Response(content=buf.getvalue(), media_type="application/zip",
                         headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    @app.post("/controls/evidence/{control_id}/transition", tags=["Compliance"])
    def evidence_transition(control_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """증적 승인 상태 전이(#4): draft→reviewed→approved→superseded / revoked.

        승인(approved)하면 그 시점 스냅샷(content_hash·PDF SHA-256·검토자·승인자)을 불변 기록으로
        고정하고, 이전 승인본은 superseded 로 대체한다(과거본 미삭제).
        """
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from mori_soc.services.evidence_approval import (
            ROLE_FOR,
            STATUSES,
            build_approval,
            can_transition,
        )
        role = _evidence_role(request)
        target = str(payload.get("target", "")).strip()
        if target not in STATUSES:
            raise HTTPException(status_code=400, detail=f"target must be one of {', '.join(STATUSES)}")
        has_ev, cur_hash = _control_evidence_state(control_id)
        if not has_ev:
            raise HTTPException(status_code=404, detail="no evidence for this control yet")
        repo = ctx.state_repo
        approvals = repo.load_evidence_approvals(control_id) if repo is not None else []
        current_status, current = _current_approval_status(approvals, cur_hash)
        if ctx.auth_enabled and role not in ROLE_FOR.get(target, ()):
            raise HTTPException(status_code=403, detail=f"{target} 전이는 {'/'.join(ROLE_FOR.get(target, ()))} 권한이 필요합니다.")
        if not can_transition(current_status, target):
            raise HTTPException(status_code=400, detail=f"{current_status} → {target} 전이는 허용되지 않습니다.")
        now = _dt.now(tz=_tz.utc).isoformat()
        actor = (ctx.get_session_username(request) if ctx.get_session_username else "") or "unknown"
        approval = build_approval(
            control_id=control_id, evidence_id=control_id,
            content_hash=cur_hash, version=cur_hash[:12],
            status=target, actor=actor, reason=str(payload.get("reason", "")),
            pdf_hash=str(payload.get("pdf_sha256", "")),
            prev_approval_id=str((current or {}).get("approval_id") or ""),
            now=now)
        if repo is not None:
            repo.save_evidence_approval(approval["approval_id"], approval)
            # 승인 시: 직전 approved 본을 superseded 로 고정(불변 보존, 삭제 아님).
            if target == "approved":
                for a in approvals:
                    if a.get("status") == "approved" and a.get("approval_id") != approval["approval_id"]:
                        a2 = dict(a); a2["status"] = "superseded"
                        a2["supersede_reason"] = f"대체: {approval['version']}"
                        repo.save_evidence_approval(a2["approval_id"], a2)
        if ctx.log_action:
            ctx.log_action(actor, "EVIDENCE_TRANSITION", f"{control_id} {current_status}→{target}")
        return {"ok": True, **approval}

    # ── 기술 Gap 워크플로(#5): 후보→담당자 판단→조치→재검증 ──────────────────────
    @app.get("/gaps", tags=["Compliance"])
    def gaps_list(request: Request, status: str | None = None) -> dict[str, Any]:
        """기술 Gap 목록(#5). admin·security."""
        _require_ev(request)
        from mori_soc.services.gap_workflow import OPEN_STATUSES
        repo = ctx.state_repo
        gaps = repo.load_gaps(status) if repo is not None else []
        return {"gaps": gaps, "open": sum(1 for g in gaps if g.get("status") in OPEN_STATUSES),
                "total": len(gaps)}

    @app.get("/controls/change-report", tags=["Compliance"])
    def change_report(request: Request, month: str | None = None) -> dict[str, Any]:
        """월별 evidence change report(#15) — 새 증적·승인/대체·신규 Gap·조치/예외를 기간 집계.

        month=YYYY-MM(미지정 시 이번 달). 별도 BI 가 아니라 MORI 데이터에서 바로 도출(모리다움).
        """
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from mori_soc.services.change_report import (
            build_evidence_change_report,
            month_bounds,
        )
        _require_ev(request)
        if not month:
            month = _dt.now(tz=_tz.utc).strftime("%Y-%m")
        try:
            start, end = month_bounds(month)
        except ValueError:
            raise HTTPException(status_code=400, detail="month must be YYYY-MM") from None
        repo = ctx.state_repo
        approvals = repo.load_evidence_approvals(None) if repo is not None else []
        gaps = repo.load_gaps() if repo is not None else []
        evidence = list((ctx.control_evidence or {}).values())
        rep = build_evidence_change_report(start, end, evidence=evidence,
                                           approvals=approvals, gaps=gaps)
        rep["month"] = month
        return rep

    @app.get("/gaps/deadlines", tags=["Compliance"])
    def gaps_deadlines(request: Request) -> dict[str, Any]:
        """Gap 조치 기한·예외 만료(#14) — 초과 조치·만료 예외·임박 예외를 표면화(자동연장 금지)."""
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from mori_soc.services.gap_workflow import evaluate_gap_deadlines
        _require_ev(request)
        repo = ctx.state_repo
        gaps = repo.load_gaps() if repo is not None else []
        now = _dt.now(tz=_tz.utc).isoformat()
        res = evaluate_gap_deadlines(gaps, now)
        res["generated_at"] = now
        return res

    @app.post("/gaps", tags=["Compliance"])
    def gap_create(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """Gap 후보 생성(candidate). 스캔 gap·finding 에서 오거나 수동 입력. 결정적 id 로 중복 방지."""
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from mori_soc.services.gap_workflow import build_gap
        _require_ev(request)
        now = _dt.now(tz=_tz.utc).isoformat()
        actor = (ctx.get_session_username(request) if ctx.get_session_username else "") or "unknown"
        gap = build_gap(source=str(payload.get("source", "manual")),
                        control_id=str(payload.get("control_id", "")),
                        key=str(payload.get("key", "") or payload.get("title", "")),
                        title=str(payload.get("title", "")), detail=str(payload.get("detail", "")),
                        now=now, created_by=actor)
        repo = ctx.state_repo
        if repo is not None:
            repo.save_gap(gap["gap_id"], gap)
        if ctx.log_action:
            ctx.log_action(actor, "GAP_CREATE", f"{gap['control_id']} {gap['title']}")
        return gap

    @app.post("/gaps/{gap_id}/transition", tags=["Compliance"])
    def gap_transition(gap_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """Gap 상태 전이(#5): candidate→confirmed/false_positive/policy_review→remediation→resolved 등."""
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from mori_soc.services.gap_workflow import (
            RESOLUTION_TYPES,
            STATUSES,
            apply_transition,
            can_transition,
        )
        _require_ev(request)
        repo = ctx.state_repo
        gaps = repo.load_gaps() if repo is not None else []
        gap = next((g for g in gaps if g.get("gap_id") == gap_id), None)
        if gap is None:
            raise HTTPException(status_code=404, detail="gap not found")
        target = str(payload.get("target", "")).strip()
        if target not in STATUSES:
            raise HTTPException(status_code=400, detail=f"target must be one of {', '.join(STATUSES)}")
        if not can_transition(str(gap.get("status")), target):
            raise HTTPException(status_code=400, detail=f"{gap.get('status')} → {target} 전이는 허용되지 않습니다.")
        resolution_type = str(payload.get("resolution_type", "")).strip()
        if target == "resolved" and resolution_type and resolution_type not in RESOLUTION_TYPES:
            raise HTTPException(status_code=400,
                                detail=f"resolution_type 은 {', '.join(RESOLUTION_TYPES)} 중 하나여야 합니다.")
        now = _dt.now(tz=_tz.utc).isoformat()
        actor = (ctx.get_session_username(request) if ctx.get_session_username else "") or "unknown"
        apply_transition(gap, target, actor=actor, now=now,
                         assignee=str(payload.get("assignee", "")),
                         due_date=str(payload.get("due_date", "")),
                         note=str(payload.get("note", "")),
                         resolution_type=resolution_type,
                         verifying_scan=str(payload.get("verifying_scan", "")),
                         evidence_ref=str(payload.get("evidence_ref", "")))
        if repo is not None:
            repo.save_gap(gap_id, gap)
        if ctx.log_action:
            ctx.log_action(actor, "GAP_TRANSITION", f"{gap_id} →{target}")
        return gap

    @app.get("/controls/maturity", tags=["Compliance"])
    def controls_maturity(request: Request) -> dict[str, Any]:
        """통제 성숙도 요약(#46) — 레벨별(draft/reviewed/mapped/auto_evidence) 통제 수.

        194개를 수기 라벨링하지 않고 status·매핑·MORI 자동증적 신호에서 도출한다.
        '나머지는 언제?'에 대한 정직한 진척도 답. admin·security 전용.
        """
        _require_ev(request)
        from mori_soc.api.routes.privacy import PRIVACY_FLOW_CONTROL_IDS
        from mori_soc.services.code_review_dispatch import CODE_REVIEW_CONTROL_IDS
        from mori_soc.services.control_catalog import maturity_summary
        auto_ids = set(CODE_REVIEW_CONTROL_IDS) | set(PRIVACY_FLOW_CONTROL_IDS)
        try:
            return maturity_summary(auto_ids=auto_ids, catalog=_merged_catalog())
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"maturity unavailable: {exc}") from exc

    def _live_gaps() -> dict[str, Any]:
        """evidence-gaps 카운트를 재계산(통제 증적 팩의 결함 수치용). 실패 시 빈 dict."""
        try:
            from datetime import timedelta
            pdca = build_pdca_payload(get_query_service(), vuln_actions=vuln_actions, alert_triage=triage_store)
            src = pdca.get("pending_sources", {}) or {}
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
            unmapped = 0
            access_uncovered = 0
            try:
                cross = build_crosscheck_payload(get_query_service())
                for chk in cross.get("checks", []) or []:
                    if chk.get("id") == "source_coverage":
                        unmapped = int(chk.get("uncovered_hosts", 0) or 0)
                    elif chk.get("id") == "access_record_coverage":
                        access_uncovered = int(chk.get("uncovered_hosts", 0) or 0)
            except Exception:
                unmapped = access_uncovered = 0
            return {"vuln_pending": int(src.get("trivy", 0) or 0), "exceptions_expiring": expiring,
                    "untriaged_alerts": int(src.get("alert", 0) or 0),
                    "code_review_pending": int(src.get("code_review", 0) or 0),
                    "overdue": int(pdca.get("overdue_count", 0) or 0),
                    "control_pending": int(src.get("control_check", 0) or 0), "unmapped_assets": unmapped,
                    "access_uncovered": access_uncovered}
        except Exception:
            return {}

    # ── 접속기록 보존 현황 (안전성 확보조치 기준 제8조 / ISMS-P 2.9.4 / ISO A.8.15) ──
    _LOG_RETENTION_TARGET_KEY = "log_retention_target_days"
    _LOG_RETENTION_PERSONAL_KEY = "log_retention_personal"

    def _retention_cfg() -> tuple[int, bool]:
        """(목표 보존일, 개인정보처리 플래그). 기본 365일, 개인정보 처리 시 최소 730일."""
        s = ctx.settings or {}
        try:
            target = int(str(s.get(_LOG_RETENTION_TARGET_KEY, 365)).strip() or 365)
        except ValueError:
            target = 365
        personal = str(s.get(_LOG_RETENTION_PERSONAL_KEY, "")).strip().lower() in ("1", "true", "yes", "on")
        if personal:
            target = max(target, 730)
        return target, personal

    def _log_retention_status() -> dict[str, Any]:
        """접속기록 보존 현황 — MORI가 **실제 관측한 기록의 시간 범위**로 보존 하한을 추정.

        주의(정직성): 이는 'MORI가 관측한 기록 범위'이지 로그시스템(Loki 등)의 실제
        retention 설정값이 아니다. 법정 보존기간(기본 1년, 고유식별정보 처리 시 2년)
        충족 판단은 로그시스템 retention 설정 증빙과 **병행**해야 한다.
        """
        target, personal = _retention_cfg()
        now = datetime.now(tz=timezone.utc)
        try:
            store = get_query_service().store
        except Exception:
            return {"target_days": target, "personal": personal, "span_days": None,
                    "sources": [], "ok": False, "observed": False}

        def _norm(ts: Any) -> "datetime | None":
            if ts is None or not hasattr(ts, "tzinfo"):
                return None
            return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts

        per: dict[str, dict[str, Any]] = {}
        for a in getattr(store, "alerts", []) or []:
            src = getattr(a, "source", "") or "(unknown)"
            ts = _norm(getattr(a, "observed_at", None))
            d = per.setdefault(src, {"count": 0, "oldest": None})
            d["count"] += 1
            if ts is not None and (d["oldest"] is None or ts < d["oldest"]):
                d["oldest"] = ts
        vulns = [v for v in getattr(store, "vulnerabilities", []) or [] if getattr(v, "source", "") == "trivy"]
        if vulns:
            oldest = None
            for v in vulns:
                ts = _norm(getattr(v, "observed_at", None))
                if ts is not None and (oldest is None or ts < oldest):
                    oldest = ts
            per["trivy"] = {"count": len(vulns), "oldest": oldest}

        rows: list[dict[str, Any]] = []
        overall_oldest: "datetime | None" = None
        for src, d in per.items():
            old = d["oldest"]
            span = int((now - old).total_seconds() // 86400) if old else None
            rows.append({"source": src, "count": d["count"],
                         "oldest": old.strftime("%Y-%m-%d") if old else None, "span_days": span})
            if old and (overall_oldest is None or old < overall_oldest):
                overall_oldest = old
        # ── Loki 라이브 접속기록(설정 시): 관측 추정 대신 실쿼리 결과로 loki 행 승격 ──
        try:
            from mori_soc.services.loki_client import access_log_summary
            lk = access_log_summary(target, now=now)
        except Exception:
            lk = {"available": False}
        if lk.get("available"):
            rows = [r for r in rows if r["source"] != "loki"]
            rows.append({"source": "loki", "count": lk.get("count", 0), "oldest": lk.get("oldest"),
                         "span_days": lk.get("span_days"), "accepted": lk.get("accepted"),
                         "failed": lk.get("failed"), "live": True})
            if lk.get("oldest"):
                try:
                    old_dt = datetime.strptime(lk["oldest"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    if overall_oldest is None or old_dt < overall_oldest:
                        overall_oldest = old_dt
                except ValueError:
                    pass
        rows.sort(key=lambda r: (r["span_days"] is None, -(r["span_days"] or 0)))
        span_days = int((now - overall_oldest).total_seconds() // 86400) if overall_oldest else None
        return {"target_days": target, "personal": personal, "span_days": span_days,
                "sources": rows, "ok": span_days is not None and span_days >= target,
                "observed": overall_oldest is not None, "loki_live": bool(lk.get("available"))}

    def _source_metrics(limit: int = 8) -> dict[str, Any]:
        """증적 소스별 라이브 실데이터 집계 + **호스트↔통제 단위 breakdown**.

        각 소스는 전역 요약(summary)에 더해, 어느 자산/엔티티가 그 증적을 갖는지
        상위 목록(breakdown: [{label, value}])을 붙인다 — 통제 상세에서 "어느 자산의
        그 통제 증적"까지 드릴다운. ``limit`` 는 breakdown 상위 개수(자동 스냅샷은 크게 줘서
        전 엔티티 상세 캡처).
        """
        from collections import defaultdict
        from datetime import timedelta
        try:
            svc = get_query_service()
            store = svc.store
        except Exception:
            return {}
        now = datetime.now(tz=timezone.utc)
        wk = now - timedelta(days=7)
        hostnames = {getattr(h, "host_id", ""): getattr(h, "hostname", "") for h in getattr(store, "hosts", [])}

        def _hn(hid: str) -> str:
            return hostnames.get(hid, "") or hid or "(unknown)"

        def _top(rows: list[dict], key: str, n: int = limit) -> tuple[list[dict], int]:
            rows.sort(key=lambda r: r.get(key, 0), reverse=True)
            return rows[:n], max(0, len(rows) - n)

        m: dict[str, Any] = {}
        # ── Trivy: 호스트별 미조치 Critical/High ──
        vulns = [v for v in getattr(store, "vulnerabilities", [])
                 if getattr(v, "source", "") == "trivy" and getattr(v, "resolved_at", None) is None]
        crit = sum(1 for v in vulns if getattr(v, "severity", "") == "critical")
        high = sum(1 for v in vulns if getattr(v, "severity", "") == "high")
        tb: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "n": 0})
        for v in vulns:
            sev = getattr(v, "severity", "")
            if sev in ("critical", "high"):
                b = tb[getattr(v, "host_id", "") or ""]
                b[sev] += 1
                b["n"] += 1
        t_rows = [{"label": _hn(h), "value": f"C{d['critical']}·H{d['high']}", "n": d["n"]} for h, d in tb.items()]
        t_top, t_more = _top(t_rows, "n")
        m["trivy"] = {"count": len(vulns),
                      "summary_ko": f"미조치 취약점 {len(vulns)}건 (Critical {crit}·High {high})",
                      "summary_en": f"{len(vulns)} open vulns (Critical {crit} · High {high})",
                      "breakdown": [{"label": r["label"], "value": r["value"]} for r in t_top], "more": t_more}
        # ── Zabbix / Wazuh: 호스트별 최근 7일 경보/탐지 ──
        alerts = list(getattr(store, "alerts", []))

        def _alert_metric(source: str, ko_word: str, en_word: str) -> dict[str, Any]:
            d: dict[str, int] = defaultdict(int)
            for a in alerts:
                if getattr(a, "source", "") == source and getattr(a, "observed_at", now) >= wk:
                    d[getattr(a, "host_id", "") or ""] += 1
            total = sum(d.values())
            rows = [{"label": _hn(h), "value": f"{n}", "n": n} for h, n in d.items()]
            top, more = _top(rows, "n")
            return {"count": total, "summary_ko": f"최근 7일 {ko_word} {total}건",
                    "summary_en": f"{total} {en_word} (7d)",
                    "breakdown": [{"label": r["label"], "value": r["value"]} for r in top], "more": more}

        fleet_hosts = zbx_hosts = 0
        try:
            for chk in (build_crosscheck_payload(svc).get("checks", []) or []):
                if chk.get("id") == "zabbix_vs_fleet":
                    fleet_hosts = int(chk.get("fleet_count", 0) or 0)
                    zbx_hosts = int(chk.get("zabbix_count", 0) or 0)
        except Exception:
            pass
        m["zabbix"] = _alert_metric("zabbix", "경보", "alerts")
        m["zabbix"]["summary_ko"] += f" · 모니터링 자산 {zbx_hosts}"
        m["zabbix"]["summary_en"] += f" · {zbx_hosts} monitored hosts"
        m["wazuh"] = _alert_metric("wazuh", "탐지", "detections")
        m["fleet"] = {"count": fleet_hosts, "summary_ko": f"수집 자산 {fleet_hosts}",
                      "summary_en": f"{fleet_hosts} collected assets", "breakdown": [], "more": 0}
        # ── Loki/접속기록: 관측 기록 범위 기반 보존현황(안전조치 제8조) ──
        ret = _log_retention_status()
        if ret.get("observed"):
            span, tgt = ret["span_days"], ret["target_days"]
            badge_ko = "충족" if ret["ok"] else "미달"
            badge_en = "meets" if ret["ok"] else "below"
            m["loki"] = {"count": span,
                         "summary_ko": f"관측 기록 범위 {span}일 / 목표 {tgt}일 — {badge_ko}"
                                       " (로그시스템 retention 설정 증빙 병행)",
                         "summary_en": f"observed record span {span}d / target {tgt}d — {badge_en}"
                                       " (attach log-system retention proof)",
                         "breakdown": [{"label": r["source"],
                                        "value": f"{r['oldest'] or '-'} · {r['span_days']}d · {r['count']}건"}
                                       for r in ret["sources"][:limit]], "more": 0}
        else:
            tgt = ret["target_days"]
            m["loki"] = {"count": 0,
                         "summary_ko": f"접속기록 미관측 — 목표 보존 {tgt}일. 로그 수집 연동·retention 증빙 필요",
                         "summary_en": f"no access records observed — target {tgt}d; wire log collection & attach proof",
                         "breakdown": [], "more": 0}
        # ── MORI: 최근 인시던트 ──
        inc_vals = list((ctx.incidents or {}).values())
        inc_sorted = sorted(inc_vals, key=lambda x: str(x.get("updated_at") or x.get("created_at") or ""), reverse=True)
        inc_bd = [{"label": (i.get("title") or i.get("incident_id") or "-"), "value": str(i.get("status") or "")}
                  for i in inc_sorted[:limit]]
        risk = len(ctx.risk_register or {})
        audit = len(ctx.action_audit_log or [])
        m["mori"] = {"count": len(inc_vals),
                     "summary_ko": f"인시던트 {len(inc_vals)} · 위험평가 {risk} · 감사이벤트 {audit}",
                     "summary_en": f"{len(inc_vals)} incidents · {risk} risk assessments · {audit} audit events",
                     "breakdown": inc_bd, "more": max(0, len(inc_vals) - limit)}
        return m

    @app.get("/controls/detail/{control_id}", tags=["Compliance"])
    def control_detail(control_id: str, request: Request) -> dict[str, Any]:
        """한 통제의 증적 상세(매핑·결함·증적 소스 + 라이브 실증적 + 현재 공백). admin·security 전용."""
        _require_ev(request)
        from mori_soc.services.control_catalog import build_control_detail
        detail = build_control_detail(control_id, gaps=_live_gaps(), metrics=_source_metrics(),
                                      catalog=_merged_catalog(), evidence_records=_evidence_for(control_id))
        if detail is None:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        # M2-7: 현재 이행 상태(편집 대상)를 상세에 병기.
        detail["runtime_status"] = ctx.control_status.get(control_id, _control_status_default(control_id))
        detail["can_edit"] = (not ctx.auth_enabled) or (_evidence_role(request) == "admin")
        return detail

    @app.put("/controls/status/{control_id}", tags=["Compliance"])
    def control_status_upsert(control_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """통제 이행 상태 편집(상태·담당자·예외사유·개선계획·기한). admin·security 전용.

        변경은 control_status 에 write-through 영속(재시작 후 유지)되고, action-audit-log 에 기록된다.
        """
        _require_ev(request)
        valid_ids = {c.get("id") for c in _merged_catalog().get("controls", [])}
        if valid_ids and control_id not in valid_ids:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        status = str(payload.get("status", "")).strip() or "미정"
        if status not in _CONTROL_STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {sorted(_CONTROL_STATUSES)}")
        due = str(payload.get("due_date", "")).strip()
        if due:
            try:
                date.fromisoformat(due[:10])
            except ValueError:
                raise HTTPException(status_code=400, detail="due_date must be YYYY-MM-DD") from None
        user = ""
        if ctx.get_session_username:
            user = ctx.get_session_username(request) or ""
        old = ctx.control_status.get(control_id, {})
        record = {
            "control_id": control_id,
            "status": status,
            "owner": str(payload.get("owner", "")).strip(),
            "exception_reason": str(payload.get("exception_reason", "")).strip(),
            "improvement_plan": str(payload.get("improvement_plan", "")).strip(),
            "due_date": due,
            "updated_at": datetime.now(tz=timezone.utc).isoformat(),
            "updated_by": user or "unknown",
        }
        ctx.control_status[control_id] = record
        if ctx.persist_control_status:
            ctx.persist_control_status(control_id)
        if ctx.log_action:
            ctx.log_action(user or "unknown", "CONTROL_STATUS",
                           f"{control_id}: {old.get('status', '미정')} → {status}")
        return record

    @app.get("/controls/detail/{control_id}/evidence.pdf", tags=["Compliance"])
    def control_evidence_pdf_route(control_id: str, request: Request) -> Any:
        """증적 문서 PDF — 자산 인벤토리 + 문서화 증적을 표로. admin·security 전용."""
        _require_ev(request)
        from mori_soc.services.control_catalog import evidence_document_pdf
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        doc = _evidence_document(control_id, user or "")
        if doc is None:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        try:
            pdf = evidence_document_pdf(doc)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        safe = control_id.replace("/", "_")
        return StreamingResponse(iter([pdf]), media_type="application/pdf",
                                 headers={"Content-Disposition": f'attachment; filename="mori-evidence-{safe}.pdf"'})

    @app.get("/controls/detail/{control_id}/evidence.csv", tags=["Compliance"])
    def control_evidence_csv_route(control_id: str, request: Request) -> Any:
        """증적 문서 CSV — 자산 인벤토리 표 + 문서화 증적 표. admin·security 전용."""
        _require_ev(request)
        from mori_soc.services.control_catalog import evidence_document_csv
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        doc = _evidence_document(control_id, user or "")
        if doc is None:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        safe = control_id.replace("/", "_")
        return StreamingResponse(iter(["﻿" + evidence_document_csv(doc)]), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="mori-evidence-{safe}.csv"'})

    def _fw_label(fw: str) -> str:
        return {"isms-p": "ISMS-P", "iso27001": "ISO27001"}.get(fw, fw or "기타")

    def _safe_name(s: str, n: int = 60) -> str:
        s = str(s or "").strip()
        for ch in '/\\:*?"<>|\n\r\t':
            s = s.replace(ch, "_")
        return (s[:n] or "_").strip()

    @app.get("/controls/evidence-bundle.zip", tags=["Compliance"])
    def evidence_bundle_zip(request: Request, scope: str = "mapped") -> Any:
        """전 통제 증적 문서를 폴더별(프레임워크/통제)로 담은 ZIP 한방 다운로드. admin·security.

        scope=mapped(기본): 증적 소스가 있거나 문서화 증적이 있는 통제만. scope=all: 전 통제.
        각 통제 폴더에 evidence.pdf + evidence.csv, 루트에 INDEX.csv.
        """
        _require_ev(request)
        import csv as csv_mod
        import io as io_mod
        import zipfile

        from mori_soc.services.control_catalog import (
            evidence_document_csv,
            evidence_document_pdf,
        )
        from mori_soc.services.evidence_bundle import (
            BundleWriter,
            signing_config_from_env,
        )
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        catalog = _merged_catalog()
        host_lists = _evidence_host_lists()
        metrics = _source_metrics(limit=200)
        ev_by_control: dict[str, int] = {}
        for r in (ctx.control_evidence or {}).values():
            ev_by_control[r.get("control_id", "")] = ev_by_control.get(r.get("control_id", ""), 0) + 1
        want_all = str(scope).strip() == "all"
        index_rows = [["control_id", "title_ko", "framework", "assets", "records"]]
        n = 0
        secret, key_id = signing_config_from_env()
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        buf = io_mod.BytesIO()
        # 스트리밍(M2): 통제별 PDF/CSV 를 생성 즉시 ZIP 에 쓰고 바이트는 버린다(files dict 미보관 → 메모리 절약).
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            writer = BundleWriter(z, secret=secret, key_id=key_id)
            for c in catalog.get("controls", []):
                cid = c.get("id")
                if not cid:
                    continue
                has_ev = bool(c.get("evidence_sources"))
                has_rec = ev_by_control.get(cid, 0) > 0
                if not want_all and not (has_ev or has_rec):
                    continue
                doc = _evidence_document(cid, user or "", host_lists=host_lists,
                                         metrics=metrics, catalog=catalog)
                if doc is None:
                    continue
                folder = f"{_safe_name(_fw_label(c.get('framework')), 20)}/{_safe_name(cid, 24)}_{_safe_name(c.get('title_ko') or c.get('title_en'), 40)}"
                try:
                    writer.add(f"{folder}/evidence.pdf", evidence_document_pdf(doc))
                except RuntimeError:
                    pass  # reportlab 미설치 시 PDF 생략(CSV는 유지)
                writer.add(f"{folder}/evidence.csv", ("﻿" + evidence_document_csv(doc)).encode("utf-8"))
                index_rows.append([cid, c.get("title_ko", ""), _fw_label(c.get("framework")),
                                   len(doc["inventory"]), len(doc["records"])])
                n += 1
            sio = io_mod.StringIO()
            csv_mod.writer(sio).writerows(index_rows)
            writer.add("INDEX.csv", ("﻿" + sio.getvalue()).encode("utf-8"))
            writer.finalize(generated_at=now_iso,
                            extra={"bundle": "evidence-bundle", "scope": str(scope), "controls": n})
        if ctx.log_action:
            ctx.log_action(user or "system", "EVIDENCE_BUNDLE_ZIP", f"{scope}: {n}건")
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
        return StreamingResponse(iter([buf.getvalue()]), media_type="application/zip",
                                 headers={"Content-Disposition": f'attachment; filename="mori-evidence-bundle-{ts}.zip"'})

    # ── M2-8: 카탈로그 정본 편집 (admin 전용) ─────────────────────────────────────
    _CATALOG_FIELDS = ("framework", "version", "domain", "section", "title_ko", "title_en",
                       "intent_ko", "intent_en", "evidence_hint_ko", "evidence_hint_en")

    def _save_catalog_control(payload: dict[str, Any], actor: str, origin: str = "manual") -> dict[str, Any]:
        control_id = str(payload.get("id", "")).strip()
        if not control_id:
            raise HTTPException(status_code=400, detail="id 가 필요합니다.")
        title = str(payload.get("title_ko", "")).strip() or str(payload.get("title_en", "")).strip()
        if not title:
            raise HTTPException(status_code=400, detail="title_ko(또는 title_en)가 필요합니다.")
        srcs = payload.get("evidence_sources") or []
        if isinstance(srcs, str):
            srcs = [s.strip() for s in srcs.replace(";", ",").split(",") if s.strip()]
        tags = payload.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.replace(";", ",").split(",") if t.strip()]
        rec: dict[str, Any] = {"control_id": control_id, "op": "upsert",
                               "framework": str(payload.get("framework", "custom")).strip() or "custom",
                               "evidence_sources": [str(s).strip().lower() for s in srcs],
                               "tags": [str(t) for t in tags],
                               "status": str(payload.get("status", "draft")).strip() or "draft",
                               "origin": origin, "updated_by": actor}
        for f in _CATALOG_FIELDS:
            if f in payload:
                rec[f] = str(payload.get(f) or "").strip()
        ctx.catalog_edits[control_id] = rec
        if ctx.persist_catalog_edit:
            ctx.persist_catalog_edit(control_id)
        return rec

    @app.post("/controls", tags=["Compliance"])
    def create_or_edit_control(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """통제 추가/수정(오버레이 upsert). admin 전용. 재싱크에도 유지."""
        actor = _require_catalog_admin(request)
        rec = _save_catalog_control(payload, actor)
        if ctx.log_action:
            ctx.log_action(actor, "CATALOG_CONTROL_UPSERT", f"{rec['control_id']}: {rec.get('title_ko','')}")
        return rec

    @app.delete("/controls/{control_id}", tags=["Compliance"])
    def delete_control(control_id: str, request: Request) -> dict[str, Any]:
        """통제 삭제. admin 전용. admin이 만든 통제면 오버레이 제거, base 통제면 숨김(op=delete)."""
        actor = _require_catalog_admin(request)
        from mori_soc.services.control_catalog import load_catalog
        base_ids = {c.get("id") for c in load_catalog().get("controls", [])}
        existing = ctx.catalog_edits.get(control_id)
        if control_id in base_ids:
            ctx.catalog_edits[control_id] = {"control_id": control_id, "op": "delete",
                                             "framework": "", "origin": "manual", "updated_by": actor}
            if ctx.persist_catalog_edit:
                ctx.persist_catalog_edit(control_id)
            action = "hidden"
        elif existing is not None:
            ctx.catalog_edits.pop(control_id, None)
            if ctx.delete_catalog_edit:
                ctx.delete_catalog_edit(control_id)
            action = "deleted"
        else:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        if ctx.log_action:
            ctx.log_action(actor, "CATALOG_CONTROL_DELETE", f"{control_id} ({action})")
        return {"ok": True, "id": control_id, "action": action}

    def _env_claude_key() -> str:
        return (os.getenv("MORI_ANTHROPIC_API_KEY", "") or os.getenv("ANTHROPIC_API_KEY", "")).strip()

    def _resolved_claude_key() -> str:
        """env 우선 → 없으면 어드민이 저장한 DB 키(ui_settings)."""
        return _env_claude_key() or str((ctx.settings or {}).get(ANTHROPIC_KEY_SETTING, "") or "").strip()

    @app.get("/controls/claude-key", tags=["Compliance"])
    def get_claude_key(request: Request) -> dict[str, Any]:
        """Claude API 키 설정 상태(마스킹). admin 전용. 실제 키는 절대 반환하지 않음."""
        _require_catalog_admin(request)
        env_key = _env_claude_key()
        db_key = str((ctx.settings or {}).get(ANTHROPIC_KEY_SETTING, "") or "").strip()
        key = env_key or db_key
        source = "env" if env_key else ("db" if db_key else "none")
        return {
            "configured": bool(key),
            "source": source,
            "masked": (("…" + key[-4:]) if len(key) >= 4 else "····") if key else "",
            "env_locked": bool(env_key),  # env 로 잠겨 있으면 UI 저장은 비활성(env가 이김)
        }

    @app.put("/controls/claude-key", tags=["Compliance"])
    def put_claude_key(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """Claude API 키 저장/삭제(ui_settings). admin 전용. 빈 문자열이면 삭제."""
        actor = _require_catalog_admin(request)
        key = str(payload.get("api_key", "") or "").strip()
        ctx.settings[ANTHROPIC_KEY_SETTING] = key
        if ctx.persist_setting:
            ctx.persist_setting(ANTHROPIC_KEY_SETTING, actor)
        if ctx.log_action:
            ctx.log_action(actor, "CATALOG_CLAUDE_KEY", "set" if key else "cleared")
        return {"ok": True, "configured": bool(key)}

    @app.post("/controls/import-nlp", tags=["Compliance"])
    def import_controls_nlp(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """법령/고시 자연어 텍스트 → 통제 초안 변환 & 저장(draft). admin 전용.

        {text, framework?, id_prefix?}. Claude API 키가 있으면 정확 구조화, 없으면 휴리스틱.
        결과는 draft 로 저장되어 카탈로그에 바로 뜨고, admin이 검토·수정한다.
        """
        actor = _require_catalog_admin(request)
        from mori_soc.services.catalog_nlp import parse_regulation_text
        text = str(payload.get("text", "")).strip()
        if not text:
            raise HTTPException(status_code=400, detail="text 가 필요합니다.")
        framework = str(payload.get("framework", "custom")).strip() or "custom"
        prefix = str(payload.get("id_prefix", "REG")).strip() or "REG"
        result = parse_regulation_text(text, framework=framework, id_prefix=prefix,
                                       api_key=_resolved_claude_key())
        saved = []
        for c in result["controls"]:
            saved.append(_save_catalog_control(c, actor, origin="nlp"))
        if ctx.log_action:
            ctx.log_action(actor, "CATALOG_NLP_IMPORT", f"{result['method']}: {len(saved)}건 ({framework})")
        return {"method": result["method"], "count": len(saved),
                "controls": [{"id": c["control_id"], "title_ko": c.get("title_ko", "")} for c in saved]}

    # ── 코드 보안 리뷰 원격 트리거 (Option A — dispatch) ──────────────────────────
    @app.post("/controls/code-review/scan", tags=["Compliance"])
    def request_code_review_scan(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """고객 GitHub 레포의 보안 리뷰를 원격 실행. admin·security.

        {repo_url, github_token, ref?, workflow?}. GitHub workflow_dispatch 로 대상 레포의
        code-review-semgrep.yml(무료) 을 트리거하면, 스캔은 **그 레포 CI 러너**에서 돌고 결과는
        /ingest/code-review 로 돌아온다. MORI 는 코드를 clone/스캔하지 않으며 토큰도
        저장하지 않는다(이 호출에만 사용).
        """
        _require_ev(request)
        from mori_soc.services.code_review_dispatch import (
            dispatch_workflow,
            parse_github_repo,
        )

        repo_url = str(payload.get("repo_url", "")).strip()
        token = str(payload.get("github_token", "")).strip()
        ref = str(payload.get("ref", "") or "main").strip() or "main"
        # 온디맨드(UI) 스캔 기본 = 무료 Semgrep(SAST)로 기존 코드 전체 감사.
        # (유료 Claude 심층 리뷰를 원하면 payload.workflow=code-review-fullscan.yml)
        workflow = str(payload.get("workflow", "") or "code-review-semgrep.yml").strip() or "code-review-semgrep.yml"
        if not repo_url:
            raise HTTPException(status_code=400, detail="repo_url 이 필요합니다.")
        if not token:
            raise HTTPException(status_code=400, detail="github_token 이 필요합니다.")
        try:
            owner, repo = parse_github_repo(repo_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # MORI 자기 URL 을 dispatch 입력으로 주입 → 고객은 MORI_INGEST_URL 시크릿 불필요(3→2).
        mori_url = str(payload.get("mori_ingest_url", "")).strip() or os.getenv("MORI_PUBLIC_URL", "").strip()
        inputs = {"mori_ingest_url": mori_url} if mori_url else None
        try:
            dispatch_workflow(owner, repo, token, ref=ref, workflow=workflow, inputs=inputs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"GitHub 워크플로 실행 실패: {exc}") from exc
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        if ctx.log_action:
            # 토큰은 절대 기록하지 않는다 — owner/repo/ref 만.
            ctx.log_action(user or "system", "CODE_REVIEW_SCAN", f"{owner}/{repo}@{ref} ({workflow})")
        return {"ok": True, "owner": owner, "repo": repo, "workflow": workflow, "ref": ref}

    # ── M2-8: 통제별 수기 증적 레코드 (admin·security) ────────────────────────────
    @app.get("/controls/detail/{control_id}/evidence-records", tags=["Compliance"])
    def list_evidence_records(control_id: str, request: Request) -> dict[str, Any]:
        _require_ev(request)
        rows = sorted(_evidence_for(control_id),
                      key=lambda r: str(r.get("collected_at") or r.get("created_at") or ""), reverse=True)
        return {"control_id": control_id, "records": rows, "total": len(rows)}

    @app.post("/controls/detail/{control_id}/evidence-records", tags=["Compliance"])
    def add_evidence_record(control_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """수기 증적 기록 추가 {title, body?, collected_by?, collected_at?, reference?}. admin·security."""
        _require_ev(request)
        import uuid
        title = str(payload.get("title", "")).strip()
        if not title:
            raise HTTPException(status_code=400, detail="title 이 필요합니다.")
        user = ""
        if ctx.get_session_username:
            user = ctx.get_session_username(request) or ""
        collected_at = str(payload.get("collected_at", "")).strip()
        if collected_at and _parse_date(collected_at) is None:
            raise HTTPException(status_code=400, detail="collected_at must be YYYY-MM-DD")
        rec = {
            "id": str(uuid.uuid4()), "control_id": control_id, "title": title,
            "body": str(payload.get("body", "")).strip(),
            "collected_by": str(payload.get("collected_by", "")).strip() or user,
            "collected_at": collected_at or datetime.now(tz=timezone.utc).strftime("%Y-%m-%d"),
            "reference": str(payload.get("reference", "")).strip(), "source": "manual",
            "created_at": datetime.now(tz=timezone.utc).isoformat(), "created_by": user or "unknown",
        }
        _persist_evidence(rec)
        if ctx.log_action:
            ctx.log_action(user or "unknown", "CONTROL_EVIDENCE_ADD", f"{control_id}: {title}")
        return rec

    # ── M2-8: 실증적 자동 스냅샷 (상세값 캡처 + 일정 자동화) ───────────────────────
    def _evidence_host_lists() -> dict[str, list[dict[str, str]]]:
        """소스별 실제 호스트 목록(hostname·ip·status) — 스냅샷에 '몇 개'가 아니라 '어떤 호스트'.

        crosscheck 와 동일하게 alias + host_id 접두어(pc-=fleet, server-=zabbix)로 분류.
        """
        try:
            store = get_query_service().store
        except Exception:
            return {}
        fleet_ids: set[str] = set()
        zbx_ids: set[str] = set()
        for alias in getattr(store, "host_aliases", []) or []:
            if getattr(alias, "source", "") == "fleet":
                fleet_ids.add(alias.host_id)
            elif getattr(alias, "source", "") == "zabbix":
                zbx_ids.add(alias.host_id)
        for h in getattr(store, "hosts", []):
            hid = getattr(h, "host_id", "")
            if hid.startswith("pc-") and hid not in fleet_ids and hid not in zbx_ids:
                fleet_ids.add(hid)
            elif hid.startswith("server-") and hid not in zbx_ids and hid not in fleet_ids:
                zbx_ids.add(hid)

        def _real(h: Any) -> bool:
            # 실제 인벤토리 자산만(스캔 아티팩트·미현행 항목 제외) — IP가 있거나 상태가 확인된 것
            return bool(getattr(h, "primary_ip", "")) or getattr(h, "status", "") in ("online", "offline")

        def _row(h: Any) -> dict[str, str]:
            return {"hostname": getattr(h, "hostname", "") or "(unknown)",
                    "ip": getattr(h, "primary_ip", "") or "-", "status": getattr(h, "status", "") or ""}
        hosts = [h for h in getattr(store, "hosts", []) if _real(h)]
        fleet = sorted((_row(h) for h in hosts if getattr(h, "host_id", "") in fleet_ids), key=lambda r: r["hostname"])
        zbx = sorted((_row(h) for h in hosts if getattr(h, "host_id", "") in zbx_ids), key=lambda r: r["hostname"])
        return {"fleet": fleet, "zabbix": zbx}

    def _compose_snapshot_body(detail: dict[str, Any], status: dict[str, Any],
                               host_lists: dict[str, list[dict[str, str]]]) -> str:
        """통제 detail(+상태)을 상세 증적 본문으로 조립 — 라이브 실호스트 목록 + 메타 + 이행상태."""
        c = detail.get("control", {})
        lines: list[str] = []
        head = f"[{c.get('id','')}] {c.get('title_ko') or c.get('title_en') or ''}"
        fw = "ISMS-P" if c.get("framework") == "isms-p" else ("ISO 27001:2022" if c.get("framework") == "iso27001" else str(c.get("framework", "")))
        lines.append(f"■ 통제: {head} ({fw})")
        if c.get("intent_ko"):
            lines.append(f"· 취지: {c.get('intent_ko')}")
        if c.get("evidence_hint_ko"):
            lines.append(f"· 증적 힌트: {c.get('evidence_hint_ko')}")
        st = (status or {}).get("status") or "미정"
        stmeta = " · ".join(x for x in [f"이행상태: {st}",
                 f"담당: {status.get('owner')}" if status.get("owner") else "",
                 f"기한: {status.get('due_date')}" if status.get("due_date") else ""] if x)
        lines.append(f"· {stmeta}")
        lines.append("")
        lines.append("■ 실증적 (수집 시점):")
        any_ev = False
        for e in detail.get("evidence_live", []):
            summ = e.get("summary_ko") or e.get("summary_en") or ""
            if summ:
                any_ev = True
                lines.append(f"  [{e.get('label_ko') or e.get('source','')}] {summ}")
            # fleet/zabbix 는 '몇 개'가 아니라 실제 호스트 목록을 직접 나열
            src_hosts = host_lists.get(e.get("source", ""))
            if src_hosts:
                for hrow in src_hosts:
                    meta = " · ".join(x for x in [hrow.get("ip", ""), hrow.get("status", "")] if x and x != "-")
                    lines.append(f"    - {hrow['hostname']}" + (f" ({meta})" if meta else ""))
            else:
                for row in (e.get("breakdown") or []):
                    lines.append(f"    - {row.get('label','')}: {row.get('value','')}")
                if e.get("more"):
                    lines.append(f"    … 외 {e.get('more')}건")
        if not any_ev:
            lines.append("  (현재 수집된 라이브 증적 없음)")
        return "\n".join(lines)

    def _snapshot_control(control_id: str, detail: dict[str, Any], user: str,
                          host_lists: dict[str, list[dict[str, str]]], kind: str = "auto") -> dict[str, Any]:
        """detail 로부터 상세 스냅샷 증적 레코드 생성·영속. kind: auto(수동) | scheduled(일정)."""
        import uuid
        status = ctx.control_status.get(control_id, {})
        now = datetime.now(tz=timezone.utc)
        today = now.strftime("%Y-%m-%d")
        label = "실증적 자동 스냅샷" if kind == "auto" else "실증적 정기 스냅샷"
        rec = {
            "id": str(uuid.uuid4()), "control_id": control_id,
            "title": f"{label} ({today})", "body": _compose_snapshot_body(detail, status, host_lists),
            "collected_by": user or "system", "collected_at": today,
            "reference": f"auto:{kind} 라이브 증적 스냅샷", "source": "auto",
            "created_at": now.isoformat(), "created_by": user or "system",
        }
        _persist_evidence(rec)
        return rec

    @app.post("/controls/detail/{control_id}/evidence-records/auto", tags=["Compliance"])
    def auto_evidence_snapshot(control_id: str, request: Request) -> dict[str, Any]:
        """실증적(현재) 라이브 집계를 날짜 찍힌 **상세** 증적 레코드로 자동 스냅샷. admin·security.

        휘발성 라이브 증적(Fleet 자산·Zabbix 경보·계정·매핑 등)을 전 엔티티 상세로 캡처해
        수기 증적처럼 영속화한다. 심사 대비 '이 날 이만큼의 증적이 있었다' 시점 증거.
        """
        _require_ev(request)
        from mori_soc.services.control_catalog import build_control_detail
        detail = build_control_detail(control_id, gaps=_live_gaps(), metrics=_source_metrics(limit=200),
                                      catalog=_merged_catalog())
        if detail is None:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        rec = _snapshot_control(control_id, detail, user or "", _evidence_host_lists(), kind="auto")
        if ctx.log_action:
            ctx.log_action(user or "system", "CONTROL_EVIDENCE_AUTO", control_id)
        return rec

    # ── 일정 자동 스냅샷 (admin 설정 — off/daily/weekly/monthly) ───────────────────
    _SNAP_SCHEDULES = ("off", "daily", "weekly", "monthly")
    _SNAP_PERIOD_DAYS = {"daily": 1, "weekly": 7, "monthly": 30}
    _SNAP_SCHED_KEY = "evidence_snapshot_schedule"
    _SNAP_SCOPE_KEY = "evidence_snapshot_scope"
    _SNAP_LAST_KEY = "evidence_snapshot_last_run"

    def _snap_cfg() -> tuple[str, str, str]:
        s = ctx.settings or {}
        sched = str(s.get(_SNAP_SCHED_KEY, "off")).strip() or "off"
        if sched not in _SNAP_SCHEDULES:
            sched = "off"
        scope = str(s.get(_SNAP_SCOPE_KEY, "mapped")).strip() or "mapped"
        if scope not in ("mapped", "all"):
            scope = "mapped"
        return sched, scope, str(s.get(_SNAP_LAST_KEY, "")).strip()

    def _snap_due(now: datetime) -> bool:
        sched, _scope, last = _snap_cfg()
        if sched == "off":
            return False
        if not last:
            return True
        try:
            lastdt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            if lastdt.tzinfo is None:
                lastdt = lastdt.replace(tzinfo=timezone.utc)
        except ValueError:
            return True
        return (now - lastdt).total_seconds() >= _SNAP_PERIOD_DAYS[sched] * 86400

    def _run_bulk_snapshot(user: str, kind: str) -> int:
        """전 통제(또는 매핑된 통제) 일괄 상세 스냅샷. 반환: 생성 건수."""
        from mori_soc.services.control_catalog import build_control_detail
        _sched, scope, _last = _snap_cfg()
        now = datetime.now(tz=timezone.utc)
        catalog = _merged_catalog()
        gaps = _live_gaps()
        metrics = _source_metrics(limit=200)
        host_lists = _evidence_host_lists()
        count = 0
        for c in catalog.get("controls", []):
            cid = c.get("id")
            if not cid:
                continue
            if scope == "mapped" and not (c.get("evidence_sources")):
                continue
            detail = build_control_detail(cid, gaps=gaps, metrics=metrics, catalog=catalog)
            if detail is None:
                continue
            _snapshot_control(cid, detail, user or "system", host_lists, kind=kind)
            count += 1
        ctx.settings[_SNAP_LAST_KEY] = now.isoformat()
        if ctx.persist_setting:
            ctx.persist_setting(_SNAP_LAST_KEY, user or "system")
        if ctx.log_action:
            ctx.log_action(user or "system", "EVIDENCE_SNAPSHOT_BULK", f"{kind}: {count}건 ({scope})")
        return count

    def _maybe_run_scheduled_snapshot() -> None:
        """부팅/열람 시 일정 도래하면 일괄 스냅샷(최선노력, 실패해도 무시)."""
        try:
            if _snap_due(datetime.now(tz=timezone.utc)):
                n = _run_bulk_snapshot("system", "scheduled")
                logger.info("[evidence] scheduled snapshot ran: %s controls", n)
        except Exception as exc:  # pragma: no cover - best effort
            logger.warning("[evidence] scheduled snapshot skipped: %s", exc)

    @app.get("/controls/evidence-snapshot/config", tags=["Compliance"])
    def get_snapshot_config(request: Request) -> dict[str, Any]:
        """일정 자동 스냅샷 설정 조회. admin 전용."""
        _require_catalog_admin(request)
        sched, scope, last = _snap_cfg()
        return {"schedule": sched, "scope": scope, "last_run": last,
                "schedules": list(_SNAP_SCHEDULES), "due": _snap_due(datetime.now(tz=timezone.utc))}

    @app.post("/controls/evidence-snapshot/config", tags=["Compliance"])
    def set_snapshot_config(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """일정 자동 스냅샷 설정 {schedule: off|daily|weekly|monthly, scope: mapped|all}. admin 전용."""
        actor = _require_catalog_admin(request)
        sched = str(payload.get("schedule", "")).strip()
        if sched not in _SNAP_SCHEDULES:
            raise HTTPException(status_code=400, detail=f"schedule must be one of {list(_SNAP_SCHEDULES)}")
        scope = str(payload.get("scope", "mapped")).strip()
        if scope not in ("mapped", "all"):
            scope = "mapped"
        ctx.settings[_SNAP_SCHED_KEY] = sched
        ctx.settings[_SNAP_SCOPE_KEY] = scope
        if ctx.persist_setting:
            ctx.persist_setting(_SNAP_SCHED_KEY, actor)
            ctx.persist_setting(_SNAP_SCOPE_KEY, actor)
        if ctx.log_action:
            ctx.log_action(actor, "EVIDENCE_SNAPSHOT_CONFIG", f"{sched} ({scope})")
        return {"schedule": sched, "scope": scope}

    @app.post("/controls/evidence-snapshot/run", tags=["Compliance"])
    def run_bulk_snapshot_now(request: Request) -> dict[str, Any]:
        """지금 전 통제(설정 scope) 일괄 스냅샷 실행. admin 전용."""
        actor = _require_catalog_admin(request)
        count = _run_bulk_snapshot(actor, "manual")
        return {"ok": True, "count": count}

    # ── 월간 접속기록 점검 (안전조치 제8조: 월 1회 이상 점검) ──────────────────────
    _LOG_REVIEW_CONTROLS = ("2.9.4", "A.8.15")

    def _log_review_records() -> list[dict[str, Any]]:
        return sorted([r for r in (ctx.control_evidence or {}).values() if r.get("source") == "log_review"],
                      key=lambda r: str(r.get("collected_at") or ""), reverse=True)

    @app.get("/compliance/log-review", tags=["Compliance"])
    def get_log_review(request: Request) -> dict[str, Any]:
        """접속기록 보존현황 + 월간 점검 이력. admin·security."""
        _require_ev(request)
        recs = _log_review_records()
        this_month = datetime.now(tz=timezone.utc).strftime("%Y-%m")
        done = any(str(r.get("collected_at", "")).startswith(this_month) for r in recs)
        return {"retention": _log_retention_status(), "this_month": this_month,
                "reviewed_this_month": done, "controls": list(_LOG_REVIEW_CONTROLS),
                "history": [{"month": str(r.get("collected_at", ""))[:7], "collected_at": r.get("collected_at"),
                             "by": r.get("collected_by"), "title": r.get("title"),
                             "control_id": r.get("control_id")} for r in recs][:24]}

    @app.post("/compliance/log-review/run", tags=["Compliance"])
    def run_log_review(request: Request) -> dict[str, Any]:
        """이번 달 접속기록 점검 수행 — 보존현황 스냅샷을 로그 통제 증적으로 적립. admin·security."""
        _require_ev(request)
        import uuid
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        ret = _log_retention_status()
        now = datetime.now(tz=timezone.utc)
        today, month = now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")
        badge = "충족" if ret.get("ok") else ("미관측" if not ret.get("observed") else "미달")
        lines = [f"■ 접속기록 월간 점검 ({month}) — 안전성 확보조치 기준 제8조",
                 f"· 목표 보존기간: {ret['target_days']}일" + (" (개인정보 처리: 2년 기준)" if ret.get("personal") else ""),
                 f"· 관측 기록 범위: {ret['span_days'] if ret.get('span_days') is not None else '미관측'}일 → {badge}",
                 "· 소스별 현황:"]
        for r in ret.get("sources", []):
            lines.append(f"   - {r['source']}: 최古 {r['oldest'] or '-'} · {r['span_days']}일 · {r['count']}건")
        lines.append("· 이상징후 검토: (심야접근·대량조회·미승인IP 등 검토 결과 기입)")
        lines.append("· 점검 결론: 로그시스템 retention 설정 증빙과 대조 후 적정성 판단")
        body = "\n".join(lines)
        ids = {c.get("id") for c in _merged_catalog().get("controls", [])}
        created = 0
        for cid in _LOG_REVIEW_CONTROLS:
            if cid not in ids:
                continue
            rec = {"id": str(uuid.uuid4()), "control_id": cid, "title": f"접속기록 월간 점검 ({month})",
                   "body": body, "collected_by": user or "system", "collected_at": today,
                   "reference": "log_review 제8조 월1회 점검", "source": "log_review",
                   "created_at": now.isoformat(), "created_by": user or "system"}
            _persist_evidence(rec)
            created += 1
        if ctx.log_action:
            ctx.log_action(user or "system", "LOG_REVIEW_RUN", f"{month}: {created} controls")
        return {"ok": True, "month": month, "created": created, "retention": ret}

    # ── SoA (ISO 27001 적용선언서, clause 6.1.3) — 카탈로그 + control_status 조립 ──────
    def _soa_rows() -> list[dict[str, Any]]:
        from mori_soc.services.soa import build_soa_rows
        return build_soa_rows(_merged_catalog(), ctx.control_status)

    @app.get("/compliance/soa", tags=["Compliance"])
    def compliance_soa(request: Request) -> dict[str, Any]:
        """ISO 27001 적용선언서(SoA) — 통제별 적용여부·근거·이행상태. admin·security."""
        _require_ev(request)
        from mori_soc.services.soa import soa_summary
        rows = _soa_rows()
        return {"rows": rows, "summary": soa_summary(rows)}

    @app.get("/compliance/soa.csv", tags=["Compliance"])
    def compliance_soa_csv(request: Request) -> Any:
        _require_ev(request)
        from mori_soc.services.soa import soa_to_csv
        return StreamingResponse(iter(["﻿" + soa_to_csv(_soa_rows())]), media_type="text/csv",
                                 headers={"Content-Disposition": 'attachment; filename="mori-soa.csv"'})

    @app.get("/compliance/soa.pdf", tags=["Compliance"])
    def compliance_soa_pdf(request: Request) -> Any:
        _require_ev(request)
        from mori_soc.services.soa import soa_summary, soa_to_pdf
        rows = _soa_rows()
        try:
            pdf = soa_to_pdf(rows, soa_summary(rows))
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"SoA PDF unavailable: {exc}") from exc
        return StreamingResponse(iter([pdf]), media_type="application/pdf",
                                 headers={"Content-Disposition": 'attachment; filename="mori-soa.pdf"'})

    @app.delete("/controls/detail/{control_id}/evidence-records/{evidence_id}", tags=["Compliance"])
    def delete_evidence_record(control_id: str, evidence_id: str, request: Request) -> dict[str, Any]:
        _require_ev(request)
        rec = ctx.control_evidence.get(evidence_id)
        if rec is None or rec.get("control_id") != control_id:
            raise HTTPException(status_code=404, detail="증적 레코드를 찾을 수 없습니다.")
        ctx.control_evidence.pop(evidence_id, None)
        if ctx.delete_control_evidence:
            ctx.delete_control_evidence(evidence_id)
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        if ctx.log_action:
            ctx.log_action(user or "unknown", "CONTROL_EVIDENCE_DELETE", f"{control_id}: {rec.get('title','')}")
        return {"ok": True, "id": evidence_id}

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
        import csv as csv_mod
        import io
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

    # 부팅 시 일정 도래하면 일괄 스냅샷(재기동으로 월간 트리거 커버). 실패해도 앱 기동 계속.
    _maybe_run_scheduled_snapshot()


__all__ = ["register_compliance"]
