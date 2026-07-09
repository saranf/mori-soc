"""Compliance routes (Task J-4b8).

Registers the PDCA / crosscheck / evidence-report endpoints on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures; only the
unpacking preamble (binding shared stores + the ``get_query_service`` helper from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
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

logger = logging.getLogger("mori_soc.api.compliance")

# M2-7: 통제 이행 상태 허용값 (ISMS-P 자율점검 관점)
_CONTROL_STATUSES = {"미정", "이행", "부분이행", "미이행", "해당없음"}


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

    @app.get("/controls/tree", tags=["Compliance"])
    def controls_tree(request: Request) -> dict[str, Any]:
        """통제 카탈로그(ISMS-P × ISO) 트리 + lite/full 커버리지. admin·security 전용.

        정본 controls/*.yaml → 패키지 JSON 아티팩트를 읽어 framework→domain→section→
        controls 트리와 증적 소스 커버리지(lite/full)를 반환한다(한/영 병기).
        """
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="control catalog requires admin or security role")
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
            try:
                cross = build_crosscheck_payload(get_query_service())
                for chk in cross.get("checks", []) or []:
                    if chk.get("id") == "source_coverage":
                        unmapped = int(chk.get("uncovered_hosts", 0) or 0)
                        break
            except Exception:
                unmapped = 0
            return {"vuln_pending": int(src.get("trivy", 0) or 0), "exceptions_expiring": expiring,
                    "untriaged_alerts": int(src.get("alert", 0) or 0),
                    "overdue": int(pdca.get("overdue_count", 0) or 0),
                    "control_pending": int(src.get("control_check", 0) or 0), "unmapped_assets": unmapped}
        except Exception:
            return {}

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
        m["loki"] = {"summary_ko": "로그 보존 정책 적용(Loki)", "summary_en": "log retention configured (Loki)",
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
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="control detail requires admin or security role")
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
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="control status edit requires admin or security role")
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
        """통제 증적 팩 PDF(1클릭 export). admin·security 전용."""
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="control evidence PDF requires admin or security role")
        from mori_soc.services.control_catalog import control_evidence_pdf
        try:
            pdf = control_evidence_pdf(control_id, gaps=_live_gaps(), metrics=_source_metrics(),
                                       catalog=_merged_catalog(), evidence_records=_evidence_for(control_id))
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if pdf is None:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        safe = control_id.replace("/", "_")
        return StreamingResponse(iter([pdf]), media_type="application/pdf",
                                 headers={"Content-Disposition": f'attachment; filename="mori-evidence-{safe}.pdf"'})

    @app.get("/controls/detail/{control_id}/evidence.csv", tags=["Compliance"])
    def control_evidence_csv_route(control_id: str, request: Request) -> Any:
        """통제 증적 팩 CSV(라이브 + 수기 증적 합본). admin·security 전용."""
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="control evidence CSV requires admin or security role")
        from mori_soc.services.control_catalog import control_evidence_csv
        csv_text = control_evidence_csv(control_id, gaps=_live_gaps(), metrics=_source_metrics(),
                                        catalog=_merged_catalog(), evidence_records=_evidence_for(control_id))
        if csv_text is None:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        safe = control_id.replace("/", "_")
        return StreamingResponse(iter(["﻿" + csv_text]), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="mori-evidence-{safe}.csv"'})

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
        result = parse_regulation_text(text, framework=framework, id_prefix=prefix)
        saved = []
        for c in result["controls"]:
            saved.append(_save_catalog_control(c, actor, origin="nlp"))
        if ctx.log_action:
            ctx.log_action(actor, "CATALOG_NLP_IMPORT", f"{result['method']}: {len(saved)}건 ({framework})")
        return {"method": result["method"], "count": len(saved),
                "controls": [{"id": c["control_id"], "title_ko": c.get("title_ko", "")} for c in saved]}

    # ── M2-8: 통제별 수기 증적 레코드 (admin·security) ────────────────────────────
    @app.get("/controls/detail/{control_id}/evidence-records", tags=["Compliance"])
    def list_evidence_records(control_id: str, request: Request) -> dict[str, Any]:
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="evidence records require admin or security role")
        rows = sorted(_evidence_for(control_id),
                      key=lambda r: str(r.get("collected_at") or r.get("created_at") or ""), reverse=True)
        return {"control_id": control_id, "records": rows, "total": len(rows)}

    @app.post("/controls/detail/{control_id}/evidence-records", tags=["Compliance"])
    def add_evidence_record(control_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """수기 증적 기록 추가 {title, body?, collected_by?, collected_at?, reference?}. admin·security."""
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="evidence records require admin or security role")
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
        ctx.control_evidence[rec["id"]] = rec
        if ctx.persist_control_evidence:
            ctx.persist_control_evidence(rec["id"])
        if ctx.log_action:
            ctx.log_action(user or "unknown", "CONTROL_EVIDENCE_ADD", f"{control_id}: {title}")
        return rec

    # ── M2-8: 실증적 자동 스냅샷 (상세값 캡처 + 일정 자동화) ───────────────────────
    def _compose_snapshot_body(detail: dict[str, Any], status: dict[str, Any]) -> str:
        """통제 detail(+상태)을 상세 증적 본문으로 조립 — 라이브 전 엔티티 + 메타 + 이행상태."""
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
            for row in (e.get("breakdown") or []):
                lines.append(f"    - {row.get('label','')}: {row.get('value','')}")
            if e.get("more"):
                lines.append(f"    … 외 {e.get('more')}건")
        if not any_ev:
            lines.append("  (현재 수집된 라이브 증적 없음)")
        if detail.get("mapped_to"):
            lines.append("")
            lines.append("■ 크로스매핑:")
            for m in detail["mapped_to"]:
                lines.append(f"  ↔ {m.get('id','')} {m.get('title_ko') or m.get('title_en') or ''} ({m.get('relation','')})")
        if detail.get("defects"):
            lines.append("")
            lines.append("■ 관련 심사 결함:")
            for d in detail["defects"]:
                gc = d.get("gap_count")
                gc_txt = f" · 현재 공백 {gc}건" if isinstance(gc, int) else ""
                lines.append(f"  ⚠ [{d.get('severity','')}] {d.get('title_ko') or ''}{gc_txt}")
        return "\n".join(lines)

    def _snapshot_control(control_id: str, detail: dict[str, Any], user: str, kind: str = "auto") -> dict[str, Any]:
        """detail 로부터 상세 스냅샷 증적 레코드 생성·영속. kind: auto(수동) | scheduled(일정)."""
        import uuid
        status = ctx.control_status.get(control_id, {})
        now = datetime.now(tz=timezone.utc)
        today = now.strftime("%Y-%m-%d")
        label = "실증적 자동 스냅샷" if kind == "auto" else "실증적 정기 스냅샷"
        rec = {
            "id": str(uuid.uuid4()), "control_id": control_id,
            "title": f"{label} ({today})", "body": _compose_snapshot_body(detail, status),
            "collected_by": user or "system", "collected_at": today,
            "reference": f"auto:{kind} 라이브 증적 스냅샷", "source": "auto",
            "created_at": now.isoformat(), "created_by": user or "system",
        }
        ctx.control_evidence[rec["id"]] = rec
        if ctx.persist_control_evidence:
            ctx.persist_control_evidence(rec["id"])
        return rec

    @app.post("/controls/detail/{control_id}/evidence-records/auto", tags=["Compliance"])
    def auto_evidence_snapshot(control_id: str, request: Request) -> dict[str, Any]:
        """실증적(현재) 라이브 집계를 날짜 찍힌 **상세** 증적 레코드로 자동 스냅샷. admin·security.

        휘발성 라이브 증적(Fleet 자산·Zabbix 경보·계정·매핑 등)을 전 엔티티 상세로 캡처해
        수기 증적처럼 영속화한다. 심사 대비 '이 날 이만큼의 증적이 있었다' 시점 증거.
        """
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="evidence records require admin or security role")
        from mori_soc.services.control_catalog import build_control_detail
        detail = build_control_detail(control_id, gaps=_live_gaps(), metrics=_source_metrics(limit=200),
                                      catalog=_merged_catalog())
        if detail is None:
            raise HTTPException(status_code=404, detail=f"control '{control_id}' not found")
        user = ctx.get_session_username(request) if ctx.get_session_username else ""
        rec = _snapshot_control(control_id, detail, user or "", kind="auto")
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
            _snapshot_control(cid, detail, user or "system", kind=kind)
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

    @app.delete("/controls/detail/{control_id}/evidence-records/{evidence_id}", tags=["Compliance"])
    def delete_evidence_record(control_id: str, evidence_id: str, request: Request) -> dict[str, Any]:
        if ctx.auth_enabled and _evidence_role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="evidence records require admin or security role")
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

    # 부팅 시 일정 도래하면 일괄 스냅샷(재기동으로 월간 트리거 커버). 실패해도 앱 기동 계속.
    _maybe_run_scheduled_snapshot()


__all__ = ["register_compliance"]
