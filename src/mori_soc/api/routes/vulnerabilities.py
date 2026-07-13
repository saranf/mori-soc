"""Per-vulnerability action routes (Task J-4b6).

Registers the vulnerability plan / exception endpoints on ``ctx.app``. Handler
bodies — and the four block-local helpers (``_vuln_action_default``,
``_vuln_exists``, ``_vuln_lookup``, ``_record_vuln_audit``) — are verbatim from
the original ``create_app`` closures; only the unpacking preamble (binding shared
stores + the ``get_query_service`` / ``get_session_username`` helpers from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext
from mori_soc.api.routes.settings import read_risk_doa
from mori_soc.services.asset_classifier import classify_server_as_dict
from mori_soc.services.risk_assessment import assess_risk, grade_from_axes

# 위험처리 결정 허용값: 조치/수용/이관/회피 (+ 미정)
_TREATMENTS = {"", "mitigate", "accept", "transfer", "avoid"}


def register_vulnerabilities(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    asset_audit_log = ctx.asset_audit_log
    vuln_actions = ctx.vuln_actions
    asset_owners = ctx.asset_owners
    risk_register = ctx.risk_register
    _get_session_username = ctx.get_session_username
    _persist_asset_audit = ctx.persist_asset_audit
    _persist_vuln_action = ctx.persist_vuln_action
    _persist_risk_assessment = ctx.persist_risk_assessment

    def _vuln_action_default(vuln_id: str) -> dict[str, Any]:
        return {
            "vuln_id": vuln_id,
            "plan_text": "", "plan_target_date": "", "plan_updated_by": "",
            "exception_until": "", "exception_reason": "", "exception_updated_by": "",
            "updated_at": None,
        }

    def _vuln_exists(vuln_id: str) -> bool:
        for v in get_query_service().store.vulnerabilities:
            if v.vuln_id == vuln_id:
                return True
        return False

    def _vuln_lookup(vuln_id: str) -> tuple[Any, str, str]:
        """vuln_id → (vuln_obj, hostname, cve_label) 반환. 없으면 (None, "", vuln_id)."""
        store_ = get_query_service().store
        for v in store_.vulnerabilities:
            if v.vuln_id == vuln_id:
                hostname = next((h.hostname for h in store_.hosts if h.host_id == v.host_id), v.host_id)
                return v, hostname, (v.cve or vuln_id)
        return None, "", vuln_id

    def _record_vuln_audit(
        hostname: str,
        cve_label: str,
        old_entry: dict[str, Any],
        new_entry: dict[str, Any],
        changed_by: str,
        now_str: str,
        fields: tuple[str, ...],
    ) -> None:
        """vuln_actions 변경분을 asset_audit_log에 기록한다."""
        if not hostname:
            return
        for fld in fields:
            old_val = old_entry.get(fld, "")
            new_val = new_entry.get(fld, "")
            if old_val == new_val:
                continue
            audit_entry = {
                "log_id": str(uuid.uuid4()),
                "hostname": hostname,
                "field": f"vuln_{fld} [{cve_label}]",
                "old_value": old_val,
                "new_value": new_val,
                "changed_by": changed_by,
                "changed_at": now_str,
            }
            asset_audit_log.append(audit_entry)
            _persist_asset_audit(audit_entry)

    @app.get("/vulnerabilities/{vuln_id}/action", tags=["Vulnerabilities"])
    def vuln_action_get(vuln_id: str) -> Any:
        if not _vuln_exists(vuln_id):
            raise HTTPException(status_code=404, detail="vulnerability not found")
        return vuln_actions.get(vuln_id, _vuln_action_default(vuln_id))

    @app.put("/vulnerabilities/{vuln_id}/plan", tags=["Vulnerabilities"])
    def vuln_plan_upsert(vuln_id: str, payload: dict[str, Any], request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        old_entry = dict(vuln_actions.get(vuln_id, _vuln_action_default(vuln_id)))
        entry = old_entry | {"vuln_id": vuln_id}
        entry["plan_text"] = str(payload.get("plan_text", "")).strip()
        entry["plan_target_date"] = str(payload.get("plan_target_date", "")).strip()
        entry["plan_updated_by"] = str(payload.get("plan_updated_by", "")).strip() or "unknown"
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        vuln_actions[vuln_id] = entry
        _persist_vuln_action(vuln_id)
        changed_by = entry["plan_updated_by"] if entry["plan_updated_by"] != "unknown" else (_get_session_username(request) or "unknown")
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("plan_text", "plan_target_date"))
        return entry

    @app.put("/vulnerabilities/{vuln_id}/exception", tags=["Vulnerabilities"])
    def vuln_exception_upsert(vuln_id: str, payload: dict[str, Any], request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        old_entry = dict(vuln_actions.get(vuln_id, _vuln_action_default(vuln_id)))
        entry = old_entry | {"vuln_id": vuln_id}
        entry["exception_until"] = str(payload.get("exception_until", "")).strip()
        entry["exception_reason"] = str(payload.get("exception_reason", "")).strip()
        entry["exception_updated_by"] = str(payload.get("exception_updated_by", "")).strip() or "unknown"
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        vuln_actions[vuln_id] = entry
        _persist_vuln_action(vuln_id)
        changed_by = entry["exception_updated_by"] if entry["exception_updated_by"] != "unknown" else (_get_session_username(request) or "unknown")
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("exception_until", "exception_reason"))
        return entry

    @app.delete("/vulnerabilities/{vuln_id}/exception", tags=["Vulnerabilities"])
    def vuln_exception_clear(vuln_id: str, request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        entry = vuln_actions.get(vuln_id)
        if entry is None:
            return {"ok": True}
        old_entry = dict(entry)
        entry["exception_until"] = ""
        entry["exception_reason"] = ""
        entry["exception_updated_by"] = ""
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        _persist_vuln_action(vuln_id)
        changed_by = _get_session_username(request) or "unknown"
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("exception_until", "exception_reason"))
        return {"ok": True, "vuln_id": vuln_id}

    # ── 위험성 평가 (Risk Assessment, R-3) ────────────────────────────────────
    def _risk_default(vuln_id: str) -> dict[str, Any]:
        return {
            "vuln_id": vuln_id, "impact": 0, "likelihood": 0, "score": 0, "level": "",
            "treatment": "", "accept_reason": "", "accept_approver": "",
            "residual_level": "", "review_due": "", "assessed_by": "",
            "assessed_at": None, "updated_at": None,
        }

    def _effective_importance(hostname: str) -> tuple[str, str]:
        """자산 중요도와 그 출처를 반환.

        Returns:
            (importance, source) — source ∈ {"owner"(담당자 수동지정),
            "auto"(호스트명 자동분류)}. payloads.py의 override 규칙과 동일.
        """
        owner_info = asset_owners.get(hostname, {})
        owner_importance = (owner_info.get("importance") or "").strip()
        if owner_importance:
            return owner_importance, "owner"
        return classify_server_as_dict(hostname).get("importance", "중"), "auto"

    def _exception_expired(vuln_id: str) -> bool:
        """등록된 예외(exception_until)가 오늘 이전이면 만료(통제 공백)로 본다."""
        raw = ((vuln_actions.get(vuln_id) or {}).get("exception_until") or "").strip()
        if not raw:
            return False
        try:
            due = date.fromisoformat(raw[:10])
        except ValueError:
            return False
        return due < datetime.now(tz=timezone.utc).date()

    def _suggest_risk(vuln_obj: Any, hostname: str, vuln_id: str) -> dict[str, Any]:
        """현재 데이터로 자동 산정한 위험등급(제안값). 저장하지 않는다.

        ``provenance``: 이 등급이 '어떤 데이터/소스 기반'인지 — 어드민이 근거를
        추적할 수 있도록 스캐너 소스·자산·패키지·버전·중요도 출처를 함께 싣는다.
        """
        importance, importance_source = _effective_importance(hostname)
        severity = getattr(vuln_obj, "severity", "info")
        fixed_version = getattr(vuln_obj, "fixed_version", None)
        fixed_available = bool(fixed_version)
        exception_expired = _exception_expired(vuln_id)
        assessment = assess_risk(
            importance, severity,
            fixed_available=fixed_available, exception_expired=exception_expired,
        )
        detected_at = getattr(vuln_obj, "detected_at", None)
        return {
            **assessment.to_dict(),
            "inputs": {
                "importance": importance, "severity": severity,
                "fixed_available": fixed_available, "exception_expired": exception_expired,
            },
            "provenance": {
                "data_source": getattr(vuln_obj, "source", ""),   # trivy / fleet (어떤 스캐너 DB 기반인지)
                "hostname": hostname,
                "host_id": getattr(vuln_obj, "host_id", ""),
                "cve": getattr(vuln_obj, "cve", None) or vuln_id,
                "package_name": getattr(vuln_obj, "package_name", None) or "",
                "installed_version": getattr(vuln_obj, "installed_version", None) or "",
                "fixed_version": fixed_version or "",
                "detected_at": _isoformat(detected_at) if detected_at else None,
                "importance": importance,
                "importance_source": importance_source,   # owner(담당자 지정) / auto(자동분류)
                "raw_ref": getattr(vuln_obj, "raw_ref", None) or "",
            },
        }

    @app.get("/vulnerabilities/{vuln_id}/risk", tags=["Vulnerabilities"])
    def vuln_risk_get(vuln_id: str) -> Any:
        vuln_obj, hostname, _cve = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        suggestion = _suggest_risk(vuln_obj, hostname, vuln_id)
        stored = risk_register.get(vuln_id)
        if stored is not None:
            return {**stored, "suggested": False, "suggestion": suggestion}
        # 미평가: 제안값을 기본 레코드에 얹어 돌려준다(저장 전).
        return {
            **_risk_default(vuln_id),
            "impact": suggestion["impact"], "likelihood": suggestion["likelihood"],
            "score": suggestion["score"], "level": suggestion["level"],
            "suggested": True, "suggestion": suggestion,
        }

    @app.put("/vulnerabilities/{vuln_id}/risk", tags=["Vulnerabilities"])
    def vuln_risk_upsert(vuln_id: str, payload: dict[str, Any], request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")

        # 영향도·발생가능성: 둘 다 주어지면 수동 산정, 아니면 자동 제안값 사용.
        if payload.get("impact") is not None and payload.get("likelihood") is not None:
            try:
                impact_in = int(payload["impact"])
                likelihood_in = int(payload["likelihood"])
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail="impact/likelihood must be integers 1..3") from exc
            if not (1 <= impact_in <= 3 and 1 <= likelihood_in <= 3):
                raise HTTPException(status_code=400, detail="impact/likelihood must be in 1..3")
            assessment = grade_from_axes(impact_in, likelihood_in)
        else:
            s = _suggest_risk(vuln_obj, hostname, vuln_id)
            assessment = grade_from_axes(s["impact"], s["likelihood"])

        treatment = str(payload.get("treatment", "")).strip()
        if treatment not in _TREATMENTS:
            raise HTTPException(status_code=400, detail=f"treatment must be one of {sorted(_TREATMENTS - {''})}")

        old_entry = dict(risk_register.get(vuln_id, _risk_default(vuln_id)))
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        assessed_by = str(payload.get("assessed_by", "")).strip() or (_get_session_username(request) or "unknown")
        entry = {
            "vuln_id": vuln_id,
            "impact": assessment.impact, "likelihood": assessment.likelihood,
            "score": assessment.score, "level": assessment.level,
            "treatment": treatment,
            "accept_reason": str(payload.get("accept_reason", "")).strip(),
            "accept_approver": str(payload.get("accept_approver", "")).strip(),
            "residual_level": str(payload.get("residual_level", "")).strip(),
            "review_due": str(payload.get("review_due", "")).strip(),
            "assessed_by": assessed_by,
            "assessed_at": old_entry.get("assessed_at") or now_str,
            "updated_at": now_str,
        }
        risk_register[vuln_id] = entry
        _persist_risk_assessment(vuln_id)
        _record_vuln_audit(
            hostname, cve_label, old_entry, entry, assessed_by, now_str,
            ("level", "treatment"),
        )
        return entry

    @app.get("/vulnerabilities/risk-summary", tags=["Vulnerabilities"])
    def vuln_risk_summary(source: str = "") -> Any:
        """전체 취약점의 위험등급 집계 — 3×3 매트릭스 히트맵 + 등급별 카운트 + 목록.

        저장된 평가가 있으면 그 값을, 없으면 자동 제안값을 쓴다(assessed 플래그로 구분).
        matrix[r][c]: r = 영향도(상→0, 중→1, 하→2 행), c = 발생가능성(하→0, 중→1, 상→2 열).
        """
        store_ = get_query_service().store
        host_by_id = {h.host_id: h.hostname for h in store_.hosts}
        src = source.strip().lower()
        doa = read_risk_doa(ctx.settings)
        matrix = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
        by_level = {"매우높음": 0, "높음": 0, "중간": 0, "낮음": 0}
        items: list[dict[str, Any]] = []
        assessed_count = 0
        accepted_count = 0
        for v in store_.vulnerabilities:
            if src and (getattr(v, "source", "") != src):
                continue
            hostname = host_by_id.get(v.host_id, v.host_id)
            stored = risk_register.get(v.vuln_id)
            if stored and stored.get("score"):
                impact, likelihood = stored["impact"], stored["likelihood"]
                score, level = stored["score"], stored["level"]
                treatment, assessed = stored.get("treatment", ""), True
                assessed_count += 1
            else:
                importance, _src2 = _effective_importance(hostname)
                a = assess_risk(
                    importance, getattr(v, "severity", "info"),
                    fixed_available=bool(getattr(v, "fixed_version", None)),
                    exception_expired=_exception_expired(v.vuln_id),
                )
                impact, likelihood, score, level = a.impact, a.likelihood, a.score, a.level
                treatment, assessed = "", False
            matrix[3 - impact][likelihood - 1] += 1
            by_level[level] = by_level.get(level, 0) + 1
            # DoA 자동 수용: 점수 ≤ DoA 이고 '조치(mitigate)'로 명시되지 않은 항목.
            # 명시적 accept/transfer/avoid 는 이미 수용/이관/회피이므로 수용 집계에 포함.
            doa_accept = score <= doa and treatment != "mitigate"
            if doa_accept:
                accepted_count += 1
            items.append({
                "vuln_id": v.vuln_id, "cve": getattr(v, "cve", None) or v.vuln_id,
                "hostname": hostname, "source": getattr(v, "source", ""),
                "severity": getattr(v, "severity", "info"),
                "impact": impact, "likelihood": likelihood, "score": score, "level": level,
                "treatment": treatment, "assessed": assessed, "doa_accept": doa_accept,
            })
        items.sort(key=lambda x: (-x["score"], x["cve"]))
        return {
            "matrix": matrix, "by_level": by_level, "items": items,
            "total": len(items), "assessed": assessed_count,
            "doa": doa, "accepted": accepted_count,
        }


__all__ = ["register_vulnerabilities"]
