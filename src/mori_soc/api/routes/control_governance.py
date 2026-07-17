"""통제 운영 플랫폼 라우트 — 기반 모델(통제 신규 에픽 Phase 1).

Framework / FrameworkVersion / ControlDefinition / ControlRelationship /
OrganizationControl / ScopeSnapshot / AssuranceCycle 의 CRUD + 버전 불변.
버전은 덮어쓰지 않는다 — active/retired 는 편집·삭제 거부(409), 새 버전으로 대체.
모든 편집은 admin·security 전용(통제 정본은 민감).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

_log = logging.getLogger("mori_soc.governance")

from mori_soc.api.routes.context import RouteContext
from mori_soc.services.control_governance import (
    APPLICABILITY_STATUSES,
    ASSESSMENT_STATUSES,
    EVIDENCE_STATUSES,
    KIND_ASSURANCE_CYCLE,
    KIND_CONTROL_DEF,
    KIND_CYCLE_CONTROL,
    KIND_EVIDENCE_CONTRACT,
    KIND_EVIDENCE_MAPPING,
    KIND_FRAMEWORK,
    KIND_FRAMEWORK_VERSION,
    KIND_ORG_CONTROL,
    KIND_RELATIONSHIP,
    KIND_SCOPE_SNAPSHOT,
    RELATIONSHIP_TYPES,
    _slug,
    apply_cycle_control_update,
    apply_overlay,
    apply_version_lifecycle,
    build_assurance_cycle,
    build_control_definition,
    build_crosswalk,
    build_cycle_audit_snapshot,
    build_cycle_control,
    build_evidence_contract,
    build_evidence_mapping,
    build_framework,
    build_framework_version,
    build_governance_event,
    build_organization_control,
    build_relationship,
    build_scope_snapshot,
    can_version_transition,
    cycle_control_as_of,
    diff_control_definitions,
    initialize_cycle_from_previous,
    is_mutable_version,
    periods_overlap,
    plan_catalog_import,
    plan_cycle_migration,
    verify_governance_chain,
)


def register_control_governance(ctx: RouteContext) -> None:
    app = ctx.app
    sessions = ctx.sessions

    def _role(request: Request) -> str | None:
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        return sess.get("role") if sess else None

    def _require(request: Request) -> str:
        if ctx.auth_enabled and _role(request) not in ("admin", "security"):
            raise HTTPException(status_code=403, detail="통제 운영은 admin·security 전용입니다.")
        return (ctx.get_session_username(request) if ctx.get_session_username else "") or "system"

    def _repo() -> Any:
        return ctx.state_repo

    def _now() -> str:
        return datetime.now(tz=timezone.utc).isoformat()

    def _load(kind: str) -> list[dict[str, Any]]:
        repo = _repo()
        return repo.load_governance(kind) if repo is not None else []

    def _find(kind: str, entity_id: str) -> dict[str, Any] | None:
        return next((r for r in _load(kind) if r.get("id") == entity_id), None)

    def _require_ref(kind: str, entity_id: str, label: str) -> None:
        """참조 대상이 실재하는지 검증(S1d) — 없으면 404. 감사 무결성상 dangling 참조 금지."""
        if entity_id and _find(kind, entity_id) is None:
            raise HTTPException(status_code=404, detail=f"{label}({entity_id})이(가) 존재하지 않습니다.")

    def _require_control_ref(entity_id: str) -> None:
        """control_ref 는 기준 통제(control_definition) 또는 내부통제(organization_control) 여야 한다."""
        if _find(KIND_CONTROL_DEF, entity_id) is None and _find(KIND_ORG_CONTROL, entity_id) is None:
            raise HTTPException(status_code=404,
                                detail=f"control_ref({entity_id})가 통제 정의·내부통제 어디에도 없습니다.")

    def _event_type(action: str) -> str:
        if "ACTIVATE" in action or "RETIRE" in action:
            return "lifecycle"
        if "MIGRATE" in action:
            return "migrate"
        if "UPDATE" in action:
            return "update"
        return "create"

    def _save(kind: str, rec: dict[str, Any], actor: str, action: str) -> dict[str, Any]:
        repo = _repo()
        if repo is not None:
            repo.save_governance(kind, rec["id"], rec)
            # append-only 이벤트 원장에 기록(hash chain) — projection 저장과 짝. 실패는 드러낸다.
            try:
                prev = repo.latest_governance_event()
                prev_hash = prev["hash"] if prev else "GENESIS"
                revision = len(repo.load_governance_events(kind, rec["id"])) + 1
                ev = build_governance_event(
                    prev_hash, kind=kind, entity_id=rec["id"], revision=revision,
                    event_type=_event_type(action), actor=actor, occurred_at=_now(),
                    payload=dict(rec))
                repo.append_governance_event(ev)
            except Exception:  # pragma: no cover - 이벤트 기록 실패가 projection 저장을 막지 않음
                _log.warning("[governance] event append failed for %s:%s", kind, rec.get("id"))
        if ctx.log_action:
            ctx.log_action(actor, action, rec["id"])
        return rec

    # ── 이중 모델 브리지(C6) — 기존 194 카탈로그를 governance 로 흡수(일방 import) ──────────
    @app.post("/governance/import-catalog", tags=["Governance"])
    def import_catalog(request: Request, framework: str | None = None) -> dict[str, Any]:
        """기존 통제 카탈로그를 governance FrameworkVersion+ControlDefinition 으로 가져온다(C6).

        정본을 둘로 두지 않기 위한 일방 흡수 경로. 이미 있는 레코드는 건너뛴다(idempotent).
        framework 쿼리로 특정 프레임워크만 가져올 수 있다. 공식 원문은 비우고 intent 는 mori_summary.
        """
        actor = _require(request)
        from mori_soc.services.control_catalog import load_catalog, merge_edits
        catalog = merge_edits(load_catalog(), ctx.catalog_edits or {})
        controls = catalog.get("controls", [])
        if framework:
            fw = _slug(framework)
            controls = [c for c in controls if _slug(str(c.get("framework") or "")) == fw]
        plan = plan_catalog_import(controls, now=_now(), created_by=actor)
        created = {"frameworks": 0, "framework_versions": 0, "control_definitions": 0}
        for fwrec in plan["frameworks"]:
            if _find(KIND_FRAMEWORK, fwrec["id"]) is None:
                _save(KIND_FRAMEWORK, fwrec, actor, "GOV_FRAMEWORK_CREATE")
                created["frameworks"] += 1
        for fv in plan["framework_versions"]:
            if _find(KIND_FRAMEWORK_VERSION, fv["id"]) is None:
                _save(KIND_FRAMEWORK_VERSION, fv, actor, "GOV_VERSION_CREATE")
                created["framework_versions"] += 1
        for cdef in plan["control_definitions"]:
            if _find(KIND_CONTROL_DEF, cdef["id"]) is None:
                _save(KIND_CONTROL_DEF, cdef, actor, "GOV_CONTROL_CREATE")
                created["control_definitions"] += 1
        return {"imported": created,
                "totals": {"frameworks": len(plan["frameworks"]),
                           "framework_versions": len(plan["framework_versions"]),
                           "control_definitions": len(plan["control_definitions"])}}

    # ── Framework ──────────────────────────────────────────────────────────────
    @app.get("/governance/frameworks", tags=["Governance"])
    def list_frameworks(request: Request) -> dict[str, Any]:
        _require(request)
        return {"frameworks": _load(KIND_FRAMEWORK)}

    @app.post("/governance/frameworks", tags=["Governance"])
    def create_framework(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        name = str(payload.get("name", "")).strip()
        fid = str(payload.get("framework_id", "") or name).strip()
        if not name or not fid:
            raise HTTPException(status_code=400, detail="framework_id 와 name 은 필수입니다.")
        rec = build_framework(framework_id=fid, name=name,
                              type_=str(payload.get("type", "certification")),
                              publisher=str(payload.get("publisher", "")), now=_now(), created_by=actor)
        if _find(KIND_FRAMEWORK, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 framework 입니다.")
        return _save(KIND_FRAMEWORK, rec, actor, "GOV_FRAMEWORK_CREATE")

    # ── FrameworkVersion (불변) ────────────────────────────────────────────────
    @app.get("/governance/frameworks/{framework_id}/versions", tags=["Governance"])
    def list_versions(framework_id: str, request: Request) -> dict[str, Any]:
        _require(request)
        fid = _slug(framework_id)  # 'ISMS-P' 든 'isms-p' 든 동일 조회(대소문자 무관)
        vs = [v for v in _load(KIND_FRAMEWORK_VERSION) if v.get("framework_id") == fid]
        vs.sort(key=lambda v: str(v.get("version")))
        return {"framework_id": fid, "versions": vs}

    @app.post("/governance/framework-versions", tags=["Governance"])
    def create_version(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        fid = str(payload.get("framework_id", "")).strip()
        version = str(payload.get("version", "")).strip()
        if not fid or not version:
            raise HTTPException(status_code=400, detail="framework_id 와 version 은 필수입니다.")
        if not _find(KIND_FRAMEWORK, fid) and not _find(KIND_FRAMEWORK, fid.lower()):
            raise HTTPException(status_code=404, detail="framework 를 먼저 등록하세요.")
        rec = build_framework_version(
            framework_id=fid, version=version,
            effective_from=str(payload.get("effective_from", "")),
            effective_to=payload.get("effective_to"),
            source_type=str(payload.get("source_type", "user_upload")),
            source_hash=str(payload.get("source_hash", "")),
            supersedes=payload.get("supersedes"),
            change_reason=str(payload.get("change_reason", "")),
            importer_version=str(payload.get("importer_version", "")), now=_now(), created_by=actor)
        if _find(KIND_FRAMEWORK_VERSION, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 버전입니다(덮어쓰기 금지).")
        return _save(KIND_FRAMEWORK_VERSION, rec, actor, "GOV_VERSION_CREATE")

    @app.post("/governance/framework-versions/{fv_id}/activate", tags=["Governance"])
    def activate_version(fv_id: str, request: Request) -> dict[str, Any]:
        """draft → active. 상태기계·framework 당 active 1개·시행기간 겹침을 강제한다(S1c)."""
        actor = _require(request)
        rec = _find(KIND_FRAMEWORK_VERSION, fv_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="버전을 찾을 수 없습니다.")
        if not can_version_transition(str(rec.get("status")), "active"):
            raise HTTPException(status_code=409,
                                detail=f"{rec.get('status')} → active 전이는 허용되지 않습니다(draft 만 활성화).")
        # 같은 framework 에 이미 active 버전이 있으면 거부(운영자가 먼저 retire).
        others = [v for v in _load(KIND_FRAMEWORK_VERSION)
                  if v.get("framework_id") == rec.get("framework_id") and v.get("id") != fv_id]
        for o in others:
            if o.get("status") == "active":
                raise HTTPException(status_code=409,
                                    detail=f"이미 active 버전({o['id']})이 있습니다. 먼저 retire 하세요.")
            if o.get("status") in ("active",) and periods_overlap(
                    rec.get("effective_from", ""), rec.get("effective_to"),
                    o.get("effective_from", ""), o.get("effective_to")):
                raise HTTPException(status_code=409, detail=f"시행기간이 {o['id']} 와 겹칩니다.")
        apply_version_lifecycle(rec, "active", actor=actor, now=_now())
        return _save(KIND_FRAMEWORK_VERSION, rec, actor, "GOV_VERSION_ACTIVATE")

    @app.post("/governance/framework-versions/{fv_id}/retire", tags=["Governance"])
    def retire_version(fv_id: str, request: Request) -> dict[str, Any]:
        """active → retired. retired 재활성은 상태기계가 막는다(S1c)."""
        actor = _require(request)
        rec = _find(KIND_FRAMEWORK_VERSION, fv_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="버전을 찾을 수 없습니다.")
        if not can_version_transition(str(rec.get("status")), "retired"):
            raise HTTPException(status_code=409,
                                detail=f"{rec.get('status')} → retired 전이는 허용되지 않습니다(active 만 폐기).")
        apply_version_lifecycle(rec, "retired", actor=actor, now=_now())
        return _save(KIND_FRAMEWORK_VERSION, rec, actor, "GOV_VERSION_RETIRE")

    # ── ControlDefinition ──────────────────────────────────────────────────────
    @app.get("/governance/framework-versions/{fv_id}/controls", tags=["Governance"])
    def list_controls(fv_id: str, request: Request) -> dict[str, Any]:
        _require(request)
        cs = [c for c in _load(KIND_CONTROL_DEF) if c.get("framework_version_id") == fv_id]
        cs.sort(key=lambda c: str(c.get("display_code")))
        return {"framework_version_id": fv_id, "controls": cs}

    @app.post("/governance/control-definitions", tags=["Governance"])
    def create_control(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        fv_id = str(payload.get("framework_version_id", "")).strip()
        display_code = str(payload.get("display_code", "")).strip()
        title = str(payload.get("title", "")).strip()
        if not fv_id or not display_code or not title:
            raise HTTPException(status_code=400, detail="framework_version_id·display_code·title 필수입니다.")
        version = _find(KIND_FRAMEWORK_VERSION, fv_id)
        if version is None:
            raise HTTPException(status_code=404, detail="framework_version 을 찾을 수 없습니다.")
        if not is_mutable_version(version):
            raise HTTPException(status_code=409, detail="active/retired 버전에는 통제를 추가할 수 없습니다(새 버전으로).")
        interp = payload.get("interpretations") if isinstance(payload.get("interpretations"), dict) else {}
        rec = build_control_definition(
            framework_version_id=fv_id, display_code=display_code, title=title,
            control_uid=str(payload.get("control_uid", "")),
            requirement_text=str(payload.get("requirement_text", "")),
            parent_control_id=payload.get("parent_control_id"),
            interpretations={str(k): str(v) for k, v in interp.items()}, now=_now(), created_by=actor)
        return _save(KIND_CONTROL_DEF, rec, actor, "GOV_CONTROL_CREATE")

    # ── ControlRelationship (계보 그래프) ──────────────────────────────────────
    @app.get("/governance/relationships", tags=["Governance"])
    def list_relationships(request: Request, control_id: str | None = None) -> dict[str, Any]:
        _require(request)
        rels = _load(KIND_RELATIONSHIP)
        if control_id:
            rels = [r for r in rels if control_id in (r.get("source_control_id"), r.get("target_control_id"))]
        return {"relationships": rels, "types": list(RELATIONSHIP_TYPES)}

    @app.post("/governance/relationships", tags=["Governance"])
    def create_relationship(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        src = str(payload.get("source_control_id", "")).strip()
        tgt = str(payload.get("target_control_id", "")).strip()
        rtype = str(payload.get("relationship_type", "")).strip()
        if not src or not tgt or rtype not in RELATIONSHIP_TYPES:
            raise HTTPException(status_code=400,
                                detail=f"source·target 필수, relationship_type 은 {', '.join(RELATIONSHIP_TYPES)} 중 하나.")
        if src == tgt:
            raise HTTPException(status_code=400, detail="source 와 target 은 서로 달라야 합니다(자기참조 금지).")
        _require_control_ref(src)
        _require_control_ref(tgt)
        # coverage_percent 검증(S1e): 있으면 0~100 정수만(비숫자 → 500 아니라 400).
        cov_raw = payload.get("coverage_percent")
        cov: int | None = None
        if cov_raw not in (None, ""):
            try:
                cov = int(cov_raw)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="coverage_percent 는 0~100 정수여야 합니다.") from None
            if not (0 <= cov <= 100):
                raise HTTPException(status_code=400, detail="coverage_percent 는 0~100 범위여야 합니다.")
        rec = build_relationship(
            source_control_id=src, target_control_id=tgt, relationship_type=rtype,
            coverage_percent=cov, rationale=str(payload.get("rationale", "")),
            provenance=str(payload.get("provenance", "HUMAN")), reviewed_by=actor, now=_now())
        # 같은 (source,target,type) 중복 생성 거부(결정적 id 로 덮어쓰기 방지).
        if _find(KIND_RELATIONSHIP, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 관계입니다.")
        return _save(KIND_RELATIONSHIP, rec, actor, "GOV_REL_CREATE")

    # ── OrganizationControl ────────────────────────────────────────────────────
    @app.get("/governance/organization-controls", tags=["Governance"])
    def list_org_controls(request: Request) -> dict[str, Any]:
        _require(request)
        return {"organization_controls": _load(KIND_ORG_CONTROL)}

    @app.post("/governance/organization-controls", tags=["Governance"])
    def create_org_control(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        code = str(payload.get("code", "")).strip()
        title = str(payload.get("title", "")).strip()
        if not code or not title:
            raise HTTPException(status_code=400, detail="code·title 필수입니다.")
        version = int(payload.get("version", 1) or 1)
        rec = build_organization_control(
            code=code, title=title, owner_team=str(payload.get("owner_team", "")),
            frequency=str(payload.get("frequency", "")), scope=str(payload.get("scope", "")),
            # 문자열(id) 또는 {control_id, coverage_role, coverage_type} 둘 다 허용(#14).
            mapped_controls=[x if isinstance(x, dict) else str(x)
                             for x in (payload.get("mapped_controls") or [])],
            version=version, supersedes=payload.get("supersedes"), now=_now(), created_by=actor)
        if _find(KIND_ORG_CONTROL, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 내부통제 버전입니다.")
        return _save(KIND_ORG_CONTROL, rec, actor, "GOV_ORGCTL_CREATE")

    # ── ScopeSnapshot ──────────────────────────────────────────────────────────
    @app.get("/governance/scope-snapshots", tags=["Governance"])
    def list_scope_snapshots(request: Request) -> dict[str, Any]:
        _require(request)
        return {"scope_snapshots": _load(KIND_SCOPE_SNAPSHOT)}

    @app.post("/governance/scope-snapshots", tags=["Governance"])
    def create_scope_snapshot(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        sid = str(payload.get("snapshot_id", "")).strip()
        if not sid:
            raise HTTPException(status_code=400, detail="snapshot_id 는 필수입니다.")
        rec = build_scope_snapshot(
            snapshot_id=sid,
            services=[str(x) for x in (payload.get("services") or [])],
            # 자산은 문자열(id) 또는 dict(당시 hostname·IP·owner·중요도) — 동결 스냅샷(#10).
            assets=[x if isinstance(x, dict) else str(x) for x in (payload.get("assets") or [])],
            organizations=[str(x) for x in (payload.get("organizations") or [])],
            locations=[str(x) for x in (payload.get("locations") or [])],
            data_processes=[str(x) for x in (payload.get("data_processes") or [])],
            approved_by=str(payload.get("approved_by", "")),
            source_query=str(payload.get("source_query", "")),
            change_reason=str(payload.get("change_reason", "")),
            now=_now(), created_by=actor)
        if _find(KIND_SCOPE_SNAPSHOT, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 scope snapshot 입니다(불변).")
        return _save(KIND_SCOPE_SNAPSHOT, rec, actor, "GOV_SCOPE_CREATE")

    # ── AssuranceCycle ─────────────────────────────────────────────────────────
    @app.get("/governance/assurance-cycles", tags=["Governance"])
    def list_cycles(request: Request) -> dict[str, Any]:
        _require(request)
        return {"assurance_cycles": _load(KIND_ASSURANCE_CYCLE)}

    @app.post("/governance/assurance-cycles", tags=["Governance"])
    def create_cycle(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        cid = str(payload.get("cycle_id", "")).strip()
        name = str(payload.get("name", "")).strip()
        fv_id = str(payload.get("framework_version_id", "")).strip()
        if not cid or not name or not fv_id:
            raise HTTPException(status_code=400, detail="cycle_id·name·framework_version_id 필수입니다.")
        _require_ref(KIND_FRAMEWORK_VERSION, fv_id, "framework_version")
        _require_ref(KIND_SCOPE_SNAPSHOT, str(payload.get("scope_snapshot_id", "")), "scope_snapshot")
        rec = build_assurance_cycle(
            cycle_id=cid, name=name, framework_version_id=fv_id,
            period_start=str(payload.get("period_start", "")),
            period_end=str(payload.get("period_end", "")),
            scope_snapshot_id=str(payload.get("scope_snapshot_id", "")),
            status=str(payload.get("status", "draft")), now=_now(), created_by=actor)
        if _find(KIND_ASSURANCE_CYCLE, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 운영주기입니다.")
        return _save(KIND_ASSURANCE_CYCLE, rec, actor, "GOV_CYCLE_CREATE")

    # ── EvidenceContract (통제별 필요 증적 정의, 버전관리) ──────────────────────────
    @app.get("/governance/evidence-contracts", tags=["Governance"])
    def list_evidence_contracts(request: Request, organization_control_id: str | None = None) -> dict[str, Any]:
        _require(request)
        rows = _load(KIND_EVIDENCE_CONTRACT)
        if organization_control_id:
            rows = [r for r in rows if r.get("organization_control_id") == organization_control_id]
        return {"evidence_contracts": rows}

    @app.post("/governance/evidence-contracts", tags=["Governance"])
    def create_evidence_contract(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        oc = str(payload.get("organization_control_id", "")).strip()
        if not oc:
            raise HTTPException(status_code=400, detail="organization_control_id 는 필수입니다.")
        _require_ref(KIND_ORG_CONTROL, oc, "organization_control")
        rec = build_evidence_contract(
            organization_control_id=oc, version=int(payload.get("version", 1) or 1),
            frequency=str(payload.get("frequency", "")),
            required_fields=[str(x) for x in (payload.get("required_fields") or [])],
            minimum_coverage=float(payload.get("minimum_coverage", 0) or 0),
            maximum_age_days=int(payload.get("maximum_age_days", 0) or 0),
            allowed_sources=[str(x) for x in (payload.get("allowed_sources") or [])],
            required_reviewer=str(payload.get("required_reviewer", "")), now=_now(), created_by=actor)
        if _find(KIND_EVIDENCE_CONTRACT, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 계약 버전입니다(새 version 으로).")
        return _save(KIND_EVIDENCE_CONTRACT, rec, actor, "GOV_CONTRACT_CREATE")

    # ── EvidenceMapping (통제 ↔ 기술 소스, 유효기간) ────────────────────────────────
    @app.get("/governance/evidence-mappings", tags=["Governance"])
    def list_evidence_mappings(request: Request, organization_control_id: str | None = None) -> dict[str, Any]:
        _require(request)
        rows = _load(KIND_EVIDENCE_MAPPING)
        if organization_control_id:
            rows = [r for r in rows if r.get("organization_control_id") == organization_control_id]
        return {"evidence_mappings": rows}

    @app.post("/governance/evidence-mappings", tags=["Governance"])
    def create_evidence_mapping(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        oc = str(payload.get("organization_control_id", "")).strip()
        src = str(payload.get("source_type", "")).strip()
        if not oc or not src:
            raise HTTPException(status_code=400, detail="organization_control_id·source_type 필수입니다.")
        _require_ref(KIND_ORG_CONTROL, oc, "organization_control")
        rec = build_evidence_mapping(
            organization_control_id=oc, source_type=src,
            collection_rule_id=str(payload.get("collection_rule_id", "")),
            valid_from=str(payload.get("valid_from", "")), valid_to=payload.get("valid_to"),
            mapping_version=int(payload.get("mapping_version", 1) or 1),
            rationale=str(payload.get("rationale", "")), approved_by=actor, now=_now())
        if _find(KIND_EVIDENCE_MAPPING, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 매핑 버전입니다(새 mapping_version 으로).")
        return _save(KIND_EVIDENCE_MAPPING, rec, actor, "GOV_MAPPING_CREATE")

    # ── CycleControl (운영주기 통제 인스턴스 — 증적/평가 분리, append-only) ────────────
    @app.get("/governance/assurance-cycles/{cycle_id}/controls", tags=["Governance"])
    def list_cycle_controls(cycle_id: str, request: Request) -> dict[str, Any]:
        _require(request)
        rows = [r for r in _load(KIND_CYCLE_CONTROL) if r.get("cycle_id") == cycle_id]
        return {"cycle_id": cycle_id, "cycle_controls": rows,
                "evidence_statuses": list(EVIDENCE_STATUSES),
                "assessment_statuses": list(ASSESSMENT_STATUSES),
                "applicability_statuses": list(APPLICABILITY_STATUSES)}

    @app.post("/governance/cycle-controls", tags=["Governance"])
    def create_cycle_control(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        actor = _require(request)
        cyc = str(payload.get("cycle_id", "")).strip()
        ref = str(payload.get("control_ref", "")).strip()
        if not cyc or not ref:
            raise HTTPException(status_code=400, detail="cycle_id·control_ref 필수입니다.")
        _require_ref(KIND_ASSURANCE_CYCLE, cyc, "assurance_cycle")
        _require_control_ref(ref)
        appl = str(payload.get("applicability", "pending_assessment"))
        if appl not in APPLICABILITY_STATUSES:
            raise HTTPException(status_code=400, detail=f"applicability 는 {', '.join(APPLICABILITY_STATUSES)} 중 하나.")
        rec = build_cycle_control(cycle_id=cyc, control_ref=ref,
                                  assignee=str(payload.get("assignee", "")),
                                  applicability=appl, now=_now(), created_by=actor)
        if _find(KIND_CYCLE_CONTROL, rec["id"]):
            raise HTTPException(status_code=409, detail="이미 존재하는 주기 통제입니다.")
        return _save(KIND_CYCLE_CONTROL, rec, actor, "GOV_CYCLECTL_CREATE")

    @app.post("/governance/cycle-controls/{cc_id}/update", tags=["Governance"])
    def update_cycle_control(cc_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """증적 상태·평가 상태·적용성·담당자 갱신. 증적≠평가(분리), history append-only."""
        actor = _require(request)
        cc = _find(KIND_CYCLE_CONTROL, cc_id)
        if cc is None:
            raise HTTPException(status_code=404, detail="주기 통제를 찾을 수 없습니다.")
        ev = str(payload.get("evidence_status", "")).strip()
        asv = str(payload.get("assessment_status", "")).strip()
        appl = str(payload.get("applicability", "")).strip()
        if ev and ev not in EVIDENCE_STATUSES:
            raise HTTPException(status_code=400, detail=f"evidence_status 는 {', '.join(EVIDENCE_STATUSES)} 중 하나.")
        if asv and asv not in ASSESSMENT_STATUSES:
            raise HTTPException(status_code=400, detail=f"assessment_status 는 {', '.join(ASSESSMENT_STATUSES)} 중 하나.")
        if appl and appl not in APPLICABILITY_STATUSES:
            raise HTTPException(status_code=400, detail=f"applicability 는 {', '.join(APPLICABILITY_STATUSES)} 중 하나.")
        apply_cycle_control_update(cc, actor=actor, now=_now(), evidence_status=ev,
                                   assessment_status=asv, applicability=appl,
                                   assignee=str(payload.get("assignee", "")),
                                   note=str(payload.get("note", "")),
                                   evidence_set_hash=str(payload.get("evidence_set_hash", "")),
                                   rationale=str(payload.get("rationale", "")),
                                   scope_snapshot_id=str(payload.get("scope_snapshot_id", "")))
        changed = bool(cc.pop("_changed", True))  # 영속 전 transient 플래그 제거(S1f)
        if changed:
            _save(KIND_CYCLE_CONTROL, cc, actor, "GOV_CYCLECTL_UPDATE")
        return {**cc, "_no_op": not changed}

    @app.get("/governance/cycle-controls/{cc_id}/as-of", tags=["Governance"])
    def cycle_control_as_of_route(cc_id: str, request: Request, date: str | None = None) -> dict[str, Any]:
        """특정 시점(date, ISO)의 통제 상태를 history 재생으로 재현(감사 시점 조회)."""
        _require(request)
        cc = _find(KIND_CYCLE_CONTROL, cc_id)
        if cc is None:
            raise HTTPException(status_code=404, detail="주기 통제를 찾을 수 없습니다.")
        as_of = date or _now()
        return {"cycle_control_id": cc_id, **cycle_control_as_of(cc, as_of)}

    # ── 버전 영향분석(P3) — 두 기준 버전 통제 diff ─────────────────────────────────
    @app.get("/governance/framework-versions/{fv_id}/compare", tags=["Governance"])
    def compare_versions(fv_id: str, request: Request, to: str) -> dict[str, Any]:
        """fv_id(구) → to(신) 통제 diff: 신규·삭제·번호변경·실질 변경 후보(담당자 검토용)."""
        _require(request)
        if _find(KIND_FRAMEWORK_VERSION, fv_id) is None or _find(KIND_FRAMEWORK_VERSION, to) is None:
            raise HTTPException(status_code=404, detail="비교할 버전을 찾을 수 없습니다.")
        old = [c for c in _load(KIND_CONTROL_DEF) if c.get("framework_version_id") == fv_id]
        new = [c for c in _load(KIND_CONTROL_DEF) if c.get("framework_version_id") == to]
        return {"from": fv_id, "to": to, **diff_control_definitions(old, new)}

    # ── 운영주기 마이그레이션(S2) — 지난 주기 + 버전 diff 를 하나로 묶은 진짜 이관 ──────────
    @app.post("/governance/assurance-cycles/{cycle_id}/initialize-from/{previous_id}", tags=["Governance"])
    def initialize_cycle(cycle_id: str, previous_id: str, request: Request) -> dict[str, Any]:
        """지난 주기(previous_id) → 새 주기(cycle_id) **진짜 버전 마이그레이션**.

        두 주기의 framework_version 통제 diff(control_uid 계보)를 사용해 번호변경은 새 참조로 이관,
        내용변경은 재설계 검토 표시, 삭제는 removed 목록, 신규는 새 통제 생성. 운영설정 승계 /
        증적·평가 초기화. 두 주기 모두 통제 정의가 있으면 계보 기반, 없으면 단순 참조 승계로 폴백.
        """
        actor = _require(request)
        new_cycle = _find(KIND_ASSURANCE_CYCLE, cycle_id)
        prev_cycle = _find(KIND_ASSURANCE_CYCLE, previous_id)
        if new_cycle is None:
            raise HTTPException(status_code=404, detail="대상 운영주기를 먼저 생성하세요.")
        prev = [r for r in _load(KIND_CYCLE_CONTROL) if r.get("cycle_id") == previous_id]
        if not prev:
            raise HTTPException(status_code=404, detail="이전 주기의 통제가 없습니다.")
        old_fv = (prev_cycle or {}).get("framework_version_id", "")
        new_fv = new_cycle.get("framework_version_id", "")
        old_controls = [c for c in _load(KIND_CONTROL_DEF) if c.get("framework_version_id") == old_fv]
        new_controls = [c for c in _load(KIND_CONTROL_DEF) if c.get("framework_version_id") == new_fv]
        res = plan_cycle_migration(prev, old_controls, new_controls, cycle_id,
                                   now=_now(), created_by=actor)
        created = 0
        for cc in res["cycle_controls"]:
            if _find(KIND_CYCLE_CONTROL, cc["id"]) is None:
                _save(KIND_CYCLE_CONTROL, cc, actor, "GOV_CYCLE_MIGRATE")
                created += 1
        res["created"] = created
        res.pop("cycle_controls", None)  # 요약만 반환(전체는 목록 API 로)
        return res

    # ── 감사 실사용(P4) — 기준일 as-of 스냅샷(과거 재현) ───────────────────────────
    @app.get("/governance/assurance-cycles/{cycle_id}/audit-snapshot", tags=["Governance"])
    def cycle_audit_snapshot(cycle_id: str, request: Request, date: str | None = None) -> dict[str, Any]:
        """감사 기준일(date, ISO)의 운영주기 전체 상태를 재현(통제별 as-of + 범위 스냅샷)."""
        _require(request)
        cyc = _find(KIND_ASSURANCE_CYCLE, cycle_id)
        if cyc is None:
            raise HTTPException(status_code=404, detail="운영주기를 찾을 수 없습니다.")
        ccs = [r for r in _load(KIND_CYCLE_CONTROL) if r.get("cycle_id") == cycle_id]
        scope = _find(KIND_SCOPE_SNAPSHOT, str(cyc.get("scope_snapshot_id") or ""))
        return build_cycle_audit_snapshot(cyc, ccs, date or _now(), scope_snapshot=scope)

    # ── 다중기준 crosswalk(P5) — 내부통제 하나가 여러 기준 충족 ─────────────────────
    @app.get("/governance/crosswalk", tags=["Governance"])
    def crosswalk(request: Request) -> dict[str, Any]:
        """내부통제의 mapped_controls 를 외부기준별로 묶은 crosswalk(증적 재사용 뷰)."""
        _require(request)
        return build_crosswalk(_load(KIND_ORG_CONTROL))

    # ── Base + Overlay(P5) — 기준 통제 + 조직 오버레이 뷰 ──────────────────────────
    @app.post("/governance/controls/{control_id}/overlay-view", tags=["Governance"])
    def overlay_view(control_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """기준 통제(base)에 조직 오버레이(payload)를 얹은 뷰. base 불변, 내용 변경 시 conflict 표시."""
        _require(request)
        cdef = _find(KIND_CONTROL_DEF, control_id)
        if cdef is None:
            raise HTTPException(status_code=404, detail="통제 정의를 찾을 수 없습니다.")
        return apply_overlay(cdef, payload if isinstance(payload, dict) else {})

    # ── append-only 이벤트 원장(S3) — 변경 이력 + hash chain 무결성 검증 ──────────────
    @app.get("/governance/events", tags=["Governance"])
    def governance_events(request: Request, kind: str | None = None,
                          entity_id: str | None = None) -> dict[str, Any]:
        """거버넌스 변경 이벤트(append-only). kind·entity_id 로 필터. seq 오름차순."""
        _require(request)
        repo = _repo()
        events = repo.load_governance_events(kind, entity_id) if repo is not None else []
        return {"events": events, "count": len(events)}

    @app.get("/governance/events/verify", tags=["Governance"])
    def governance_events_verify(request: Request) -> dict[str, Any]:
        """전체 이벤트 원장의 hash chain 무결성 검증(변조·삭제·재배열 감지)."""
        _require(request)
        repo = _repo()
        events = repo.load_governance_events() if repo is not None else []
        return verify_governance_chain(events)
