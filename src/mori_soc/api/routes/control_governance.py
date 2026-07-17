"""통제 운영 플랫폼 라우트 — 기반 모델(통제 신규 에픽 Phase 1).

Framework / FrameworkVersion / ControlDefinition / ControlRelationship /
OrganizationControl / ScopeSnapshot / AssuranceCycle 의 CRUD + 버전 불변.
버전은 덮어쓰지 않는다 — active/retired 는 편집·삭제 거부(409), 새 버전으로 대체.
모든 편집은 admin·security 전용(통제 정본은 민감).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

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
    apply_cycle_control_update,
    build_assurance_cycle,
    build_control_definition,
    build_cycle_control,
    build_evidence_contract,
    build_evidence_mapping,
    build_framework,
    build_framework_version,
    build_organization_control,
    build_relationship,
    build_scope_snapshot,
    cycle_control_as_of,
    diff_control_definitions,
    initialize_cycle_from_previous,
    is_mutable_version,
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

    def _save(kind: str, rec: dict[str, Any], actor: str, action: str) -> dict[str, Any]:
        repo = _repo()
        if repo is not None:
            repo.save_governance(kind, rec["id"], rec)
        if ctx.log_action:
            ctx.log_action(actor, action, rec["id"])
        return rec

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
        vs = [v for v in _load(KIND_FRAMEWORK_VERSION) if v.get("framework_id") == framework_id]
        vs.sort(key=lambda v: str(v.get("version")))
        return {"framework_id": framework_id, "versions": vs}

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
        actor = _require(request)
        rec = _find(KIND_FRAMEWORK_VERSION, fv_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="버전을 찾을 수 없습니다.")
        rec["status"] = "active"
        rec["activated_at"] = _now()
        rec["activated_by"] = actor
        return _save(KIND_FRAMEWORK_VERSION, rec, actor, "GOV_VERSION_ACTIVATE")

    @app.post("/governance/framework-versions/{fv_id}/retire", tags=["Governance"])
    def retire_version(fv_id: str, request: Request) -> dict[str, Any]:
        actor = _require(request)
        rec = _find(KIND_FRAMEWORK_VERSION, fv_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="버전을 찾을 수 없습니다.")
        rec["status"] = "retired"
        rec["effective_to"] = rec.get("effective_to") or _now()
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
        cov = payload.get("coverage_percent")
        rec = build_relationship(
            source_control_id=src, target_control_id=tgt, relationship_type=rtype,
            coverage_percent=int(cov) if cov not in (None, "") else None,
            rationale=str(payload.get("rationale", "")),
            provenance=str(payload.get("provenance", "HUMAN")), reviewed_by=actor, now=_now())
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
            mapped_controls=[str(x) for x in (payload.get("mapped_controls") or [])],
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
            assets=[str(x) for x in (payload.get("assets") or [])],
            organizations=[str(x) for x in (payload.get("organizations") or [])],
            locations=[str(x) for x in (payload.get("locations") or [])],
            data_processes=[str(x) for x in (payload.get("data_processes") or [])],
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
        rec = build_evidence_mapping(
            organization_control_id=oc, source_type=src,
            collection_rule_id=str(payload.get("collection_rule_id", "")),
            valid_from=str(payload.get("valid_from", "")), valid_to=payload.get("valid_to"),
            mapping_version=int(payload.get("mapping_version", 1) or 1),
            rationale=str(payload.get("rationale", "")), approved_by=actor, now=_now())
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
        rec = build_cycle_control(cycle_id=cyc, control_ref=ref,
                                  assignee=str(payload.get("assignee", "")),
                                  applicability=str(payload.get("applicability", "pending_assessment")),
                                  now=_now(), created_by=actor)
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
                                   note=str(payload.get("note", "")))
        return _save(KIND_CYCLE_CONTROL, cc, actor, "GOV_CYCLECTL_UPDATE")

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

    # ── 운영주기 마이그레이션(P3) — 지난 주기에서 새 주기 통제 승계 ─────────────────────
    @app.post("/governance/assurance-cycles/{cycle_id}/initialize-from/{previous_id}", tags=["Governance"])
    def initialize_cycle(cycle_id: str, previous_id: str, request: Request) -> dict[str, Any]:
        """지난 주기(previous_id)에서 새 주기(cycle_id) 통제 생성.

        승계: 담당자·적용성·증적계약. 초기화: 증적·평가 상태(작년 판정 자동 승계 금지).
        """
        actor = _require(request)
        if _find(KIND_ASSURANCE_CYCLE, cycle_id) is None:
            raise HTTPException(status_code=404, detail="대상 운영주기를 먼저 생성하세요.")
        prev = [r for r in _load(KIND_CYCLE_CONTROL) if r.get("cycle_id") == previous_id]
        if not prev:
            raise HTTPException(status_code=404, detail="이전 주기의 통제가 없습니다.")
        res = initialize_cycle_from_previous(prev, cycle_id, now=_now(), created_by=actor)
        created = 0
        for cc in res["cycle_controls"]:
            if _find(KIND_CYCLE_CONTROL, cc["id"]) is None:
                _save(KIND_CYCLE_CONTROL, cc, actor, "GOV_CYCLE_MIGRATE")
                created += 1
        res["created"] = created
        res.pop("cycle_controls", None)  # 요약만 반환(전체는 목록 API 로)
        return res
