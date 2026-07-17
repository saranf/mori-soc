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
    KIND_ASSURANCE_CYCLE,
    KIND_CONTROL_DEF,
    KIND_FRAMEWORK,
    KIND_FRAMEWORK_VERSION,
    KIND_ORG_CONTROL,
    KIND_RELATIONSHIP,
    KIND_SCOPE_SNAPSHOT,
    RELATIONSHIP_TYPES,
    build_assurance_cycle,
    build_control_definition,
    build_framework,
    build_framework_version,
    build_organization_control,
    build_relationship,
    build_scope_snapshot,
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
