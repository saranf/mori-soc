"""통제 운영 플랫폼 — 기반 모델(통제 신규 에픽 Phase 1).

MORI 를 'Control-to-Evidence Operating System' 으로 확장하는 기반 객체들. 핵심 원칙:
- **버전 불변**: FrameworkVersion·ControlDefinition·OrganizationControl 은 덮어쓰지 않고 새 버전으로
  쌓는다. `supersedes` 로 계보를 잇고 과거본은 그대로 재현 가능.
- **해석 층 분리**: 공식 요구사항(official) · MORI 요약(mori_summary) · 조직 해석(org_interpretation)
  · 운영 가이드(operation_guide)를 절대 한 필드에 섞지 않는다.
- **사람 승인**: AI/규칙은 후보를 만들고 사람이 확정한다(모리다움).

순수 함수 — I/O 없음. 시각은 호출자가 ISO 문자열로 주입.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# 저장 네임스페이스(kind).
KIND_FRAMEWORK = "framework"
KIND_FRAMEWORK_VERSION = "framework_version"
KIND_CONTROL_DEF = "control_definition"
KIND_RELATIONSHIP = "control_relationship"
KIND_ORG_CONTROL = "organization_control"
KIND_ASSURANCE_CYCLE = "assurance_cycle"
KIND_SCOPE_SNAPSHOT = "scope_snapshot"
KIND_CYCLE_CONTROL = "cycle_control"          # 운영주기 안의 통제 인스턴스(P2)
KIND_EVIDENCE_CONTRACT = "evidence_contract"  # 통제별 필요 증적 정의(버전관리, P2)
KIND_EVIDENCE_MAPPING = "evidence_mapping"    # 통제 ↔ 기술 소스 매핑(시간축, P2)

KINDS = (KIND_FRAMEWORK, KIND_FRAMEWORK_VERSION, KIND_CONTROL_DEF, KIND_RELATIONSHIP,
         KIND_ORG_CONTROL, KIND_ASSURANCE_CYCLE, KIND_SCOPE_SNAPSHOT,
         KIND_CYCLE_CONTROL, KIND_EVIDENCE_CONTRACT, KIND_EVIDENCE_MAPPING)

# 증적 상태 vs 통제 평가 상태 — 절대 같은 컬럼으로 쓰지 않는다.
EVIDENCE_STATUSES = ("missing", "available", "stale", "partial", "reviewed", "approved", "superseded")
ASSESSMENT_STATUSES = ("not_assessed", "design_deficient", "implemented", "operating",
                       "ineffective", "effective", "exception_approved", "remediation_required")
APPLICABILITY_STATUSES = ("applicable", "not_applicable", "partially_applicable",
                          "inherited", "shared_responsibility", "pending_assessment")

# 통제 관계 유형(계보 그래프). coverage_percent 는 자동 법적 판정이 아니라 담당자 판단값.
RELATIONSHIP_TYPES = (
    "same_as", "replaces", "replaced_by", "split_into", "merged_from",
    "derived_from", "related_to", "partially_covers", "conflicts_with",
)

# 해석 층 — 절대 섞지 않는다.
INTERPRETATION_TYPES = ("official", "mori_summary", "org_interpretation", "operation_guide")

# FrameworkVersion 생명주기 상태.
VERSION_STATUSES = ("draft", "active", "retired")


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "-" for c in str(s or "").strip().lower())[:60]


def content_hash(record: dict[str, Any]) -> str:
    """레코드 내용 해시(sha256:...). 시각·감사 필드 제외한 실질 내용만."""
    volatile = {"content_hash", "created_at", "updated_at", "created_by", "id"}
    core = {k: v for k, v in record.items() if k not in volatile}
    blob = json.dumps(core, ensure_ascii=False, sort_keys=True)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ── Framework — 외부 기준 그 자체(이름만 가진 상위 개념) ────────────────────────────
def build_framework(*, framework_id: str, name: str, type_: str = "certification",
                    publisher: str = "", now: str = "", created_by: str = "") -> dict[str, Any]:
    fid = _slug(framework_id)
    return {"id": fid, "framework_id": fid, "name": name, "type": type_,
            "publisher": publisher, "created_at": now, "created_by": created_by}


# ── FrameworkVersion — 특정 시점의 기준 버전(불변) ─────────────────────────────────
def build_framework_version(*, framework_id: str, version: str, effective_from: str = "",
                            effective_to: str | None = None, status: str = "draft",
                            source_type: str = "user_upload", source_hash: str = "",
                            supersedes: str | None = None, change_reason: str = "",
                            importer_version: str = "", now: str = "",
                            created_by: str = "") -> dict[str, Any]:
    """기준 버전 레코드. id = framework_id:version(중복 시 서비스층에서 거부)."""
    fid = _slug(framework_id)
    fv_id = f"{fid}:{_slug(version)}"
    rec = {
        "id": fv_id, "framework_version_id": fv_id, "framework_id": fid, "version": str(version),
        "effective_from": effective_from, "effective_to": effective_to, "status": status,
        "source_type": source_type, "source_hash": source_hash, "supersedes": supersedes,
        "change_reason": change_reason, "importer_version": importer_version,
        "created_at": now, "created_by": created_by,
    }
    rec["content_hash"] = content_hash(rec)
    return rec


# ── ControlDefinition — 그 버전 안의 개별 통제 ─────────────────────────────────────
def build_control_definition(*, framework_version_id: str, display_code: str, title: str,
                             control_uid: str = "", requirement_text: str = "",
                             parent_control_id: str | None = None,
                             interpretations: dict[str, str] | None = None,
                             now: str = "", created_by: str = "") -> dict[str, Any]:
    """통제 정의. control_uid 는 표시번호가 바뀌어도 이어지는 개념적 계보 식별자."""
    uid = _slug(control_uid or display_code)
    cid = f"{framework_version_id}:{_slug(display_code)}"
    # 해석 층 분리 — official/mori_summary/org_interpretation/operation_guide.
    interp = {k: "" for k in INTERPRETATION_TYPES}
    if requirement_text:
        interp["official"] = requirement_text
    for k, v in (interpretations or {}).items():
        if k in interp:
            interp[k] = v
    rec = {
        "id": cid, "control_id": cid, "framework_version_id": framework_version_id,
        "control_uid": uid, "display_code": str(display_code), "title": title,
        "requirement_text": requirement_text, "interpretations": interp,
        "parent_control_id": parent_control_id, "created_at": now, "created_by": created_by,
    }
    rec["content_hash"] = content_hash(rec)
    return rec


# ── ControlRelationship — 통제 계보 그래프 ────────────────────────────────────────
def build_relationship(*, source_control_id: str, target_control_id: str, relationship_type: str,
                       coverage_percent: int | None = None, rationale: str = "",
                       provenance: str = "HUMAN", reviewed_by: str = "", now: str = "") -> dict[str, Any]:
    rel_id = "rel-" + hashlib.sha1(
        f"{source_control_id}|{target_control_id}|{relationship_type}".encode("utf-8")).hexdigest()[:16]
    return {
        "id": rel_id, "relationship_id": rel_id, "source_control_id": source_control_id,
        "target_control_id": target_control_id, "relationship_type": relationship_type,
        "coverage_percent": coverage_percent, "rationale": rationale,
        "provenance": provenance, "reviewed_by": reviewed_by, "reviewed_at": now,
    }


# ── OrganizationControl — 회사 내부통제(여러 외부기준 동시 충족) ─────────────────────
def build_organization_control(*, code: str, title: str, owner_team: str = "", frequency: str = "",
                               scope: str = "", mapped_controls: list[str] | None = None,
                               version: int = 1, supersedes: str | None = None,
                               now: str = "", created_by: str = "") -> dict[str, Any]:
    oc_id = f"{_slug(code)}:v{version}"
    rec = {
        "id": oc_id, "organization_control_id": oc_id, "code": str(code), "title": title,
        "owner_team": owner_team, "frequency": frequency, "scope": scope,
        "mapped_controls": list(mapped_controls or []), "version": version,
        "supersedes": supersedes, "status": "draft", "created_at": now, "created_by": created_by,
    }
    rec["content_hash"] = content_hash(rec)
    return rec


# ── ScopeSnapshot — 운영주기별 인증범위 고정 ──────────────────────────────────────
def build_scope_snapshot(*, snapshot_id: str, services: list[str] | None = None,
                         assets: list[str] | None = None, organizations: list[str] | None = None,
                         locations: list[str] | None = None, data_processes: list[str] | None = None,
                         now: str = "", created_by: str = "") -> dict[str, Any]:
    sid = _slug(snapshot_id)
    rec = {
        "id": sid, "scope_snapshot_id": sid, "services": list(services or []),
        "assets": list(assets or []), "organizations": list(organizations or []),
        "locations": list(locations or []), "data_processes": list(data_processes or []),
        "created_at": now, "created_by": created_by,
    }
    rec["content_hash"] = content_hash(rec)
    return rec


# ── AssuranceCycle — 연도·기간별 운영 인스턴스 ────────────────────────────────────
def build_assurance_cycle(*, cycle_id: str, name: str, framework_version_id: str,
                          period_start: str = "", period_end: str = "",
                          scope_snapshot_id: str = "", status: str = "draft",
                          now: str = "", created_by: str = "") -> dict[str, Any]:
    cid = _slug(cycle_id)
    return {
        "id": cid, "cycle_id": cid, "name": name, "framework_version_id": framework_version_id,
        "period_start": period_start, "period_end": period_end,
        "scope_snapshot_id": scope_snapshot_id, "status": status,
        "created_at": now, "created_by": created_by,
    }


def is_mutable_version(record: dict[str, Any]) -> bool:
    """draft 만 편집 가능. active/retired 는 불변(새 버전으로 대체)."""
    return str(record.get("status") or "draft") == "draft"


# ── EvidenceContract — 통제별 '어떤 증적이 있어야 하는가'(버전관리) ─────────────────
def build_evidence_contract(*, organization_control_id: str, version: int = 1,
                            frequency: str = "", required_fields: list[str] | None = None,
                            minimum_coverage: float = 0.0, maximum_age_days: int = 0,
                            allowed_sources: list[str] | None = None,
                            required_reviewer: str = "", now: str = "",
                            created_by: str = "") -> dict[str, Any]:
    """증적 계약. 증적은 이 계약 '버전'으로 생성됐는지 각인한다(과거 증적 재사용 판정용)."""
    cid = f"{_slug(organization_control_id)}:v{version}"
    rec = {
        "id": cid, "evidence_contract_id": cid,
        "organization_control_id": organization_control_id, "version": version,
        "frequency": frequency, "required_fields": list(required_fields or []),
        "minimum_coverage": minimum_coverage, "maximum_age_days": maximum_age_days,
        "allowed_sources": list(allowed_sources or []), "required_reviewer": required_reviewer,
        "created_at": now, "created_by": created_by,
    }
    rec["content_hash"] = content_hash(rec)
    return rec


# ── EvidenceMapping — 통제 ↔ 기술 소스(유효기간·버전) ─────────────────────────────
def build_evidence_mapping(*, organization_control_id: str, source_type: str,
                           collection_rule_id: str = "", valid_from: str = "",
                           valid_to: str | None = None, mapping_version: int = 1,
                           rationale: str = "", approved_by: str = "", now: str = "") -> dict[str, Any]:
    mid = f"{_slug(organization_control_id)}:{_slug(source_type)}:v{mapping_version}"
    return {
        "id": mid, "mapping_id": mid, "organization_control_id": organization_control_id,
        "source_type": source_type, "collection_rule_id": collection_rule_id,
        "valid_from": valid_from, "valid_to": valid_to, "mapping_version": mapping_version,
        "rationale": rationale, "approved_by": approved_by, "created_at": now,
    }


# ── CycleControl — 운영주기 안의 통제 인스턴스(증적/평가 분리, append-only history) ──
def build_cycle_control(*, cycle_id: str, control_ref: str, assignee: str = "",
                        applicability: str = "pending_assessment", now: str = "",
                        created_by: str = "") -> dict[str, Any]:
    """운영주기별 통제 인스턴스. evidence_status 와 assessment_status 를 분리 보관한다."""
    cc_id = f"{_slug(cycle_id)}:{_slug(control_ref)}"
    return {
        "id": cc_id, "cycle_control_id": cc_id, "cycle_id": cycle_id, "control_ref": control_ref,
        "assignee": assignee, "applicability": applicability,
        "evidence_status": "missing", "assessment_status": "not_assessed",
        "evidence_contract_ref": "", "created_at": now, "created_by": created_by,
        "updated_at": now,
        "history": [{"ts": now, "actor": created_by, "action": "created"}],
    }


def apply_cycle_control_update(cc: dict[str, Any], *, actor: str, now: str,
                               evidence_status: str = "", assessment_status: str = "",
                               applicability: str = "", assignee: str = "",
                               note: str = "") -> dict[str, Any]:
    """운영주기 통제 상태 갱신(제자리 + append-only history). 증적·평가 상태는 서로 독립.

    유효성(상태값 소속)은 호출자가 확인한다. history 로 특정 시점 재현이 가능하다(event-sourcing 근사).
    """
    changed: dict[str, Any] = {}
    if evidence_status:
        changed["evidence_status"] = evidence_status
        cc["evidence_status"] = evidence_status
    if assessment_status:
        changed["assessment_status"] = assessment_status
        cc["assessment_status"] = assessment_status
    if applicability:
        changed["applicability"] = applicability
        cc["applicability"] = applicability
    if assignee:
        changed["assignee"] = assignee
        cc["assignee"] = assignee
    cc["updated_at"] = now
    cc.setdefault("history", []).append(
        {"ts": now, "actor": actor, "action": "update", "changed": changed, "note": note})
    return cc


def cycle_control_as_of(cc: dict[str, Any], as_of_ts: str) -> dict[str, Any]:
    """history 를 재생해 특정 시점(as_of_ts)의 통제 상태를 재현한다(감사 시점 조회)."""
    state = {"evidence_status": "missing", "assessment_status": "not_assessed",
             "applicability": "pending_assessment", "assignee": ""}
    for h in cc.get("history") or []:
        if str(h.get("ts") or "") > as_of_ts:
            break
        for k, v in (h.get("changed") or {}).items():
            state[k] = v
    state["as_of"] = as_of_ts
    return state


__all__ = [
    "KINDS", "KIND_FRAMEWORK", "KIND_FRAMEWORK_VERSION", "KIND_CONTROL_DEF", "KIND_RELATIONSHIP",
    "KIND_ORG_CONTROL", "KIND_ASSURANCE_CYCLE", "KIND_SCOPE_SNAPSHOT", "KIND_CYCLE_CONTROL",
    "KIND_EVIDENCE_CONTRACT", "KIND_EVIDENCE_MAPPING", "RELATIONSHIP_TYPES",
    "INTERPRETATION_TYPES", "VERSION_STATUSES", "EVIDENCE_STATUSES", "ASSESSMENT_STATUSES",
    "APPLICABILITY_STATUSES", "content_hash", "build_framework", "build_framework_version",
    "build_control_definition", "build_relationship", "build_organization_control",
    "build_scope_snapshot", "build_assurance_cycle", "is_mutable_version",
    "build_evidence_contract", "build_evidence_mapping", "build_cycle_control",
    "apply_cycle_control_update", "cycle_control_as_of",
]
