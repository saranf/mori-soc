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


# content_hash 캐노니컬화 규칙(리뷰 #6) — 나중에 방식이 바뀌면 같은 내용도 해시가 달라질 수
# 있으므로, 어떤 규칙·알고리즘으로 해시했는지 레코드에 함께 기록한다.
#   canonicalization = mori-jcs-v1: json.dumps(정렬 키 · 비ASCII 보존 · UTF-8, lifecycle/감사 제외)
CANONICALIZATION = "mori-jcs-v1"
HASH_ALGORITHM = "sha256"

# content_hash 대상에서 제외하는 **lifecycle/감사/해시메타** — 실질 내용이 아니다.
# status·activated_*·retired_*·effective_to·lifecycle 는 상태 전환 시 바뀌지만 '기준 원문 내용'이
# 바뀐 건 아니므로 해시를 흔들면 안 된다. canonicalization·hash_algorithm 은 해시 방식 메타라 제외.
_HASH_VOLATILE = frozenset({
    "content_hash", "created_at", "updated_at", "created_by", "id",
    "status", "activated_at", "activated_by", "retired_at", "retired_by",
    "effective_to", "lifecycle", "history", "canonicalization", "hash_algorithm",
    "applicability_pending_review",
})


def content_hash(record: dict[str, Any]) -> str:
    """레코드 **실질 내용** 해시(sha256:...). 시각·감사·lifecycle·해시메타는 제외한다.

    같은 내용이면 draft/active/retired 어느 상태든 동일 해시 — 버전 무결성·diff·export 에서
    상태 전환에 흔들리지 않는 안정적 지문이 된다. 캐노니컬화 규칙은 CANONICALIZATION(mori-jcs-v1).
    """
    core = {k: v for k, v in record.items() if k not in _HASH_VOLATILE}
    blob = json.dumps(core, ensure_ascii=False, sort_keys=True)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _stamp_hash(record: dict[str, Any]) -> dict[str, Any]:
    """레코드에 content_hash + 해시 방식 메타(canonicalization·hash_algorithm)를 함께 기록."""
    record["content_hash"] = content_hash(record)
    record["canonicalization"] = CANONICALIZATION
    record["hash_algorithm"] = HASH_ALGORITHM
    return record


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
    rec: dict[str, Any] = {
        "id": fv_id, "framework_version_id": fv_id, "framework_id": fid, "version": str(version),
        "effective_from": effective_from, "effective_to": effective_to, "status": status,
        "source_type": source_type, "source_hash": source_hash, "supersedes": supersedes,
        "change_reason": change_reason, "importer_version": importer_version,
        "created_at": now, "created_by": created_by,
    }
    _stamp_hash(rec)
    rec["lifecycle"] = [{"ts": now, "actor": created_by, "to": status}]
    return rec


# FrameworkVersion 상태기계 — draft → active → retired 만 허용(역행·재활성 금지).
VERSION_TRANSITIONS: dict[str, set[str]] = {"active": {"draft"}, "retired": {"active"}}


def can_version_transition(current: str, target: str) -> bool:
    return target in VERSION_TRANSITIONS and str(current or "draft") in VERSION_TRANSITIONS[target]


def apply_version_lifecycle(rec: dict[str, Any], target: str, *, actor: str, now: str) -> dict[str, Any]:
    """버전 상태 전환(제자리). content_hash 는 재계산하지 않는다(상태는 내용이 아님).

    lifecycle 이벤트를 append 해 전환 이력을 남긴다. 유효성은 호출자가 can_version_transition 으로 확인.
    """
    rec["status"] = target
    if target == "active":
        rec["activated_at"] = now
        rec["activated_by"] = actor
    elif target == "retired":
        rec["retired_at"] = now
        rec["retired_by"] = actor
        rec["effective_to"] = rec.get("effective_to") or now
    rec.setdefault("lifecycle", []).append({"ts": now, "actor": actor, "to": target})
    return rec


def periods_overlap(a_from: str, a_to: str | None, b_from: str, b_to: str | None) -> bool:
    """두 시행기간이 겹치는가(빈 값은 열린 구간). 같은 framework 의 active 기간 겹침 검증용."""
    a_end = a_to or "9999-12-31"
    b_end = b_to or "9999-12-31"
    a_start = a_from or "0000-01-01"
    b_start = b_from or "0000-01-01"
    return a_start <= b_end and b_start <= a_end


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
    _stamp_hash(rec)
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
    _stamp_hash(rec)
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
    _stamp_hash(rec)
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


# ── 이중 모델 브리지(C6) — 기존 194 카탈로그를 governance 모델로 흡수 ────────────────────
def plan_catalog_import(
    controls: list[dict[str, Any]], *, now: str = "", created_by: str = "",
) -> dict[str, Any]:
    """기존 통제 카탈로그(controls/status/evidence)를 governance FrameworkVersion+ControlDefinition
    으로 변환할 계획을 만든다(C6). 정본을 둘로 두지 않기 위한 **일방 흡수 경로**.

    - 프레임워크·버전별로 묶어 Framework + FrameworkVersion(draft) 생성.
    - 각 카탈로그 통제 → ControlDefinition. 카탈로그의 intent/evidence_hint 는 MORI 해석이므로
      `mori_summary`·`operation_guide` 층에 넣고, **공식 원문(official)은 비워 둔다**(원문은 사용자
      import — 라이선스·정직). control_uid = 카탈로그 id(그 프레임워크 내 안정 식별자).
    반환: {frameworks, framework_versions, control_definitions} (저장은 호출자가 _save 로).
    """
    frameworks: dict[str, dict[str, Any]] = {}
    versions: dict[str, dict[str, Any]] = {}
    defs: list[dict[str, Any]] = []
    for c in controls:
        fw = _slug(str(c.get("framework") or ""))
        ver = str(c.get("version") or "").strip() or "current"
        cid = str(c.get("id") or "").strip()
        if not fw or not cid:
            continue
        if fw not in frameworks:
            frameworks[fw] = build_framework(framework_id=fw, name=str(c.get("framework") or fw),
                                             now=now, created_by=created_by)
        fv = build_framework_version(framework_id=fw, version=ver, now=now, created_by=created_by)
        versions[fv["id"]] = fv
        title = str(c.get("title_ko") or c.get("title_en") or cid)
        interp = {"mori_summary": str(c.get("intent_ko") or c.get("intent_en") or ""),
                  "operation_guide": str(c.get("evidence_hint_ko") or c.get("evidence_hint_en") or "")}
        defs.append(build_control_definition(
            framework_version_id=fv["id"], display_code=cid, title=title, control_uid=cid,
            requirement_text="", interpretations=interp, now=now, created_by=created_by))
    return {"frameworks": list(frameworks.values()),
            "framework_versions": list(versions.values()),
            "control_definitions": defs}


# ── append-only 이벤트 hash chain(S3) — 감사로그와 동일 방식으로 변조 검증 ─────────────
_EVENT_HASH_FIELDS = ("event_id", "kind", "entity_id", "revision", "event_type",
                      "actor", "occurred_at", "payload")


def governance_event_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """이벤트 해시 = sha256(prev_hash | canonical(핵심 필드)). 앞 이벤트에 연결된 체인."""
    core = {k: entry.get(k) for k in _EVENT_HASH_FIELDS}
    payload = json.dumps(core, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(f"{prev_hash}|{payload}".encode()).hexdigest()


def build_governance_event(prev_hash: str, *, kind: str, entity_id: str, revision: int,
                           event_type: str, actor: str, occurred_at: str,
                           payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """append-only 이벤트 1건(hash 포함). event_id 는 kind:entity:revision 로 결정적."""
    entry = {
        "event_id": f"{kind}:{entity_id}:r{revision}",
        "kind": kind, "entity_id": entity_id, "revision": revision, "event_type": event_type,
        "actor": actor, "occurred_at": occurred_at, "payload": payload or {},
        "prev_hash": prev_hash,
    }
    entry["hash"] = governance_event_hash(prev_hash, entry)
    return entry


def verify_governance_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """이벤트 원장의 hash chain 무결성 검증(변조·삭제·재배열 감지).

    반환: {ok, count, broken_at(첫 불일치 event_id 또는 None)}.
    """
    prev_link: str | None = None
    for e in events:
        recomputed = governance_event_hash(str(e.get("prev_hash", "")), e)
        if recomputed != e.get("hash"):
            return {"ok": False, "count": len(events), "broken_at": e.get("event_id")}
        if prev_link is not None and e.get("prev_hash") != prev_link:
            return {"ok": False, "count": len(events), "broken_at": e.get("event_id")}
        prev_link = e.get("hash")
    return {"ok": True, "count": len(events), "broken_at": None}


# ── 감사 실사용(P4) — as-of 스냅샷 · 승인 · 재현 패키지 ─────────────────────────────
def build_cycle_audit_snapshot(
    cycle: dict[str, Any], cycle_controls: list[dict[str, Any]], as_of: str,
    *, scope_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """감사 기준일(as_of)의 운영주기 상태를 재현한다(P4).

    각 통제를 history 재생으로 그 시점 상태로 복원 + 당시 범위 스냅샷을 함께 고정한다.
    '지금' 값이 바뀌어도 심사 당시 상태를 그대로 재현할 수 있다(모리다움 — 과거본 불변 재현).
    """
    controls = []
    for cc in cycle_controls:
        st = cycle_control_as_of(cc, as_of)
        controls.append({"cycle_control_id": cc.get("id"), "control_ref": cc.get("control_ref"), **st})
    ev: dict[str, int] = {}
    asmt: dict[str, int] = {}
    for c in controls:
        ev[c["evidence_status"]] = ev.get(c["evidence_status"], 0) + 1
        asmt[c["assessment_status"]] = asmt.get(c["assessment_status"], 0) + 1
    return {
        "cycle_id": cycle.get("id"), "cycle_name": cycle.get("name"),
        "framework_version_id": cycle.get("framework_version_id"),
        "as_of": as_of, "control_count": len(controls),
        "evidence_status_counts": ev, "assessment_status_counts": asmt,
        "scope_snapshot_id": (scope_snapshot or {}).get("id") or cycle.get("scope_snapshot_id"),
        "controls": controls,
    }


# ── 다중기준 crosswalk(P5) — 내부통제 하나가 여러 외부기준을 충족 ──────────────────
def build_crosswalk(org_controls: list[dict[str, Any]]) -> dict[str, Any]:
    """내부통제의 mapped_controls 를 외부기준(framework)별로 묶어 crosswalk 를 만든다.

    통제 id 는 'framework:version:code' 관례 — 첫 세그먼트를 framework 로 본다.
    같은 기술 증적을 여러 인증에서 재사용할 수 있음을 보여준다.
    """
    rows = []
    fw_set: set[str] = set()
    for oc in org_controls:
        by_fw: dict[str, list[str]] = {}
        for cid in oc.get("mapped_controls") or []:
            fw = str(cid).split(":", 1)[0]
            fw_set.add(fw)
            by_fw.setdefault(fw, []).append(cid)
        rows.append({
            "organization_control_id": oc.get("id"), "code": oc.get("code"),
            "title": oc.get("title"), "frameworks": sorted(by_fw),
            "framework_count": len(by_fw), "mappings": by_fw,
        })
    return {"organization_controls": rows, "frameworks": sorted(fw_set),
            "reusable_note": "하나의 운영통제·기술증적을 여러 기준에 재사용(중복 증적 방지)."}


# ── Base + Organization Overlay(P5) — 기준 업데이트와 조직 커스터마이즈 분리 ───────────
_OVERLAY_FIELDS = ("owner_team", "frequency", "scope", "evidence_sources", "approver")


def apply_overlay(control_def: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """기준 통제(base)에 조직 오버레이를 얹은 '뷰'를 만든다(base 불변).

    기준 업데이트가 들어와도 overlay 를 유지하며, base 요구 내용이 바뀌면 conflict 로 표시한다.
    """
    view = {
        "control_id": control_def.get("id"),
        "display_code": control_def.get("display_code"),
        "title": control_def.get("title"),
        "base_requirement": (control_def.get("interpretations") or {}).get("official")
        or control_def.get("requirement_text", ""),
        "base_content_hash": control_def.get("content_hash"),
        "overlay": {k: overlay.get(k, "") for k in _OVERLAY_FIELDS},
    }
    # base 내용이 overlay 가 마지막으로 검토한 해시와 다르면 재검토 필요.
    reviewed_hash = overlay.get("reviewed_base_hash")
    view["conflict"] = bool(reviewed_hash) and reviewed_hash != control_def.get("content_hash")
    return view


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
    _stamp_hash(rec)
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
    initial = {
        "assignee": assignee, "applicability": applicability,
        "evidence_status": "missing", "assessment_status": "not_assessed",
        "evidence_contract_ref": "",
    }
    return {
        "id": cc_id, "cycle_control_id": cc_id, "cycle_id": cycle_id, "control_ref": control_ref,
        **initial, "created_at": now, "created_by": created_by, "updated_at": now,
        # 최초 history 에 초기값을 changed 로 박아, as-of 재생이 생성 시점 상태를 정확히 복원한다.
        "history": [{"ts": now, "actor": created_by, "action": "created", "changed": dict(initial)}],
    }


def apply_cycle_control_update(cc: dict[str, Any], *, actor: str, now: str,
                               evidence_status: str = "", assessment_status: str = "",
                               applicability: str = "", assignee: str = "",
                               note: str = "") -> dict[str, Any]:
    """운영주기 통제 상태 갱신(제자리 + append-only history). 증적·평가 상태는 서로 독립.

    실제로 값이 바뀐 필드만 changed 로 기록한다. 아무 변화가 없으면(단순 재호출·note 없음)
    history 를 남기지 않는다(no-op 오염 방지). 반환에 `_changed` 로 변경 여부를 알린다.
    """
    changed: dict[str, Any] = {}
    for field, val in (("evidence_status", evidence_status), ("assessment_status", assessment_status),
                       ("applicability", applicability), ("assignee", assignee)):
        if val and cc.get(field) != val:
            changed[field] = val
            cc[field] = val
    # 담당자가 적용성을 명시 설정하면 '재확인 필요'(#9) 해제 — 사람이 확정한 것.
    if applicability and cc.get("applicability_pending_review"):
        cc["applicability_pending_review"] = False
        changed["applicability_pending_review"] = False
    if not changed and not note:
        cc["_changed"] = False   # no-op — history 오염 없음
        return cc
    cc["updated_at"] = now
    cc.setdefault("history", []).append(
        {"ts": now, "actor": actor, "action": "update", "changed": changed, "note": note})
    cc["_changed"] = True
    return cc


# ── 버전 영향분석(P3) — Framework diff · 계보 · 운영주기 마이그레이션 ─────────────────
def _control_uid(c: dict[str, Any]) -> str:
    return str(c.get("control_uid") or c.get("display_code") or "")


def _control_body(c: dict[str, Any]) -> str:
    """실질 요구 내용만(버전·번호 제외) — 번호변경 vs 내용변경 구분용."""
    return json.dumps({"title": c.get("title"), "requirement_text": c.get("requirement_text"),
                       "interpretations": c.get("interpretations")},
                      ensure_ascii=False, sort_keys=True)


def _migration_reason(old_def: dict[str, Any], new_def: dict[str, Any]) -> str:
    """old→new 통제의 이관 사유: text_changed / renumbered / carried(동일)."""
    if _control_body(old_def) != _control_body(new_def):
        return "text_changed"
    if str(old_def.get("display_code")) != str(new_def.get("display_code")):
        return "renumbered"
    return "carried"


def diff_control_definitions(
    old_controls: list[dict[str, Any]], new_controls: list[dict[str, Any]],
) -> dict[str, Any]:
    """두 기준 버전의 통제를 control_uid 기준으로 비교한다(P3).

    - added: 신규 통제(구 버전에 uid 없음).
    - removed: 삭제 통제(신 버전에 uid 없음).
    - renumbered: uid 같고 display_code 만 바뀜(실질 요구 동일 후보).
    - text_changed: uid 같고 content_hash(요구 내용) 바뀜(실질 요구 변경 후보).
    - unchanged: uid·내용 동일.
    AI 확정이 아니라 후보 — 담당자가 계보·영향을 검토한다(모리다움).
    """
    _uid = _control_uid
    _body = _control_body

    old_by = {_uid(c): c for c in old_controls}
    new_by = {_uid(c): c for c in new_controls}
    added, removed, renumbered, text_changed, unchanged = [], [], [], [], []

    for uid, nc in new_by.items():
        oc = old_by.get(uid)
        if oc is None:
            added.append({"control_uid": uid, "display_code": nc.get("display_code"),
                          "title": nc.get("title")})
            continue
        code_changed = str(oc.get("display_code")) != str(nc.get("display_code"))
        body_changed = _body(oc) != _body(nc)
        row = {"control_uid": uid, "old_code": oc.get("display_code"),
               "new_code": nc.get("display_code"), "title": nc.get("title")}
        if body_changed:
            text_changed.append(row)
        elif code_changed:
            renumbered.append(row)
        else:
            unchanged.append(row)
    for uid, oc in old_by.items():
        if uid not in new_by:
            removed.append({"control_uid": uid, "display_code": oc.get("display_code"),
                            "title": oc.get("title")})

    return {
        "added": added, "removed": removed, "renumbered": renumbered,
        "text_changed": text_changed, "unchanged": unchanged,
        "counts": {"added": len(added), "removed": len(removed), "renumbered": len(renumbered),
                   "text_changed": len(text_changed), "unchanged": len(unchanged)},
    }


# 새 운영주기 생성 시 **승계 O / 승계 X** — 작년 Effective 가 올해 Effective 는 아니다.
_CARRY_FIELDS = ("assignee", "applicability", "evidence_contract_ref")
_RESET_EVIDENCE = "missing"
_RESET_ASSESSMENT = "not_assessed"


def initialize_cycle_from_previous(
    prev_cycle_controls: list[dict[str, Any]], new_cycle_id: str, *, now: str, created_by: str = "",
) -> dict[str, Any]:
    """지난 운영주기에서 새 주기 통제들을 생성한다(P3).

    승계(carry): 담당자·적용성·증적계약 참조·매핑(운영 설정).
    초기화(reset): 증적 상태·평가 상태·승인·과거증적·위험수용(작년 판정 자동 승계 금지).
    """
    new_controls: list[dict[str, Any]] = []
    for prev in prev_cycle_controls:
        ref = str(prev.get("control_ref") or "")
        cc = build_cycle_control(cycle_id=new_cycle_id, control_ref=ref,
                                 assignee=str(prev.get("assignee") or ""),
                                 applicability=str(prev.get("applicability") or "pending_assessment"),
                                 now=now, created_by=created_by)
        cc["evidence_contract_ref"] = prev.get("evidence_contract_ref", "")
        cc["evidence_status"] = _RESET_EVIDENCE      # 초기화
        cc["assessment_status"] = _RESET_ASSESSMENT  # 초기화
        cc["applicability_pending_review"] = True    # 적용성 재확인 필요(#9)
        cc["carried_from"] = prev.get("id")
        cc["history"].append({"ts": now, "actor": created_by, "action": "carried_from_previous",
                              "note": "승계: 담당자·적용성(재확인 필요) / 초기화: 증적·평가"})
        new_controls.append(cc)
    return {
        "new_cycle_id": new_cycle_id,
        "carried": len(new_controls),
        "carried_fields": list(_CARRY_FIELDS),
        "reset_fields": ["evidence_status", "assessment_status", "approvals", "past_evidence"],
        "cycle_controls": new_controls,
    }


def _carry_cycle_control(prev: dict[str, Any], new_ref: str, reason: str, review: bool,
                         new_cycle_id: str, now: str, created_by: str) -> dict[str, Any]:
    """이전 주기 통제를 새 참조로 이관 — 운영설정 승계 + 증적·평가 초기화 + 계보 기록."""
    cc = build_cycle_control(cycle_id=new_cycle_id, control_ref=new_ref,
                             assignee=str(prev.get("assignee") or ""),
                             applicability=str(prev.get("applicability") or "pending_assessment"),
                             now=now, created_by=created_by)
    cc["evidence_contract_ref"] = prev.get("evidence_contract_ref", "")
    cc["evidence_status"] = _RESET_EVIDENCE
    cc["assessment_status"] = _RESET_ASSESSMENT
    # 적용성은 값을 복사하되 **재확인 필요**로 표시(리뷰 #9) — 범위 변경으로 달라질 수 있으므로
    # 작년 판단을 확정 승계하지 않는다(자동 연장 금지 원칙과 동일).
    cc["applicability_pending_review"] = True
    cc["carried_from_control_ref"] = prev.get("control_ref")
    cc["carried_from"] = prev.get("id")
    cc["migration_reason"] = reason
    cc["requires_design_review"] = review
    cc["history"].append({"ts": now, "actor": created_by, "action": "migrated",
                          "note": f"{reason} — 승계: 담당자·적용성 / 초기화: 증적·평가"})
    return cc


def plan_cycle_migration(
    prev_cycle_controls: list[dict[str, Any]], old_controls: list[dict[str, Any]],
    new_controls: list[dict[str, Any]], new_cycle_id: str, *, now: str, created_by: str = "",
) -> dict[str, Any]:
    """**진짜 버전 마이그레이션**(S2) — version diff 와 운영주기 승계를 하나로 묶는다.

    이전 주기 통제(control_ref = 구버전 통제 id)를 control_uid 계보로 신버전 통제에 연결한다.
    - 번호 변경(renumbered): 새 참조로 이관.
    - 내용 변경(text_changed): 새 참조로 이관 + requires_design_review=True.
    - 삭제(removed): 새 주기에 만들지 않고 removed 목록 + 검토 대상(unresolved).
    - 신규(added): 신규 통제 생성(requires_design_review=True).
    운영설정(담당자·적용성)은 승계, 증적·평가는 초기화. 담당자 검토 후보이지 자동 확정이 아니다.
    """
    old_by_id = {c["id"]: c for c in old_controls}
    new_by_uid = {_control_uid(c): c for c in new_controls}

    controls: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    counts = {"carried": 0, "renumbered": 0, "text_changed": 0,
              "new_controls": 0, "removed_controls": 0, "unresolved_mappings": 0}
    carried_uids: set[str] = set()

    for prev in prev_cycle_controls:
        ref = str(prev.get("control_ref") or "")
        old_def = old_by_id.get(ref)
        if old_def is None:
            # 이전 참조가 구버전 통제 정의가 아님(내부통제 등) — 그대로 승계.
            controls.append(_carry_cycle_control(prev, ref, "carried", False,
                                                 new_cycle_id, now, created_by))
            counts["carried"] += 1
            continue
        uid = _control_uid(old_def)
        new_def = new_by_uid.get(uid)
        if new_def is None:
            removed.append({"control_uid": uid, "old_ref": ref,
                            "display_code": old_def.get("display_code"),
                            "title": old_def.get("title"),
                            "action_required": "종료 또는 대체 매핑 검토"})
            counts["removed_controls"] += 1
            counts["unresolved_mappings"] += 1
            continue
        carried_uids.add(uid)
        reason = _migration_reason(old_def, new_def)
        review = reason == "text_changed"
        controls.append(_carry_cycle_control(prev, new_def["id"], reason, review,
                                             new_cycle_id, now, created_by))
        counts["carried"] += 1
        if reason == "renumbered":
            counts["renumbered"] += 1
        elif reason == "text_changed":
            counts["text_changed"] += 1

    # 신규 통제(어느 이전 통제에도 연결 안 됨) — 새로 생성, 재설계 검토 대상.
    for uid, new_def in new_by_uid.items():
        if uid in carried_uids:
            continue
        cc = build_cycle_control(cycle_id=new_cycle_id, control_ref=new_def["id"],
                                 now=now, created_by=created_by)
        cc["migration_reason"] = "new"
        cc["requires_design_review"] = True
        cc["history"].append({"ts": now, "actor": created_by, "action": "new_control",
                              "note": "신규 통제 — 설계·적용성 검토 필요"})
        controls.append(cc)
        counts["new_controls"] += 1

    return {
        "new_cycle_id": new_cycle_id, "counts": counts,
        "removed_controls": removed,
        "changed_controls_requiring_review": [c["control_ref"] for c in controls
                                              if c.get("requires_design_review")],
        "cycle_controls": controls,
    }


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
    "diff_control_definitions", "initialize_cycle_from_previous",
    "build_cycle_audit_snapshot", "build_crosswalk", "apply_overlay",
    "VERSION_TRANSITIONS", "can_version_transition", "apply_version_lifecycle", "periods_overlap",
    "plan_cycle_migration", "governance_event_hash", "build_governance_event",
    "verify_governance_chain", "plan_catalog_import",
]
