#!/usr/bin/env python3
"""controls/ 통제 카탈로그 검증 — 스키마 준수 + 상호참조 무결성.

의존성: PyYAML 만 필요(표준 라이브러리 + 내장 미니 JSON-Schema 체커).
Phase 2 정식 단계에서 jsonschema 기반 CI 로 교체 예정. 현재는 어디서나 실행되도록
stdlib 만으로 draft-07 부분집합(type/required/properties/enum/items/additionalProperties)
을 검증한다.

    python controls/validate.py        # 통과 시 exit 0, 오류 시 exit 1
"""
from __future__ import annotations

import json
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML 이 필요합니다: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent
errors: list[str] = []


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schema" / name).read_text(encoding="utf-8"))


def _check(inst, schema: dict, path: str) -> None:
    """draft-07 부분집합 검증."""
    t = schema.get("type")
    if t == "object":
        if not isinstance(inst, dict):
            errors.append(f"{path}: object 여야 함"); return
        for req in schema.get("required", []):
            if req not in inst:
                errors.append(f"{path}: 필수 키 '{req}' 누락")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in inst:
                if key not in props:
                    errors.append(f"{path}: 허용되지 않은 키 '{key}'")
        for key, val in inst.items():
            if key in props:
                _check(val, props[key], f"{path}.{key}")
    elif t == "array":
        if not isinstance(inst, list):
            errors.append(f"{path}: array 여야 함"); return
        items = schema.get("items")
        if items:
            for i, val in enumerate(inst):
                _check(val, items, f"{path}[{i}]")
    elif t == "string":
        if not isinstance(inst, str):
            errors.append(f"{path}: string 여야 함")
    if "enum" in schema and inst not in schema["enum"]:
        errors.append(f"{path}: '{inst}' 는 허용값 {schema['enum']} 중 하나가 아님")


def _load(path: pathlib.Path):
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        errors.append(f"{path.name}: YAML 파싱 실패 — {exc}")
        return None


def main() -> int:
    control_schema = _schema("control.schema.json")
    mapping_schema = _schema("mapping.schema.json")
    defect_schema = _schema("defect.schema.json")

    ids: dict[str, set] = {"isms-p": set(), "iso27001": set()}
    n_controls = 0
    for framework in ("isms-p", "iso27001"):
        for f in sorted((ROOT / framework).glob("*.yaml")):
            doc = _load(f)
            if doc is None:
                continue
            _check(doc, control_schema, f.name)
            if isinstance(doc, dict):
                if doc.get("framework") != framework:
                    errors.append(f"{f.name}: framework 는 '{framework}' 여야 함")
                if "id" in doc:
                    ids[framework].add(doc["id"])
            n_controls += 1

    all_ids = ids["isms-p"] | ids["iso27001"]

    n_map = 0
    for f in sorted((ROOT / "mappings").glob("*.yaml")):
        doc = _load(f)
        if doc is None:
            continue
        _check(doc, mapping_schema, f.name)
        for m in (doc.get("mappings") if isinstance(doc, dict) else []) or []:
            n_map += 1
            if m.get("isms_p") not in ids["isms-p"]:
                errors.append(f"{f.name}: 매핑 isms_p '{m.get('isms_p')}' 가 카탈로그에 없음")
            for iso in m.get("iso27001", []) or []:
                if iso not in ids["iso27001"]:
                    errors.append(f"{f.name}: 매핑 iso27001 '{iso}' 가 카탈로그에 없음")

    known_signals = {
        "", "vuln_pending", "exceptions_expiring", "untriaged_alerts",
        "overdue", "control_pending", "unmapped_assets", "code_review_pending",
    }
    n_def = 0
    for f in sorted((ROOT / "common_defects").glob("*.yaml")):
        doc = _load(f)
        if doc is None:
            continue
        _check(doc, defect_schema, f.name)
        n_def += 1
        if isinstance(doc, dict):
            for cid in doc.get("controls", []) or []:
                if cid not in all_ids:
                    errors.append(f"{f.name}: defect controls '{cid}' 가 카탈로그에 없음")
            sig = doc.get("mori_signal", "")
            if sig not in known_signals:
                errors.append(
                    f"{f.name}: mori_signal '{sig}' 가 evidence-gap 타일 키와 불일치 "
                    f"(허용: {sorted(known_signals - {''})})"
                )

    print(f"controls={n_controls} (isms-p {len(ids['isms-p'])}, iso {len(ids['iso27001'])}), "
          f"mappings={n_map}, defects={n_def}")
    if errors:
        print("\n".join("  ✗ " + e for e in errors))
        print(f"FAIL: {len(errors)} 오류")
        return 1
    print("OK: 카탈로그 검증 통과")
    return 0


if __name__ == "__main__":
    sys.exit(main())
