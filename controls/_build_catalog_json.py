#!/usr/bin/env python3
"""controls/*.yaml (정본) → src/mori_soc/data/controls_catalog.json (런타임 아티팩트).

앱 이미지는 src/ 만 복사하고 PyYAML 이 없으므로, YAML 카탈로그를 패키지 내부 JSON 으로
빌드해 런타임은 stdlib json 으로만 읽는다. controls/ 를 수정하면 이 스크립트를 다시 실행:

    python controls/_build_catalog_json.py     # (PyYAML 필요; 호스트에서 실행)

생성물은 커밋한다(생성 아티팩트). 검증은 controls/validate.py.
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
OUT = ROOT.parent / "src" / "mori_soc" / "data" / "controls_catalog.json"


def _load_dir(subdir: str) -> list[dict]:
    docs = []
    for f in sorted((ROOT / subdir).glob("*.yaml")):
        docs.append(yaml.safe_load(f.read_text(encoding="utf-8")))
    return docs


def main() -> int:
    controls = _load_dir("isms-p") + _load_dir("iso27001")
    mappings: list[dict] = []
    for f in sorted((ROOT / "mappings").glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        mappings.extend(doc.get("mappings", []))
    defects = _load_dir("common_defects")

    isms = [c for c in controls if c.get("framework") == "isms-p"]
    iso = [c for c in controls if c.get("framework") == "iso27001"]
    reviewed = [c for c in controls if c.get("status") == "reviewed"]

    payload = {
        "meta": {
            "controls": len(controls),
            "isms_p": len(isms),
            "iso27001": len(iso),
            "reviewed": len(reviewed),
            "mappings": len(mappings),
            "defects": len(defects),
        },
        "controls": controls,
        "mappings": mappings,
        "defects": defects,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT.parent)} — {payload['meta']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
