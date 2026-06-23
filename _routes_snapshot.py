"""One-time route-set snapshot for the J-4b routes modularization.

Builds the app via ``create_app`` and emits a stable, order-independent JSON
representation of every registered route (methods, path, endpoint name, tags).
Used as the regression baseline: re-run after each domain move and diff against
``_routes_baseline.json`` to prove no route was lost, added, or altered.

    python _routes_snapshot.py            # prints JSON to stdout
"""
from __future__ import annotations

import json

from mori_soc.api.server import create_app


def snapshot() -> list[dict[str, object]]:
    app = create_app()
    rows: list[dict[str, object]] = []
    for route in getattr(app, "routes", []):
        path = getattr(route, "path", None)
        if path is None:
            continue
        methods = sorted(getattr(route, "methods", None) or [])
        tags = sorted(getattr(route, "tags", None) or [])
        name = getattr(route, "name", "")
        rows.append({"path": path, "methods": methods, "name": name, "tags": tags})
    rows.sort(key=lambda r: (r["path"], ",".join(r["methods"]), r["name"]))
    return rows


if __name__ == "__main__":
    print(json.dumps(snapshot(), ensure_ascii=False, indent=2))
