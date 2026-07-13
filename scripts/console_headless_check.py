#!/usr/bin/env python3
"""헤드리스 렌더 가드 (P7-2 선결) — admin console JS가 브라우저에서 예외 없이 로드/초기화되는지.

dashboard_headless_check.py와 동형: 렌더된 admin 콘솔 HTML을 chromium(headless)으로 로드해
**uncaught JS 예외(pageerror)**가 0인지 확인한다. 백엔드가 없으므로 fetch/네트워크 오류는
예상된 것이라 필터하고, JS 구문·초기화 붕괴(P7-2 JS 외부화의 핵심 리스크)만 잡는다.
탭 전환(switchAdminTab)도 ko/en 양쪽으로 실행해 본다.

실행(플레이라이트 이미지 — 브라우저 포함, python 바인딩만 설치):
  docker run --rm -v "$PWD":/app -w /app -e PYTHONPATH=src \
    mcr.microsoft.com/playwright/python:v1.47.0-jammy \
    bash -c 'pip install -q playwright==1.47.0; python scripts/console_headless_check.py'
종료코드 0 = 통과(예외 0), 1 = uncaught JS 예외 발견.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, "src")
from mori_soc.api.templates.console import render_query_console_html  # noqa: E402

html = render_query_console_html()
# P7-2: JS가 /static/js/console.js 로 외부화됨 → file:// 로드용으로 인라인 주입해 런타임 검증
_js_path = pathlib.Path(__file__).resolve().parent.parent / "src" / "mori_soc" / "api" / "static" / "js" / "console.js"
if _js_path.is_file():
    _js = _js_path.read_text(encoding="utf-8")
    html = html.replace('<script src="/static/js/console.js"></script>',
                        "<script>\n" + _js + "\n</script>")
tmp = pathlib.Path(tempfile.gettempdir()) / "mori_console.html"
tmp.write_text(html, encoding="utf-8")

from playwright.sync_api import sync_playwright  # noqa: E402

page_errors: list[str] = []
console_errors: list[str] = []

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.on("pageerror", lambda e: page_errors.append(str(e)))
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.goto(tmp.as_uri(), wait_until="domcontentloaded")
    page.wait_for_timeout(1200)
    # 탭 전환 JS 실행(정의·구문 붕괴 시 여기서 예외) — ko/en 양쪽 경로 실행
    for lang in ("ko", "en"):
        try:
            page.evaluate(f"window.lang = '{lang}'")
        except Exception as exc:  # noqa: BLE001
            page_errors.append(f"setLang({lang}): {exc}")
        for tab in ("overview", "logs", "access", "assets", "remediation", "settings"):
            try:
                page.evaluate(f"typeof switchAdminTab==='function' && switchAdminTab('{tab}')")
            except Exception as exc:  # noqa: BLE001
                page_errors.append(f"switchAdminTab({tab},{lang}): {exc}")
    page.wait_for_timeout(300)
    browser.close()


# 백엔드 없음 → fetch/네트워크성 console.error 는 예상된 것이라 분리
def _net(c: str) -> bool:
    c = c.lower()
    return any(k in c for k in ("fetch", "failed to load", "net::", "load resource", "http"))


non_net_console = [c for c in console_errors if not _net(c)]

print(f"[headless] uncaught JS 예외(pageerror): {len(page_errors)}")
for e in page_errors[:15]:
    print("  JS-ERROR:", e)
print(f"[headless] 비-네트워크 console.error: {len(non_net_console)} (참고)")
for c in non_net_console[:15]:
    print("  CONSOLE:", c)

sys.exit(1 if page_errors else 0)
