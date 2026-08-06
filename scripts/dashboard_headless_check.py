#!/usr/bin/env python3
"""헤드리스 렌더 가드 (P2 선결) — dashboard JS가 브라우저에서 예외 없이 로드/초기화되는지.

렌더된 대시보드 HTML을 chromium(headless)으로 로드해 **uncaught JS 예외(pageerror)**가
0인지 확인한다. 백엔드가 없으므로 fetch/네트워크 오류는 예상된 것이라 필터하고, JS
구문·초기화 붕괴(P2 JS 외부화의 핵심 리스크)만 잡는다. 탭 전환도 한 번 실행해 본다.

실행(플레이라이트 이미지 — 브라우저 포함, python 바인딩만 설치):
  docker run --rm -v "$PWD":/app -w /app -e PYTHONPATH=src \
    mcr.microsoft.com/playwright/python:v1.47.0-jammy \
    bash -c 'pip install -q playwright==1.47.0; python scripts/dashboard_headless_check.py'
종료코드 0 = 통과(예외 0), 1 = uncaught JS 예외 발견. (baseline: 0 확인됨)
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, "src")
from mori_soc.api.templates.dashboard import render_user_dashboard_html  # noqa: E402

html = render_user_dashboard_html()
# P2: JS가 /static/js/dashboard.js 로 외부화됨 → file:// 로드용으로 인라인 주입해 런타임 검증
_js_path = pathlib.Path(__file__).resolve().parent.parent / "src" / "mori_soc" / "api" / "static" / "js" / "dashboard.js"
if _js_path.is_file():
    _js = _js_path.read_text(encoding="utf-8")
    html = html.replace('<script src="/static/js/dashboard.js"></script>',
                        "<script>\n" + _js + "\n</script>")
tmp = pathlib.Path(tempfile.gettempdir()) / "mori_dashboard.html"
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
        for tab in ("compliance", "accounts", "triage", "assets", "incidents", "guides", "dashboard"):
            try:
                page.evaluate(f"typeof switchTab==='function' && switchTab('{tab}')")
            except Exception as exc:  # noqa: BLE001
                page_errors.append(f"switchTab({tab},{lang}): {exc}")
    # 신규 상호작용도 실행(R1) — 빈 상태 CTA·해시 딥링크. 정의·구문 붕괴 시 여기서 예외.
    for expr in (
        "typeof openControlCatalog==='function' && openControlCatalog()",
        "location.hash='#compliance'",
        "typeof renderMoriHeader==='function'",
    ):
        try:
            page.evaluate(expr)
        except Exception as exc:  # noqa: BLE001
            page_errors.append(f"{expr}: {exc}")
    page.wait_for_timeout(300)
    # i18n 가드(개선①): EN 적용 후 [data-i18n] 요소에 한글이 남으면 = 사전 en 누락/키 없는 라벨.
    page.evaluate("window.lang='en'; window.applyI18n && window.applyI18n(document);")
    page.wait_for_timeout(150)
    i18n_leftover = page.evaluate(
        r"""() => { const H=/[가-힣]/; const out=[];
        document.querySelectorAll('[data-i18n],[data-i18n-html],[data-i18n-doctitle]').forEach(el=>{
          const t=(el.textContent||'').trim();
          if(t && H.test(t)) out.push((el.getAttribute('data-i18n')||el.getAttribute('data-i18n-html')||'?')+' :: '+t.slice(0,50)); });
        return [...new Set(out)]; }"""
    )
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
print(f"[headless] EN 렌더 [data-i18n] 한글 잔존: {len(i18n_leftover)}")
for k in i18n_leftover[:20]:
    print("  I18N-LEFTOVER:", k)

sys.exit(1 if (page_errors or i18n_leftover) else 0)
