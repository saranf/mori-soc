"""Temp scanner: find Korean text that EN mode will NOT translate.

Static HTML leak = a text node / placeholder / title / option whose element
(or ancestor) lacks data-i18n / data-i18n-html / data-i18n-placeholder etc.
JS leak = a Korean string literal inside a <script> not passed through t()/tt().
The embedded window.MORI_I18N dictionary block is excluded.
"""

import re
from html.parser import HTMLParser

from mori_soc.api.server import (
    render_user_dashboard_html,
    render_query_console_html,
)

KO = re.compile(r"[\uac00-\ud7a3]")
COVER_TEXT = {"data-i18n", "data-i18n-html"}


def strip_dict_script(html: str) -> str:
    # Remove the window.MORI_I18N={...}; dictionary so its KO isn't flagged.
    return re.sub(r"window\.MORI_I18N=\{.*?\};", "window.MORI_I18N={};", html, flags=re.S)


class Scanner(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []          # list of (tag, covered_bool)
        self.in_script = False
        self.in_style = False
        self.script_buf = []
        self.static_leaks = []   # (tag_path, snippet)
        self.attr_leaks = []     # (tag, attr, value)
        self.js_leaks = []       # snippet

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        covered = (self.stack and self.stack[-1][1]) or any(k in COVER_TEXT for k in ad)
        # attribute-level KO leaks
        ph = ad.get("placeholder")
        if ph and KO.search(ph) and "data-i18n-placeholder" not in ad:
            self.attr_leaks.append((tag, "placeholder", ph))
        ti = ad.get("title")
        if ti and KO.search(ti) and "data-i18n-title" not in ad:
            self.attr_leaks.append((tag, "title", ti))
        if tag == "script":
            self.in_script = True
            self.script_buf = []
            self.script_is_dict = ad.get("type") == "application/json"
        if tag == "style":
            self.in_style = True
        self.stack.append((tag, bool(covered)))

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
            self._scan_js("".join(self.script_buf))
        if tag == "style":
            self.in_style = False
        while self.stack:
            t, _ = self.stack.pop()
            if t == tag:
                break

    def handle_data(self, data):
        if self.in_script:
            self.script_buf.append(data)
            return
        if self.in_style:
            return
        if not KO.search(data):
            return
        covered = self.stack and self.stack[-1][1]
        if covered:
            return
        path = "/".join(t for t, _ in self.stack[-4:])
        snippet = " ".join(data.split())[:70]
        if snippet:
            self.static_leaks.append((path, snippet))

    def _scan_js(self, js):
        # KO string literals not immediately preceded by t( / tt( / window.t(
        for m in re.finditer(r"(['\"`])((?:\\.|(?!\1).)*?)\1", js):
            s = m.group(2)
            if not KO.search(s):
                continue
            pre = js[max(0, m.start() - 14):m.start()]
            if re.search(r"\b(t|tt)\($", pre) or pre.endswith("window.t("):
                continue
            self.js_leaks.append(" ".join(s.split())[:70])


def scan(name, html):
    p = Scanner()
    p.feed(strip_dict_script(html))
    print(f"\n===== {name} =====")
    print(f"static text leaks: {len(p.static_leaks)}")
    for path, s in p.static_leaks:
        print(f"  [{path}] {s}")
    print(f"attr leaks (placeholder/title): {len(p.attr_leaks)}")
    for tag, attr, v in p.attr_leaks:
        print(f"  <{tag} {attr}> {v[:60]}")
    print(f"js literal leaks: {len(p.js_leaks)}  (unique {len(set(p.js_leaks))})")
    for s in list(dict.fromkeys(p.js_leaks)):
        print(f"  js: {s}")


scan("dashboard", render_user_dashboard_html())
scan("console", render_query_console_html())
