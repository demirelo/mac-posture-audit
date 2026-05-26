#!/usr/bin/env python3
"""Render a mac-posture-audit --json document as a self-contained HTML report.

Opt-in companion (v1.4). The core auditor stays a single read-only shell script;
this tool is a separate, stdlib-only renderer so the report can be shared as one
HTML file with no external assets, no network, and no dependencies beyond the
Python 3 that ships with macOS.

    ./mac-posture-audit.sh --json --redact > posture.json
    python3 tools/render_report.py posture.json > report.html
    # or pipe:
    ./mac-posture-audit.sh --json --redact | python3 tools/render_report.py > report.html

Exit codes: 0 on success, 2 on usage/parse error.
"""

from __future__ import annotations

import html
import json
import sys

TIER_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
STATUS_LABEL = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "skip": "SKIP"}

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
       margin: 0; padding: 2rem; max-width: 60rem; margin-inline: auto;
       background: #fbfbfd; color: #1d1d1f; }
@media (prefers-color-scheme: dark) { body { background: #16161a; color: #e8e8ea; } }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.2rem; margin: 2rem 0 .75rem; border-bottom: 1px solid #8884; padding-bottom: .25rem; }
.meta { color: #8a8a8e; font-size: .9rem; margin-bottom: 1.5rem; }
.verdict { padding: 1rem 1.25rem; border-radius: .6rem; background: #8881; border-left: 4px solid #8888; }
.prio { font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.prio-urgent { color: #d11; } .prio-high { color: #e60; }
.prio-medium { color: #b80; } .prio-low, .prio-none { color: #2a8; }
table { border-collapse: collapse; width: 100%; font-size: .92rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #8883; vertical-align: top; }
th { font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; color: #8a8a8e; }
code { font: .85em ui-monospace, SFMono-Regular, Menlo, monospace; background: #8882; padding: .05rem .3rem; border-radius: .25rem; }
.tag { font-weight: 700; font-size: .78rem; padding: .1rem .45rem; border-radius: .3rem; }
.tag-urgent { background: #d112; color: #d11; } .tag-high { background: #e602; color: #e60; }
.tag-medium { background: #b802; color: #b80; } .tag-low { background: #2a82; color: #2a8; }
.s-pass { color: #2a8; } .s-warn { color: #b80; } .s-fail { color: #d11; font-weight: 700; } .s-skip { color: #8a8a8e; }
footer { margin-top: 2.5rem; color: #8a8a8e; font-size: .82rem; }
"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def render(doc: dict) -> str:
    summary = doc.get("summary", {})
    verdict = doc.get("executive_verdict", {})
    top = sorted(
        doc.get("top_risks", []),
        key=lambda r: (TIER_ORDER.get(r.get("tier", ""), 9), r.get("rank", 0)),
    )
    results = doc.get("results", [])
    tier = verdict.get("tier", "none")

    out: list[str] = []
    out.append("<!doctype html><html lang=en><head><meta charset=utf-8>")
    out.append('<meta name=viewport content="width=device-width, initial-scale=1">')
    out.append("<title>macOS Posture Audit</title>")
    out.append(f"<style>{CSS}</style></head><body>")
    out.append("<h1>macOS Posture Audit</h1>")
    out.append(
        f'<p class=meta>Host <code>{esc(doc.get("host", "?"))}</code> · '
        f'macOS {esc(doc.get("macos", "?"))} · {esc(doc.get("arch", "?"))} · '
        f'profile <code>{esc(verdict.get("profile", "?"))}</code></p>'
    )

    out.append('<div class=verdict>')
    if verdict.get("text"):
        out.append(f"<p>{esc(verdict['text'])}</p>")
    out.append(
        f'<p class="prio prio-{esc(tier)}">Action priority: {esc(tier)}</p></div>'
    )
    out.append(
        f'<p class=meta>{summary.get("pass", 0)} pass · {summary.get("warn", 0)} warn · '
        f'{summary.get("fail", 0)} fail · {summary.get("skip", 0)} skip '
        f'({summary.get("total", len(results))} total)</p>'
    )

    out.append("<h2>Top risks to address</h2>")
    if top:
        out.append("<table><thead><tr><th>#</th><th>tier</th><th>id</th><th>finding</th></tr></thead><tbody>")
        for r in top:
            t = esc(r.get("tier", ""))
            out.append(
                f'<tr><td>{esc(r.get("rank", ""))}</td>'
                f'<td><span class="tag tag-{t}">{t}</span></td>'
                f'<td><code>{esc(r.get("id", ""))}</code></td>'
                f'<td>{esc(r.get("label", ""))}</td></tr>'
            )
        out.append("</tbody></table>")
    else:
        out.append("<p><em>No warnings or failures.</em></p>")

    out.append("<h2>All checks</h2>")
    out.append("<table><thead><tr><th>status</th><th>id</th><th>finding</th></tr></thead><tbody>")
    for r in results:
        st = r.get("status", "skip")
        out.append(
            f'<tr><td class="s-{esc(st)}">{esc(STATUS_LABEL.get(st, st))}</td>'
            f'<td><code>{esc(r.get("id", ""))}</code></td>'
            f'<td>{esc(r.get("label", ""))}</td></tr>'
        )
    out.append("</tbody></table>")

    out.append(
        "<footer>Generated by mac-posture-audit (read-only audit). "
        "This report can list sensitive details — run the audit with "
        "<code>--redact</code> before sharing.</footer>"
    )
    out.append("</body></html>")
    return "".join(out)


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("usage: render_report.py [posture.json]  (or pipe JSON on stdin)", file=sys.stderr)
        return 2
    try:
        raw = open(argv[1]).read() if len(argv) == 2 else sys.stdin.read()
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        print(f"render_report: could not read/parse input: {e}", file=sys.stderr)
        return 2
    if not isinstance(doc, dict) or "results" not in doc:
        print("render_report: input is not a mac-posture-audit JSON document", file=sys.stderr)
        return 2
    sys.stdout.write(render(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
