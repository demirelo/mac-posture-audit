#!/usr/bin/env python3
"""Render a mac-posture-audit --json document as a self-contained HTML report.

Opt-in companion (v1.4). The core auditor stays a single read-only shell script;
this tool is a separate, stdlib-only renderer so the report can be shared as one
HTML file with no external assets, no network, and no dependencies beyond an
installed Python 3 interpreter.

    ./mac-posture-audit.sh --json --redact > posture.json
    python3 tools/render_report.py posture.json --output report.html
    # or pipe:
    ./mac-posture-audit.sh --json --redact | python3 tools/render_report.py --output report.html

Use --output report.html to create a private file without replacing an existing
path. Shell redirection uses the shell's permissions and overwrite rules.

Exit codes: 0 on success, 2 on input/output or usage error.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import os
import subprocess
import sys

TIER_ORDER = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
STATUS_LABEL = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "skip": "SKIP"}
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ROWS = 10000
MAX_TEXT_LENGTH = 65536

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
.hint { margin-top: .3rem; font-size: .88em; color: #666; white-space: pre-wrap; }
@media (prefers-color-scheme: dark) { .hint { color: #aaa; } }
td { overflow-wrap: anywhere; }
footer { margin-top: 2.5rem; color: #8a8a8e; font-size: .82rem; }
"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _text(value: object, field: str, *, nonempty: bool = False) -> None:
    if not isinstance(value, str) or (nonempty and not value):
        raise ValueError(f"{field} must be a {'non-empty ' if nonempty else ''}string")
    if len(value) > MAX_TEXT_LENGTH:
        raise ValueError(f"{field} exceeds {MAX_TEXT_LENGTH} characters")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"{field} contains an invalid Unicode surrogate")


def _count(value: object, field: str) -> None:
    # bool is an int subclass, but is not an audit counter.
    if type(value) is not int or not 0 <= value <= MAX_ROWS:
        raise ValueError(f"{field} must be an integer from 0 to {MAX_ROWS}")


def validate(doc: object) -> dict:
    """Check fields used by the renderer; permit additive/legacy schema fields.

    Counts and top-risk references must agree with the check rows. Validation
    is also used by render(), so imported callers get the same protection as
    the command line. No input data is modified.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        raise ValueError("input must be a mac-posture-audit object with a results array")
    results = doc["results"]
    if len(results) > MAX_ROWS:
        raise ValueError(f"results exceeds {MAX_ROWS} rows")
    for field in ("host", "macos", "arch"):
        if field in doc:
            _text(doc[field], field)

    counts = dict.fromkeys(STATUS_LABEL, 0)
    by_id = {}
    for index, row in enumerate(results):
        field = f"results[{index}]"
        if not isinstance(row, dict):
            raise ValueError(f"{field} must be an object")
        _text(row.get("id"), f"{field}.id", nonempty=True)
        _text(row.get("label"), f"{field}.label")
        if "hint" in row:
            _text(row["hint"], f"{field}.hint")
        status = row.get("status")
        if not isinstance(status, str) or status not in STATUS_LABEL:
            raise ValueError(f"{field}.status must be pass, warn, fail, or skip")
        if row["id"] in by_id:
            raise ValueError(f"{field}.id duplicates another check")
        by_id[row["id"]] = row
        counts[status] += 1
    counts["total"] = len(results)

    if "summary" in doc:
        summary = doc["summary"]
        if not isinstance(summary, dict):
            raise ValueError("summary must be an object")
        for status in STATUS_LABEL:
            _count(summary.get(status), f"summary.{status}")
            if summary[status] != counts[status]:
                raise ValueError(f"summary.{status} does not match results")
        if "total" in summary:
            _count(summary["total"], "summary.total")
            if summary["total"] != len(results):
                raise ValueError("summary.total does not match results")

    verdict = doc.get("executive_verdict", {})
    if not isinstance(verdict, dict):
        raise ValueError("executive_verdict must be an object")
    for field in ("profile", "text"):
        if field in verdict:
            _text(verdict[field], f"executive_verdict.{field}")
    if "tier" in verdict:
        tier = verdict["tier"]
        if not isinstance(tier, str) or tier not in (*TIER_ORDER, "none"):
            raise ValueError("executive_verdict.tier is not a valid priority")
        if tier == "none" and counts["warn"] + counts["fail"]:
            raise ValueError("executive_verdict.tier is none but results contain risks")

    top = doc.get("top_risks", [])
    if not isinstance(top, list) or len(top) > MAX_ROWS:
        raise ValueError(f"top_risks must be an array of at most {MAX_ROWS} rows")
    seen = set()
    ranks = set()
    for index, risk in enumerate(top):
        field = f"top_risks[{index}]"
        if not isinstance(risk, dict):
            raise ValueError(f"{field} must be an object")
        _text(risk.get("id"), f"{field}.id", nonempty=True)
        _text(risk.get("label"), f"{field}.label")
        if "hint" in risk:
            _text(risk["hint"], f"{field}.hint")
        tier = risk.get("tier")
        if not isinstance(tier, str) or tier not in TIER_ORDER:
            raise ValueError(f"{field}.tier is not a valid risk priority")
        _count(risk.get("rank"), f"{field}.rank")
        if not 1 <= risk["rank"] <= len(top) or risk["rank"] in ranks:
            raise ValueError(f"{field}.rank must be unique and contiguous from 1")
        ranks.add(risk["rank"])
        if risk["id"] in seen:
            raise ValueError(f"{field}.id duplicates another top risk")
        seen.add(risk["id"])
        original = by_id.get(risk["id"])
        if original is None or original["status"] not in ("warn", "fail"):
            raise ValueError(f"{field} must refer to a warning or failure in results")
        if risk.get("status") != original["status"] or risk["label"] != original["label"]:
            raise ValueError(f"{field} does not match its result row")
    return counts


def render(doc: dict) -> str:
    summary = validate(doc)
    verdict = doc.get("executive_verdict", {})
    top = sorted(
        doc.get("top_risks", []),
        key=lambda r: (TIER_ORDER.get(r.get("tier", ""), 9), r.get("rank", 0)),
    )
    results = doc.get("results", [])
    tier = verdict.get("tier", "not provided")
    # Keep CSS classes restricted even if accepted metadata expands later.
    tier_class = tier if tier in (*TIER_ORDER, "none") else "unknown"

    out: list[str] = []
    out.append("<!doctype html><html lang=en><head><meta charset=utf-8>")
    # No scripts, forms, frames, remote assets, or navigation base are needed.
    # Escaping and validation are the primary controls; CSP is defense in depth.
    out.append('<meta http-equiv="Content-Security-Policy" content="'
               "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
               "form-action 'none'\">")
    out.append('<meta name="referrer" content="no-referrer">')
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
        f'<p class="prio prio-{esc(tier_class)}">Action priority: {esc(tier)}</p></div>'
    )
    out.append(
        f'<p class=meta>{esc(summary["pass"])} pass · {esc(summary["warn"])} warn · '
        f'{esc(summary["fail"])} fail · {esc(summary["skip"])} skip '
        f'({esc(summary["total"])} total)</p>'
    )

    out.append("<h2>Top risks to address</h2>")
    if top:
        out.append("<table><thead><tr><th>#</th><th>tier</th><th>id</th><th>finding</th></tr></thead><tbody>")
        for r in top:
            risk_tier = r.get("tier", "")
            t = esc(risk_tier)
            risk_class = risk_tier if risk_tier in TIER_ORDER else "unknown"
            out.append(
                f'<tr><td>{esc(r.get("rank", ""))}</td>'
                f'<td><span class="tag tag-{esc(risk_class)}">{t}</span></td>'
                f'<td><code>{esc(r.get("id", ""))}</code></td>'
                f'<td>{esc(r.get("label", ""))}</td></tr>'
            )
        out.append("</tbody></table>")
    else:
        if summary["warn"] + summary["fail"]:
            out.append("<p><em>No ranked risks were included. Review the warnings and failures below.</em></p>")
        else:
            out.append("<p><em>No warnings or failures.</em></p>")

    out.append("<h2>All checks</h2>")
    out.append("<table><thead><tr><th>status</th><th>id</th><th>finding</th></tr></thead><tbody>")
    for r in results:
        st = r.get("status", "skip")
        status_class = st if st in STATUS_LABEL else "unknown"
        hint = f'<div class="hint">{esc(r["hint"])}</div>' if r.get("hint") else ""
        out.append(
            f'<tr><td class="s-{esc(status_class)}">{esc(STATUS_LABEL.get(st, st))}</td>'
            f'<td><code>{esc(r.get("id", ""))}</code></td>'
            f'<td>{esc(r.get("label", ""))}{hint}</td></tr>'
        )
    out.append("</tbody></table>")

    out.append(
        "<footer>Generated by mac-posture-audit (read-only audit). "
        "This report can list sensitive details — run the audit with "
        "<code>--redact</code> before sharing.</footer>"
    )
    out.append("</body></html>")
    return "".join(out)


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("input contains a duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("input contains a non-finite JSON number")


def _parse_number(value: str):
    # Bound numeric conversion on older macOS Python versions that do not have
    # the newer interpreter limit on integer-string conversion.
    if len(value) > 128:
        raise ValueError("input contains an excessively long JSON number")
    if any(char in value for char in ".eE"):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("input contains a non-finite JSON number")
        return number
    return int(value)


def read_document(stream) -> object:
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant,
                      parse_int=_parse_number, parse_float=_parse_number)


def _clear_inherited_acl(fd: int) -> None:
    if sys.platform != "darwin":
        return
    # macOS mode 0600 does not restrict an inherited allow ACL. Clear the ACL
    # on the newly created file before writing content. Passing the open FD to
    # the stock utility avoids reopening a pathname that could be replaced.
    try:
        subprocess.run(["/bin/chmod", "-N", f"/dev/fd/{fd}"], pass_fds=(fd,),
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, check=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        raise OSError("could not remove inherited ACL from the new output file") from error


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", nargs="?", help="posture JSON file (default: stdin)")
    parser.add_argument("--output", metavar="FILE",
                        help="create a private HTML file; refuse an existing path")
    args = parser.parse_args(argv[1:])
    try:
        if args.input:
            with open(args.input, "rb") as stream:
                doc = read_document(stream)
        else:
            doc = read_document(sys.stdin.buffer)
        output = render(doc)
    except (OSError, ValueError, RecursionError) as e:
        print(f"render_report: invalid input: {e}", file=sys.stderr)
        return 2
    try:
        if args.output:
            # O_EXCL also refuses symlinks (including dangling links). Validate
            # before creating anything. Never open an existing target for write.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                _clear_inherited_acl(stream.fileno())
                stream.write(output)
        else:
            sys.stdout.buffer.write(output.encode("utf-8"))
            sys.stdout.buffer.flush()
    except BrokenPipeError:
        # Prevent a second flush and an interpreter traceback on shutdown when
        # a consumer closes the pipe early (for example, piping into head).
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        print("render_report: output pipe closed before the report was written", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as e:
        print(f"render_report: could not write report: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
