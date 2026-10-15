"""Atheris coverage-guided fuzzer for tools/render_report.py.

Goal: surface crashes / unhandled exceptions in the JSON → HTML rendering path
when fed malformed or hostile audit JSON. The renderer is stdlib-only and is
meant to be safe against an attacker-controlled posture.json (e.g. one shared
by a collaborator); this fuzzer keeps it honest.

Run locally:
    python3 -m venv /tmp/mac-posture-fuzz
    /tmp/mac-posture-fuzz/bin/pip install --require-hashes -r .clusterfuzzlite/requirements.txt
    /tmp/mac-posture-fuzz/bin/python .clusterfuzzlite/fuzz_render_report.py
"""

import io
import os
import sys

import atheris

# build.sh colocates render_report.py with this file inside the
# ClusterFuzzLite Docker build, so it sits on `sys.path` already after
# PyInstaller bundling. The fallback below lets the fuzzer also run directly
# from a developer checkout where render_report.py still lives in tools/.
_HERE = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(_HERE, "render_report.py")):
    sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "tools"))

with atheris.instrument_imports():
    import render_report  # noqa: E402  (post-instrumentation import)


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    # Use the CLI's bounded, strict UTF-8 loader, including duplicate-key and
    # numeric limits. ValueError includes JSONDecodeError/UnicodeDecodeError;
    # deeply nested JSON can also raise the documented RecursionError.
    try:
        doc = render_report.read_document(io.BytesIO(data))
    except (ValueError, RecursionError):
        return

    # validate() documents ValueError for invalid report fields. Do not hide
    # KeyError, TypeError, AttributeError, or other implementation failures.
    try:
        render_report.validate(doc)
    except ValueError:
        return

    # Once validation has accepted a document, rendering and UTF-8 output must
    # succeed. Keep this outside both rejection handlers so real bugs crash.
    render_report.render(doc).encode("utf-8")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
