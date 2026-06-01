"""Atheris coverage-guided fuzzer for tools/render_report.py.

Goal: surface crashes / unhandled exceptions in the JSON → HTML rendering path
when fed malformed or hostile audit JSON. The renderer is stdlib-only and is
meant to be safe against an attacker-controlled posture.json (e.g. one shared
by a collaborator); this fuzzer keeps it honest.

Run locally:
    pip install atheris
    python3 .clusterfuzzlite/fuzz_render_report.py
"""

import json
import os
import sys

import atheris

# Make tools/ importable when the fuzzer runs from the repo root (local) and
# from $SRC/mac-posture-audit (in ClusterFuzzLite's Docker build).
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_REPO, "tools"))

with atheris.instrument_imports():
    import render_report  # noqa: E402  (post-instrumentation import)


def TestOneInput(data: bytes) -> None:
    # Decode the fuzzer's random bytes as UTF-8 JSON. If parsing fails we
    # return early — render_report doesn't open the file itself, it expects
    # a Python dict, so non-JSON inputs are not a meaningful fuzz state.
    try:
        doc = json.loads(data.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return
    if not isinstance(doc, dict) or "results" not in doc:
        return
    try:
        render_report.render(doc)
    except (KeyError, TypeError, AttributeError, ValueError):
        # These are "expected" failure modes for hostile JSON: a missing or
        # wrong-typed field. They are not crashes — the wrapper main() converts
        # them to exit-2 user errors. Atheris should keep mutating.
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
