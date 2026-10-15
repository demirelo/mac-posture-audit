#!/bin/bash -eu
#
# ClusterFuzzLite (via $SRC/compile.sh) invokes this script inside the
# Dockerfile's build environment to compile the fuzz targets for the opt-in
# tools/render_report.py renderer.

# Make tools/render_report.py importable by the compiled fuzzer. PyInstaller
# (which compile_python_fuzzer wraps) picks up modules in the same directory
# as the fuzzer entry point, so we colocate render_report.py with the fuzzer
# rather than wrestling with --add-data / --paths flags across PyInstaller
# versions.
cp "$SRC/mac-posture-audit/tools/render_report.py" \
  "$SRC/mac-posture-audit/.clusterfuzzlite/render_report.py"

# compile_python_fuzzer is provided by gcr.io/oss-fuzz-base/base-builder-python.
# It wraps the Atheris-instrumented Python script into a runnable fuzzer
# binary. Package the seed corpus separately below.
compile_python_fuzzer \
  "$SRC/mac-posture-audit/.clusterfuzzlite/fuzz_render_report.py"

# ClusterFuzzLite uses the OSS-Fuzz convention: <target>_seed_corpus.zip
# beside the target in $OUT. Include synthetic inputs, never real reports.
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#seed-corpus
python3 - "$SRC/mac-posture-audit/.clusterfuzzlite/seed_corpus" \
  "$OUT/fuzz_render_report_seed_corpus.zip" <<'PY'
from pathlib import Path
import sys
import zipfile

seeds = sorted(Path(sys.argv[1]).glob("*.json"))
if not seeds:
    raise SystemExit("No JSON seed inputs found for fuzz_render_report")
with zipfile.ZipFile(sys.argv[2], "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for seed in seeds:
        archive.write(seed, arcname=seed.name)
PY
