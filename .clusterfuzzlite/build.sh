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
# binary plus a seed corpus.
compile_python_fuzzer \
  "$SRC/mac-posture-audit/.clusterfuzzlite/fuzz_render_report.py"
