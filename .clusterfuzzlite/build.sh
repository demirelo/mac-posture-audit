#!/bin/bash -eu
#
# ClusterFuzzLite invokes this script inside the Dockerfile's build
# environment to compile the fuzz targets for tools/render_report.py.

# compile_python_fuzzer is provided by gcr.io/oss-fuzz-base/base-builder-python.
# It wraps the Atheris-instrumented Python script into a runnable fuzzer
# binary plus a seed corpus.
compile_python_fuzzer \
  $SRC/mac-posture-audit/.clusterfuzzlite/fuzz_render_report.py \
  --add-binary "$SRC/mac-posture-audit/tools/render_report.py:tools"
