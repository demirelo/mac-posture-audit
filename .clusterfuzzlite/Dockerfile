# ClusterFuzzLite build environment for the opt-in tools/render_report.py
# renderer. The audit script itself is bash 3.2 — covered by shellcheck +
# the read-only tripwire (see scripts/check-read-only.sh and the negative
# fixtures under tests/check-read-only/should_fail/). Fuzzing exists here
# primarily for the OpenSSF Scorecard Fuzzing signal and to harden the
# Python rendering surface against malformed JSON inputs.

FROM gcr.io/oss-fuzz-base/base-builder-python

# Atheris is the Google Python coverage-guided fuzzer that ClusterFuzzLite
# uses by default for Python projects. Pinned via pip's resolver; the
# base-builder-python image bundles a recent Python.
RUN pip install --no-cache-dir atheris

COPY . $SRC/mac-posture-audit
WORKDIR $SRC/mac-posture-audit

# build.sh is what ClusterFuzzLite invokes to compile the fuzzers.
COPY .clusterfuzzlite/build.sh /
