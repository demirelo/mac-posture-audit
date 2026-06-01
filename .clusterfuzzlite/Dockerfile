# ClusterFuzzLite build environment for the opt-in tools/render_report.py
# renderer. The audit script itself is bash 3.2 — covered by shellcheck +
# the read-only tripwire (see scripts/check-read-only.sh and the negative
# fixtures under tests/check-read-only/should_fail/). Fuzzing exists here
# primarily for the OpenSSF Scorecard Fuzzing signal and to harden the
# Python rendering surface against malformed JSON inputs.

# Pinned to a sha256 digest — Scorecard's Pinned-Dependencies check rejects
# any unpinned containerImage. Refresh this digest when bumping (gcr.io is
# public, no auth needed):
#
#   TOKEN=$(curl -sS "https://gcr.io/v2/token?scope=repository:oss-fuzz-base/base-builder-python:pull&service=gcr.io" | jq -r .token)
#   curl -sSI -H "Authorization: Bearer $TOKEN" \
#     -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
#     https://gcr.io/v2/oss-fuzz-base/base-builder-python/manifests/latest \
#     | grep -i docker-content-digest
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:68bd7fc69673d3e46e0fc21affa28d360994985f36626ace6cc93c1119406ae6

# Atheris is the Google Python coverage-guided fuzzer that ClusterFuzzLite
# uses by default for Python projects. Pinned to an exact version so
# Scorecard's pipCommand check passes. Bump deliberately.
RUN pip install --no-cache-dir atheris==3.0.0

COPY . $SRC/mac-posture-audit
WORKDIR $SRC/mac-posture-audit

# ClusterFuzzLite's compile.sh entry point runs `$SRC/build.sh` (i.e.
# /src/build.sh) — not /build.sh. Copying to / silently broke the build with
# "bash: /src/build.sh: No such file or directory".
COPY .clusterfuzzlite/build.sh $SRC/
