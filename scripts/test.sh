#!/bin/bash
# Local and CI checks. Integration smoke tests read host posture in quick mode.
set -euo pipefail
cd "$(dirname "$0")/.."

check_tools_only=false
case "${1:-}" in
"") ;;
--check-tools) check_tools_only=true ;;
*)
  printf 'Usage: %s [--check-tools]\n' "$0" >&2
  exit 2
  ;;
esac
if [[ "$#" -gt 1 ]]; then
  printf 'Usage: %s [--check-tools]\n' "$0" >&2
  exit 2
fi

tool_error() {
  local tool="$1" tool_path="$2" binary_info="" machine
  machine=$(/usr/bin/uname -m 2>/dev/null || printf 'unknown')
  printf 'Test tool cannot run: %s\nResolved executable: %s\nHost architecture: %s\n' \
    "$tool" "$tool_path" "$machine" >&2
  if [[ -x /usr/bin/file ]]; then
    binary_info=$(/usr/bin/file -bL "$tool_path" 2>/dev/null || true)
  fi
  if [[ "$machine" == arm64 && "$binary_info" == *x86_64* && "$binary_info" != *arm64* ]]; then
    printf 'This is an Intel-only executable. Use an Apple silicon (arm64) or universal build.\n' >&2
  else
    printf 'Use a build of this tool that can run on this Mac.\n' >&2
  fi
  printf 'If a working version is already installed, put its directory first in PATH and retry.\n' >&2
  printf 'Check the tools without running tests: ./scripts/test.sh --check-tools\n' >&2
}

for tool in bats shellcheck shfmt python3; do
  if ! tool_path=$(command -v "$tool"); then
    printf 'Missing test tool: %s. Install it or add its directory to PATH.\n' "$tool" >&2
    exit 2
  fi
  # Resolve and execute a harmless version request. Finding a path alone does
  # not show that its architecture or interpreter can run on this system.
  if ! tool_version=$("$tool_path" --version 2>&1); then
    tool_error "$tool" "$tool_path"
    exit 2
  fi
  if [[ "$tool" == python3 ]] && ! "$tool_path" -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
    printf 'The test suite requires Python 3.9 or later: %s\n' "$tool_path" >&2
    printf 'Put a supported Python 3 interpreter first in PATH and retry.\n' >&2
    exit 2
  fi
  if $check_tools_only; then
    printf 'Ready: %s (%s)\n%s\n' "$tool" "$tool_path" "$tool_version"
  fi
done

$check_tools_only && exit 0

for script in mac-posture-audit.sh scripts/check-read-only.sh scripts/test.sh .clusterfuzzlite/build.sh; do
  /bin/bash -n "$script"
done
shellcheck -S warning mac-posture-audit.sh scripts/check-read-only.sh scripts/test.sh tests/helpers.bash .clusterfuzzlite/build.sh
shfmt -d -i 2 mac-posture-audit.sh scripts/check-read-only.sh scripts/test.sh tests/helpers.bash .clusterfuzzlite/build.sh
./scripts/check-read-only.sh

failures=0
accepted=0
rejected=0
for fixture in tests/check-read-only/should_pass/*.sh; do
  [[ -f "$fixture" ]] || {
    echo "Missing positive fixtures" >&2
    exit 2
  }
  accepted=$((accepted + 1))
  if ! ./scripts/check-read-only.sh "$fixture"; then
    printf 'Checker rejected a safe fixture: %s\n' "$fixture" >&2
    failures=$((failures + 1))
  fi
done
# Inspect these fixtures as text. Never execute them.
for fixture in tests/check-read-only/should_fail/*; do
  [[ -f "$fixture" ]] || {
    echo "Missing negative fixtures" >&2
    exit 2
  }
  rejected=$((rejected + 1))
  if ./scripts/check-read-only.sh "$fixture" >/dev/null 2>&1; then
    printf 'Checker accepted an unsafe fixture: %s\n' "$fixture" >&2
    failures=$((failures + 1))
  fi
done
[[ "$failures" -eq 0 ]]
printf "Safety fixtures passed: %s accepted, %s rejected\n" "$accepted" "$rejected"
# Keep host smoke tests away from the caller's home directory. System settings
# and installed applications are still visible; this is not a hermetic suite.
test_home=$(mktemp -d "${TMPDIR:-/tmp}/mac-posture-tests.XXXXXX")
trap 'rm -rf -- "$test_home"' EXIT
HOME="$test_home" bats tests/sections tests/integration
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s tests/check-read-only -p 'test_*.py'
