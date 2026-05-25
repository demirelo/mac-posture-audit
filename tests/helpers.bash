# shellcheck shell=bash
# Test helpers reset globals that are consumed by sourced audit functions and
# individual Bats cases, so ShellCheck's local unused-variable view is noisy.
# shellcheck disable=SC2034

REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
FIXTURE_ROOT="$REPO_ROOT/tests/fixtures"
export FIXTURE_ROOT

setup_test_path() {
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

mock_cli() {
  local name="$1" fixture="$2" rc="${3:-0}"
  local fixture_path="$FIXTURE_ROOT/$fixture"
  local stub="$BATS_TEST_TMPDIR/bin/$name"

  setup_test_path
  {
    printf '#!/usr/bin/env bash\n'
    printf 'cat %q\n' "$fixture_path"
    printf 'exit %q\n' "$rc"
  } >"$stub"
  chmod +x "$stub"
}

mock_cli_script() {
  local name="$1" body="$2"
  local stub="$BATS_TEST_TMPDIR/bin/$name"

  setup_test_path
  printf '%s\n' "$body" >"$stub"
  chmod +x "$stub"
}

load_script() {
  # The script's source guard keeps main from running when sourced here.
  # shellcheck source=../mac-posture-audit.sh
  source "$REPO_ROOT/mac-posture-audit.sh"
  reset_state
}

reset_state() {
  PASS_N=0
  WARN_N=0
  FAIL_N=0
  SKIP_N=0
  RESULTS_PASS=()
  RESULTS_WARN=()
  RESULTS_FAIL=()
  RESULTS_SKIP=()
  JSON_ROWS=()
  EMITTED_IDS=" "
  STATUS_BY_ID=""
  MODE="json"
  QUICK=false
  NETWORK=false
  REDACT=false
  PROFILE="normal"
  ARCH="arm64"
  MACOS_VER="test"
  IS_APPLE_SILICON=false
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  DIM=""
  BOLD=""
  NC=""
  # v1.2.0: reset exposure-catalog + selftest + summary-line state.
  EXPOSURE_CATALOG_PATH=""
  CATALOG_LOADED=false
  CATALOG_CATEGORIES=()
  CATALOG_NAMES=()
  CATALOG_SEVERITIES=()
  CATALOG_IDS=()
  SUMMARY_LINE=false
  SELFTEST=false
  # Drop any AV_TABLE override left from a previous test so the section
  # falls back to AV_TABLE_DEFAULT unless a test sets it explicitly.
  unset AV_TABLE
  # Drop any *_ROOTS overrides left from previous v1.2 tests.
  unset BROWSER_EXT_CHROMIUM_ROOTS
  unset BROWSER_EXT_FIREFOX_ROOTS
  unset EDITOR_EXT_ROOTS
  unset MCP_CONFIG_PATHS
}

assert_recorded() {
  local status="$1" needle="$2" haystack=""

  case "$status" in
  pass) haystack="${RESULTS_PASS[*]-}" ;;
  warn) haystack="${RESULTS_WARN[*]-}" ;;
  fail) haystack="${RESULTS_FAIL[*]-}" ;;
  skip) haystack="${RESULTS_SKIP[*]-}" ;;
  *)
    printf 'unknown status: %s\n' "$status" >&2
    return 2
    ;;
  esac

  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'expected %s result containing: %s\n' "$status" "$needle" >&2
    printf 'actual %s results: %s\n' "$status" "$haystack" >&2
    return 1
  fi
}

status_count() {
  case "$1" in
  pass) printf '%s\n' "$PASS_N" ;;
  warn) printf '%s\n' "$WARN_N" ;;
  fail) printf '%s\n' "$FAIL_N" ;;
  skip) printf '%s\n' "$SKIP_N" ;;
  *) return 2 ;;
  esac
}
