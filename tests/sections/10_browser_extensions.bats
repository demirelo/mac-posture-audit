#!/usr/bin/env bats
# shellcheck disable=SC2034

load '../helpers'

setup() {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
  mock_cli_script pluginkit $'#!/usr/bin/env bash\nexit 0'
}

detect_ext_by_name() {
  return 0
}

@test "redacted Rabby simulator advice preserves PASS without leaking wallet brand" {
  detect_ext_in_chromium() {
    case "$1" in
    acmacodkjbdgmoleebolmdjonilkdbch) printf 'Brave' ;;
    *) return 0 ;;
    esac
  }

  REDACT=true
  section_10_browser_extensions

  assert_recorded warn "1 wallet extension(s) installed"
  assert_recorded pass "wallet has built-in transaction simulation"
  [[ "${RESULTS_PASS[*]-} ${RESULTS_WARN[*]-} ${RESULTS_SKIP[*]-}" != *"Rabby"* ]]
}

@test "redacted MetaMask simulator advice warns without leaking wallet brand" {
  detect_ext_in_chromium() {
    case "$1" in
    nkbihfbeogaeaoehlefnkodbefgpgknn) printf 'Brave' ;;
    *) return 0 ;;
    esac
  }

  REDACT=true
  section_10_browser_extensions

  assert_recorded warn "1 wallet extension(s) installed"
  assert_recorded warn "No external transaction simulator detected"
  [[ "${RESULTS_PASS[*]-} ${RESULTS_WARN[*]-} ${RESULTS_SKIP[*]-}" != *"MetaMask"* ]]
}
