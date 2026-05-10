#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
  HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
}

# Override AV_TABLE so we never accidentally detect the real
# /Applications/Bitdefender / /Applications/Malwarebytes etc. on the
# test machine. Only process detection (mock pgrep) drives outcomes.
override_av_table() {
  AV_TABLE=(
    "/never/exists/Falcon.app|falcond|CrowdStrike Falcon"
    "/never/exists/SentinelOne.app|sentineld|SentinelOne"
    "/never/exists/Defender.app|wdavdaemon|Microsoft Defender for Endpoint"
    "/never/exists/Bitdefender.app|BDLDaemon|Bitdefender"
  )
}

# Inline mock that matches PATTERN against the full pgrep argv.
mock_pgrep() {
  local pattern="$1"
  mock_cli_script pgrep "#!/usr/bin/env bash
case \"\$*\" in
  *${pattern}*) exit 0 ;;
  *) exit 1 ;;
esac"
}

@test "_proc_running passes the pattern verbatim to pgrep -qfi" {
  TRACE="$BATS_TEST_TMPDIR/pgrep-trace.log"
  export TRACE
  mock_cli_script pgrep "#!/usr/bin/env bash
echo \"\$*\" >> \"\$TRACE\"
exit 1"
  _proc_running 'falcond' || true
  _proc_running 'foo|bar' || true
  [[ "$(cat "$TRACE")" == *"-qfi -- falcond"* ]]
  [[ "$(cat "$TRACE")" == *"-qfi -- foo|bar"* ]]
  # Sanity: ensure no BRE-style escape sneaks back in.
  ! grep -F '\|' "$TRACE"
}

@test "no AV table hits -> warn 'No antivirus / EDR'" {
  override_av_table
  mock_pgrep "no_match_for_anything_real"
  AV_FOUND=()
  section_08_av_endpoint
  assert_recorded warn "No antivirus / EDR process detected"
}

@test "CrowdStrike Falcon detected via pgrep -fi against 'falcond'" {
  override_av_table
  mock_pgrep "falcond"
  AV_FOUND=()
  section_08_av_endpoint
  assert_recorded pass "CrowdStrike Falcon"
}

@test "Microsoft Defender for Endpoint detected via 'wdavdaemon' argv" {
  # Canonical regression: old code had `pgrep -qi mdatp` which only
  # matched p_comm, missing wdavdaemon (the actual daemon binary).
  override_av_table
  mock_pgrep "wdavdaemon"
  AV_FOUND=()
  section_08_av_endpoint
  assert_recorded pass "Microsoft Defender for Endpoint"
}

@test "no BRE alternation regression in source" {
  # If anyone reintroduces pgrep -qi "a\|b", this catches it.
  ! grep -E 'pgrep[^"]*"[^"]*\\\|' "$REPO_ROOT/mac-posture-audit.sh"
}

@test "AV row with multi-segment PROC_ERE matches the alternation tail" {
  # Regression: the parser was `proc="${rest%%|*}"` which only kept the
  # first alternation segment. A row "BUNDLES|proc1|proc2|NAME" would
  # detect proc1 only and silently miss proc2. This locks in the fix
  # by detecting via proc2.
  AV_TABLE=(
    "/never/exists/Acme.app|primary_daemon|secondary_daemon|Acme EDR"
  )
  mock_pgrep "secondary_daemon"
  AV_FOUND=()
  section_08_av_endpoint
  assert_recorded pass "Acme EDR"
}

@test "AV row with multi-segment PROC_ERE still matches the first segment" {
  AV_TABLE=(
    "/never/exists/Acme.app|primary_daemon|secondary_daemon|Acme EDR"
  )
  mock_pgrep "primary_daemon"
  AV_FOUND=()
  section_08_av_endpoint
  assert_recorded pass "Acme EDR"
}

@test "AV row name comes from the last pipe-separated field, not the alternation" {
  # The brand label must be "Acme EDR" (last field), never "secondary_daemon".
  AV_TABLE=(
    "/never/exists/Acme.app|primary_daemon|secondary_daemon|Acme EDR"
  )
  mock_pgrep "secondary_daemon"
  AV_FOUND=()
  section_08_av_endpoint
  ! assert_recorded pass "secondary_daemon" 2>/dev/null
}

@test "AV row with 3+ engines suppresses brand names under --redact" {
  # F-1 regression: the *) arm of `case ${#AV_FOUND[@]} in` previously
  # interpolated ${AV_FOUND[*]} unconditionally, leaking the brand list
  # even when --redact was active. The fix mirrors the 1) and 2) arms.
  AV_TABLE=(
    "/never/exists/Alpha.app|alpha_daemon|Alpha AV"
    "/never/exists/Beta.app|beta_daemon|Beta EDR"
    "/never/exists/Gamma.app|gamma_daemon|Gamma EPP"
  )
  # Match anything — three rows, three different daemons.
  mock_cli_script pgrep $'#!/usr/bin/env bash\nexit 0'
  AV_FOUND=()
  REDACT=true
  section_08_av_endpoint
  assert_recorded warn "Multiple AV/EDR engines detected"
  # The brand names must NOT appear in any emitted label under --redact.
  [[ "${RESULTS_WARN[*]}" != *"Alpha AV"* ]]
  [[ "${RESULTS_WARN[*]}" != *"Beta EDR"* ]]
  [[ "${RESULTS_WARN[*]}" != *"Gamma EPP"* ]]
}
