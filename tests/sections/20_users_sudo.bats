#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
}

# Mock `dscl` so that the GroupMembership probe returns the supplied
# space-separated user list, and the UniqueID list probe returns nothing
# (we only test the admin count branches here; the human-count branch
# and NOPASSWD path are exercised elsewhere).
mock_dscl_admin() {
  local membership="$1"
  mock_cli_script dscl "#!/usr/bin/env bash
case \"\$*\" in
  *GroupMembership*) printf 'GroupMembership: %s\\n' \"$membership\" ;;
  *UniqueID*)        printf '' ;;
  *)                 exit 0 ;;
esac"
}

# Empty membership simulates the parse failure (dscl exits 0 but returns
# nothing useful, or the field is missing). The old code took this path
# and emitted PASS "1 admin user" with an empty list — false confidence
# on a privilege check. Fix: SKIP.
mock_dscl_admin_empty() {
  mock_cli_script dscl $'#!/usr/bin/env bash\nexit 0'
}

@test "empty admin GroupMembership emits SKIP, not a false PASS" {
  mock_dscl_admin_empty
  QUICK=true
  section_20_users_sudo
  assert_recorded skip "Admin group membership could not be parsed"
  # And critically, no PASS row for user.admin.count.
  [[ "${RESULTS_PASS[*]-}" != *"admin user"* ]]
}

@test "single admin user reports actual count, not hardcoded '1'" {
  mock_dscl_admin "alice"
  QUICK=true
  section_20_users_sudo
  assert_recorded pass "1 admin user"
  # Make sure the label includes the actual user.
  [[ "${RESULTS_PASS[*]}" == *"alice"* ]]
}

@test "two admin users still PASS" {
  mock_dscl_admin "alice bob"
  QUICK=true
  section_20_users_sudo
  assert_recorded pass "2 admin users"
}

@test "three+ admin users WARN" {
  mock_dscl_admin "alice bob carol dave"
  QUICK=true
  section_20_users_sudo
  assert_recorded warn "4 admin users"
}

@test "dscl run only once for admin parsing (no double-call)" {
  # Regression: the old code ran dscl twice for the same query. Trace
  # invocations and assert exactly one call with GroupMembership args.
  TRACE="$BATS_TEST_TMPDIR/dscl-trace.log"
  export TRACE
  mock_cli_script dscl "#!/usr/bin/env bash
echo \"\$*\" >> \"\$TRACE\"
case \"\$*\" in
  *GroupMembership*) echo 'GroupMembership: alice bob' ;;
  *UniqueID*)        echo '' ;;
esac"
  QUICK=true
  section_20_users_sudo
  count=$(grep -c 'GroupMembership' "$TRACE")
  [[ "$count" -eq 1 ]]
}
