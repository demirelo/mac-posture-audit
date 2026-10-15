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
  mock_cli_script dscacheutil $'#!/usr/bin/env bash\nexit 0'
}

@test "admin parser falls back to dscacheutil when dscl omits membership" {
  mock_dscl_admin_empty
  mock_cli_script dscacheutil $'#!/usr/bin/env bash\nprintf "name: admin\\npassword: *\\ngid: 80\\nusers: alice bob\\n"'
  QUICK=true
  section_20_users_sudo
  assert_recorded pass "2 admin users"
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

@test "underscore service accounts in admin remain visible" {
  mock_dscl_admin "alice _service"
  QUICK=true
  section_20_users_sudo
  assert_recorded warn "Service accounts present in admin group: _service"
}

# Run the actual fixed find/awk reader against private fixtures. Only sudo and
# its two absolute input paths are replaced; the probe's exit status is real.
mock_sudoers_reader() {
  export SUDOERS_FIXTURE_ROOT="$BATS_TEST_TMPDIR/sudoers-fixture"
  mkdir -p "$SUDOERS_FIXTURE_ROOT/sudoers.d"
  : >"$SUDOERS_FIXTURE_ROOT/sudoers"
  mock_cli_script sudo '#!/bin/bash
[[ "$1" == -n && "$2" == /usr/bin/find ]] || exit 99
shift
args=()
for arg in "$@"; do
  case "$arg" in
    /etc/sudoers) arg="$SUDOERS_FIXTURE_ROOT/sudoers" ;;
    /etc/sudoers.d) arg="$SUDOERS_FIXTURE_ROOT/sudoers.d" ;;
  esac
  args+=("$arg")
done
exec "${args[@]}"'
}

@test "sudoers with no NOPASSWD text passes after a complete read" {
  mock_sudoers_reader
  printf 'root ALL=(ALL) ALL\n' >"$SUDOERS_FIXTURE_ROOT/sudoers"
  printf 'alice ALL=(ALL) PASSWD: ALL\n' >"$SUDOERS_FIXTURE_ROOT/sudoers.d/local"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = pass ]
}

@test "empty inspected sudoers files are a successful no-match read" {
  mock_sudoers_reader
  : >"$SUDOERS_FIXTURE_ROOT/sudoers.d/empty"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = pass ]
}

@test "sudo denial cannot produce a safe sudoers result" {
  mock_cli_script sudo $'#!/bin/bash\nexit 1'
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "sudoers read failure with no match remains unverified" {
  mock_sudoers_reader
  printf 'root ALL=(ALL) ALL\n' >"$SUDOERS_FIXTURE_ROOT/sudoers"
  rmdir "$SUDOERS_FIXTURE_ROOT/sudoers.d"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "batched find propagates an awk file read failure" {
  mock_sudoers_reader
  run /usr/bin/find -P "$SUDOERS_FIXTURE_ROOT/sudoers" -type f \
    -exec /usr/bin/awk '/NOPASSWD/ { print }' "$SUDOERS_FIXTURE_ROOT/missing" {} +
  [ "$status" -ne 0 ]
}

@test "sudoers include directory loop remains unverified" {
  mock_sudoers_reader
  ln -s . "$SUDOERS_FIXTURE_ROOT/sudoers.d/loop"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "dangling sudoers include remains unverified" {
  mock_sudoers_reader
  ln -s missing "$SUDOERS_FIXTURE_ROOT/sudoers.d/dangling"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "dangling main sudoers file remains unverified" {
  mock_sudoers_reader
  rm "$SUDOERS_FIXTURE_ROOT/sudoers"
  ln -s missing "$SUDOERS_FIXTURE_ROOT/sudoers"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "main sudoers directory cannot produce a safe result" {
  mock_sudoers_reader
  rm "$SUDOERS_FIXTURE_ROOT/sudoers"
  mkdir "$SUDOERS_FIXTURE_ROOT/sudoers"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "regular file in place of sudoers include directory remains unverified" {
  mock_sudoers_reader
  rmdir "$SUDOERS_FIXTURE_ROOT/sudoers.d"
  : >"$SUDOERS_FIXTURE_ROOT/sudoers.d"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "sudoers FIFO remains unverified without opening it" {
  mock_sudoers_reader
  mkfifo "$SUDOERS_FIXTURE_ROOT/sudoers.d/pipe"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "partial sudoers output containing only a comment remains unverified" {
  mock_cli_script sudo $'#!/bin/bash\necho "# example NOPASSWD: ALL"\nexit 2'
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "partial sudoers read with a NOPASSWD match still fails" {
  mock_sudoers_reader
  printf 'alice ALL=(ALL) NOPASSWD: ALL\n' >"$SUDOERS_FIXTURE_ROOT/sudoers"
  rmdir "$SUDOERS_FIXTURE_ROOT/sudoers.d"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = fail ]
}

@test "many sudoers finding markers still fail with pipefail enabled" {
  mock_cli_script sudo '#!/bin/bash
for ((i = 0; i < 10000; i++)); do printf "AUDIT_NOPASSWD\n"; done'
  set -o pipefail
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = fail ]
}

@test "diagnostic containing marker text is not an active policy finding" {
  mock_cli_script sudo $'#!/bin/bash\necho "find: /etc/sudoers.d/AUDIT_NOPASSWD: read failed"\nexit 0'
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = skip ]
}

@test "commented NOPASSWD does not produce a false failure" {
  mock_sudoers_reader
  printf '  # example NOPASSWD: ALL\n' >"$SUDOERS_FIXTURE_ROOT/sudoers"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = pass ]
}

@test "active NOPASSWD in an included file fails" {
  mock_sudoers_reader
  printf 'alice ALL=(ALL) NOPASSWD: ALL\n' >"$SUDOERS_FIXTURE_ROOT/sudoers.d/local"
  _check_sudo_nopasswd
  [ "$(_status_of user.sudo.nopasswd)" = fail ]
}
