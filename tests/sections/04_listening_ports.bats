#!/usr/bin/env bats

load '../helpers'

# Tests for _check_listening_all_interfaces. We mock `lsof` directly so
# the runner's actual listening sockets don't influence the test.

mock_lsof() {
  local body="$1"
  mock_cli_script lsof "#!/usr/bin/env bash
cat <<'OUT'
${body}
OUT"
}

@test "no listeners — passes" {
  load_script
  mock_lsof ""

  _check_listening_all_interfaces

  assert_recorded pass "No TCP listeners on all-interfaces"
}

@test "lsof unavailable — skip" {
  load_script
  # Mock lsof to fail; output empty.
  mock_cli_script lsof '#!/usr/bin/env bash
exit 1'

  _check_listening_all_interfaces

  assert_recorded skip "lsof unavailable"
}

@test "only localhost listeners — passes" {
  load_script
  mock_lsof "p1000
cnode
n127.0.0.1:3000
p1001
cpython
n[::1]:8080"

  _check_listening_all_interfaces

  assert_recorded pass "No TCP listeners on all-interfaces"
}

@test "0.0.0.0:PORT bind — warns" {
  load_script
  mock_lsof "p1000
cvite
n0.0.0.0:5173"

  _check_listening_all_interfaces

  assert_recorded warn "TCP listeners on all-interfaces"
  [[ "${RESULTS_WARN[*]}" == *"vite:5173"* ]]
}

@test "*:PORT bind (IPv4 wildcard) — warns" {
  load_script
  mock_lsof "p2000
cpython
n*:8000"

  _check_listening_all_interfaces

  assert_recorded warn "python:8000"
}

@test "IPv6 [::]:PORT bind — warns" {
  load_script
  mock_lsof "p3000
cnode
n[::]:3000"

  _check_listening_all_interfaces

  assert_recorded warn "node:3000"
}

@test "mix of localhost + wildcard — only wildcard flagged" {
  load_script
  mock_lsof "p1000
cnode
n127.0.0.1:3000
p1001
cpython
n0.0.0.0:8000
p1002
cnpm
n127.0.0.1:5173"

  _check_listening_all_interfaces

  assert_recorded warn "python:8000"
  [[ "${RESULTS_WARN[*]}" != *"node:3000"* ]]
  [[ "${RESULTS_WARN[*]}" != *"npm:5173"* ]]
}

@test "developer profile escalates warn to fail" {
  load_script
  PROFILE="developer"
  mock_lsof "p1000
cvite
n0.0.0.0:5173"

  _check_listening_all_interfaces

  assert_recorded fail "TCP listeners on all-interfaces"
}

@test "founder profile escalates warn to fail" {
  load_script
  PROFILE="founder"
  mock_lsof "p1000
cnode
n0.0.0.0:3000"

  _check_listening_all_interfaces

  assert_recorded fail "node:3000"
}

@test "paranoid profile escalates warn to fail" {
  load_script
  PROFILE="paranoid"
  mock_lsof "p1000
cpython
n*:8000"

  _check_listening_all_interfaces

  assert_recorded fail "python:8000"
}

@test "process name suppressed under --redact, ports still surfaced" {
  load_script
  REDACT=true
  mock_lsof "p1000
cvite
n0.0.0.0:5173
p1001
cnode
n0.0.0.0:3000"

  _check_listening_all_interfaces

  # Process names should NOT appear; ports SHOULD.
  [[ "${RESULTS_WARN[*]}" != *"vite"* ]]
  [[ "${RESULTS_WARN[*]}" != *"node"* ]]
  [[ "${RESULTS_WARN[*]}" == *":5173"* ]]
  [[ "${RESULTS_WARN[*]}" == *":3000"* ]]
  [[ "${RESULTS_WARN[*]}" == *"2 TCP listener(s)"* ]]
}
