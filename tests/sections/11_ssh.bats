#!/usr/bin/env bats
# shellcheck disable=SC2034

load '../helpers'

@test "SSH key classifier distinguishes unencrypted and passphrase-protected keys" {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME/.ssh"
  : >"$HOME/.ssh/id_ed25519"
  : >"$HOME/.ssh/id_rsa"
  mock_cli_script ssh-keygen '#!/usr/bin/env bash
key=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "-f" ]]; then key="$arg"; fi
  prev="$arg"
done
case "$key" in
  *id_ed25519) exit 0 ;;
  *id_rsa) echo "incorrect passphrase supplied to decrypt private key" >&2; exit 255 ;;
  *) exit 1 ;;
esac'
  export SSH_AUTH_SOCK="/var/run/com.apple.launchd/test/Listeners"

  section_11_ssh

  assert_recorded warn "Unencrypted SSH private key(s) on disk: id_ed25519"
  assert_recorded pass "SSH private key(s) appear passphrase-protected: id_rsa"
  assert_recorded warn "macOS default ssh-agent"
}

@test "SSH section passes when no private keys are present" {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME/.ssh"
  unset SSH_AUTH_SOCK

  section_11_ssh

  assert_recorded pass "No private SSH keys in ~/.ssh/"
  assert_recorded skip "SSH_AUTH_SOCK is unset"
}

@test "SSH redaction suppresses private key basenames" {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME/.ssh"
  : >"$HOME/.ssh/id_ed25519"
  : >"$HOME/.ssh/id_rsa"
  mock_cli_script ssh-keygen '#!/usr/bin/env bash
key=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "-f" ]]; then key="$arg"; fi
  prev="$arg"
done
case "$key" in
  *id_ed25519) exit 0 ;;
  *id_rsa) echo "incorrect passphrase supplied to decrypt private key" >&2; exit 255 ;;
  *) exit 1 ;;
esac'
  export SSH_AUTH_SOCK="/var/run/com.apple.launchd/test/Listeners"

  REDACT=true
  section_11_ssh

  assert_recorded warn "Unencrypted SSH private key(s) on disk: 1"
  assert_recorded pass "SSH private key(s) appear passphrase-protected: 1"
  [[ "${RESULTS_PASS[*]-} ${RESULTS_WARN[*]-} ${RESULTS_FAIL[*]-} ${RESULTS_SKIP[*]-}" != *"id_ed25519"* ]]
  [[ "${RESULTS_PASS[*]-} ${RESULTS_WARN[*]-} ${RESULTS_FAIL[*]-} ${RESULTS_SKIP[*]-}" != *"id_rsa"* ]]
}

@test "section_11_ssh: nullglob state is not leaked to subsequent sections" {
  # Regression for B.1: `shopt -s nullglob` was set in section_11 and
  # never reset, so every later section ran with nullglob enabled —
  # silently changing glob semantics in §13/§17/§22 (where unmatched
  # globs are expected to become literal, not disappear).
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME/.ssh"
  unset SSH_AUTH_SOCK

  # Ensure caller starts with nullglob OFF (the default).
  shopt -u nullglob 2>/dev/null || true
  ! shopt -q nullglob

  section_11_ssh >/dev/null 2>&1 || true

  # After the section, the caller's nullglob state must be restored.
  ! shopt -q nullglob
}
