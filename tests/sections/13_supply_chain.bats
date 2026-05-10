#!/usr/bin/env bats

load '../helpers'

@test "gh auth status is skipped in offline mode" {
  load_script
  marker="$BATS_TEST_TMPDIR/gh-called"
  mock_cli_script gh "#!/usr/bin/env bash
printf called > '$marker'
echo 'Logged in to github.com'
exit 0"
  NETWORK=false

  section_13_supply_chain

  assert_recorded skip "gh CLI auth status not checked (offline mode)"
  [ ! -e "$marker" ]
}

@test "gh auth status runs only when network mode is enabled" {
  load_script
  marker="$BATS_TEST_TMPDIR/gh-called"
  mock_cli_script gh "#!/usr/bin/env bash
printf called > '$marker'
echo 'Logged in to github.com'
exit 0"
  NETWORK=true

  section_13_supply_chain

  assert_recorded pass "gh CLI: logged in to GitHub"
  [ -e "$marker" ]
}

# `git config --global ...` is mocked via env-driven stub. Each test sets
# MOCK_INSTEADOF (one rewrite per line, in `git config --get-regexp` format).
mock_git_config() {
  mock_cli_script git "#!/usr/bin/env bash
case \"\$*\" in
  'config --global --get-regexp url\\..*\\.insteadof') printf '%s' \"\${MOCK_INSTEADOF:-}\" ;;
  'config --global '*) exit 0 ;;
  *) exit 0 ;;
esac"
}

@test "no insteadOf rewrites -> pass" {
  load_script
  mock_git_config
  MOCK_INSTEADOF=""
  export MOCK_INSTEADOF

  section_13_supply_chain

  assert_recorded pass "No global git url.insteadOf rewrites"
}

@test "single trusted SSH-forge insteadOf rewrite (github) -> pass" {
  load_script
  mock_git_config
  MOCK_INSTEADOF=$'url.git@github.com:.insteadof https://github.com/'
  export MOCK_INSTEADOF

  section_13_supply_chain

  assert_recorded pass "all targeting trusted SSH forges"
}

@test "trusted github + gitlab insteadOf rewrites -> pass with count of 2" {
  load_script
  mock_git_config
  MOCK_INSTEADOF=$'url.git@github.com:.insteadof https://github.com/\nurl.git@gitlab.com:.insteadof https://gitlab.com/'
  export MOCK_INSTEADOF

  section_13_supply_chain

  assert_recorded pass "2 git url.<base>.insteadOf rewrite(s), all targeting trusted SSH forges"
}

@test "non-forge insteadOf rewrite -> warn" {
  load_script
  mock_git_config
  MOCK_INSTEADOF=$'url.https://my-mirror.example.invalid/.insteadof https://github.com/'
  export MOCK_INSTEADOF

  section_13_supply_chain

  assert_recorded warn "non-SSH-forge git url.<base>.insteadOf rewrite"
}

@test "mixed trusted + untrusted -> warn counts only the untrusted" {
  load_script
  mock_git_config
  MOCK_INSTEADOF=$'url.git@github.com:.insteadof https://github.com/\nurl.https://hostile.example/.insteadof https://gitlab.com/'
  export MOCK_INSTEADOF

  section_13_supply_chain

  assert_recorded warn "1 non-SSH-forge"
}

@test "credential.helper unset + trusted SSH-forge insteadOf -> pass (SSH-only)" {
  load_script
  mock_git_config
  MOCK_HELPER=""
  MOCK_INSTEADOF=$'url.git@github.com:.insteadof https://github.com/'
  export MOCK_HELPER MOCK_INSTEADOF

  section_13_supply_chain

  assert_recorded pass "Git credential helper not needed (SSH-only"
}

@test "credential.helper unset + no insteadOf -> skip with osxkeychain hint" {
  load_script
  mock_git_config
  MOCK_HELPER=""
  MOCK_INSTEADOF=""
  export MOCK_HELPER MOCK_INSTEADOF

  section_13_supply_chain

  assert_recorded skip "Git credential helper not configured"
}
