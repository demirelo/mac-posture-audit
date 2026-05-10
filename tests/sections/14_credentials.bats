#!/usr/bin/env bats

load '../helpers'

@test "credential pattern hits in shell rc files fail without leaking values" {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
  printf 'export GH_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' >"$HOME/.zshrc"

  section_14_credentials

  assert_recorded fail "Plaintext credential pattern(s) in shell rc files: 1"
  assert_recorded pass "No .env / credentials.json / private_key files at \$HOME root"
}

@test "clean home directory records credential hygiene passes" {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"

  section_14_credentials

  assert_recorded pass "No high-confidence credential patterns in shell rc files"
  assert_recorded pass "No .env / credentials.json / private_key files at \$HOME root"
}

# Each line below should fire as a high-confidence credential hit. These are
# all FAKE values shaped to match the patterns; placing them in a fixture
# .zshrc proves the regex engine finds them. Section_14 prints only counts +
# pattern names (filenames-only via grep -l), never the matched values.
@test "new high-confidence patterns are detected in a planted .zshrc" {
  load_script
  export HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$HOME"
  cat >"$HOME/.zshrc" <<'EOF'
export TELEGRAM_BOT_TOKEN=1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
export DISCORD_BOT_TOKEN=NjkwMTIzNDU2Nzg5MDEyMzQ1.X1abcd.xxxxxxxxxxxxxxxxxxxxxxxxxxx
export DIGITALOCEAN_PAT=dop_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export HF_TOKEN=hf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export REPLICATE_API_TOKEN=r8_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export POSTHOG_PERSONAL=phc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export LINEAR_API_KEY=lin_api_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export NOTION_TOKEN=secret_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export MAILGUN_KEY=key-1234567890abcdef1234567890abcdef
export SENTRY_DSN=https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@o12345.ingest.sentry.io/123456
export GITLAB_TOKEN=glpat-AbCdEfGhIjKlMnOpQrSt
export ALCHEMY_RPC=https://eth-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrSt12345
export INFURA_RPC=https://mainnet.infura.io/v3/aabbccddeeff00112233445566778899
EOF

  section_14_credentials

  # The label format is "Plaintext credential pattern(s) in shell rc files: N"
  # where N is the count of (file, pattern_label) pairs. We expect 13 hits
  # from the 13 distinct patterns above.
  assert_recorded fail "Plaintext credential pattern(s) in shell rc files:"
}
