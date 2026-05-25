#!/usr/bin/env bats

load '../helpers'

# Tests for _check_mcp_servers (v1.2.0).
#
# Hermetic via MCP_CONFIG_PATHS — when set, the helper reads exactly those
# files and does not probe ~/.claude/ for plugin configs.

isolate_home() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
}

write_mcp_config() {
  # write_mcp_config <path> <body>
  local path="$1" body="$2"
  mkdir -p "$(dirname "$path")"
  printf '%s' "$body" >"$path"
}

write_catalog() {
  local path="$1"
  shift
  : >"$path"
  for line in "$@"; do
    printf '%s\n' "$line" >>"$path"
  done
  EXPOSURE_CATALOG_PATH="$path"
  load_exposure_catalog
}

@test "no MCP configs anywhere — all rows skip" {
  load_script
  isolate_home
  MCP_CONFIG_PATHS=("$BATS_TEST_TMPDIR/does-not-exist.json")

  _check_mcp_servers

  assert_recorded skip "No MCP config files found"
  [[ "$SKIP_N" -ge 4 ]]
}

@test "one pinned local stdio server — count=1, unpinned pass, remote pass" {
  load_script
  isolate_home
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"good":{"command":"npx","args":["-y","@foo/bar@1.2.3"]}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  assert_recorded skip "MCP servers configured: 1"
  assert_recorded pass "No MCP servers reference @latest"
  assert_recorded pass "No MCP servers configured via remote"
}

@test "@latest in args — unpinned warn" {
  load_script
  isolate_home
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"unpinned":{"command":"npx","args":["-y","@foo/bar@latest"]}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  assert_recorded warn "MCP launcher(s) reference @latest"
}

@test "Docker :latest tag — unpinned warn" {
  load_script
  isolate_home
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"dockerd":{"command":"docker","args":["run","-i","--rm","org/server:latest"]}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  assert_recorded warn "MCP launcher(s) reference @latest or :latest"
}

@test "remote HTTP transport — remote_http warn" {
  load_script
  isolate_home
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"remote":{"url":"https://api.example.com/mcp"}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  assert_recorded warn "MCP server(s) configured via remote HTTP/SSE"
}

@test "catalog-matched server ID — suspicious fail" {
  load_script
  isolate_home
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"malicious-thing":{"command":"npx","args":["-y","@evil/server@1.0.0"]}}}'
  MCP_CONFIG_PATHS=("$cfg")
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "mcp_server|malicious-thing|critical|advisory-mcp-1"

  _check_mcp_servers

  assert_recorded fail "Catalog-matched MCP servers"
  assert_recorded fail "malicious-thing"
}

@test "env values and key names never leak into any record" {
  load_script
  isolate_home
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"with-secrets":{"command":"npx","args":["-y","@foo/bar@1.0.0"],"env":{"SECRET_TOKEN":"sk-ant-supersecret-do-not-leak","API_KEY":"AKIAIOSFODNN7EXAMPLE"}}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  # No row should ever contain any env key or value.
  local all="${RESULTS_PASS[*]:-} ${RESULTS_WARN[*]:-} ${RESULTS_FAIL[*]:-} ${RESULTS_SKIP[*]:-}"
  [[ "$all" != *"SECRET_TOKEN"* ]]
  [[ "$all" != *"sk-ant-supersecret"* ]]
  [[ "$all" != *"API_KEY"* ]]
  [[ "$all" != *"AKIAIOSFODNN7EXAMPLE"* ]]
}

@test "web3 profile escalates unpinned warn to fail" {
  load_script
  isolate_home
  PROFILE="web3"
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"unpinned":{"command":"npx","args":["-y","@foo/bar@latest"]}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  assert_recorded fail "MCP launcher(s) reference @latest"
}

@test "paranoid profile escalates remote_http warn to fail" {
  load_script
  isolate_home
  PROFILE="paranoid"
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"remote":{"url":"https://api.example.com/mcp"}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  assert_recorded fail "MCP server(s) configured via remote HTTP/SSE"
}

@test "founder profile escalates both remote_http and unpinned" {
  load_script
  isolate_home
  PROFILE="founder"
  local cfg="$BATS_TEST_TMPDIR/cursor.json"
  write_mcp_config "$cfg" '{"mcpServers":{"a":{"command":"npx","args":["-y","@foo/bar@latest"]},"b":{"url":"https://api.example.com/mcp"}}}'
  MCP_CONFIG_PATHS=("$cfg")

  _check_mcp_servers

  assert_recorded fail "MCP launcher(s) reference @latest"
  assert_recorded fail "MCP server(s) configured via remote HTTP/SSE"
}

@test "multi-config aggregation — counts sum across files" {
  load_script
  isolate_home
  local cfg1="$BATS_TEST_TMPDIR/cursor.json"
  local cfg2="$BATS_TEST_TMPDIR/claude.json"
  write_mcp_config "$cfg1" '{"mcpServers":{"s1":{"command":"npx","args":["-y","@a/x@1.0"]}}}'
  write_mcp_config "$cfg2" '{"mcpServers":{"s2":{"command":"npx","args":["-y","@b/y@2.0"]}}}'
  MCP_CONFIG_PATHS=("$cfg1" "$cfg2")

  _check_mcp_servers

  assert_recorded skip "MCP servers configured: 2"
}

@test "malformed JSON skipped (plutil -convert rejects, no rows from that file)" {
  if ! command -v plutil >/dev/null 2>&1; then
    skip "plutil not available — validation step is a no-op on this host"
  fi
  load_script
  isolate_home
  local bad="$BATS_TEST_TMPDIR/bad.json"
  local good="$BATS_TEST_TMPDIR/good.json"
  printf '{not valid json' >"$bad"
  write_mcp_config "$good" '{"mcpServers":{"ok":{"command":"npx","args":["-y","@a/x@1.0"]}}}'
  MCP_CONFIG_PATHS=("$bad" "$good")

  _check_mcp_servers

  assert_recorded skip "MCP servers configured: 1"
}
