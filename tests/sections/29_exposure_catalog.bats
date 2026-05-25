#!/usr/bin/env bats

load '../helpers'

# Tests for load_exposure_catalog + _catalog_match (v1.2.0).

write_catalog() {
  local path="$1"
  shift
  : >"$path"
  for line in "$@"; do
    printf '%s\n' "$line" >>"$path"
  done
}

@test "no EXPOSURE_CATALOG_PATH set — load_exposure_catalog is a no-op" {
  load_script

  load_exposure_catalog

  [[ "$CATALOG_LOADED" == "false" ]]
}

@test "valid catalog — entries populate arrays + CATALOG_LOADED=true" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "browser_extension_id|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|critical|drainer-1" \
    "editor_extension|evil.publisher|warn|advisory-2"
  EXPOSURE_CATALOG_PATH="$cat"

  load_exposure_catalog

  [[ "$CATALOG_LOADED" == "true" ]]
  [[ "${#CATALOG_CATEGORIES[@]}" -eq 2 ]]
  [[ "${CATALOG_NAMES[0]}" == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]]
  [[ "${CATALOG_SEVERITIES[1]}" == "warn" ]]
}

@test "_catalog_match returns severity|id on exact hit" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "mcp_server|evil-server|critical|advisory-mcp-1"
  EXPOSURE_CATALOG_PATH="$cat"
  load_exposure_catalog

  run _catalog_match "mcp_server" "evil-server"
  [[ "$output" == "critical|advisory-mcp-1" ]]
}

@test "_catalog_match is case-insensitive on name" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "editor_extension|evil.PUBLISHER|warn|advisory-2"
  EXPOSURE_CATALOG_PATH="$cat"
  load_exposure_catalog

  run _catalog_match "editor_extension" "EVIL.publisher"
  [[ "$output" == "warn|advisory-2" ]]
}

@test "_catalog_match returns empty for miss" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "mcp_server|known|critical|advisory-1"
  EXPOSURE_CATALOG_PATH="$cat"
  load_exposure_catalog

  run _catalog_match "mcp_server" "unknown"
  [[ -z "$output" ]]
}

@test "_catalog_match returns empty when category does not match" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "browser_extension_id|abc|critical|advisory-1"
  EXPOSURE_CATALOG_PATH="$cat"
  load_exposure_catalog

  run _catalog_match "mcp_server" "abc"
  [[ -z "$output" ]]
}

@test "comments and blank lines ignored" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  : >"$cat"
  printf '# this is a comment\n' >>"$cat"
  printf '\n' >>"$cat"
  printf '   # leading-space comment\n' >>"$cat"
  printf 'mcp_server|real-entry|warn|advisory-1\n' >>"$cat"
  EXPOSURE_CATALOG_PATH="$cat"

  load_exposure_catalog

  [[ "${#CATALOG_CATEGORIES[@]}" -eq 1 ]]
  [[ "${CATALOG_NAMES[0]}" == "real-entry" ]]
}

@test "unknown severity values are silently dropped" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "mcp_server|good|critical|advisory-1" \
    "mcp_server|bad|invalid-severity|advisory-2" \
    "mcp_server|alsobad|FATAL|advisory-3"
  EXPOSURE_CATALOG_PATH="$cat"

  load_exposure_catalog

  [[ "${#CATALOG_CATEGORIES[@]}" -eq 1 ]]
  [[ "${CATALOG_NAMES[0]}" == "good" ]]
}

@test "incomplete lines (missing fields) are dropped" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "mcp_server|good|warn|advisory-1" \
    "mcp_server|missing-severity|" \
    "editor_extension||critical|advisory-3"
  EXPOSURE_CATALOG_PATH="$cat"

  load_exposure_catalog

  [[ "${#CATALOG_CATEGORIES[@]}" -eq 1 ]]
}

@test "missing optional id field is OK — defaults to empty" {
  load_script
  local cat="$BATS_TEST_TMPDIR/cat.txt"
  write_catalog "$cat" \
    "mcp_server|good|warn"
  EXPOSURE_CATALOG_PATH="$cat"

  load_exposure_catalog

  [[ "${#CATALOG_CATEGORIES[@]}" -eq 1 ]]
  [[ -z "${CATALOG_IDS[0]}" ]]

  run _catalog_match "mcp_server" "good"
  [[ "$output" == "warn|" ]]
}

@test "unreadable catalog file — script exits 2 with message" {
  load_script
  EXPOSURE_CATALOG_PATH="$BATS_TEST_TMPDIR/does-not-exist.txt"

  run load_exposure_catalog
  [[ "$status" -eq 2 ]]
  [[ "$output" == *"cannot read"* ]]
}

@test "_catalog_match returns empty when catalog not loaded" {
  load_script
  # No load_exposure_catalog call.

  run _catalog_match "mcp_server" "anything"
  [[ -z "$output" ]]
}
