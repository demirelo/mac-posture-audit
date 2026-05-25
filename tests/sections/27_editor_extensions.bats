#!/usr/bin/env bats

load '../helpers'

# Tests for _check_editor_extensions (v1.2.0).
#
# Hermetic via EDITOR_EXT_ROOTS (pipe-delimited "<editor>|<root>").

isolate_home_and_roots() {
  ISOLATED_HOME="$BATS_TEST_TMPDIR/home"
  mkdir -p "$ISOLATED_HOME"
  export HOME="$ISOLATED_HOME"
  VSCODE_ROOT="$ISOLATED_HOME/vscode-ext"
  CURSOR_ROOT="$ISOLATED_HOME/cursor-ext"
  EDITOR_EXT_ROOTS=("vscode|$VSCODE_ROOT" "cursor|$CURSOR_ROOT")
}

write_editor_ext() {
  # write_editor_ext <root> <publisher.name> <version> [platform_suffix]
  local root="$1" pubname="$2" version="$3" platform="${4:-}"
  local dir="$root/${pubname}-${version}${platform:+-$platform}"
  mkdir -p "$dir"
  printf '{"name":"%s","version":"%s"}' "$pubname" "$version" >"$dir/package.json"
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

@test "no editor extensions dirs — both rows skip" {
  load_script
  isolate_home_and_roots

  _check_editor_extensions

  assert_recorded skip "No editor extensions found"
  assert_recorded skip "No exposure catalog loaded"
}

@test "single vscode extension — count=1, suspicious skip (no catalog)" {
  load_script
  isolate_home_and_roots
  write_editor_ext "$VSCODE_ROOT" "ms-python.python" "2024.0.0"

  _check_editor_extensions

  assert_recorded skip "Editor extensions detected: 1"
  assert_recorded skip "No exposure catalog loaded"
}

@test "platform-suffixed dir parsed correctly" {
  load_script
  isolate_home_and_roots
  write_editor_ext "$VSCODE_ROOT" "rust-lang.rust-analyzer" "0.4.2" "darwin-arm64"

  _check_editor_extensions

  assert_recorded skip "Editor extensions detected: 1"
}

@test "catalog match at severity=critical — fail with publisher.name listed" {
  load_script
  isolate_home_and_roots
  write_editor_ext "$VSCODE_ROOT" "malicious.publisher-pkg" "1.0.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "editor_extension|malicious.publisher-pkg|critical|advisory-ext-1"

  _check_editor_extensions

  assert_recorded fail "Catalog-matched editor extensions"
  assert_recorded fail "malicious.publisher-pkg"
}

@test "catalog match at severity=warn — warn (not fail)" {
  load_script
  isolate_home_and_roots
  write_editor_ext "$CURSOR_ROOT" "deprecated.thing" "0.5.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "editor_extension|deprecated.thing|warn|advisory-2"

  _check_editor_extensions

  assert_recorded warn "Catalog-matched editor extensions"
  [[ "${RESULTS_FAIL[*]:-}" != *"Catalog-matched editor extensions"* ]]
}

@test "case-insensitive catalog match" {
  load_script
  isolate_home_and_roots
  write_editor_ext "$VSCODE_ROOT" "MixedCase.PuBlIsHeR" "1.0.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "editor_extension|mixedcase.publisher|critical|advisory-3"

  _check_editor_extensions

  assert_recorded fail "Catalog-matched editor extensions"
}

@test "non-publisher-name dirs ignored (.obsolete, node_modules, etc.)" {
  load_script
  isolate_home_and_roots
  mkdir -p "$VSCODE_ROOT/.obsolete"
  mkdir -p "$VSCODE_ROOT/node_modules"
  mkdir -p "$VSCODE_ROOT/just-a-name"
  write_editor_ext "$VSCODE_ROOT" "real.extension" "1.0.0"

  _check_editor_extensions

  assert_recorded skip "Editor extensions detected: 1"
}

@test "multi-editor dedup — same publisher.name in vscode + cursor counted once each" {
  load_script
  isolate_home_and_roots
  write_editor_ext "$VSCODE_ROOT" "common.linter" "1.0.0"
  write_editor_ext "$CURSOR_ROOT" "common.linter" "1.0.0"

  _check_editor_extensions

  # Distinct by editor, so 2 entries total.
  assert_recorded skip "Editor extensions detected: 2"
}

@test "--redact suppresses publisher.name in suspicious label" {
  load_script
  isolate_home_and_roots
  REDACT=true
  write_editor_ext "$VSCODE_ROOT" "malicious.publisher-pkg" "1.0.0"
  write_catalog "$BATS_TEST_TMPDIR/catalog.txt" \
    "editor_extension|malicious.publisher-pkg|critical|advisory-ext-1"

  _check_editor_extensions

  assert_recorded fail "1 editor extension(s) match exposure catalog"
  [[ "${RESULTS_FAIL[*]:-}" != *"malicious.publisher-pkg"* ]]
}
