#!/usr/bin/env bats

load '../helpers.bash'

setup() {
  load_script
  uname() { printf 'arm64\n'; }
  sysctl() { printf '0\n'; }
}

@test "runtime reads macOS 27 and future numeric versions" {
  sw_vers() { printf '27.0.1\n'; }
  detect_runtime
  [ "$MACOS_VER" = 27.0.1 ]
  [ "$ARCH" = arm64 ]
  $IS_APPLE_SILICON
  _macos_at_least 27 0
  sw_vers() { printf '28.1\n'; }
  detect_runtime
  [ "$MACOS_VER" = 28.1 ]
  _macos_at_least 27 0
}

@test "runtime rejects empty malformed and partial failed version probes" {
  for value in '' unknown 'macOS 27.0' '27.0.1 extra' '27.0.1.2' $'27.0.1\n26.5' '99999999999999999.0'; do
    sw_vers() { printf '%s\n' "$value"; }
    detect_runtime
    [ "$MACOS_VER" = unknown ]
    ! _macos_at_least 10 0
  done
  sw_vers() {
    printf '27.0.1\n'
    return 1
  }
  detect_runtime
  [ "$MACOS_VER" = unknown ]
}

@test "version gates preserve 26 and earlier boundaries" {
  MACOS_VER=26.0
  _macos_at_least 26 0
  ! _macos_at_least 26 1
  MACOS_VER=26.1
  _macos_at_least 26 1
  ! _macos_at_least 27 0
  MACOS_VER=15.7.1
  _macos_at_least 10 0
  ! _macos_at_least 26 0
  MACOS_VER=027.00.1
  _macos_at_least 27 0
}

@test "failed architecture probes cannot enable Apple silicon checks" {
  sw_vers() { printf '27.0.1\n'; }
  uname() {
    printf 'arm64\n'
    return 1
  }
  detect_runtime
  [ "$ARCH" = unknown ]
  ! $IS_APPLE_SILICON
  uname() { printf 'x86_64\n'; }
  detect_runtime
  [ "$ARCH" = x86_64 ]
  ! $IS_APPLE_SILICON
}

@test "translated x86 process still uses Apple silicon boot checks" {
  sw_vers() { printf '27.0.1\n'; }
  uname() { printf 'x86_64\n'; }
  sysctl() {
    [ "$*" = '-n hw.optional.arm64' ] || return 2
    printf '1\n'
  }
  detect_runtime
  [ "$ARCH" = x86_64 ]
  $IS_APPLE_SILICON
  sysctl() {
    printf '1\n'
    return 1
  }
  detect_runtime
  ! $IS_APPLE_SILICON
}
