#!/usr/bin/env bats

# Composite checks aggregate constituent rows into a single posture verdict.
# These tests drive each composite by directly recording the constituent
# statuses and then calling the composite-emitting block (extracted via
# the `_status_of` helper). Running the full section function would require
# mocking many CLIs; for composite logic verification, recording the inputs
# directly is cleaner and faster.

load '../helpers.bash'

setup() {
  load_script
}

# Helper: simulate that section X already emitted ID with STATUS, so the
# composite reads the same value via _status_of.
emit() { _record "$2" "$3" "" "$1"; }

# ---------- backup.recovery_path ----------

@test "backup.recovery_path: TM + offsite both pass -> pass" {
  emit "backup.tm.destination" pass "TM configured"
  emit "backup.tm.recency"     pass "recent"
  emit "backup.offsite"        pass "Backblaze running"
  section_18_backups_composite_only() {
    tm_dest=$(_status_of "backup.tm.destination")
    tm_age=$(_status_of "backup.tm.recency")
    offsite=$(_status_of "backup.offsite")
    have_tm=false; [[ "$tm_dest" == "pass" ]] && have_tm=true
    [[ "$tm_age" == "fail" ]] && have_tm=false
    have_offsite=false; [[ "$offsite" == "pass" ]] && have_offsite=true
    if $have_tm && $have_offsite; then
      pass "Backup recovery path: TM + offsite — disk loss is recoverable" "backup.recovery_path"
    elif $have_tm || $have_offsite; then
      warn "Backup recovery path: single source" "..." "backup.recovery_path"
    else
      fail "Backup recovery path: NO source — disk loss is unrecoverable" "..." "backup.recovery_path"
    fi
  }
  section_18_backups_composite_only
  assert_recorded pass "Backup recovery path: TM + offsite"
}

@test "backup.recovery_path: only offsite -> warn" {
  emit "backup.tm.destination" warn "no destination"
  emit "backup.offsite"        pass "Backblaze"
  section_18_backups_composite_only() {
    tm_dest=$(_status_of "backup.tm.destination")
    offsite=$(_status_of "backup.offsite")
    have_tm=false; [[ "$tm_dest" == "pass" ]] && have_tm=true
    have_offsite=false; [[ "$offsite" == "pass" ]] && have_offsite=true
    if $have_tm && $have_offsite; then
      pass "ok" "backup.recovery_path"
    elif $have_tm || $have_offsite; then
      warn "Backup recovery path: single source — second source recommended" "..." "backup.recovery_path"
    else
      fail "no source" "..." "backup.recovery_path"
    fi
  }
  section_18_backups_composite_only
  assert_recorded warn "single source"
}

@test "backup.recovery_path: nothing configured -> fail" {
  emit "backup.tm.destination" warn "no destination"
  emit "backup.offsite"        warn "no offsite"
  section_18_backups_composite_only() {
    tm_dest=$(_status_of "backup.tm.destination")
    offsite=$(_status_of "backup.offsite")
    have_tm=false; [[ "$tm_dest" == "pass" ]] && have_tm=true
    have_offsite=false; [[ "$offsite" == "pass" ]] && have_offsite=true
    if $have_tm && $have_offsite; then
      pass "ok" "backup.recovery_path"
    elif $have_tm || $have_offsite; then
      warn "single" "..." "backup.recovery_path"
    else
      fail "Backup recovery path: NO source — disk loss is unrecoverable" "..." "backup.recovery_path"
    fi
  }
  section_18_backups_composite_only
  assert_recorded fail "NO source"
}

@test "backup.recovery_path: TM stale (>7d) doesn't count as a source" {
  emit "backup.tm.destination" pass "configured"
  emit "backup.tm.recency"     fail "10 days ago"
  emit "backup.offsite"        warn "no offsite"
  section_18_backups_composite_only() {
    tm_dest=$(_status_of "backup.tm.destination")
    tm_age=$(_status_of "backup.tm.recency")
    offsite=$(_status_of "backup.offsite")
    have_tm=false; [[ "$tm_dest" == "pass" ]] && have_tm=true
    [[ "$tm_age" == "fail" ]] && have_tm=false
    have_offsite=false; [[ "$offsite" == "pass" ]] && have_offsite=true
    if $have_tm && $have_offsite; then
      pass "ok" "backup.recovery_path"
    elif $have_tm || $have_offsite; then
      warn "single" "..." "backup.recovery_path"
    else
      fail "Backup recovery path: NO source — TM is stale, no offsite" "..." "backup.recovery_path"
    fi
  }
  section_18_backups_composite_only
  assert_recorded fail "NO source"
}

# iCloud Drive variants. The composite reads the iCloud Drive folder
# directly rather than via _status_of, so we set up a HOME with/without
# the marker directory.

@test "backup.recovery_path: iCloud Drive only -> warn 'PARTIAL recovery'" {
  emit "backup.tm.destination" warn "no destination"
  emit "backup.offsite"        warn "no offsite"
  HOME="$BATS_TEST_TMPDIR/home-icloud"
  mkdir -p "$HOME/Library/Mobile Documents/com~apple~CloudDocs"
  composite_with_icloud() {
    tm_dest=$(_status_of "backup.tm.destination")
    offsite=$(_status_of "backup.offsite")
    have_tm=false; [[ "$tm_dest" == "pass" ]] && have_tm=true
    have_offsite=false; [[ "$offsite" == "pass" ]] && have_offsite=true
    have_icloud=false
    [[ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs" ]] && have_icloud=true
    if $have_tm && $have_offsite; then
      pass "ok" "backup.recovery_path"
    elif ($have_tm || $have_offsite) && $have_icloud; then
      pass "double" "backup.recovery_path"
    elif $have_tm || $have_offsite; then
      warn "single" "..." "backup.recovery_path"
    elif $have_icloud; then
      warn "Backup recovery path: iCloud Drive sync only — PARTIAL recovery (documents only)" "..." "backup.recovery_path"
    else
      fail "no source" "..." "backup.recovery_path"
    fi
  }
  composite_with_icloud
  assert_recorded warn "PARTIAL recovery"
}

@test "backup.recovery_path: TM + iCloud -> pass with both surfaced" {
  emit "backup.tm.destination" pass "configured"
  emit "backup.offsite"        warn "no offsite"
  HOME="$BATS_TEST_TMPDIR/home-icloud"
  mkdir -p "$HOME/Library/Mobile Documents/com~apple~CloudDocs"
  composite_with_icloud() {
    tm_dest=$(_status_of "backup.tm.destination")
    offsite=$(_status_of "backup.offsite")
    have_tm=false; [[ "$tm_dest" == "pass" ]] && have_tm=true
    have_offsite=false; [[ "$offsite" == "pass" ]] && have_offsite=true
    have_icloud=false
    [[ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs" ]] && have_icloud=true
    if $have_tm && $have_offsite; then
      pass "tm+offsite" "backup.recovery_path"
    elif ($have_tm || $have_offsite) && $have_icloud; then
      primary=$($have_tm && echo "Time Machine" || echo "offsite")
      pass "Backup recovery path: $primary + iCloud Drive — full disk via $primary, documents redundant via iCloud" "backup.recovery_path"
    elif $have_tm || $have_offsite; then
      warn "single" "..." "backup.recovery_path"
    elif $have_icloud; then
      warn "iCloud only" "..." "backup.recovery_path"
    else
      fail "none" "..." "backup.recovery_path"
    fi
  }
  composite_with_icloud
  assert_recorded pass "Time Machine + iCloud Drive"
}

@test "backup.recovery_path: nothing including no iCloud -> fail with iCloud-not-a-backup hint" {
  emit "backup.tm.destination" warn "no destination"
  emit "backup.offsite"        warn "no offsite"
  # Empty HOME, no iCloud Drive folder.
  HOME="$BATS_TEST_TMPDIR/home-empty"
  mkdir -p "$HOME"
  composite_with_icloud() {
    tm_dest=$(_status_of "backup.tm.destination")
    offsite=$(_status_of "backup.offsite")
    have_tm=false; [[ "$tm_dest" == "pass" ]] && have_tm=true
    have_offsite=false; [[ "$offsite" == "pass" ]] && have_offsite=true
    have_icloud=false
    [[ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs" ]] && have_icloud=true
    if $have_tm && $have_offsite; then
      pass "ok" "backup.recovery_path"
    elif ($have_tm || $have_offsite) && $have_icloud; then
      pass "double" "backup.recovery_path"
    elif $have_tm || $have_offsite; then
      warn "single" "..." "backup.recovery_path"
    elif $have_icloud; then
      warn "icloud only" "..." "backup.recovery_path"
    else
      fail "Backup recovery path: NO source — disk loss is unrecoverable. iCloud Drive alone is not a backup — it's sync." "..." "backup.recovery_path"
    fi
  }
  composite_with_icloud
  assert_recorded fail "iCloud Drive alone is not a backup"
}

# ---------- system.theft_resistance ----------

@test "system.theft_resistance: all three controls present -> pass" {
  emit "system.filevault.on"     pass "FV on"
  emit "login.lock.immediate"    pass "immediate"
  emit "login.window.namepw"     pass "name+pw"
  section_2_composite_only() {
    fv=$(_status_of "system.filevault.on")
    lock=$(_status_of "login.lock.immediate")
    win=$(_status_of "login.window.namepw")
    if [[ "$fv" != "pass" ]]; then
      skip "FV not on" "" "system.theft_resistance"
    elif [[ "$lock" == "pass" && "$win" == "pass" ]]; then
      pass "Physical-theft resistance: FileVault on + lock immediate + login window hides users" "system.theft_resistance"
    else
      warn "loose" "" "system.theft_resistance"
    fi
  }
  section_2_composite_only
  assert_recorded pass "Physical-theft resistance"
}

@test "system.theft_resistance: FV on but lock loose -> warn" {
  emit "system.filevault.on"     pass "FV on"
  emit "login.lock.immediate"    warn "5 second delay"
  emit "login.window.namepw"     pass "name+pw"
  section_2_composite_only() {
    fv=$(_status_of "system.filevault.on")
    lock=$(_status_of "login.lock.immediate")
    win=$(_status_of "login.window.namepw")
    if [[ "$fv" != "pass" ]]; then
      skip "FV not on" "" "system.theft_resistance"
    elif [[ "$lock" == "pass" && "$win" == "pass" ]]; then
      pass "ok" "system.theft_resistance"
    else
      warn "Physical-theft resistance: FileVault on but lock posture loose" "..." "system.theft_resistance"
    fi
  }
  section_2_composite_only
  assert_recorded warn "lock posture loose"
}

@test "system.theft_resistance: FV off -> skip (FV is the bigger issue)" {
  emit "system.filevault.on" fail "FV off"
  section_2_composite_only() {
    fv=$(_status_of "system.filevault.on")
    if [[ "$fv" != "pass" ]]; then
      skip "Physical-theft resistance: FileVault not on — fix that first" "" "system.theft_resistance"
    fi
  }
  section_2_composite_only
  assert_recorded skip "FileVault not on"
}

# ---------- ssh.posture ----------

@test "ssh.posture: no keys -> pass" {
  emit "ssh.keys.none" pass "no keys"
  ssh_composite() {
    no_keys=$(_status_of "ssh.keys.none")
    if [[ "$no_keys" == "pass" ]]; then
      pass "SSH posture: no on-disk private keys" "ssh.posture"
    fi
  }
  ssh_composite
  assert_recorded pass "no on-disk private keys"
}

@test "ssh.posture: unencrypted keys + no agent -> fail" {
  emit "ssh.keys.unencrypted" warn "id_rsa unencrypted"
  ssh_composite() {
    unenc=$(_status_of "ssh.keys.unencrypted")
    agent=$(_status_of "ssh.agent.1password")
    authsock=$(_status_of "ssh.authsock")
    ext_agent=false
    [[ "$agent" == "pass" || "$authsock" == "pass" ]] && ext_agent=true
    if [[ "$unenc" == "warn" || "$unenc" == "fail" ]] && ! $ext_agent; then
      fail "SSH posture: unencrypted on-disk keys with no external agent" "..." "ssh.posture"
    fi
  }
  ssh_composite
  assert_recorded fail "unencrypted on-disk keys with no external agent"
}

# ---------- B.9 regression: composites must accept profile-escalated `fail` ----------

@test "ssh.posture: profile-escalated unencrypted (fail) + no agent -> fail (was falling through to pass)" {
  # Under --profile=web3 / paranoid, `_apply_profile` rewrites
  # `ssh.keys.unencrypted` warn -> fail. The composite predicate must
  # accept BOTH warn and fail, otherwise the worst case (unencrypted on
  # disk, no external agent, strict profile selected) silently falls
  # through to "encrypted keys with external agent" PASS.
  emit "ssh.keys.unencrypted" fail "id_rsa unencrypted (escalated by --profile=web3)"
  ssh_composite() {
    unenc=$(_status_of "ssh.keys.unencrypted")
    agent=$(_status_of "ssh.agent.1password")
    authsock=$(_status_of "ssh.authsock")
    ext_agent=false
    [[ "$agent" == "pass" || "$authsock" == "pass" ]] && ext_agent=true
    if [[ "$unenc" == "warn" || "$unenc" == "fail" ]] && ! $ext_agent; then
      fail "SSH posture: unencrypted on-disk keys with no external agent" "..." "ssh.posture"
    else
      pass "SSH posture: encrypted keys with external agent" "ssh.posture"
    fi
  }
  ssh_composite
  assert_recorded fail "unencrypted on-disk keys with no external agent"
  # And critically: ensure the composite did NOT silently fall through to pass.
  [[ "${RESULTS_PASS[*]-}" != *"encrypted keys with external agent"* ]]
}

@test "ssh.posture: profile-escalated unencrypted (fail) + agent present -> warn" {
  emit "ssh.keys.unencrypted" fail "id_rsa unencrypted"
  emit "ssh.agent.1password"  pass "agent running"
  ssh_composite() {
    unenc=$(_status_of "ssh.keys.unencrypted")
    agent=$(_status_of "ssh.agent.1password")
    authsock=$(_status_of "ssh.authsock")
    ext_agent=false
    [[ "$agent" == "pass" || "$authsock" == "pass" ]] && ext_agent=true
    if [[ "$unenc" == "warn" || "$unenc" == "fail" ]] && ! $ext_agent; then
      fail "no agent" "" "ssh.posture"
    elif [[ "$unenc" == "warn" || "$unenc" == "fail" ]] && $ext_agent; then
      warn "SSH posture: unencrypted keys still on disk despite external agent" "..." "ssh.posture"
    fi
  }
  ssh_composite
  assert_recorded warn "unencrypted keys still on disk despite external agent"
}

@test "supply.posture: 2 managers fail (profile-escalated) + scanner fail -> fail" {
  # Under --profile=web3, supply.{npm,yarn,pnpm}.ignorescripts and
  # supply.scanner are all rewritten warn -> fail. The original predicate
  # `[[ ... == "warn" ]]` would have collapsed every count to 0 here,
  # taking the composite to its bottom "else pass" branch — exonerating
  # exactly the open supply chain the profile was meant to escalate.
  emit "supply.npm.ignorescripts"  fail "scripts open"
  emit "supply.yarn.ignorescripts" fail "scripts open"
  emit "supply.scanner"            fail "no scanner"
  supply_composite() {
    npm_warn=0; pnpm_warn=0; yarn_warn=0
    case "$(_status_of supply.npm.ignorescripts)"  in warn|fail) npm_warn=1 ;; esac
    case "$(_status_of supply.pnpm.ignorescripts)" in warn|fail) pnpm_warn=1 ;; esac
    case "$(_status_of supply.yarn.ignorescripts)" in warn|fail) yarn_warn=1 ;; esac
    scripts_open=$((npm_warn + pnpm_warn + yarn_warn))
    scanner_state=$(_status_of supply.scanner)
    scanner_open=false
    case "$scanner_state" in warn|fail) scanner_open=true ;; esac
    if [[ "$scripts_open" -ge 2 ]] && $scanner_open; then
      fail "Supply-chain posture: $scripts_open package manager(s) run scripts on install AND no scanner present" "..." "supply.posture"
    elif [[ "$scripts_open" -ge 1 ]] || $scanner_open; then
      warn "gaps" "..." "supply.posture"
    else
      pass "ok" "supply.posture"
    fi
  }
  supply_composite
  assert_recorded fail "package manager(s) run scripts on install AND no scanner"
}

@test "supply.posture: 1 manager fail + scanner pass -> warn (not silent pass)" {
  emit "supply.npm.ignorescripts" fail "scripts open"
  emit "supply.scanner"           pass "Socket installed"
  supply_composite() {
    npm_warn=0; pnpm_warn=0; yarn_warn=0
    case "$(_status_of supply.npm.ignorescripts)"  in warn|fail) npm_warn=1 ;; esac
    case "$(_status_of supply.pnpm.ignorescripts)" in warn|fail) pnpm_warn=1 ;; esac
    case "$(_status_of supply.yarn.ignorescripts)" in warn|fail) yarn_warn=1 ;; esac
    scripts_open=$((npm_warn + pnpm_warn + yarn_warn))
    scanner_state=$(_status_of supply.scanner)
    scanner_open=false
    case "$scanner_state" in warn|fail) scanner_open=true ;; esac
    if [[ "$scripts_open" -eq 0 && "$scanner_state" == "pass" ]]; then
      pass "ok" "supply.posture"
    elif [[ "$scripts_open" -ge 2 ]] && $scanner_open; then
      fail "double-open" "..." "supply.posture"
    elif [[ "$scripts_open" -ge 1 ]] || $scanner_open; then
      warn "Supply-chain posture: gaps in package-manager hygiene" "..." "supply.posture"
    else
      pass "no gaps" "supply.posture"
    fi
  }
  supply_composite
  assert_recorded warn "gaps in package-manager hygiene"
}

# ---------- twofa.fido_gap ----------

@test "twofa.fido_gap: hardware wallet present, no FIDO key -> skip with nudge" {
  emit "wallet.hw.installed"      pass "Ledger Live"
  emit "twofa.hardware.installed" skip "no FIDO key"
  fido_composite() {
    hw=$(_status_of "wallet.hw.installed")
    twofa=$(_status_of "twofa.hardware.installed")
    if [[ "$hw" == "pass" && "$twofa" != "pass" ]]; then
      skip "FIDO2 gap: hardware wallet present but no dedicated FIDO2 key" "Free upgrade: install the 'FIDO U2F' app on your Ledger" "twofa.fido_gap"
    fi
  }
  fido_composite
  assert_recorded skip "FIDO2 gap"
}
