# Changelog

All notable changes to this project will be documented in this file.

## [1.5.0] - 2026-05-26

Threat-model and prioritization polish on top of v1.3's decision layer. Adds a `journalist` profile and a `--profile auto` recommender, remediation-effort ranking so high-impact / low-effort wins stand out, and a fourth named attack chain. 168 → 169 checks; read-only / bash 3.2 invariants preserved (the only write remains the opt-in `--snapshot`).

### Added

- **`--profile journalist`** — nation-state-spyware lens. Surfaces Lockdown Mode being off and escalates the surveillance surface to `fail`: Bluetooth/AirDrop, ad + diagnostics telemetry, firewall stealth/block-all, remote-access apps, browser remote debugging, VPN killswitch, and stale software/updates. Deliberately not crypto/supply-chain focused.
- **`--profile auto`** — advisory: detects signals (IDE apps, dev toolchains on `PATH`, hardware-wallet apps, known wallet browser-extension ids) and prints a recommended profile (`founder`/`web3`/`developer`/`normal`), then exits. Read-only, no scan; never auto-picks `paranoid`/`journalist` (deliberate threat-model choices).
- **Remediation effort ranking** — every Top Risk now carries an effort hint (`low` = flip a setting, `high` = structural work). Text shows `[tier · effort]`; JSON `top_risks` entries gain an additive `effort` field. Surfaces high-impact / low-effort "fix these first" wins.
- **`chain.cloud_exfil`** — fourth named attack chain. Fires when SSH keys, wallet data, or dotfiles sit under a cloud-sync root (crystallizes the per-domain `data.*.cloud_sync_exposure` rows). Default `warn`; `web3`/`founder`/`paranoid` → `fail`.

### Changed

- The `check_ids` PROFILE_OVERRIDES validator now ignores comment lines, so override-table comments may contain quoted words without breaking CI.

## [1.4.0] - 2026-05-26

Shareable and longitudinal output, all opt-in. The default run stays read-only; the only write the tool ever performs is `--snapshot`, to its own data dir.

### Added

- **`--report md`** — render a shareable Markdown report (Executive Verdict + ranked Top risks with effort + full results table) instead of the terminal report. Honors `--redact`.
- **`tools/render_report.py`** — a stdlib-only Python companion that turns a `--json` document into a self-contained HTML report (no external assets, no network, no dependencies). Keeps the core a single shell file; every dynamic value is HTML-escaped.
- **`--snapshot`** — append a redacted JSON snapshot to `~/.mac-posture-audit/history/` (implies `--redact`, so stored history is safe to keep). The sole write the tool performs; documented as the one read-only exception.
- **`--trend`** — read-only longitudinal view: compares the oldest and newest stored snapshot and reports which checks improved or regressed. No scan, no writes.
- **`catalog/known-bad.txt`** — a maintained, separately-versioned exposure-catalog feed (starter + format/refresh/signing docs) for `--exposure-catalog`.

### Changed

- The JSON document is now assembled from a single full-row store, so `--snapshot` produces a complete document even from a text-mode run. `--json` output is unchanged.

## [1.3.0] - 2026-05-26

The "High-Value Mac Threat Model Update." mac-posture-audit stops being a flat checklist and becomes a decision artifact: every run now ends with a profile-aware **Executive Verdict** and a **Top risks to address** list ranked by what can actually hurt *this* user first — not scan order. Adds depth in the two highest-leverage areas (IDE malicious-repo defense, agent/MCP exposure) and three named attack-chain composites. 9 new check IDs (159 → 168); 29 sections. Read-only, single-file, bash 3.2, no-network-by-default invariants preserved. JSON additions are non-breaking (additive top-level fields).

### Added — decision layer (flagship)

- **Action-priority tiering** (`urgent` > `high` > `medium` > `low`). `urgent` = a `fail` on a high-blast row or a fully-assembled `chain.*`; `high` = any other `fail` or a profile-relevant `warn`; `medium` = an ordinary `warn`; `low` = optional/cosmetic hardening. An ordinary `fail` under `--profile normal` lands in `high`, never `urgent` — the report does not scream catastrophe.
- **Executive Verdict** — a profile-aware, calm one-liner with an `Action priority:` level. Never panics when `fail == 0`: a clean baseline with concentrated risk (wallet + dev + backups on one machine) reads as control-plane concentration, not "compromised."
- **"Top risks to address"** — replaces the flat fail→warn dump; rows are tier-prefixed and ordered by action priority, so wallet exposure and a missing recovery path rise above "firewall not in block-all mode."
- **JSON**: new additive top-level fields `executive_verdict` (`profile`, `tier`, `text`, `top_counts`) and `top_risks` (ranked `{rank,id,status,tier,label,hint}`), plus `summary.total`. The per-row contract (`id`/`status`/`label`/`hint`) is unchanged.
- **`--top N`** (default 7) caps the list; `--top 0` hides the list but keeps the verdict (`top_risks: []`).
- **`--explain <id>`** prints the threat rationale + per-profile severity for one check and exits without scanning. Scoped to the high-value ids (chains, MCP, IDE trust, wallet isolation); unknown ids point at `docs/AGENTS.md`.

### Added — IDE depth (Section 24)

- **`ide.{vscode,cursor}.automatic_tasks`** — flags `task.allowAutomaticTasks: "on"`, the exact `tasks.json` `runOn:folderOpen` autorun used by Contagious-Interview repos. `warn`; `web3`/`developer`/`paranoid`/`founder` → `fail`.
- **`ide.{vscode,cursor}.trusted_folders`** — best-effort trust-sprawl proxy (per-workspace storage dir count); `warn` above 25.

### Added — agent/MCP depth (Section 28)

- **`mcp.servers.launcher`** — informational classification of dynamic launchers (npx/uvx/bunx/pipx/docker). Not a failure on its own.
- **`mcp.servers.filesystem_capable`** — hedged heuristic (`"appears filesystem-capable"`, never a capability proof) for the filesystem MCP server or broad path args. `warn`; `web3`/`developer`/`founder` → `fail`.

### Added — Section 29: attack-chain composites

Named cross-section composites that fire only when a full attack path is assembled (`warn` default, high-blast; `web3`/`founder` → `fail`; informational `skip` otherwise):

- **`chain.fake_interview`** — IDE auto-runs untrusted code AND no sandbox runtime to contain it.
- **`chain.wallet_drain`** — wallet present AND isolation missing AND no outbound monitor.
- **`chain.agent_exposure`** — a filesystem/remote-capable MCP server on the same machine as a wallet.

### Profile overrides (v1.3)

New `PROFILE_OVERRIDES` entries for `ide.*.automatic_tasks` (web3/developer/paranoid/founder), `mcp.servers.filesystem_capable` (web3/developer/founder), and the three `chain.*` rows (web3/founder).

### Tests

- New `tests/sections/31_top_risks.bats` (tiering, verdict, ranked JSON helpers, `--top`/`--top 0`, golden output fixture, HIGH_BLAST/LOW_TIER id-resolution guard), `tests/sections/29_attack_chains.bats` (12 chain cases), and `tests/integration/decision_layer.bats` (real-run JSON contract + `--explain`). Section 24 and 28 suites extended for the new rows. 353 → 400 tests.

### Notes

- `_tier_of` matches `HIGH_BLAST_IDS` with a shell-glob helper (`ide.*.workspace_trust`, `chain.*`). The sandbox signal for `chain.fake_interview` is read from detection state, not `sandbox.runtime.present`'s status (which is always `skip`). No monetization language in the CLI — positioning stays in docs.

## [1.2.0] - 2026-05-25

Inspired by [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee)'s supply-chain inventory model. Adds three new sections (browser extension inventory, editor extension inventory, MCP server audit), a generic exposure-catalog framework for shipping deny-lists separately from the script, a `selftest` subcommand for post-deploy smoke checks, and a `--summary-line` mode for fleet log scraping. 8 new check IDs (151 → 159). Read-only and bash 3.2 invariants preserved throughout.

### Added (Section 26 — Browser Extension Inventory)

- **`browser.extensions.count`** (informational) — walks Chromium-family (Chrome / Brave / Edge / Arc / Vivaldi / Opera / Chromium) `<root>/<profile>/Extensions/<ext_id>/<version>/manifest.json` and Firefox-family (Firefox / LibreWolf / Waterfox) `<root>/<profile>/extensions.json`. Deduplicates by (brand, extension-id) so multi-profile installs aren't double-counted. Firefox theme entries (`"type":"theme"`) are excluded — extensions only. Only `manifest.json` files are opened; cookies / Login Data / IndexedDB / Cache are never touched.
- **`browser.extensions.suspicious`** — for each extension ID found, looks up `browser_extension_id` in the loaded exposure catalog. Catalog severity `critical` → `fail`, `warn` → `warn`, `info` → `skip`. When no catalog is loaded, emits `skip` (advisory). Crypto-relevant use case: ship a maintained `threat_intel/` catalog of known drainer / clipboard-hijacker / wallet-impersonator extension IDs separately from the script. Under `--redact` the extension IDs are suppressed and only the count + severity breakdown surfaces.

### Added (Section 27 — Editor Extension Inventory)

- **`dev.editor_extensions.count`** (informational) — walks `~/.vscode/extensions`, `~/.cursor/extensions`, `~/.windsurf/extensions`, `~/.vscodium/extensions` plus their `-server` remote-dev twins. Each subdir is named `<publisher>.<name>-<version>[-<platform>]`; the parser extracts `publisher.name` with a single sed. Non-extension dirs (`.obsolete`, `node_modules`, etc.) are filtered. Editor extensions run with full read/write access to repos, secrets, and editor session.
- **`dev.editor_extensions.suspicious`** — catalog category `editor_extension`. Same severity-mapping behaviour as `browser.extensions.suspicious`. Case-insensitive matching on `publisher.name`.

### Added (Section 28 — MCP Server Audit)

- **`mcp.servers.count`** (informational) — counts MCP server entries across `~/.cursor/mcp.json`, `~/.claude/.mcp.json` (plus any nested `.mcp.json` / `mcp.json` under `~/.claude/` plugin subdirectories), `~/.codeium/windsurf/mcp_config.json`, `~/Library/Application Support/Claude/claude_desktop_config.json`, and `~/.gemini/settings.json`. Validates each config as JSON with `plutil -convert json` (skipped silently if malformed). Both `"mcpServers"` and `"servers"` envelopes are recognised.
- **`mcp.servers.unpinned`** — `warn` when any MCP launcher references `@latest` or Docker `:latest`. Unpinned launchers fetch the newest registry release each time the host starts; a supply-chain compromise of the upstream package propagates immediately. `web3` / `paranoid` / `founder` escalate to `fail`.
- **`mcp.servers.remote_http`** — `warn` when any server uses a remote HTTP/SSE transport (`"url"` / `"httpUrl"` / `"serverUrl"` with `https?://`). Remote MCP servers receive tool calls and tool-call results (which may include file contents) — treat the operator as a privileged third party. For web3 / wallet-related work, prefer local stdio MCP servers. `web3` / `paranoid` / `founder` escalate to `fail`.
- **`mcp.servers.suspicious`** — catalog category `mcp_server` matched against each server's id. Severity mapping mirrors the other inventory checks.

**Hygiene invariant**: the MCP helper never captures, logs, prints, or surfaces env values or env key names from any host config. MCP configs frequently embed provider credentials in their env blocks. A dedicated integration test asserts that even with secrets-bearing input, no output row references the secret values or keys.

### Added (exposure catalog framework)

- **`--exposure-catalog PATH`** — loads a deny-list of `(category, name, severity[, id])` tuples that any check can consume. Format is one entry per line, pipe-separated. Categories: `browser_extension_id`, `editor_extension`, `mcp_server`, `mcp_package`, `app_bundle_id`, `brew_formula`. Severity: `info` (skip), `warn`, `critical` (fail). Lines starting with `#` are comments. Unknown severities and incomplete lines are silently dropped (forward-compatible).
- New helpers: `load_exposure_catalog`, `_catalog_match` (case-insensitive on name), `_catalog_status_for`.
- **Why separate**: lets users distribute team-wide threat-intel catalogs (e.g. fresh wallet-drainer extension IDs, compromised npm package names) without rev'ing the audit script. Bumblebee-style — collector and threat intel split into independently versioned artifacts.

### Added (housekeeping)

- **`--selftest`** — runs a minimal end-to-end smoke test against in-memory fixtures (catalog loader, `_catalog_match` round-trip, `_record` counter parity) and exits. Non-zero exit means the install can no longer detect what it should — pre-deploy smoke check for MDM rollouts and CI binary stamps. Hermetic: reads no host state. Uses portable `mktemp` (works on Linux + macOS).
- **`--summary-line`** — appends one extra machine-parseable line at the end of the report: `mac-posture-audit summary version=X.Y.Z profile=… pass=N warn=N fail=N skip=N`. Stable token-stream shape for shell scripts that just need counters. Combines with `--json`, `--quick`, `--profile`, `--redact`.

### Profile overrides (v1.2)

- `web3 | mcp.servers.remote_http | warn → fail`
- `web3 | mcp.servers.unpinned | warn → fail`
- `paranoid | mcp.servers.remote_http | warn → fail`
- `paranoid | mcp.servers.unpinned | warn → fail`
- `founder | mcp.servers.remote_http | warn → fail`
- `founder | mcp.servers.unpinned | warn → fail`

### Tests (v1.2)

- New `tests/sections/26_browser_extensions_inventory.bats` — 10 cases: no browsers, single Chromium ext (count + no-catalog skip), catalog match critical → fail, catalog match warn → warn, Firefox addon counted (themes ignored), Chromium + Firefox combined, multi-profile dedup, `--redact` suppresses IDs, miss produces pass, manifest-absent ext dir skipped.
- New `tests/sections/27_editor_extensions.bats` — 9 cases: no editors, single vscode ext, platform-suffixed dir parse, catalog critical → fail, catalog warn → warn, case-insensitive match, junk dirs ignored, multi-editor dedup, `--redact` suppresses publisher.name.
- New `tests/sections/28_mcp_servers.bats` — 12 cases: no configs, one pinned local server (all rows pass-or-skip), `@latest` unpinned warn, Docker `:latest` unpinned warn, remote HTTP warn, catalog-matched server → fail, env values never leak (hygiene assertion), web3 / paranoid / founder escalations on unpinned and remote_http, multi-config aggregation, malformed JSON skipped.
- New `tests/sections/29_exposure_catalog.bats` — 12 cases for `load_exposure_catalog` + `_catalog_match`: no-op without path, valid catalog populates arrays, exact match returns `severity|id`, case-insensitive match, miss returns empty, category mismatch returns empty, comments + blanks ignored, unknown severity dropped, incomplete lines dropped, missing optional id OK, unreadable file exits 2, no-match-when-not-loaded.
- New `tests/sections/30_selftest_summary.bats` — 4 cases: `run_selftest` exits 0 + prints "selftest OK"; `_emit_summary_line` produces stable token-stream; profile fallback; version stamp.

### ID registry (v1.2)

Eight new entries in `tests/fixtures/expected_ids.txt`:
- `browser.extensions.count`
- `browser.extensions.suspicious`
- `dev.editor_extensions.count`
- `dev.editor_extensions.suspicious`
- `mcp.servers.count`
- `mcp.servers.unpinned`
- `mcp.servers.remote_http`
- `mcp.servers.suspicious`

### Release

- `SCRIPT_VERSION` bumped to `1.2.0`.

## [1.1.0] - 2026-05-14

Seven new checks across two PRs, all factored into testable `_check_*` helpers. Bumps the registry from 146 to 151 IDs. Read-only and bash 3.2 compatibility preserved throughout.

### Added (PR 8 — three highest-signal new checks)

- **`network.listening.all_interfaces`** (Section 4, `_check_listening_all_interfaces` helper) — parses `lsof -nP -iTCP -sTCP:LISTEN -F pcn` for TCP listeners bound to `0.0.0.0`, `*`, or `[::]` (the IPv4/IPv6 wildcards). Localhost-only listeners (`127.0.0.1`, `[::1]`) are explicitly excluded; interface-specific binds are assumed intentional and not flagged. Real-world failure mode: a developer runs `vite --host 0.0.0.0` / `python -m http.server` / `next dev -H 0.0.0.0` and forgets to stop it; anything on the local network can then reach the service. Default `warn`, `developer` / `founder` / `paranoid` escalate to `fail`. Under `--redact` the label drops process names and surfaces port numbers only (so a sysadmin reading a redacted report can still spot the exposure pattern).
- **`ssh.config.risky_options`** (Section 11, `_check_ssh_config_risky_options` helper) — scope-aware parser for `~/.ssh/config` that flags three dangerous options when they apply to global scope (top-level, before any `Host` block) or `Host *` / `Match all` (wildcard) blocks: `ForwardAgent yes`, `StrictHostKeyChecking no`, `UserKnownHostsFile /dev/null`. Per-host blocks (`Host github.com`) are deliberately NOT flagged — `ForwardAgent yes` under `Host trusted.internal.example` is a defensible setup. Default `warn`, `developer` / `founder` / `paranoid` escalate to `fail`. Option names redacted under `--redact`.
- **`browser.remote_debugging`** (Section 9, `_check_browser_remote_debugging` helper) — detects the `--remote-debugging-port` (and `--inspect-brk` / `--inspect`) flag on Chromium browsers (Chrome / Brave / Edge / Chromium / Arc / Vivaldi / Opera) and Electron-based IDEs (VS Code / Cursor). With this flag, the browser exposes the Chrome DevTools Protocol on a TCP socket; anything that can reach that socket (including DNS-rebinding from a malicious page in another tab) can dump cookies, extract session tokens, intercept wallet popups, and execute JS in any open tab. Documented technique behind multiple 2024 crypto-drainer incidents. Three-tier emission: **`fail` if any matching process is currently running**; `warn` if found in `~/Library/LaunchAgents/*.plist` or shell rc files (persisted but not running); `pass` otherwise. `web3` / `paranoid` / `founder` escalate the persisted-warn to `fail`. Process / file names redacted under `--redact`.

### Profile overrides (PR 8)

- `developer | network.listening.all_interfaces | warn → fail`
- `paranoid | network.listening.all_interfaces | warn → fail`
- `founder | network.listening.all_interfaces | warn → fail`
- `developer | ssh.config.risky_options | warn → fail`
- `paranoid | ssh.config.risky_options | warn → fail`
- `founder | ssh.config.risky_options | warn → fail`
- `web3 | browser.remote_debugging | warn → fail`
- `paranoid | browser.remote_debugging | warn → fail`
- `founder | browser.remote_debugging | warn → fail`

### Tests (PR 8)

- New `tests/sections/04_listening_ports.bats` — 11 cases for `_check_listening_all_interfaces`: empty / lsof-unavailable / localhost-only / `0.0.0.0:PORT` / `*:PORT` / `[::]:PORT` / mixed (only wildcard flagged) / developer escalation / founder escalation / paranoid escalation / `--redact` process-name suppression with ports preserved.
- New `tests/sections/11_ssh_risky_options.bats` — 16 cases for `_check_ssh_config_risky_options`: missing config / empty / each risky option in isolation at global scope / each under `Host *` / per-host scope (Host github.com — NOT flagged) / `Match all` scope (flagged) / `Match host` (not flagged) / all three combined / dedupe (global + Host * for same option counted once) / developer / founder / paranoid escalations / comment + blank-line tolerance / `--redact`.
- New `tests/sections/09_browser_remote_debugging.bats` — 12 cases for `_check_browser_remote_debugging`: empty / Chrome running / Brave running / Cursor running / non-browser process (NOT flagged) / LaunchAgent persisted / shell rc persisted / running dominates persisted / `--redact` running / `--redact` persisted / web3 escalation / paranoid escalation.

### ID registry (PR 8)

Three new entries in `tests/fixtures/expected_ids.txt`:
- `network.listening.all_interfaces`
- `ssh.config.risky_options`
- `browser.remote_debugging`

### Added (PR 9 — informational and behavioral coverage)

- **`browser.password_autofill`** (Section 9, `_check_browser_password_autofill` helper) — for each detected Chromium-based profile (Chrome / Brave / Edge / Arc, across `Default` and `Profile N` directories), greps `Preferences` JSON for `"credentials_enable_service": false`. When absent or `true` (Chromium's default-on), the browser-native password manager autofills site logins; a phishing site mimicking a wallet-exchange URL can trigger that autofill. Default `skip` with advisory hint; `web3` / `paranoid` / `founder` escalate `skip → warn`. Profile names redacted under `--redact`.
- **`update.macos.recency`** (Section 21, `_check_update_macos_recency` helper) — parses `softwareupdate --history` for the most recent system-relevant install (lines matching `macOS`, `Security Update`, `Safari`, `Rapid Security Response`) and computes its age in days. `update.auto` only verifies the auto-update setting; this catches the "auto-update on but every prompt gets 'Later'" case. Threshold: ≤45 days → pass; 46–90 days → warn ("apply pending updates"); >90 days → warn ("significantly behind"). `paranoid` profile escalates either warn to fail. Skip if `softwareupdate` is unavailable or the date can't be parsed (handles macOS-version drift in the history format).
- **`persist.background_items`** (Section 22, `_check_persist_background_items` helper) — placeholder advisory row for the Ventura-era Background Task Manager. The natural data source (`sfltool dumpbtm`) cannot be invoked from a read-only audit because it uses AuthorizationServices to request elevation — even with `sudo -n`, macOS 13+ pops a GUI prompt ("sfltool wants to make changes") that's incompatible with the audit's no-modal-prompts invariant. The check therefore emits an informational `skip` pointing the user at the manual `sfltool dumpbtm | less` command. If we later find a signal we can read non-interactively (e.g., a user-owned plist), we'll switch to it. No profile escalation.
- **`tcc.appleevents`** and **`tcc.camera_microphone`** (Section 22) — extend the existing TCC parser to surface AppleEvents and Camera + Microphone grants as separate rows. Both are informational by design: AppleEvents is common (Zoom / Slack / Raycast / IDE automation each request it); Camera + Microphone is common for video-conferencing apps. Pass when no clients; skip with count + holder list otherwise. Holder names redacted under `--redact`. No profile escalation — the audit's job is to surface what has been granted, not to suggest those grants are necessarily wrong.

### Profile overrides (PR 9)

- `web3 | browser.password_autofill | skip → warn`
- `paranoid | browser.password_autofill | skip → warn`
- `founder | browser.password_autofill | skip → warn`
- `paranoid | update.macos.recency | warn → fail`

### Tests (PR 9)

- 4 new TCC cases appended to `tests/sections/22_persistence_tcc.bats`: QUICK-mode skip for the new IDs, no-grants pass on both, mixed AppleEvents + Camera + Microphone grants populating both rows, `--redact` holder-name suppression.
- 4 new background-items cases also appended to `22_persistence_tcc.bats`: QUICK-mode skip, sfltool-unavailable skip, empty-output skip, count parsing across `=== Item ===` delimiters, zero-items pass.
- New `tests/sections/09_browser_password_autofill.bats` — 11 cases: no browsers, Chrome `Default` with autofill explicitly disabled (pass), with `credentials_enable_service: true` (skip-advisory), key absent (counts as enabled — Chromium default-on), multi-profile filtering, Chrome + Brave both enabled, both disabled, web3 + founder + paranoid escalations, `--redact` brand:profile suppression.
- New `tests/sections/21_update_recency.bats` — 10 cases: softwareupdate-missing skip, empty-history skip, no-system-relevant-rows skip, 10d pass, 45d pass (at-threshold), 60d warn, 120d warn ('significantly behind'), paranoid escalation to fail, multiple installs (most recent wins), Security Update lines count as system-relevant.

### ID registry (PR 9)

Five new entries in `tests/fixtures/expected_ids.txt`:
- `browser.password_autofill`
- `update.macos.recency`
- `persist.background_items`
- `tcc.appleevents`
- `tcc.camera_microphone`

### Release

- `SCRIPT_VERSION` bumped to `1.1.0`.

## [1.0.1] - 2026-05-14

Patch release addressing post-v1.0.0 review findings. No new check IDs; correctness + redaction fixes only.

### Fixed

- **P1: `backup.tm.encrypted` false-PASS on mixed Time Machine destinations.** The encryption check was an ordered grep: any `Encrypted : 1` anywhere in `tmutil destinationinfo` output emitted `pass` even if another destination was explicitly unencrypted. A user with two TM disks (one encrypted, one not) would see a clean pass and miss the real exposure. The fix counts both states and lets "any unencrypted" dominate "any encrypted." New label for the mixed case: `Time Machine: mixed destinations — N unencrypted, M encrypted`. Two new fixtures (`destinations_mixed.txt`, `destinations_both_encrypted.txt`) + two regression tests.

- **P2: `network.wifi.known_networks` double-count on plists with both formats.** The SSID counter was a single regex matching modern top-level keys (`wifi.network.ssid.*`) AND nested legacy fields (`SSIDString`, `SSID_STR`) in one pass. Plists that carry both (modern format with legacy-compat section) had every network counted twice — 20 real SSIDs became 40, tipping the user from `pass` (≤30) into `warn` (≥31) artificially. The fix probes modern format first and only falls back to legacy if zero modern matches. Two new regression tests cover the mixed-format and legacy-only cases.

- **P2: Redaction leaks in v0.2–v1.0 rows.** Four new rows didn't have `REDACT` branches and leaked identifying values into `--redact` JSON output:
  - `network.vpn.killswitch` pass label included `mullvad:on` (brand identifier).
  - `data.ssh.cloud_sync_exposure` fail label listed `.ssh → iCloud Drive` (specific dir name + provider).
  - `data.crypto.cloud_sync_exposure` warn label listed `Ledger Live → iCloud Drive` (wallet brand + provider).
  - `data.dotfiles.cloud_sync_exposure` warn label listed `.zshrc → iCloud Drive` (dotfile name + provider).

  All four now collapse to count-only labels under `--redact`. Five new assertions in `tests/integration/redaction.bats` (one per row plus a combined VPN-brands check) prevent regression — these would have caught the original leak before v1.0.0 shipped.

- **P3: README compatibility claim corrected.** v1.0.0 README said "macOS Tahoe (26): primary target, CI runner." CI actually uses GitHub Actions `macos-latest`, which is a floating image tag. Reworded the compatibility table to separate "Tested" (manual run, with specific version) from "CI" (floating tag, with resolved-version printed in logs) from "Expected compatible" (older macOS releases).

### Added

- **CI: print resolved runtime versions on every build.** New "Print runtime versions" step in `.github/workflows/safety.yml` outputs `sw_vers`, `uname -a`, `/bin/bash --version`, `bats --version`, `shellcheck --version`, `shfmt --version`. Every release log now records exactly what "tested" meant for that build. Useful for chasing macOS-version-specific regressions later.

### Backlog (v1.1.0 targets)

Eight new check suggestions from the v1.0.0 review, deferred to v1.1.0 so the patch stays scoped to correctness fixes:

1. `persist.background_items` — Background items via `sfltool dumpbtm` (modern macOS persistence surface; sfltool is read-only).
2. `ssh.config.risky_options` — `ForwardAgent yes` / `StrictHostKeyChecking no` / `UserKnownHostsFile /dev/null` in `~/.ssh/config`.
3. `browser.remote_debugging` — running browsers or LaunchAgents / shell-rc entries with `--remote-debugging-port` (cookie / wallet theft surface).
4. `system.xprotect.fresh` — XProtect / XProtect Remediator bundle mtime freshness.
5. `tcc.appleevents`, `tcc.camera_microphone` — extend the sensitive-services list in TCC parsing.
6. `network.listening.all_interfaces` — `lsof -nP -iTCP -sTCP:LISTEN`, warn on `*:PORT` / `0.0.0.0` dev servers. Developer/founder profile only.
7. `browser.password_autofill` — browser-native password manager / autofill posture by grepping Preferences.
8. `network.wifi.auto_join_count` — complement `network.wifi.known_networks` with auto-join count.

## [1.0.0] - 2026-05-13

First public release. The audit has been used in iteration on a real macOS Tahoe machine since v0.1.0 (initial release, 2026-05-10); v1.0.0 collapses the v0.5.0 milestone into the public cut. From this version forward, IDs and the JSON schema are a stability contract — see `docs/schema.md` for the versioning policy.

### Added

- **`gaming.client.installed`** (Section 22) — informational scan of `/Applications` and `~/Applications` for Steam, Discord, Epic Games Launcher, GOG Galaxy, and Battle.net. None of these are bad on their own, but each carries side effects worth surfacing on a wallet-holding Mac: Steam asks for Accessibility for the in-game overlay (UI introspection); Discord is the dominant crypto-phishing channel (fake admin DMs, "verify your wallet" links, malicious bot invites); the others are stored-credential / account-takeover surfaces. Emits `pass` if none found, `skip` with an advisory if any are found. No profile escalation — the audit doesn't penalise legitimate use.
- **`network.wifi.known_networks`** (Section 5, factored into `_check_wifi_known_networks` helper) — counts remembered SSIDs. macOS probes every remembered network when scanning, which is a passive triangulation surface (correlating SSID lists to known coffee shops, conference networks, the user's home / office). Reads `/Library/Preferences/com.apple.wifi.known-networks.plist` (Big Sur+) with `plutil -p`, falling back to the older `SystemConfiguration/com.apple.airport.preferences.plist`. Tries unprivileged first; if that fails and not in `--quick`, retries with `sudo -n` (no-prompt). If neither read works, skip-with-advisory pointing at the plist path. Thresholds: 0 (parse failure → skip), 1-30 (pass), 31+ (warn with a nudge to prune). `WIFI_KNOWN_PLISTS` env override for tests.

- **`supply.direnv.allow_list`** (Section 13, factored into `_check_supply_direnv` helper) — counts entries in `~/.local/share/direnv/allow/`. Each file there is an approved `.envrc` path whose contents auto-execute in the user's shell on `cd`. Long-stale allow lists accumulate cruft and widen the attack surface: a stale approval for an old repo that has since been compromised auto-executes on entry. Emits `pass` if the directory exists but is empty, `skip` informational under 20 approvals, `warn` if ≥21 (with a nudge to run `direnv prune` and review the rest), `skip` "not in use" if the directory doesn't exist at all.
- **`supply.pip.extra_index_url`** (Section 13, `_check_supply_pip_extra_index` helper) — greps user, system, and site pip configs (`~/.pip/pip.conf`, `~/.config/pip/pip.conf`, `~/Library/Application Support/pip/pip.conf`, `/etc/pip.conf`) for `extra-index-url = ...` lines. When configured, pip pulls from a secondary index in addition to PyPI; if a private package name collides with a public PyPI package, the public one wins by default — the classic dependency-confusion attack pattern. Emits `pass` if a config exists without the key, `warn` (escalated to `fail` under `developer` / `paranoid` / `founder`) if the key is set, `skip` if no config exists. Paths are redacted to a count under `--redact`.
- **`supply.uv.config`** (Section 13, `_check_supply_uv_config` helper) — extends the same dependency-confusion pattern to uv (`~/.config/uv/uv.toml`) and pixi (`~/.config/pixi/config.toml`). Greps for all four spelling variants of the extra-index-url key (kebab/snake × singular/plural) since the schema is still stabilising across uv/pixi versions. Same severity / escalation / redaction shape as the pip check.

### Profile system

- **New `--profile founder`** preset — explicit union of `developer` + `web3` escalations, intended for solo founders shipping their own code who also custody crypto. The entries are listed verbatim rather than computed so the override table stays greppable and the bash 3.2 linear-lookup stays simple. If a future `developer` or `web3` entry is added, the `founder` block needs the same entry. CI doesn't enforce this yet — track if it becomes a problem.
- All four supply chain v0.5 escalations land in `developer`, `paranoid`, and `founder` (web3 doesn't pick up the pip/uv ones since they're not crypto-specific): `developer | supply.pip.extra_index_url | warn → fail`, `developer | supply.uv.config | warn → fail`, plus matching `paranoid` and `founder` entries.

### Refactor

- The three new supply chain checks are factored out of `section_13_supply_chain` into standalone helpers (`_check_supply_direnv`, `_check_supply_pip_extra_index`, `_check_supply_uv_config`) so they can be unit-tested without having to mock out npm / yarn / pnpm / brew / gh just to verify a HOME-relative file probe. Same pattern as the `_check_vpn_killswitch` helper in v0.4.0. Production call sites unchanged.

### Tests

- New `tests/sections/13_supply_extras.bats` — 16 cases covering all three new helpers. direnv: absent (skip "not in use"), empty (pass), 3 entries (skip informational), 25 entries (warn to prune). pip: no config (skip), config without key (pass), config with key (warn), paranoid + developer + founder escalations (fail), `--redact` path suppression. uv/pixi: no config (skip), uv config without key (pass), uv kebab-case key (warn), pixi snake_case plural (warn), founder escalation (fail).

### Test-only overrides

- (None new — all three helpers read from `$HOME`, which the tests isolate with `isolate_home`.)

### Formatting

- Apply shfmt-style arithmetic formatting throughout `mac-posture-audit.sh` (no inner whitespace inside `$(())` or `(())`). The v0.4.0 commit was caught by CI on this — `STALE_THRESHOLD=$((28 * 86400))`, `count=$((count + 1))`, `if ((count > 0))`. Behaviour identical; cleans the repo's style invariant.

### ID registry

Five new entries in `tests/fixtures/expected_ids.txt`:
- `supply.direnv.allow_list`
- `supply.pip.extra_index_url`
- `supply.uv.config`
- `gaming.client.installed`
- `network.wifi.known_networks`

### New profile

- `--profile founder` — explicit union of `developer` + `web3` escalations, intended for solo founders who ship their own code AND custody crypto. Added inline (rather than computed) so the override table stays greppable and the bash 3.2 linear-lookup stays simple.

### Public release

This version represents the planned cutover from "iterating with one user" to "ready for wider feedback." README polish + a final read-through of `docs/AGENTS.md` precede the public announcement. The CI tripwire, JSON schema, redaction smoke tests, and stable ID contract are all stable shape from v0.2.0 onward.

## [0.4.0] - 2026-05-13

### Added

- **`messaging.telegram.advisory`** (new Section 25) — advisory check for Telegram Desktop, Telegram Desktop variant bundles, and Telegram Lite (App Store build). Detects presence under `APP_ROOTS`. tdata is encrypted, so the audit can't read the actual privacy settings; the check is therefore intentionally informational. When Telegram is present, emits a `skip` with an explicit settings checklist: "Who can add me to group chats?" → My Contacts/Nobody, Automatic Media Download → OFF for private/groups/channels, Read time + Last Seen restricted to contacts. When Telegram is absent, emits `pass`. Default-on auto-download is the most common targeting vector — an attacker DMs a "PDF" and the file lands on disk silently before the user has decided whether to open it.
- **`browser.version_currency`** (Section 9) — bundle mtime check across Chromium-based browsers (Chrome, Brave, Edge, Arc, Opera) and Firefox. Safari is deliberately excluded — it's managed by macOS updates and already covered by `update.auto`. The check iterates over a brand→bundle-name table, looks for each under `APP_ROOTS`, and compares the bundle's mtime against a 28-day threshold. Chromium and Firefox auto-updaters replace the bundle in place on first launch after a release, which touches the bundle's directory mtime, so a stale mtime is a strong signal that the browser hasn't auto-updated recently — either the user hasn't launched it, or auto-update is disabled / failing. Either way, every page render hits unpatched CVEs. Emits `pass` if all installed browsers are fresh, `warn` if any are stale (label enumerates each with its age in days), `skip` if no non-Safari browser is installed. `web3` and `paranoid` profiles escalate `warn → fail`. Stale browser names are redacted to a count under `--redact`.

### Profile overrides

- `web3 | browser.version_currency | warn → fail`
- `paranoid | browser.version_currency | warn → fail`

### Tests

- New `tests/sections/25_messaging.bats` — 4 cases: Telegram absent (pass), `Telegram.app` present, `Telegram Desktop.app` (vendor variant) present, `Telegram Lite.app` (App Store) present. All assert the skip-with-advisory label on the present path.
- New `tests/sections/09_browsers.bats` — 9 cases for `browser.version_currency`: no browser baseline, fresh single browser pass, single stale warn with age in label, mixed fresh+stale (only stale flagged), multi-stale aggregation, web3 + paranoid escalation, REDACT name suppression, near-threshold inside (27d) fresh, near-threshold outside (29d) stale. Uses `touch -t` macOS-style timestamps to control bundle mtime, and `APP_ROOTS` sandboxing so the check doesn't see real browsers on the runner.

### New section

- Section 25 — Messaging Apps (advisory). Wired into `run_all_sections()` after Section 24. Reserves space for future `messaging.signal.advisory`, `messaging.discord.advisory`, etc.; current scope is Telegram only per stated review preference.

- **`browser.profile_count`** (Section 9) — purely informational signal that the user has already adopted some form of profile-level browser isolation (e.g. "Work" / "Personal" / "Wallet" profiles). Profiles aren't a strong security boundary (same OS user, same keychain) but a multi-profile setup is a strong tell that the user has thought about isolation, which lowers the leverage of further nudges. Counts Chromium-derived browsers (Chrome / Brave / Edge) by enumerating `Default` (with `Preferences` present) plus `Profile <N>` directories under each browser's User Data root, and Firefox by counting direct children of `~/Library/Application Support/Firefox/Profiles/`. Emits `pass` when ≥2 profiles are found anywhere across browsers (label enumerates per-browser counts like `Brave:2 Firefox:1`), `skip` with a nudge when exactly 1 is found, `skip` with N/A when 0 are enumerable. Per-browser counts are redacted to a total under `--redact`. No profile escalation — this is observational.
- **`network.vpn.killswitch`** (Section 6, factored into `_check_vpn_killswitch` helper for testability) — verifies the killswitch / always-on / "block when disconnected" state on installed VPNs. Without it, brief tunnel drops leak the user's real IP to whatever they were connecting to — the exact failure mode VPN customers buy the product to avoid. Currently supports: Mullvad (parsed from `~/Library/Application Support/Mullvad VPN/settings.json` — `block_when_disconnected: true` → pass, `false` → warn, missing key → skip-with-advisory). ProtonVPN and NordVPN store their killswitch state in binary plists or sqlite DBs that aren't safe to parse without more code; for those brands the check falls back to a per-brand advisory ("Preferences → Connection → Kill Switch") so the user at least knows to verify. `web3` and `paranoid` profiles escalate `warn → fail`. Brand names are redacted under `--redact`. `VPN_KILLSWITCH_ROOTS` env is overridable for tests.

### Profile overrides

- `web3 | browser.version_currency | warn → fail`
- `paranoid | browser.version_currency | warn → fail`
- `web3 | network.vpn.killswitch | warn → fail`
- `paranoid | network.vpn.killswitch | warn → fail`

### Tests

- New `tests/sections/25_messaging.bats` — 4 cases: Telegram absent (pass), `Telegram.app` present, `Telegram Desktop.app` (vendor variant) present, `Telegram Lite.app` (App Store) present. All assert the skip-with-advisory label on the present path.
- New `tests/sections/09_browsers.bats` — 17 cases. version_currency block: no-browser baseline, fresh-only pass, single stale warn, mixed fresh+stale (only stale flagged), multi-stale aggregation, web3 + paranoid escalation, REDACT name suppression, near-threshold inside/outside (27d vs 29d). profile_count block: no-data skip, single-profile skip with nudge, multi-profile pass, multi-browser aggregation, Firefox multi-profile, REDACT per-browser suppression. Uses `touch -t` macOS-style timestamps to control bundle mtime, `APP_ROOTS` sandboxing, and an isolated `$HOME` for profile dir reads.
- New `tests/sections/06_vpn_killswitch.bats` — 11 cases for the `_check_vpn_killswitch` helper. No-brand skip, Mullvad on (pass), Mullvad off (warn, with web3 and paranoid escalation to fail), Mullvad missing-key (skip-advisory), ProtonVPN advisory, NordVPN advisory, mixed Mullvad-on + ProtonVPN-advisory (advisory wins over verified pass), Mullvad-off + ProtonVPN (fail wins over advisory), REDACT brand-name suppression. `VPN_KILLSWITCH_ROOTS` sandbox isolates HOME-relative settings reads.

### New section

- Section 25 — Messaging Apps (advisory). Wired into `run_all_sections()` after Section 24. Reserves space for future `messaging.signal.advisory`, `messaging.discord.advisory`, etc.; current scope is Telegram only per stated review preference.

### Refactor

- The VPN killswitch logic is factored out of `section_06_dns_outbound` into a standalone `_check_vpn_killswitch` helper. Production calls it from the same place as before (right after the existing `network.vpn.running` emit) — behaviour unchanged. The factoring enables direct unit-level testing without having to mock the entire surrounding DNS / outbound-monitor stack.

### Test-only overrides

- `VPN_KILLSWITCH_ROOTS` — array of HOME-equivalent roots to scan for VPN settings files. Defaults to `$HOME`; tests set it to a `$BATS_TEST_TMPDIR/home` sandbox.

### ID registry

Four new entries in `tests/fixtures/expected_ids.txt`:
- `messaging.telegram.advisory`
- `browser.version_currency`
- `browser.profile_count`
- `network.vpn.killswitch`

## [0.3.0] - 2026-05-13

### Added

- **`backup.tm.encrypted`** (Section 18) — checks whether Time Machine destinations advertise `Encrypted : 1` (or `Yes`) via `tmutil destinationinfo`. Surfaces the case where TM is configured but the destination is *not* encrypted, which leaves a full-disk image readable by anyone who steals the backup drive — defeats FileVault at rest. Emits `pass` when encrypted, `warn` when explicitly unencrypted, `skip` when no destination is configured or the field is absent on this `tmutil` version. `paranoid` profile escalates `warn → fail`.
- **`data.ssh.cloud_sync_exposure`** (Section 17) — iterates over `~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`; resolves real path via `cd + pwd -P` so symlinks into cloud-sync roots are caught; calls `_path_in_cloud_root`; **fails by default** (no profile escalation needed — uploading SSH keys to iCloud Drive / Dropbox / etc. is recoverable by anyone with cloud-account access and defeats key passphrases since the encrypted form is offline-brute-forceable). Provider name (iCloud Drive / Dropbox / Google Drive / OneDrive / Box / generic File Provider) is included in the label.
- **`data.crypto.cloud_sync_exposure`** (Section 17) — same pattern against wallet application-support dirs: Ledger Live, Trezor Suite, Electrum, Sparrow, Bitcoin, plus `~/Library/Ethereum` and `~/.ethereum`. Wallet metadata, watch-only descriptors, and (for some wallets) encrypted seed material live in these dirs. Default `warn`; `web3` and `paranoid` profiles escalate to `fail`.
- **`data.dotfiles.cloud_sync_exposure`** (Section 17) — covers `~/.gitconfig`, `~/.zshrc`, `~/.bashrc`, `~/.zprofile`, `~/.profile`, `~/.netrc`, `~/.pypirc`, `~/.npmrc`, `~/.cargo/credentials`, `~/.gem/credentials`. Files (not directories), so resolution is via parent's `pwd -P` + basename to catch symlinks. Complements Section 14 credential-pattern detection on the *location* axis: even unscanned secrets leak when these files are inside a cloud-sync root. Default `warn`.
- **`apps.remote_access.present`** (Section 22) — detects AnyDesk, TeamViewer (+ Host), Splashtop (Business + Streamer), RustDesk, Chrome Remote Desktop, LogMeIn, GoToMyPC, ScreenConnect / ConnectWise Control, RealVNC, VNC Viewer, Parsec under `/Applications` and `~/Applications`. Closes the most common "fake interview" / ClickFake crypto-drainer playbook gap: attacker convinces target to install a remote-control app for a "screen-share interview," grants Accessibility + Screen Recording, drains wallets. Default `warn`; `web3` and `paranoid` profiles escalate to `fail`. App names are listed in the terminal label, redacted to a count under `--redact`. Brand list is overridable via `APP_ROOTS` env for tests.
- **`sandbox.runtime.present`** (Section 22) — informational nudge. Detects Docker.app, OrbStack.app, UTM.app, Parallels Desktop, VMware Fusion (via app bundles) and Lima / Colima (via `command -v`). Emits `skip` either way: present gets a positive acknowledgement with a use-case hint ("use this for untrusted npm/pip packages"); absent gets a recommendation to install OrbStack or UTM. `SANDBOX_CLI_BINS` env is overridable for tests.
- **`cloud.icloud.desktop_documents_sync`** (Section 19) — detects whether Apple's "Desktop & Documents Folders in iCloud Drive" feature is on by probing for `~/Library/Mobile Documents/com~apple~CloudDocs/Desktop` and `~/Library/Mobile Documents/com~apple~CloudDocs/Documents` as real directories. When on, every file on the user's Desktop or in Documents is uploaded to iCloud and replicated to every signed-in device — a major blast-radius expander, especially when the user drags wallet seed material, tax docs, or `Vault.sparsebundle` to the Desktop "temporarily." Default `warn`; surfaces *which* folders are redirected.
- **`ide.vscode.workspace_trust`** + **`ide.cursor.workspace_trust`** (new Section 24) — per-IDE workspace trust posture. VS Code shipped Workspace Trust in 1.57 as the in-editor defence against the "open malicious repo → tasks.json autoruns" attack; Cursor inherits it. The check greps each IDE's `settings.json` (`~/Library/Application Support/{Code,Cursor}/User/settings.json`) for three known-bad opt-outs: `security.workspace.trust.enabled: false` (hard `fail` — reverts to pre-1.57 unsafe behaviour), `security.workspace.trust.untrustedFiles: "open"` (`warn`), and `security.workspace.trust.startupPrompt: "never"` (`warn`). Skips with `not detected` if neither settings file nor app bundle exists; passes with `installed; no user settings` when the app is present but the user hasn't overridden defaults. `IDE_APP_ROOTS` env is overridable for tests. JSONC comments are not stripped — a documented limitation; we prefer false negatives ("looks OK") over false positives. `web3` and `paranoid` profiles escalate `warn → fail`.
- **`users.crypto_isolation_indicator`** (Section 24) — cross-section composite that fires only when wallet extensions are present (`ext.wallet` post-profile status is `warn` or `fail`). Measures whether the wallet workflow has isolation indicators by reading `user.human.count` (multi-user account posture) and `browser.default` (whether the default risk-surface browser overlaps with the wallet browser). `skip` if no wallet detected, `pass` if both indicators are healthy, `warn` if any indicator is missing (label enumerates the specific gaps). `web3` and `paranoid` profiles escalate `warn → fail`. Tightly scoped — deliberately does NOT roll in the FIDO2 gap; that's its own `twofa.fido_gap` composite.

### Profile overrides

- `web3 | data.crypto.cloud_sync_exposure | warn → fail`
- `paranoid | data.crypto.cloud_sync_exposure | warn → fail`
- `paranoid | backup.tm.encrypted | warn → fail`
- `web3 | apps.remote_access.present | warn → fail`
- `paranoid | apps.remote_access.present | warn → fail`
- `web3 | ide.vscode.workspace_trust | warn → fail`
- `paranoid | ide.vscode.workspace_trust | warn → fail`
- `web3 | ide.cursor.workspace_trust | warn → fail`
- `paranoid | ide.cursor.workspace_trust | warn → fail`
- `web3 | users.crypto_isolation_indicator | warn → fail`
- `paranoid | users.crypto_isolation_indicator | warn → fail`

### Tests

- New `tests/sections/17_folder_layout.bats` — 10 cases covering: no-finding baseline, SSH/AWS/kube/gnupg under iCloud, wallet-app-data under iCloud with default + web3 + paranoid severity, dotfiles under iCloud, downloads hygiene, vault sparsebundle detection. Uses an isolated `$HOME` inside `$BATS_TEST_TMPDIR` (`isolate_home` / `isolate_home_in_icloud` helpers in the file) so tests never touch real user dotfiles.
- Five new `tests/sections/18_backups.bats` cases covering the four `backup.tm.encrypted` outcomes (pass / warn / skip-no-destination / skip-older-tmutil) plus a paranoid-profile escalation case.
- Nine new `tests/sections/22_persistence_tcc.bats` cases — remote-access absence baseline, AnyDesk-only warn, TeamViewer+RustDesk multi-find, web3 + paranoid escalation to fail, label redaction under `--redact`; sandbox no-runtime nudge, OrbStack positive ack, Docker+UTM multi-list. All use a sandbox `APP_ROOTS` so detection doesn't depend on what's installed on the runner machine.
- New `tests/sections/19_icloud.bats` — 5 cases for `cloud.icloud.desktop_documents_sync`: baseline pass, iCloud root present but no redirected folders (still pass), Desktop-only warn, Documents-only warn, both-redirected warn with combined label.
- New `tests/sections/24_ide_trust.bats` — 16 cases. IDE block: no-IDE skip, VS Code-installed-no-settings pass, three opt-out failure/warn cases each in isolation, all-three-combined fail (DISABLE dominates), clean settings pass, Cursor-only fail, two web3 escalation cases. Composite block: no-wallet skip, healthy-indicators pass, single-gap warn (each variant), combined-gap warn, web3 escalation to fail. `IDE_APP_ROOTS` sandbox + a `set_status` helper that pre-seeds `STATUS_BY_ID` so composite dependencies don't need section orchestration.

### Fixtures

- `tests/fixtures/tmutil/destination_encrypted.txt` — `Encrypted : 1`
- `tests/fixtures/tmutil/destination_unencrypted.txt` — `Encrypted : 0`

### Test-only overrides

- `APP_ROOTS` — array of directories to scan for risky/sandbox apps. Defaults to `/Applications $HOME/Applications` in production; bats sets it to a `$BATS_TEST_TMPDIR/apps` sandbox.
- `SANDBOX_CLI_BINS` — array of CLI runtime binaries to probe via `command -v`. Defaults to `lima colima`; tests set to empty array to deterministically suppress lookups against the runner's `$PATH`.
- `IDE_APP_ROOTS` — array of directories to scan for IDE app bundles. Same shape as `APP_ROOTS`, separated so apps and IDEs can be sandboxed independently.

### ID registry

Ten new entries in `tests/fixtures/expected_ids.txt`:
- `backup.tm.encrypted`
- `data.ssh.cloud_sync_exposure`
- `data.crypto.cloud_sync_exposure`
- `data.dotfiles.cloud_sync_exposure`
- `apps.remote_access.present`
- `sandbox.runtime.present`
- `cloud.icloud.desktop_documents_sync`
- `ide.vscode.workspace_trust`
- `ide.cursor.workspace_trust`
- `users.crypto_isolation_indicator`

### New section

- Section 24 — IDE Workspace Trust + Wallet Isolation. Two per-IDE checks plus the cross-section wallet-isolation composite. Wired into `run_all_sections()` after `section_23_device_mgmt_privacy`.

## [0.1.0] - 2026-05-10

Initial release.

### Audit script

- Single executable audit script: `mac-posture-audit.sh`. Bash 3.2 compatible (works on stock macOS without `brew install bash`).
- Twenty-three sections of read-only checks: system integrity, login & lock screen, privacy & telemetry, firewall & sharing, AirDrop & Bluetooth, DNS & outbound monitoring, filters & proxies, antivirus & endpoint protection, browsers, browser extensions (Chromium / Safari via `pluginkit` / Firefox via `extensions.json`), SSH, Git signing, supply chain (npm/yarn/pnpm + `gh auth`, git credential helper, `url.insteadOf` rewrites, `core.hooksPath`, cargo/pypi/gem/Homebrew taps, `brew analytics`), credential hygiene, password manager & 2FA hardware, crypto hardware wallet, folder layout, backups, iCloud, user accounts & sudo, software updates & Find My Mac, persistence (LaunchAgents/Daemons, login items, crontab) & TCC permission holders, and device management & privacy awareness (MDM enrollment, screenshot location iCloud-leak detection, clipboard manager presence).
- Offline-by-default behavior. `--network` is the only mode that permits live external probes, currently limited to NextDNS routing verification and `gh auth status`.
- Optional sudo mode for fuller read-only visibility, while preserving the invoking user's home directory instead of auditing `/var/root`.
- Combinable flags: `--quick`, `--json`, `--network`, `--offline`, `--redact`, `--profile {normal,web3,paranoid,developer}`, `--diff <previous.json>`, `--version`, and `--help`.

### Output

- Stable JSON output with unique check IDs, summary counters, result rows, redaction support, schema documented in `docs/schema.md`, and a stdlib-only validator at `tests/lib/validate_schema.py`. Macs ship `python3` but not `jsonschema`; the validator hand-checks structure, types, the status enum, counter parity, and id uniqueness.
- `_json_escape` covers the full JSON control-character set (newline, carriage return, tab, backspace, form feed) so labels and hints round-trip cleanly. Applied uniformly to row label/hint/id AND to the top-level `host` / `macos` / `arch` fields in `emit_summary` so a hostname containing `"` or `\` can't break the document.
- `--redact` is now meaningfully stronger. Rows that previously embedded identifying values into their labels — VPN process names (`ProtonVPN`, `Mullvad`), system-extension bundle IDs (`com.acme.vpn`), third-party Homebrew taps, Time Machine destination names, AV brand names (all three arms of the count case, including the rare 3+-engine warn), AV-browser-plugin host browser names, wallet extension brands, the `*)` arm of `browser.default`, sensitive TCC holders, clipboard manager names, and the DNS resolver list — collapse to a count or a brand-suppressed string under `--redact`. Default (un-redacted) terminal output is unchanged so local audits keep their detail.
- Stable `id` field on every JSON result row, threaded through ~190 reporter call sites. IDs are unique within a single run and stable across runs so external consumers can diff successive scans by `id`. Canonical fixed-id list in `tests/fixtures/expected_ids.txt`; templated-id patterns (e.g. `^network\.sharing\.[a-z0-9_]+$`, `^persist\.system\.[a-z0-9_]+$`) in `tests/fixtures/expected_id_patterns.txt`; both gated in CI.
- Runtime duplicate-id detection in `_record` — a colliding id exits 2 at the offending emitter rather than being caught later by the JSON validator.
- `--diff <previous.json>` runs the audit, compares against a previously saved JSON output by id, and prints one line per status flip plus `+` / `-` for newly emitted and removed ids. Exit 0 if no diffs, 1 if any, 2 on parse / file error.
- Per-row inline detail for `persist.cron` (each non-comment crontab entry shown beneath the warn row in terminal mode; suppressed in `--redact` and JSON modes so cron content can't leak into a shareable report).
- Per-row inline detail for `persist.user.launchagents` (each user LaunchAgent plist filename shown beneath the warn row in terminal mode; suppressed in `--redact` and JSON modes for the same reason — bundle IDs encoded in plist names can identify the user).
- `persist.login_items` label suppresses the comma-separated app names under `--redact` and `--json` (count only — `9 login item(s) detected`), so app inventory can't end up in a shared report. Terminal mode without `--redact` still shows the names inline for local audit.

### Severity profiles

- `--profile {normal,web3,paranoid,developer}` for severity calibration. Profiles escalate selected checks past their default status — e.g. wallet-on-main-user is `warn` under `normal`, `fail` under `web3` and `paranoid`; supply-chain `ignore-scripts` and Socket-CLI absence escalate to `fail` under `web3`/`paranoid`/`developer`; Bluetooth/AirDrop/firewall warnings escalate to `fail` under `paranoid`. The active profile is surfaced in the header. The override matrix lives in `mac-posture-audit.sh:PROFILE_OVERRIDES` and is gated by a CI test asserting every override id is recognised.

### Read-only safety

- `scripts/check-read-only.sh` rejects command-position mutation patterns: file writes/deletes, mutating `defaults`/`plutil`/`launchctl`/`profiles` calls, package installs (`brew install/upgrade/uninstall/tap NAME`, `npm install/update/uninstall`, `pip install`), kill commands, disk tooling, `curl | bash`, writable `sqlite3`, mutating `osascript`, and unguarded network probes.
- Narrow read-only allowlists for `sqlite3 -readonly` (TCC.db inspection), read-only-verb `osascript` (login-items query), bare `brew tap` listing, guarded NextDNS `curl`, and guarded `gh auth status` — each covered by positive and negative tripwire fixtures so the allowlist itself is regression-tested.
- Credential check (§14) reports filenames and pattern names only, never secret values; uses `grep -l` (filenames-only) and `grep -c` (counts), never content mode.

### Detection details worth noting

- AV/EDR detection is a `BUNDLE | PROC_ERE | NAME` table that uses bundle presence (the dominant signal — survives the daemon being idle) plus full-argv `pgrep -fi`. Catches launchd-spawned daemons whose binary name differs from the brand string (CrowdStrike's `falcond`, Microsoft Defender's `wdavdaemon`, SentinelOne's `sentineld`, Bitdefender's `BDLDaemon`).
- Configuration profiles use `system_profiler SPConfigurationProfileDataType` for device scope (no sudo), augmented with `sudo profiles list` when available — so a fully MDM-managed machine isn't a false negative without sudo.
- `pgrep` patterns are ERE (macOS `pgrep` doesn't honour BRE-style `\|`); CI has a regression test that fails if `\|` reappears in a pgrep call.
- `supply.git.insteadof` recognises SSH-target rewrites of trusted forges (`git@github.com:`, `git@gitlab.com:`, `git@bitbucket.org:`, the `ssh://git@…` equivalents, `git@codeberg.org:`, `git@gitea.com:`) as a security improvement, not a MITM risk; only warns on rewrites whose target is something else.
- `supply.git.credentialhelper` flips from a "consider osxkeychain" SKIP to a PASS when the user has gone SSH-only on purpose (credential helper unset *and* a trusted-SSH-forge `insteadOf` rewrite exists).
- `cred.gitleaks.hint` flips from "install via brew" SKIP to a PASS with a periodic-scan hint when `gitleaks` is on PATH.
- `network.firewall.stealth` matches both the macOS 13/14 phrasing (`stealth mode enabled|disabled`) and macOS 15+ phrasing (`Firewall stealth mode is on|off`).
- `persist.login_items` distinguishes "no login items" from "Automation permission denied" and from any other osascript failure. The probe captures osascript's exit code separately from its merged stdout/stderr; non-zero with a permission-denial fingerprint (`not authori[sz]ed` / `errOSACantAuth` / `-1743` / `access for assistive`) emits SKIP with a "grant Automation → System Events" hint, non-zero with any other text emits a generic `osascript exited N` SKIP. The previous `2>/dev/null` + `elif -n $LOGIN_OUT` combo could either silently PASS on permission denial OR mistakenly report the error stderr as login-item names (`1 login item(s): execution error: ...`).
- `update.auto` is now honest about ambiguity. The previous fallback (when `softwareupdate --schedule` was unparseable) OR'd six unrelated `com.apple.SoftwareUpdate` keys (`AutomaticDownload`, `CriticalUpdateInstall`, `AutomaticallyInstallMacOSUpdates`, …) and emitted PASS the moment any one was `1` — but those keys answer different questions ("if a check runs, also download", "install XProtect data files", "auto-apply macOS updates", …) and the OR was a near-tautology that ignored the explicit `AutomaticCheckEnabled=0`. The fallback now reads exactly `AutomaticCheckEnabled`: `1 → PASS`, `0 → WARN`, absent → `SKIP`.
- Composites that read profile-overridden constituents (`ssh.posture` reading `ssh.keys.unencrypted`; `supply.posture` reading `supply.{npm,yarn,pnpm}.ignorescripts` and `supply.scanner`) now accept both `warn` AND `fail` for their constituent predicates. `_apply_profile` rewrites those constituents warn→fail under `--profile=web3` / `paranoid` / `developer`; the previous `== "warn"` predicates silently fell through to a misleading PASS for exactly the inputs the stricter profile was meant to catch.
- `network.dns.resolvers` preserves `scutil --dns` primary-first order (`awk '!seen[$0]++' | head -3`). The previous `sort -u | head -3` reordered lexically, so on a host with `1.1.1.1, 8.8.8.8, 192.168.1.1` the local router got pulled forward and looked like the primary resolver.
- `shopt -s nullglob` inside section 11 (SSH) is now scoped to that section: the caller's prior state is recorded with `shopt -q nullglob` and restored on section exit. The previous unconditional set leaked process-globally and silently changed glob semantics in §13 / §17 / §22 (unmatched globs would disappear instead of becoming literal — the opposite of what those sections assume).
- `user.admin.count` parses the admin group once (was twice) and counts from the parsed list. An empty/unparseable result now emits SKIP rather than the previous hardcoded `pass "1 admin user: <empty>"` — a false PASS on a privilege check is the worst possible failure mode here. The single-/two-/three+-admin branches use the actual list count in their labels.
- AV/EDR table rows use a `BUNDLES | PROC_ERE | NAME` schema where `PROC_ERE` itself may contain `|` alternation (`clamd|clamscan`, `falcond|CSFalconAgent`, `wdavdaemon|mdatp`). Parser captures `proc="${rest%|*}"` and `name="${row##*|}"` so the alternation passed to `pgrep -fi` is preserved end-to-end. The previous `proc="${rest%%|*}"` silently dropped every alternation segment after the first, breaking detection for AV engines whose daemon name differs from the brand string.

### Credential pattern coverage

- `CRED_PATTERNS` includes high-confidence prefixed tokens: AWS access keys, GitHub PATs (classic + fine-grained), GitLab PATs, npm tokens, OpenAI / Anthropic / HuggingFace / Replicate, Stripe live secrets/publishables, Google API keys, Slack bot tokens, Twilio, Sendgrid, Mailgun, Sentry DSN, PostHog, Linear, Notion integration secrets, DigitalOcean PATs, Telegram bot tokens, Discord bot tokens, Discord MFA tokens, generic JWT, plus three Web3 RPC URL forms that embed the secret in the URL itself (Alchemy, Infura, QuickNode).

### Test harness & CI

- Bats test harness with mocked macOS CLI fixtures, per-section unit tests, integration tests, profile tests, diff tests, schema tests, JSON-escape coverage, redaction smoke tests, and tripwire positive/negative fixtures. 125 tests at v0.1.0.
- GitHub Actions safety workflow runs on `macos-latest`: Bash syntax, ShellCheck (warning level), `shfmt -d -i 2`, the read-only tripwire, the tripwire's positive/negative fixture suite, the bats suite, the strengthened JSON smoke (counter parity, status enum, id non-empty + unique, `--redact` masking), and the stdlib schema validator.
- `tests/check-read-only/should_pass/*.sh` and `should_fail/*.sh` cover each tripwire allowlist and each rejected mutation pattern (`rm`, `chmod`, `defaults write`, `plutil -replace`, `launchctl load`, `brew install`, `brew tap NAME`, `npm install`, `killall`, `curl|bash`, unguarded `curl`, writable `sqlite3`, mutating `osascript`).

### Repo hygiene

- `SECURITY.md` documenting the read-only guarantee, opt-in network behavior, privileged-check behavior, verification steps, disclosure contact, and practical OS logging limits.
- `docs/schema.md` documenting the JSON output format, status enum, id grammar, versioning rules, and `--diff` semantics.
- `docs/AGENTS.md` — explicit guide for an LLM/AI agent reviewing the JSON output. Covers the audit's design intent (raw signals over baked-in opinions), threat-model lenses (casual / developer / web3 / journalist / shared Mac), and composite patterns to detect.

### Composite checks

The audit emits five new aggregate check IDs that combine constituent rows into a single posture verdict — surfacing risks that no individual row would flag on its own:

- `network.dns.encrypted` — encrypted DNS posture (DoH/DoT live + profile + VPN); warn when traffic goes to ISP in plaintext.
- `backup.recovery_path` — combines `backup.tm.destination` + `backup.tm.recency` + `backup.offsite` + iCloud Drive presence. iCloud Drive is treated as a *partial* source (covers `~/Documents` + `~/Desktop` + Photos + iCloud-aware app data; does NOT cover `/Applications`, `~/Dev`, brew installs, system state; deletes propagate; ≤30d versioning; needs ADP for E2E). **Fails when no source is configured at all**; warns when only iCloud Drive is present (partial recovery); passes when a full source (TM / offsite) is present, with iCloud Drive surfaced as added redundancy when present alongside.
- `system.theft_resistance` — combines `system.filevault.on` + `login.lock.immediate` + `login.window.namepw`. FileVault alone is meaningless against a thief grabbing a sleeping/unlocked Mac (key extractable from memory).
- `ssh.posture` — combines key state with external-agent state. **Fails when unencrypted keys are on disk with no 1Password / Secretive agent.**
- `supply.posture` — combines `supply.{npm,yarn,pnpm}.ignorescripts` + `supply.scanner`. **Fails when ≥2 managers run scripts AND no scanner is present** — one malicious `postinstall` lands.
- `twofa.fido_gap` — when a hardware wallet (Ledger / Trezor) is present but no FIDO2 key, point at the wallet's built-in FIDO2 companion app (Ledger ships "FIDO U2F") as a free upgrade for account 2FA.

Each composite reads constituent statuses via a new `_status_of` helper that maintains an `id → status` map populated by `_record` after profile overrides are applied. Bats coverage in `tests/integration/composites.bats`.
