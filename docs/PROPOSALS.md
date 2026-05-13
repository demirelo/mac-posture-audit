# Personal Security — Proposed Additions to `mac-posture-audit`

This document proposes additional checks for `mac-posture-audit`, distilled from current OpSec literature for crypto founders, DeFi developers, and high-value individual targets. The existing 23 sections cover most foundational hardening. The gaps below are concentrated in three threat surfaces that have become measurably worse in 2025–2026:

1. **Targeted social engineering against developers** — the "Contagious Interview" / "ClickFake" / DeceptiveDevelopment campaign families (Lazarus Group / DPRK). These compromise high-value individuals by getting them to open a malicious repo in a *trusted* IDE on their *main* machine. Defenses are checkable.
2. **Treat-the-frontend-as-financial-infrastructure** posture (Sherlock, Bybit Safe-UI incident postmortem). Some of this maps to wallet/browser profile isolation that the audit currently only partially flags.
3. **Cloud-sync exfiltration of sensitive directories** — already partially addressed (screenshot leak detection); extending the pattern to `~/.ssh` and wallet directories closes a high-likelihood leak.

The proposed work is scoped to additions that fit the existing constraints: read-only, bash 3.2 compatible, no new external dependencies beyond what ships with macOS plus the existing `python3` for JSON parsing, and IDs that follow the `<area>.<subject>.<fact>` grammar.

---

## Section 24 (new) — IDE & untrusted-code sandboxing

**Why a new section.** The single most impactful attack pattern against crypto founders in 2025–2026 has been: recruiter contact on LinkedIn → "please clone this repo and open it in VS Code for a quick technical assessment" → malware executes on folder open via `.vscode/tasks.json`, `package.json` lifecycle scripts, or autorun extensions. Documented victims include Fireblocks' CEO target and the Allsecure CEO writeup (Mar 2026). The defense is `Workspace Trust` (off-by-default execution for untrusted folders), which is a real macOS-level setting in user-scope `settings.json` files. None of the existing 23 sections cover IDE configuration; this is the highest-leverage net-new section.

### `ide.vscode.installed`
- **Severity:** info (not a finding; gates downstream checks)
- **Check:** `/Applications/Visual Studio Code.app` exists OR `~/Library/Application Support/Code` exists
- **Purpose:** allow downstream checks to SKIP cleanly if VS Code is not installed.

### `ide.vscode.workspace_trust.enabled`
- **Default severity:** warn — **`web3` → fail, `developer` → fail**
- **Check:** parse `~/Library/Application Support/Code/User/settings.json` for the key `security.workspace.trust.enabled`. PASS if absent (default is `true`) or `true`. FAIL if explicitly `false`.
- **Implementation note:** VS Code settings.json supports comments (JSONC). Strip `//`-style line comments and trailing commas before feeding to `python3 -c "import json,sys;print(json.load(sys.stdin).get('security.workspace.trust.enabled', True))"`. A 10-line awk preprocessor is sufficient and stays bash 3.2 compatible.
- **Why:** Workspace Trust is the kill-switch for the attack chain. When enabled, opening an untrusted folder disables tasks, debug configs, and most extensions until the user explicitly trusts the folder.
- **Hint:** Settings → search "workspace trust" → ensure all four sub-options are enabled.

### `ide.vscode.workspace_trust.untrusted_files`
- **Default severity:** warn
- **Check:** key `security.workspace.trust.untrustedFiles`. PASS if `prompt` or `newWindow` (default is `prompt`). FAIL if `open`.
- **Why:** controls how single untrusted files (not folders) are handled. `open` bypasses trust prompts entirely.

### `ide.vscode.allow_automatic_tasks`
- **Default severity:** warn — **`web3` → fail**
- **Check:** key `task.allowAutomaticTasks`. PASS if `auto` (default) or `off`. FAIL if `on`.
- **Why:** `on` makes `.vscode/tasks.json` with `"runOptions": { "runOn": "folderOpen" }` execute the moment a folder is opened — the exact mechanism used by several Contagious Interview repos.

### `ide.vscode.trusted_folders.count`
- **Default severity:** info; warn if count > 25
- **Check:** read `~/Library/Application Support/Code/User/globalStorage/state.vscdb` is a sqlite store and is read-only-safe under `sqlite3 -readonly` (matches existing allowlist). Count entries in the workspace trust list, or parse `~/Library/Application Support/Code/User/workspaceStorage/` directory entries as a coarse proxy.
- **Why:** each trusted folder is a bypass of `workspace_trust.enabled`. A long list is an erosion of the defense; many users click "Trust" on every clone.
- **Implementation note:** sqlite read of `state.vscdb` is preferred but the schema is internal and changes; a directory-count proxy is acceptable for a first cut. Mark as "best-effort" in the hint.

### `ide.cursor.installed`, `ide.cursor.workspace_trust.enabled`, `ide.cursor.workspace_trust.untrusted_files`, `ide.cursor.allow_automatic_tasks`
- **Same as VS Code, paths under `~/Library/Application Support/Cursor/User/settings.json`.** Cursor inherits the VS Code settings schema. Same severities, same `web3`/`developer` escalations.
- **Why broken out separately:** Cursor is the dominant IDE for many crypto/AI developers in 2026 and ships with telemetry and AI features off the same trust model. A user who hardened VS Code two years ago and switched to Cursor likely has unhardened defaults.

### `ide.windsurf.installed` / `ide.zed.installed` (info only)
- **Severity:** info
- **Purpose:** future-proofing. If detected and the underlying trust model is known, downstream checks can be added later. For v1, just emit the inventory signal.

### `sandbox.runtime.present`
- **Default severity:** info — **`developer` → warn, `web3` → warn**
- **Check:** any of the following in `/Applications` or on `$PATH`:
  - Docker Desktop / OrbStack / Colima / Lima / Rancher Desktop
  - UTM / Parallels Desktop / VMware Fusion / VirtualBox
  - Tart (Apple Silicon VM)
  - `devcontainer` CLI
- **Why:** the defense for "I received an unsolicited repo to evaluate" is to run it in a disposable environment. The audit cannot enforce *use* of a sandbox, but it can flag the absence of one as a missing capability. Pair this finding with the IDE checks in the report to make the recommendation actionable.
- **Hint:** install OrbStack (lightweight) or UTM (free, Apple Silicon native) and run untrusted clones inside a fresh VM/container.

### `sandbox.devcontainer_default`
- **Severity:** info (advisory)
- **Check:** any global VS Code / Cursor setting steering new clones into devcontainers (e.g., `dev.containers.defaultExtensions`).
- **Purpose:** positive signal; no finding if absent. Useful for the `--diff` workflow when a user adopts this practice.

---

## Section 25 (new) — Messaging & social-engineering surface

**Why a new section.** The audit already catches one social-eng surface (clipboard managers logging seed-phrase pastes). It doesn't catch the most-cited malware-delivery channel of 2024–2026: Telegram Desktop with auto-download enabled. Slack and Discord auto-download are also vectors. This section is intentionally small (4–5 checks) and mostly informational; the value is making the channels visible in the report.

### `messaging.telegram.installed`
- **Severity:** info
- **Check:** `/Applications/Telegram.app` exists OR `~/Library/Group Containers/*ru.keepcoder.Telegram*` exists OR `~/Library/Application Support/Telegram Desktop` exists.

### `messaging.telegram.auto_download.audit`
- **Default severity:** warn — **`paranoid` → fail**
- **Check:** Telegram Desktop stores per-account auto-download settings in a binary file at `~/Library/Application Support/Telegram Desktop/tdata/`. The setting is not in a plist; it's serialized binary. Reading it reliably requires the Telegram source. **Recommended approach for v1:** emit a warn whenever Telegram Desktop is installed, with the hint "Settings → Advanced → Automatic media download → disable for all channel types and disable Auto-Play GIFs/videos from unknown senders." Once a robust parser exists, upgrade to a real read.
- **Why:** every OpSec guide reviewed (OfficerCia, QuillAudits, BTCC, Edouard) specifically names Telegram Desktop auto-download as a malware ingress vector. Files arrive from any chat the user is in (including DMs from impersonators) and are written to disk before the user sees them.

### `messaging.signal.installed`
- **Severity:** info (positive inventory signal)
- **Check:** `/Applications/Signal.app` exists.
- **Purpose:** appears in reports as a soft positive — provides an out-of-band verification channel that doesn't run arbitrary attachments by default.

### `messaging.discord.installed`
- **Severity:** info; **`paranoid` → warn**
- **Check:** `/Applications/Discord.app` exists.
- **Why:** Discord on a developer machine is a known credential-grabbing surface (token theft via local config). Not a fail by default — many devs need it — but a paranoid-profile signal is justified.

### `messaging.slack.desktop.auto_download_indicator`
- **Severity:** info
- **Check:** Slack Desktop settings live under `~/Library/Application Support/Slack/storage/` (LevelDB). Reliable parsing is not bash-friendly. **Recommendation:** skip for v1; document in `docs/AGENTS.md` as a manual review item ("Slack → Preferences → Notifications → review automatic download behavior").

---

## Additions to Section 13 — Supply chain (existing)

### `supply.shell.direnv_present`
- **Default severity:** info — **`developer` → warn**
- **Check:** `direnv` on `$PATH` AND `~/.direnvrc` or `~/.config/direnv/direnvrc` exists.
- **Why:** `direnv` (and `mise`, `asdf` with `auto-bootstrap`) auto-execute `.envrc` files when `cd`-ing into a directory. Cloning a malicious repo and `cd`-ing into it is sufficient to trigger execution even without opening it in an IDE. `direnv` itself prompts on first-allow, but users develop reflexes. The information signal is more important than a hard fail.
- **Hint:** if used, ensure the global `direnv` allow-list is reviewed periodically; never `direnv allow` a fresh clone without inspection.

### `supply.npm.preinstall_hooks_global`
- **Default severity:** info
- **Check:** `npm config get init-module` returns non-default, OR `~/.npm-init.js` exists, OR `~/.npmrc` contains `init-module=` line.
- **Why:** `ignore-scripts=true` (already covered) blocks per-package install scripts. Global init hooks are a separate execution surface.

### `supply.python.pip_config_extra_index`
- **Default severity:** warn
- **Check:** `~/.pip/pip.conf`, `~/.config/pip/pip.conf`, or `$PIP_CONFIG_FILE` contains `extra-index-url` lines pointing outside `pypi.org`.
- **Why:** dependency confusion attacks (where a private package name is squatted on PyPI) require an extra index. Listing them surfaces the trust delegation.

### `supply.uv_or_pixi_present`
- **Default severity:** info (positive)
- **Check:** `uv`, `pixi`, or `rye` on `$PATH`.
- **Purpose:** positive signal for reproducible Python environments. No finding if absent.

---

## Additions to Section 16 — Folder layout & sensitive data (existing)

The existing screenshot-leak-detection pattern (iCloud / Dropbox / Google Drive / OneDrive / Box) is the right architecture; these additions reuse it for other sensitive directories.

### `data.ssh.cloud_sync_exposure`
- **Default severity:** **fail** (no profile escalation needed — this is a hard rule)
- **Check:** resolve real paths for `~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`. For each, check whether the resolved path is inside any cloud-sync root detected earlier in the run (`~/Library/Mobile Documents/com~apple~CloudDocs`, `~/Dropbox`, `~/Google Drive`, `~/OneDrive`, `~/Library/CloudStorage/*`).
- **Why:** `~/.ssh` inside iCloud Drive uploads every SSH private key to Apple infrastructure. This is recoverable by anyone with the iCloud password (even if FileVault is on locally). Same applies to `~/.aws/credentials` and `~/.kube/config`. The screenshot-leak detection logic generalizes directly.
- **Hint:** move the directory out of the synced tree; use a real path under `$HOME` and either a symlink that excludes the target from sync, or pure local storage.

### `data.crypto.cloud_sync_exposure`
- **Default severity:** warn — **`web3` → fail**
- **Check:** same pattern as above, against:
  - `~/Library/Application Support/Ledger Live`
  - `~/Library/Application Support/Trezor Suite`
  - `~/Library/Ethereum`
  - `~/.ethereum`
  - `~/Library/Application Support/Electrum`
  - `~/Library/Application Support/Sparrow`
  - `~/Library/Application Support/Bitcoin`
- **Why:** wallet metadata, watch-only descriptors, and (for some wallets) encrypted seed material end up in these directories. Cloud-syncing them is a partial-key-exposure incident waiting to happen.

### `data.dotfiles.cloud_sync_exposure`
- **Default severity:** warn
- **Check:** as above, against `~/.gitconfig`, `~/.zshrc`, `~/.bashrc`, `~/.zprofile`, `~/.profile`, `~/.netrc`, `~/.pypirc`, `~/.npmrc`, `~/.cargo/credentials`, `~/.gem/credentials`.
- **Why:** complements existing credential pattern detection in Section 14 by covering the *location* axis: even unscanned secret strings leak when these files are in a cloud-sync root.

---

## Additions to Section 18 — Backups (existing)

### `backup.timemachine.encrypted`
- **Default severity:** warn — **`paranoid` → fail**
- **Check:** `tmutil destinationinfo 2>/dev/null` returns key/value blocks; PASS if every destination shows `Encrypted = 1`. FAIL if any destination shows `Encrypted = 0`. SKIP if no destinations configured (already handled by existing recency check).
- **Why:** an unencrypted Time Machine backup is a full-disk image readable by anyone who steals the backup drive. It defeats FileVault entirely. The existing "TM destinations + recency" check tells the user backups exist; it does not tell them whether the backups themselves are protected.
- **Hint:** System Settings → General → Time Machine → select disk → "Encrypt Backup."

### `backup.timemachine.local_snapshots_present`
- **Default severity:** info
- **Check:** `tmutil listlocalsnapshots / 2>/dev/null | wc -l` non-zero.
- **Why:** APFS local snapshots are an under-appreciated recovery resource (and an under-appreciated forensic resource for an attacker with disk access). Surfaces the inventory.

### `backup.cloud.bitlocker_or_b2_indicator`
- **Default severity:** info
- **Check:** detect Arq, Restic, Kopia, Borgmatic, or rclone with `--crypt` flag in launchd plists.
- **Why:** positive signal for encrypted off-site backup beyond Backblaze (already checked) and CCC.

---

## Additions to Section 19 — iCloud (existing)

### `cloud.icloud.desktop_documents_sync`
- **Default severity:** warn — **`web3` → fail, `paranoid` → fail**
- **Check:** best-effort heuristic — examine `~/Library/Mobile Documents/com~apple~CloudDocs/Desktop` and `.../Documents` for existence and recent files (last 7d).
- **Why:** users who enable "Desktop & Documents in iCloud Drive" frequently keep ephemeral notes, scratch files, exported wallet JSONs, and recovery-phrase TXTs on the Desktop. Uploading these to iCloud Drive defeats most local hardening. Distinct from the existing iCloud sign-in check, which only confirms the account is configured.
- **Hint:** System Settings → Apple ID → iCloud → iCloud Drive → "Desktop & Documents Folders" → off, OR move sensitive files out of Desktop/Documents.

---

## Additions to Section 09 — Browser extensions (existing)

The existing wallet-extension and transaction-simulator detection is strong. These additions target *isolation* posture.

### `browser.profiles.<brand>.count`
- **Templated ID** — register pattern in `tests/fixtures/expected_id_patterns.txt`.
- **Default severity:** info; warn if `count == 1` AND a wallet extension is detected in that browser
- **Check:** count subdirectories in `~/Library/Application Support/<browser>/` matching the profile-directory convention (Chrome: `Default`, `Profile 1`, `Profile 2`, ...; Brave: same; Firefox: `Profiles/*.default*`).
- **Why:** Sherlock's 2026 OpSec piece treats the browser frontend as a financial-grade trust boundary. Profile separation is the cheapest form of isolation: a "wallet profile" with only the wallet extension and bookmarked dApps, and a "daily" profile for everything else. Detecting a single-profile setup with a wallet installed flags the riskiest configuration.

### `browser.<brand>.version_currency`
- **Default severity:** warn if more than 30 days behind a known-good version
- **Check:** read the bundle's `CFBundleShortVersionString` from `/Applications/<browser>.app/Contents/Info.plist`. Compare against a constant in the script body (updated per release).
- **Why:** browser auto-update is on by default but breaks on machines that haven't restarted the browser in weeks (common with people who restore session tabs). Drive-by exploits target unpatched browser versions; the lag between patch and update install is the entire window of exposure.
- **Implementation note:** the constant list of "current-as-of-release" versions is the maintenance cost. Mark this clearly in `CHANGELOG.md` so each release explicitly records the version baseline.

### `browser.<brand>.extension_count`
- **Default severity:** info; warn if `> 20`
- **Check:** count detected extensions per browser.
- **Why:** every extension is an execution surface. The supply-chain articles (GlassWorm targeted 400+ VS Code extensions; npm extension equivalents exist) make extension inventory size a meaningful posture signal.

---

## Additions to Section 11 — Password manager & 2FA hardware (existing)

### `auth.passkeys.icloud_keychain_count`
- **Default severity:** info (positive signal)
- **Check:** `security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null | grep -c 'class.*pass'` — best-effort, the precise class is implementation-defined and changes across macOS releases. Alternative: count Apple-Passkey entries via `security find-generic-password` with appropriate filters.
- **Why:** WebAuthn / passkey adoption is the strongest phishing-resistant defense available. Presence of any passkey is a positive posture signal; absence is silent (not a finding). Surfaces capability.
- **Implementation note:** if reliable extraction proves too brittle, fall back to a binary "any passkey-related Keychain entry exists" check.

### `auth.yubikey.touch_required_policy_indicator`
- **Default severity:** info
- **Check:** if YubiKey detected (already covered), additionally check for `ykman` on `$PATH` and presence of `~/.config/Yubico` — soft signal that the user has configured PIV/PGP slots and likely set touch-required.
- **Why:** a YubiKey with no touch requirement on PIV/PGP slots is a much weaker defense (malware can still sign with a plugged-in key). Cannot directly verify the touch policy without writing to the device (read-only constraint), but presence of `ykman` is a strong proxy that the user has gone beyond plug-and-play.

---

## Additions to Section 20 — User accounts & sudo (existing)

### `users.crypto_isolation_indicator`
- **Default severity:** info — **`web3` → warn, `paranoid` → fail**
- **Check:** evaluate jointly:
  - exactly one human user account exists (`dscl . list /Users | grep -vE '^_|daemon|nobody|root' | wc -l == 1`)
  - that user is an admin
  - a wallet extension or HW wallet app was detected elsewhere in the run
- **Why:** every personal-OpSec guide reviewed (Edouard, Lopp, Three Sigma, OfficerCia) recommends running daily-driver activities (browsing, mail, Telegram, Slack) as a non-admin user, distinct from the admin account used for crypto operations. Detecting the single-admin-with-wallet pattern flags the highest-risk configuration explicitly.
- **Hint:** create a non-admin "daily" user; reserve the admin account for installing software and managing crypto wallets.

---

## Additions to Section 07 — DNS & outbound (existing)

### `network.wifi.known_networks_count`
- **Default severity:** info; warn if `> 50`
- **Check:** count entries in `/Library/Preferences/com.apple.wifi.known-networks.plist` (Sequoia+) or `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` (older). The former is root-readable only; the check is `sudo`-gated and SKIPs cleanly without elevation.
- **Why:** BTCC and OfficerCia OpSec guides specifically call out public Wi-Fi for crypto activity. A large known-network list correlates with promiscuous auto-join behavior. Not a fail by itself — users travel — but a signal worth surfacing.

### `network.vpn.killswitch_indicator.<brand>`
- **Templated ID per detected VPN client**
- **Default severity:** warn if VPN client detected but no kill-switch indicator
- **Check, best-effort per brand:**
  - **Mullvad:** `~/Library/Application Support/Mullvad VPN/settings.json` — key `block_when_disconnected: true`
  - **ProtonVPN:** killswitch state in `~/Library/Application Support/ProtonVPN/`
  - **WireGuard:** no built-in kill switch — if WireGuard is the *only* VPN client detected, emit warn with hint to layer a firewall-based kill switch (e.g., PF rules)
- **Why:** a VPN without a kill switch leaks the real IP every time the tunnel drops, which on macOS happens routinely on network transitions (Wi-Fi → cellular hotspot, sleep/wake). For pseudonymous on-chain identity this is fatal to the threat model.

---

## Additions to Section 04 — System integrity & related (or new bucket "Endpoint hygiene")

### `apps.gaming_clients.present`
- **Default severity:** info — **`paranoid` → warn**
- **Check:** detect any of `/Applications/Steam.app`, `/Applications/Epic Games Launcher.app`, `/Applications/Battle.net.app`, `/Applications/Riot Client.app`, `/Applications/EA app.app` in `/Applications`.
- **Why:** OfficerCia's guide cites the Dota 2 V8 exploit as historical precedent. Gaming clients run with broad permissions, frequently auto-update, and have a strong history of RCE-grade bugs delivered through game content. They are also a vector for browser-extension impersonators (fake Steam phishing). On a dedicated crypto/development machine, their presence is a posture signal.
- **Hint:** consider moving gaming to a separate machine or user account.

### `apps.remote_access.present`
- **Default severity:** warn — **`paranoid` → fail**
- **Check:** detect AnyDesk, TeamViewer, Splashtop, Chrome Remote Desktop helpers, RealVNC, Jump Desktop Connect in `/Applications` or as launchd items.
- **Why:** crypto founders are specifically socially-engineered into installing remote-access tools (fake "support agent" calls). Persistent presence of these tools — not just one-off use — is a documented compromise vector. The existing Section 04 covers Remote Login (SSH) and Sharing services; this complements with third-party tools that don't show up in the same surface.
- **Hint:** if not in active use, uninstall. If in active use, ensure unattended-access passwords are disabled.

---

## Fixes / refinements to existing checks

A small set of refinements to existing logic, identified while drafting the above:

### Refine `network.wifi.known_networks` access pattern
The Sequoia-era known-networks plist requires root. If the script is already running without sudo, the check should SKIP rather than emit a misleading warn. Current behavior is unknown from the README; verify and align with the rest of the audit's sudo-gating pattern.

### Generalize cloud-sync detection helper
The existing screenshot-leak detection has cloud-sync root identification logic. The proposed `data.ssh.cloud_sync_exposure`, `data.crypto.cloud_sync_exposure`, and `data.dotfiles.cloud_sync_exposure` checks should reuse it as a shared bash function rather than duplicating regexes. Suggest extracting `_msa_resolve_cloud_root()` and `_msa_path_in_cloud_root()` helpers near the top of the script.

### Document `--profile web3` baseline assumption
The README's profile table is clear, but a brief paragraph in `docs/` describing what threat model `web3` assumes (active on-chain operator, wallet on the machine, social-eng risk from impersonators) would let users self-select correctly. The additions above lean heavily on `web3` escalation; defining the profile crisply makes that defensible.

### Add `--profile founder` (optional)
The crypto-founder profile combines `web3` with the social-engineering checks added here. Could be:
- everything in `web3`
- `ide.vscode.workspace_trust.enabled` → fail
- `ide.cursor.workspace_trust.enabled` → fail
- `users.crypto_isolation_indicator` → warn
- `apps.remote_access.present` → fail
- `messaging.telegram.auto_download.audit` → warn
- `browser.profiles.<brand>.count` (single profile + wallet) → fail

Optional; `web3` already covers most of this if the escalations above are accepted.

---

## Implementation constraints reminder

- **Bash 3.2 only.** No associative arrays, no `mapfile`, no `[[ -v ]]`, no `${var,,}`. The existing codebase already navigates this; new checks must follow.
- **Read-only.** Every plist read uses `defaults read` or `plutil -p` in read-only mode. Every sqlite read uses `sqlite3 -readonly` (matches the existing allowlist). No new external HTTP calls — the version-currency check uses a constant baked into the script at release time.
- **JSONC parsing for VS Code/Cursor settings.** A small awk preprocessor to strip line comments (`//...$`) and trailing commas before `python3 -c "import json,sys; ..."`. Test fixtures must include both pure-JSON and JSONC-with-comments cases.
- **Sudo gating.** IDE settings.json reads are user-scope, no sudo needed. Known-networks plist needs sudo. Wallet-app directory reads are user-scope.
- **Test fixtures.** For each new check, register the ID in `tests/fixtures/expected_ids.txt` (or `expected_id_patterns.txt` for templated IDs), and add at minimum one positive and one negative fixture under `tests/sections/`.

---

## Suggested PR sequence

Ordered by leverage-per-line-of-code, with each PR independently mergeable:

1. **PR 1 — Section 24: IDE & untrusted-code sandboxing.** Self-contained new section. Largest single security gain (defeats the dominant attack chain against crypto founders). Touches the script, two new test fixture files, README section list, expected_ids.txt.
2. **PR 2 — Section 16 extensions: cloud-sync exposure for `~/.ssh`, wallet dirs, dotfiles.** Reuses existing cloud-root detection logic; small surface area; high impact.
3. **PR 3 — Section 18 extension: `backup.timemachine.encrypted`.** Single-line addition once the existing TM block is located. Should ship with PR 2.
4. **PR 4 — Section 25: Messaging & social-engineering surface.** New section, mostly inventory signals; Telegram auto-download check is best-effort warn-when-installed for v1.
5. **PR 5 — Section 09 extensions: browser profile count, version currency, extension count.** Touches the largest existing section; needs careful test fixture work for each browser.
6. **PR 6 — Section 07 extension: VPN kill switch indicator + known-networks count.** Brand-specific best-effort logic; isolate behind feature flags so adding new brands doesn't break old fixtures.
7. **PR 7 — Section 20 extension: `users.crypto_isolation_indicator`.** Cross-section check (needs results from wallet detection); cleanest if implemented after the wallet section is otherwise stable.
8. **PR 8 — Apps hygiene: gaming clients, remote-access tools.** Soft signals; can ship anytime; useful as a "quick win" PR after the structural work above.
9. **PR 9 — `--profile founder` (optional).** Pure config; ships after the underlying checks land.

---

## Appendix — Profile escalation matrix for proposed additions

Default severities and per-profile overrides for new checks, in the format the existing `PROFILE_OVERRIDES` table uses (`profile|id|from_status|to_status`):

```
web3|ide.vscode.workspace_trust.enabled|warn|fail
web3|ide.cursor.workspace_trust.enabled|warn|fail
web3|ide.vscode.allow_automatic_tasks|warn|fail
web3|data.crypto.cloud_sync_exposure|warn|fail
web3|users.crypto_isolation_indicator|info|warn
web3|cloud.icloud.desktop_documents_sync|warn|fail

developer|ide.vscode.workspace_trust.enabled|warn|fail
developer|ide.cursor.workspace_trust.enabled|warn|fail
developer|sandbox.runtime.present|info|warn
developer|supply.shell.direnv_present|info|warn

paranoid|messaging.telegram.auto_download.audit|warn|fail
paranoid|messaging.discord.installed|info|warn
paranoid|backup.timemachine.encrypted|warn|fail
paranoid|users.crypto_isolation_indicator|info|fail
paranoid|apps.gaming_clients.present|info|warn
paranoid|apps.remote_access.present|warn|fail
paranoid|cloud.icloud.desktop_documents_sync|warn|fail
```

These are recommended starting values, not commitments. The PR for each section is the right place to bikeshed the exact severities against the existing audit's calibration.
