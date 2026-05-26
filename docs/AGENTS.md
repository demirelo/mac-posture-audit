# AI agent review guide

This document is written **for an AI coding agent or LLM** that has been pointed at this repository (or just at a `--json` output from the audit) and asked to review a Mac's security posture. It explains the audit's design intent, what each row is and is not, and where to find the high-signal composite patterns that no individual row will tell you about on its own.

The script that produces the data is deliberately *under-opinionated*. It emits raw, stable signals and leaves the synthesis to whoever reads the report. That "whoever" is increasingly an LLM. This file is the user manual for that LLM.

## TL;DR for an agent

1. Run `mac-posture-audit.sh --json --quick --redact > posture.json` (or read a saved file). Schema: [`schema.md`](schema.md).
2. Identify the user's threat model from context (their work, their tools, their stated concerns). If unknown, ask one clarifying question rather than assume.
3. Walk the rows by `id`. Hard `fail` rows are unconditional — surface them first.
4. Look for the **composite patterns** in §3 below. These are places where the audit is intentionally split across multiple rows because the meaning depends on combinations the script can't safely opinionate on.
5. Frame your output around what *this user* should do, not what's generically recommended. Cite specific row IDs in your reasoning so the user can verify.

## 1. The audit's posture

The script is deliberate about three things:

- **Read-only.** Every check is a probe. There's a CI tripwire that fails if a mutating command sneaks into the source. The narrow allowlists (sqlite3 `-readonly`, `osascript ... to get`, bare `brew tap`, NextDNS curl, `gh auth status`) are tested on every commit.
- **Stable IDs over labels.** Treat `id` as the stable contract. Labels and hints will be reworded between versions; IDs won't.
- **Status semantics.** `pass` = a measurable security control is in the desired state. `fail` = a hard control is in the *wrong* state (FileVault off, plaintext PAT in shell rc, Internet Sharing on, NOPASSWD sudoers, world-readable AWS credentials). `warn` = a recommendation that a typical user would benefit from. `skip` = informational, or "couldn't determine without more privilege/network." Profiles can rewrite a status (`warn → fail` for `web3` on `ext.wallet`) but never lower a `fail`.

What the audit deliberately does NOT do:

- It does not aggregate. There is no overall "score." Rows are independent.
- It does not encode strong opinions about debatable choices. Lockdown Mode for non-targeted users, single-vs-multi-user for crypto, native macOS Keychain vs 1Password — the audit either marks these as informational SKIPs or hedges in the hint.
- It does not phone home. Default mode never makes a network call. `--network` adds exactly one allowlisted probe.

That last bullet is why this guide exists. The audit gives you the raw observations; you're responsible for the contextual recommendation.

## 2. The threat-model lenses

Pick the lens that fits the user before reading the rows. The same `warn` row can be ignorable on one machine and a P0 on another.

**Casual home user.** Cares about: device theft, malware drive-bys, family photo loss. Doesn't care about: wallet exposure, journalist-grade threat actors. Prioritise FileVault, screen lock, software updates, backups, AV. De-prioritise SSH agents, Lockdown Mode, hardware wallets.

**Developer (no crypto).** Cares about: supply-chain attacks (npm/pypi/go modules), credential leakage from shell rcs, machine compromise that grants access to private repos. Prioritise `cred.*`, `supply.*`, `git.signing.*`, `ssh.*`, `persist.*`. The bare presence of saved tokens is a higher concern than for a casual user.

**Web3 / wallet user.** All of "Developer" PLUS: wallet isolation, transaction simulators, hardware wallet, browser blast-radius separation, FIDO2 hardware key. Every `ext.wallet` row matters. Profile this user as `--profile web3` and surface escalations.

**Solo founder shipping crypto-adjacent code.** Lives in both threat models simultaneously: writes / merges code (dependency confusion, malicious `postinstall`, unencrypted SSH keys, IDE workspace trust) AND custodies crypto (wallet exposure, remote-access apps, cloud-sync exfil of seed material). Profile as `--profile founder` — explicit union of `developer` and `web3` escalations.

**Journalist / activist / dissident.** Threat model includes nation-state spyware. Lockdown Mode flips from "skip" to "should be ON." Bluetooth, AirDrop, MDM, telemetry, unfamiliar profiles all become concerns. Profile as `--profile journalist` (v1.5 — surfaces Lockdown-off and hardens the surveillance surface: RF, telemetry, remote access, browser debugging, VPN killswitch, stale software). `--profile paranoid` remains the broader lock-everything-down option.

**Shared / family Mac.** Multiple human users, mixed trust. Service accounts in admin group, sharing services, AirDrop mode all matter more.

If the user's lens is unclear, ask **one** specific question (e.g., "Do you hold meaningful crypto on this Mac, or is this primarily a development workstation?") before anything else.

## 3. Composite patterns

These are pairs/triples of rows that are individually low-signal or `skip`/`warn`, but together indicate something the user should know.

**Six of these are now first-class check IDs in the audit itself.** They aggregate the constituent rows and emit a single posture verdict so the user can't miss the combined signal. The remaining ones live here as guidance for an AI reviewer that wants to do additional synthesis (e.g. cross-reference user context the audit can't have).

| § | Pattern | Composite check ID | Status |
|---|---|---|---|
| 3.1 | Encrypted-DNS gap | `network.dns.encrypted` | ✅ baked in |
| 3.2 | Backup desert | `backup.recovery_path` | ✅ baked in |
| 3.3 | Wallet exposure on main user | `users.crypto_isolation_indicator` | ✅ baked in |
| 3.4 | Plaintext disk on theft | `system.theft_resistance` | ✅ baked in |
| 3.5 | SSH risk surface | `ssh.posture` | ✅ baked in |
| 3.6 | Supply-chain composite | `supply.posture` | ✅ baked in |
| 3.7 | Persistence sprawl | — | agent-only (count parsing is brittle) |
| 3.8 | Identity confusion | — | agent-only (needs external context) |
| 3.9 | Two AVs running | `av.engine.conflict` | ✅ baked in (existing) |
| 3.10 | FIDO2 gap with hardware wallet present | `twofa.fido_gap` | ✅ baked in |
| 3.11 | iCloud blast radius | `cloud.icloud.desktop_documents_sync` + `data.*.cloud_sync_exposure` | ✅ baked in (per-check) |
| 3.12 | Remote-access crypto-theft surface | `apps.remote_access.present` + `tcc.holders` + `ext.wallet` | ✅ baked in (per-check) |
| 3.13 | Cloud-sync exfiltration | `data.ssh.cloud_sync_exposure` + `data.crypto.cloud_sync_exposure` + `data.dotfiles.cloud_sync_exposure` | ✅ baked in (per-domain) |
| 3.14 | IDE malicious-repo auto-run | `ide.{vscode,cursor}.workspace_trust` + `ide.{vscode,cursor}.automatic_tasks` | ✅ baked in (per-IDE) |
| 3.15 | Fake-interview attack chain | `chain.fake_interview` | ✅ baked in (v1.3) |
| 3.16 | Wallet-drain attack chain | `chain.wallet_drain` | ✅ baked in (v1.3) |
| 3.17 | Agent-exposure attack chain | `chain.agent_exposure` | ✅ baked in (v1.3) |
| 3.18b | Cloud-exfil attack chain | `chain.cloud_exfil` | ✅ baked in (v1.5) |

### 3.0 VPN killswitch posture → `network.vpn.killswitch`

Not a composite — included here because it's the second VPN-related row and pairs naturally with `network.vpn.running` for any answer about the user's VPN setup. Verifies (where the brand exposes a parseable settings file) that the killswitch / always-on / "block when disconnected" toggle is on. A VPN without a killswitch leaks the user's real IP every time the tunnel briefly drops — defeats most of the reason a privacy-conscious user pays for the service.

Per-brand support today: **Mullvad** is verifiable (`settings.json` key `block_when_disconnected`); ProtonVPN and NordVPN settings are in binary plists / sqlite, so the check emits a per-brand advisory pointing to the in-app toggle. When surfacing this to a user with a verifiable brand, treat the `warn` (killswitch off) as actionable. When it's advisory-only, frame as "please verify in the app" — don't tell the user they have a gap if we couldn't confirm.

### 3.1 Encrypted-DNS gap → `network.dns.encrypted`

Combines DoH/DoT live state, NextDNS profile, other DoH/DoT profiles, and VPN state. Pass = encrypted DNS active or configured. Skip-with-caveat = VPN up, plaintext-when-off. Warn = plaintext to ISP.

### 3.2 Backup desert → `backup.recovery_path`

Combines `backup.tm.destination` + `backup.tm.recency` + `backup.offsite` + iCloud Drive presence. Stale TM (>7d) doesn't count as a source.

Related individual check: **`backup.tm.encrypted`** answers a different question — *is the existing TM destination encrypted at rest?* An unencrypted TM drive is a full-disk image readable by anyone who walks off with the drive, so it silently defeats FileVault for the backup data. Default `warn`; `--profile paranoid` escalates to `fail`. Skips when no destination is configured (covered by `backup.recovery_path`) or when the running `tmutil` is old enough that it doesn't expose the `Encrypted` field. When surfacing the backup story to a user, treat `backup.recovery_path` (do they *have* a backup) and `backup.tm.encrypted` (is the backup *itself* safe) as a paired narrative.

iCloud Drive is treated as a *partial* source — it covers `~/Documents` + `~/Desktop` (only if the user opted into "Desktop & Documents Folders"), Photos, and iCloud-aware app data. It does NOT cover `/Applications`, `~/Dev`, brew installs, system state, or anything outside iCloud-aware containers. Deletes propagate (no ransomware resilience). Versioning is ≤30 days. End-to-end encryption requires Advanced Data Protection turned on.

- Pass = TM + offsite both present, or one full source paired with iCloud Drive.
- Warn = single full source (TM or offsite) — second source recommended.
- Warn = iCloud Drive only — *partial* recovery; hint explicitly enumerates what's not covered and the ADP requirement.
- **Fail = no source at all — disk loss is unrecoverable**, with a hint that iCloud Drive alone is not a backup.

Note: "iCloud Backup" (the iPhone feature) does not apply to Macs. iCloud Drive sync is the relevant signal.

### 3.3 Wallet exposure on main user → `users.crypto_isolation_indicator`

Combines `ext.wallet` (post-profile) + `user.human.count` + `browser.default`. Fires only when wallet extensions are present. Two isolation indicators are checked:

1. **Multiple human user accounts** (`user.human.count = pass`) — the user can create a dedicated macOS user for wallet operations, accessed only when signing.
2. **Default browser is at the recommended baseline** (`browser.default = pass`) — implying random-link browsing happens in a browser separate from the one holding the wallet.

`pass` = both indicators healthy. `warn` = one or two missing, label enumerates which. `skip` = no wallet detected (composite N/A). Under `--profile web3` / `paranoid`, the `warn` is escalated to `fail` via `PROFILE_OVERRIDES` — same pattern as `ssh.posture` and `supply.posture`.

The composite deliberately does NOT roll in the FIDO2 gap (that's its own `twofa.fido_gap` row, §3.10), nor the broader cloud-sync exposures (§3.13), nor `apps.remote_access.present` (§3.12). Each composite is tightly scoped so an LLM reviewer can pair them as needed.

### 3.4 Plaintext disk on theft → `system.theft_resistance`

Combines `system.filevault.on` + `login.lock.immediate` + `login.window.namepw`. FV alone is meaningless against a thief grabbing a sleeping/unlocked Mac (key in memory). Pass = all three locked down. Warn = FV on but lock or window posture loose. Skip = FV off (the FileVault failure itself is more important and lives in §1).

### 3.5 SSH risk surface → `ssh.posture`

Combines key state (encrypted / unencrypted / none) with external-agent state (1Password / Secretive). Pass = no keys, OR encrypted keys + agent. Warn = encrypted keys without agent (passphrase-fatigue), OR unencrypted keys *with* agent (agent helps but keys still on disk). **Fail = unencrypted keys with no external agent.**

### 3.6 Supply-chain composite → `supply.posture`

Combines `supply.{npm,yarn,pnpm}.ignorescripts` + `supply.scanner`. Pass = scripts disabled across managers and scanner present. Warn = partial coverage. **Fail = ≥2 managers running scripts AND no scanner**, since one malicious `postinstall` lands.

### 3.7 Persistence sprawl — agent-only

If many user LaunchAgents AND service accounts in admin, the persistence surface is unusually broad. The audit emits `persist.user.launchagents` (warn if any) and `user.admin.svcaccts` (warn if any) separately; combining them into a numeric threshold is brittle (parsing counts out of label text), so it's left to AI-side synthesis. Recommend: list `~/Library/LaunchAgents/` and demote any `_*` / `sys_*` user out of admin.

### 3.8 Identity confusion — agent-only

If `git.email.set` shows an email that's not among the user's known vault items / `gh auth` accounts, the user might be committing under the wrong identity. Surface gently — this is more often a per-repo override the user set deliberately than a misconfiguration.

### 3.9 Two AVs running → `av.engine.conflict`

Already an explicit row. Two real-time engines fight over hooks and miss things. Recommend picking one for real-time and demoting the other to scheduled scans.

### 3.10 FIDO2 gap with hardware wallet present → `twofa.fido_gap`

Combines `wallet.hw.installed` + `twofa.hardware.installed`. If the user has Ledger / Trezor but no YubiKey, the same hardware wallet usually ships a FIDO2 companion app — free upgrade for account 2FA on 1Password / GitHub / exchanges. Skip-with-nudge.

### 3.11 iCloud blast radius → `cloud.icloud.desktop_documents_sync` + `data.*.cloud_sync_exposure`

`cloud.icloud.desktop_documents_sync` detects Apple's "Desktop & Documents Folders" feature, which silently redirects `~/Desktop` and `~/Documents` into `~/Library/Mobile Documents/com~apple~CloudDocs/`. Anything the user saves to Desktop or Documents is then uploaded to iCloud and replicated to every signed-in device. Without Advanced Data Protection on, Apple holds the keys.

When this fires alongside any of the `data.*.cloud_sync_exposure` checks, do not treat them as separate findings. The composite story is: the user's home directory has effectively been turned into an iCloud-synced volume, and sensitive subdirectories underneath inherit that exposure. Surface as a single recommendation: turn the feature off, or (if the user wants it on for low-sensitivity work) move sensitive subdirs out of `~/Documents` and `~/Desktop` first.

### 3.12 Remote-access crypto-theft surface → `apps.remote_access.present` + TCC sensitive holders + `ext.wallet`

`apps.remote_access.present` is the ClickFake / "fake interview" pattern's first move: attacker tricks the target into installing AnyDesk / TeamViewer "for a screen-share interview," gets them to grant Accessibility + Screen Recording, then drains wallets via the browser extension. The audit reports the three components as separate rows:

- `apps.remote_access.present` (warn / fail under `web3` + `paranoid`) — is the tool installed at all?
- `tcc.holders` (skip with sensitive-service breakdown) — have any clients been granted Accessibility / Screen Recording?
- `ext.wallet` (warn / fail under `web3` + `paranoid`) — is there a wallet extension on the same machine?

When all three fire together, the user has the exact configuration the attack relies on. Recommend: uninstall the remote-access app, revoke its TCC grants explicitly (System Settings → Privacy & Security → Accessibility + Screen Recording), then audit `ext.wallet` for any extension you didn't install yourself in the last 24 hours.

### 3.13 Cloud-sync exfiltration → `data.ssh.cloud_sync_exposure` + `data.crypto.cloud_sync_exposure` + `data.dotfiles.cloud_sync_exposure`

iCloud Drive, Dropbox, Google Drive, OneDrive, and Box all silently replicate whatever lives under their root to every other device on the same account — and to the provider's servers. When a sensitive directory ends up under one of those roots (because the user moved their home, symlinked `~/.ssh`, or enabled "Desktop & Documents Folders" in iCloud), the threat model collapses: a compromise of any *other* signed-in device or of the provider's storage leaks the secret.

The script splits this pattern across three IDs by sensitivity domain:

- **`data.ssh.cloud_sync_exposure`** — `.ssh`, `.aws`, `.kube`, `.gnupg` under a cloud root. Hard `fail` in every profile. Private keys, cloud admin creds, kubeconfigs, GPG private keyrings. There is no scenario where these belong in cloud sync.
- **`data.crypto.cloud_sync_exposure`** — wallet app data directories (Ledger Live, Trezor Suite, Electrum, Sparrow, Bitcoin Core, `~/Library/Ethereum`, `~/.ethereum`) under a cloud root. Default `warn`; `--profile web3` and `--profile paranoid` escalate to `fail`. The wallet app's data dir can hold encrypted seed material; replicating that to a less-trusted device weakens the hardware boundary.
- **`data.dotfiles.cloud_sync_exposure`** — common dotfiles (`.zshrc`, `.bashrc`, `.profile`, `.gitconfig`, `.npmrc`, `.netrc`) under a cloud root. Default `warn`. These don't always contain secrets, but `.npmrc` and `.netrc` frequently do, and `.gitconfig` leaks the user's commit identity. The audit can't safely read these files to confirm; surface as "review before assuming this is fine."

Detection uses `cd "$d" && pwd -P` (or `dirname` + `pwd -P` + basename for files) so symlinks resolve to their real on-disk path before matching the cloud-root patterns in `_path_in_cloud_root`. A real example caught in the wild: `~/.ssh` symlinked into `~/Library/Mobile Documents/com~apple~CloudDocs/dotfiles/.ssh` so the user could "share dotfiles across machines" — every key sitting in Apple's storage and on every other Mac signed into the same Apple ID.

When all three fire on the same Mac, do not list them as three separate problems. Surface as: "Your home directory is layered over a cloud-sync root. Move it back, or move the sensitive subdirectories out, before doing anything else."

### 3.14 IDE malicious-repo auto-run → `ide.vscode.workspace_trust` + `ide.cursor.workspace_trust`

VS Code shipped Workspace Trust in 1.57 (2021) as the in-editor defence against the most common "open malicious repo → tasks.json autoruns" attack chain. Cursor inherits the same machinery. With trust enabled (the default), opening an untrusted folder:

- Disables `tasks.json` auto-run on folder open.
- Disables language servers and extensions that opted in to restricted mode.
- Disables debugger configurations.
- Shows a prompt before letting any of the above run.

Three known-bad opt-outs land the user back in the pre-1.57 unsafe world:

- `security.workspace.trust.enabled: false` — hard `fail`. Every cloned repo can immediately execute code on open. The most common attack chain for a developer wallet user is: target receives a "code review for a job interview" link, clones the repo, the IDE auto-runs a `tasks.json` step that exfiltrates `~/.ssh/`, `~/.aws/`, or browser cookies for wallet sessions.
- `security.workspace.trust.untrustedFiles: "open"` — `warn`. Dropped files open without the trust prompt.
- `security.workspace.trust.startupPrompt: "never"` — `warn`. Suppresses the on-startup decision moment so the user becomes less aware of the model.

The check uses `grep`, not a JSONC parser. VS Code's settings.json is JSONC (JSON with comments and trailing commas); shelling out to a parser would be a portability headache for what's essentially a string-match on three well-known keys. The documented trade-off: a setting buried inside a `//`-comment block, or split awkwardly across multiple lines with the value on its own line, can be missed. The check prefers false negatives ("looks OK") over false positives.

Cross-reference: if `users.crypto_isolation_indicator` is also firing (§3.3) and `apps.remote_access.present` is on (§3.12), the IDE trust posture should be the next thing surfaced — these three together describe the full "fake interview" attack chain: tools to phish the user, no workflow isolation to contain damage, and the IDE itself acting as the payload's runtime.

### 3.15–3.17 Named attack chains (v1.3) → `chain.*`

v1.3 promotes three of the prose chains above into first-class rows that fire **only when the full path is assembled**. Each is `warn` by default and `fail` under `web3`/`founder`; all are high-blast (so even a `warn` ranks `high` in the decision layer, a `fail` ranks `urgent`). They are deliberately mechanical — when the chain is incomplete they emit an informational `skip`, not noise.

- **`chain.fake_interview`** — (`ide.*.workspace_trust` loose OR `ide.*.automatic_tasks` on) AND no sandbox runtime available. The §3.14 + §3.12 story as one row. Remote-access apps are an amplifier you can layer on, not part of the row's logic. Note the sandbox signal is read from detection state, not `sandbox.runtime.present`'s status (which is always `skip`).
- **`chain.wallet_drain`** — `ext.wallet` present AND `users.crypto_isolation_indicator` is `warn`/`fail` AND `network.outboundmonitor.running` ≠ `pass`. Funds movable, exfiltration unflagged.
- **`chain.agent_exposure`** — MCP present with `mcp.servers.filesystem_capable` or `mcp.servers.remote_http` AND `ext.wallet` present. An agent with file/network reach on the same machine as a wallet.

When a `chain.*` fires, lead with it: it already names the combination, so you don't have to reconstruct it from constituents. Layer your own context (is the user actively job-hunting? is the MCP server one they installed?) on top.

### 3.18 The in-tool decision layer (v1.3)

The audit now emits a profile-aware **`executive_verdict`** and a ranked **`top_risks`** array (JSON), and an "Executive Verdict" + "Top risks to address" block (text). This is a *light* prioritization layer — it ranks by action priority (`urgent`/`high`/`medium`/`low`) so the highest-leverage findings surface first. Treat it as a starting point, not the final word: it deliberately does **not** encode the deep, user-specific "why this matters for YOU" synthesis — that's still your job, using this guide. The verdict stays calm when `fail == 0` (a clean baseline with concentrated risk reads as `Action priority: high`, never "compromised").

## 4. Things that are NOT issues

The audit emits a lot of rows that look concerning until you understand the context. Don't surface these as gaps:

- `privacy.lockdown.on: skip` — Lockdown Mode is intentionally off for typical users. Apple's recommendation. Only flag if the user fits the journalist/activist/dissident lens.
- `network.bluetooth.off: warn` (`paranoid` profile only) — Bluetooth being on for AirPods is fine for almost everyone. Don't recommend disabling unless threat model warrants.
- `cred.gitleaks.hint: skip` — Hint to install gitleaks, not a finding.
- `2fa.hardware.installed: skip` (with Ledger present) — The hint already says Ledger covers FIDO2.
- `network.dns.resolvers: skip` — Pure informational dump of DNS server IPs.
- `sandbox.runtime.present: skip` — Always a `skip`. Present means "you have Docker / OrbStack / UTM available, use it for untrusted code." Absent means "consider installing one." Neither state is a finding; don't surface as a gap.
- `messaging.telegram.advisory: skip` (when Telegram is installed) — The audit cannot read tdata, so this is an advisory pointer to settings the user should confirm by hand. Do NOT treat Telegram's presence as a finding; surface the hint as a follow-up checklist, not a gap.
- `browser.profile_count: pass` or `skip` — Purely observational. `pass` with multiple profiles means the user already has some isolation; don't recommend additional changes. `skip "Single browser profile"` is a soft nudge worth surfacing if other wallet-related rows are firing (§3.3), but is not a gap on its own.
- Single high `ext.total.count` — Browser extension count alone isn't actionable without knowing the contents.
- `browser.installed` informational — Counts and reports, doesn't fail.

## 5. How to surface findings to the user

Good AI-driven recommendations cite specific row IDs and explain why *this combination* matters for *this user*. Bad recommendations restate the audit's hint text verbatim or rank generic best practices.

**Bad pattern:**
> "You should enable Touch ID for sudo. Run: `sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local`."

**Better pattern:**
> "Three findings combine into a single risk for your wallet workflow:
> - `ext.wallet` shows MetaMask + Rabby + Phantom in Brave (your default browser).
> - `user.human.count: skip` — you have one human account.
> - `network.outboundmonitor.running: warn` — no Little Snitch or LuLu.
>
> Together: a malicious dApp signature in Brave can drain wallets, and you'd have no outbound monitor to flag the exfiltration. Highest-leverage fix: create a second macOS user that holds the wallets, switch to it for any transaction. Lower-cost mitigation: install LuLu (free) so any unfamiliar outbound connection prompts you."

The first reads like the script's own hint. The second uses three rows in combination, names the threat, and offers tiered actions.

## 5b. Implementation invariants worth knowing

A small handful of design rules constrain how the script's pieces interact. Future contributors keep tripping over the same ones; calling them out here saves a re-derivation.

**Composites that read `_status_of` for a profile-overridden ID must accept both `warn` AND `fail`.** `_apply_profile` rewrites constituent statuses *before* `STATUS_BY_ID` is updated, so composites see the post-profile value. A composite predicate like `[[ "$x" == "warn" ]]` silently misses the `fail`-escalated case under `--profile=web3` / `paranoid` / `developer` — which is exactly the case the stricter profile was meant to catch. Today the affected composites are `ssh.posture` (reads `ssh.keys.unencrypted`) and `supply.posture` (reads `supply.{npm,yarn,pnpm}.ignorescripts` + `supply.scanner`); any new composite reading an ID listed in `PROFILE_OVERRIDES` is subject to the same rule.

**Rows that embed identifying values into their labels must branch on `$REDACT`.** Hostnames, VPN brands, system-extension bundle IDs, AV brands, wallet brands, Time Machine destination names — anything that varies between two same-config Macs of the same threat profile must collapse to a count or category under `--redact`. Status-only changes (pass↔warn↔fail) are always safe; embedded `$variable` interpolation usually is not. The `tests/integration/redaction.bats` smoke suite asserts absence of known leak tokens in the produced JSON; new emit sites that bypass the gate fail it.

**The audit must exit 0 when no FAIL rows were emitted, and 1 when any were.** Test harnesses that run the script end-to-end need `|| true` around the invocation to tolerate the exit-1 "I found problems" signal — that is normal output, not a runtime error.

## 6. When to ask the user vs. recommend directly

Ask first when:
- The audit can't tell which profile fits — `paranoid` vs `web3` produce very different priorities.
- A row's status depends on intent (`network.bluetooth.off` is fine if AirPods are in active use, less fine on a Mac that never leaves the desk).
- The fix involves identity decisions (which email to commit under, which 1Password vault to use).

Recommend directly when:
- A `fail` row is present. Don't ask if FileVault should be on.
- A composite pattern in §3 fires unambiguously.
- The user has explicitly described their context already in the conversation.

## 7. Schema reference

Each result row in the JSON has these fields:

| field | always present | what it means |
|---|---|---|
| `id` | yes | Stable ID. Treat this as the contract. |
| `status` | yes | One of `pass`, `warn`, `fail`, `skip`. |
| `label` | yes | Human-readable summary. May be reworded across versions. |
| `hint` | yes (often `""`) | Remediation pointer. |

Top-level: `host`, `macos`, `arch`, `summary` (now incl. `total`), `executive_verdict`, `top_risks` (each entry carries an `effort` hint as of v1.5.0), `results` — the verdict/top_risks/total trio added in v1.3.0 (additive). Full schema: [`schema.md`](schema.md).

Output modes for a reviewer (v1.4+): `--report md` (shareable Markdown), `tools/render_report.py` (stdlib Python → self-contained HTML from a JSON document), `--snapshot` (append a redacted JSON to `~/.mac-posture-audit/history/` — the only write the tool performs), and `--trend` (read-only oldest-vs-newest delta). `--profile auto` recommends a profile from detected signals and exits. Canonical fixed-id list: [`tests/fixtures/expected_ids.txt`](../tests/fixtures/expected_ids.txt). Templated-id patterns: [`tests/fixtures/expected_id_patterns.txt`](../tests/fixtures/expected_id_patterns.txt).

`--diff <previous.json>` produces a structured changelog by `id` between two runs — useful for a longitudinal review of "what improved or regressed since last week."

## 8. What this guide is not

- A list of fixes for every possible Mac. Threat models vary; surface findings, don't broadcast a checklist.
- A replacement for the audit's hints. Hints are the script's most generic guidance; this guide is for layering on top.
- A static document. As patterns prove useful in practice, add them to §3. Pull requests welcome.
