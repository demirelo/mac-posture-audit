# mac-posture-audit

[![Safety](https://github.com/demirelo/mac-posture-audit/actions/workflows/safety.yml/badge.svg?branch=main)](https://github.com/demirelo/mac-posture-audit/actions/workflows/safety.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Bash 3.2 compatible](https://img.shields.io/badge/bash-3.2%20compatible-blue)](#compatibility)

A read-only, single-file shell script that audits a macOS machine's security posture and prints a colored report.

Designed for personal use — runs in seconds, makes no changes, has no external dependencies beyond what ships with macOS.

## Inspect before running

Do not run security tooling on trust alone. This project is intentionally a single shell script so you can inspect it first.

```bash
git clone https://github.com/demirelo/mac-posture-audit
cd mac-posture-audit

# 1. Read it. The whole script is in one file.
less mac-posture-audit.sh

# 2. Syntax-check on stock macOS Bash 3.2.
/bin/bash -n mac-posture-audit.sh

# 3. Run the CI-enforced tripwire that fails on any file/system mutation
#    command added in command position (rm, mv, chmod, defaults write,
#    launchctl load, brew/npm/pip install, curl|bash, …) and on any
#    network call outside the explicit --network opt-in probe.
./scripts/check-read-only.sh

# 4. (Optional) Verify the SSH-signed tag. Tags and commits are signed,
#    but `git tag -v` only means something if you've trusted the
#    signer's public key out-of-band. Fetch it from a channel you trust
#    (GitHub publishes user pubkeys at /<user>.keys) and add to
#    ~/.config/git/allowed_signers, then:
#       git tag -v v0.1.0
#    Otherwise skip this step; the prior three already prove read-only.

# 5. Pin a known-good checksum if you re-pull later.
shasum -a 256 mac-posture-audit.sh
```

The tripwire is regression-tested by `tests/check-read-only/should_pass/*.sh` (allowlist samples that must be accepted) and `tests/check-read-only/should_fail/*.sh` (mutation patterns that must be rejected), so the safety check itself has teeth. See [SECURITY.md](./SECURITY.md) for the full read-only guarantee, the narrow `sqlite3 -readonly` / read-only-verb `osascript` exceptions, and the disclosure contact.

## What it checks

25 sections covering 143 checks:

- **System integrity** — SIP, Gatekeeper, FileVault, Apple Silicon Secure Boot, third-party kernel extensions
- **Login & lock screen** — auto-login, screen lock delay, login window mode, Touch ID for sudo
- **Privacy & telemetry** — Apple personalized ads, analytics sharing, Lockdown Mode (situational)
- **Network — firewall & sharing** — App Firewall state, stealth mode, Remote Login, Sharing services, Internet Sharing
- **Network — AirDrop, Bluetooth & Wi-Fi** — discoverability mode, Bluetooth on/off, count of remembered Wi-Fi networks (passive triangulation surface)
- **Network — DNS, VPN & outbound** — NextDNS profile detection, active resolvers, DoH profiles, VPN clients, VPN killswitch state (verified for Mullvad; advisory for ProtonVPN / NordVPN), outbound monitors (Little Snitch / LuLu)
- **Network — filters & proxies** — HTTP/HTTPS/SOCKS proxies, PAC URLs, WPAD, configuration profiles, system extensions, `/etc/hosts` audit
- **Antivirus & endpoint protection** — 16 AV/EDR engines detected, Objective-See tools, browser-side AV extensions
- **Browsers** — installed browsers, default browser, **bundle-mtime version currency** (Chromium / Firefox >28d stale warns), **profile count** across Chrome / Brave / Edge / Firefox
- **Browser extensions** — Chromium (Brave/Chrome/Edge/Arc/Vivaldi), Safari (via `pluginkit`), Firefox (via `extensions.json`); detects protective (uBlock, 1Password, Privacy Badger), wallet (MetaMask, Phantom, Rabby), and transaction simulators (Wallet Guard, Pocket Universe)
- **SSH** — plaintext private keys, 1Password agent socket, `SSH_AUTH_SOCK`, config file permissions
- **Git signing** — commit signing config, allowedSignersFile, user.email
- **Supply chain** — npm/yarn/pnpm `ignore-scripts`, Socket CLI, custom cooldown wrappers, `.npmrc` audit, `gh auth status`, git credential helper, global `git url.insteadOf` rewrites, `core.hooksPath`, `~/.cargo/credentials`, `~/.pypirc`, `~/.gem/credentials`, third-party Homebrew taps, `brew analytics`, **direnv allow-list size**, **pip / uv / pixi `extra-index-url`** (dependency-confusion risk)
- **Credential & secret hygiene** — 14+ credential patterns in shell rc files, project-style `.env` files at $HOME, sensitive dotfiles (`.aws`, `.netrc`, `.npmrc` token, `.docker`, `.kube`, embedded URLs in git config)
- **Password manager & 2FA hardware** — 1Password / Bitwarden / Dashlane, YubiKey / Yubico Authenticator, Ledger as FIDO2 hint
- **Crypto hardware wallet** — Ledger Live, Trezor Suite, Keystone, GridPlus
- **Folder layout & sensitive data** — encrypted Vault sparsebundle, Downloads hygiene, sensitive folder names at `$HOME`, **`.ssh` / `.aws` / `.kube` / wallet data / dotfiles in cloud-sync roots** (iCloud Drive, Dropbox, Google Drive, OneDrive, Box) with symlink resolution
- **Backups** — Time Machine destinations + recency, **TM encryption state**, Backblaze, Carbon Copy Cloner, file-encryption tools
- **iCloud** — sign-in detection, save-to-cloud default, iCloud Drive sync, ADP placeholder, **Desktop & Documents Folders sync detection**
- **User accounts & sudo** — admin count, service accounts in admin group, NOPASSWD in sudoers
- **Software updates & Find My Mac** — automatic update checks, Find My Mac multi-signal
- **Persistence & TCC** — user/system LaunchAgents and LaunchDaemons, login items, crontab, TCC.db permission holders for Accessibility / Screen Recording / Full Disk Access / Input Monitoring (read-only `sqlite3 -readonly`; needs sudo + Full Disk Access on the running terminal), **remote-access apps** (AnyDesk / TeamViewer / Splashtop / RustDesk / Chrome Remote Desktop / VNC / Parsec), **sandbox runtime detection** (Docker / OrbStack / UTM), **gaming clients** (Steam / Discord / Epic / GOG / Battle.net)
- **Device management & privacy awareness** — MDM enrollment status, screenshot save location (iCloud / Dropbox / Google Drive / OneDrive / Box leak detection), clipboard-manager presence (Maccy / Paste / Raycast / Alfred / Pastebot / CopyClip / Pasta)
- **IDE workspace trust + wallet isolation** — VS Code and Cursor `security.workspace.trust.*` settings (defends against "open malicious repo → tasks.json autoruns"), plus a `users.crypto_isolation_indicator` cross-section composite that flags single-user-Mac + default-browser-is-wallet-browser combinations
- **Messaging apps (advisory)** — Telegram Desktop presence triggers a settings-to-verify checklist (auto-download OFF, group-add restricted)

Composite checks combine multiple rows into a single posture verdict where the meaning depends on the combination: `system.theft_resistance`, `backup.recovery_path`, `ssh.posture`, `supply.posture`, `network.dns.encrypted`, `users.crypto_isolation_indicator`, `twofa.fido_gap`, and `av.engine.conflict`. See [`docs/AGENTS.md`](docs/AGENTS.md) §3 for the full table and the additional agent-only patterns that an LLM reviewer can layer on top.

## Usage

```bash
# Default: offline, read-only audit
./mac-posture-audit.sh

# Fuller read-only audit; privileged probes skip if sudo is unavailable
sudo ./mac-posture-audit.sh

# Optional live verification: only NextDNS routing + gh auth status
./mac-posture-audit.sh --network

# Shareable machine-readable report
./mac-posture-audit.sh --json --quick --redact > posture.json
```

Run normally first. Use `sudo` for the fullest read-only audit; it lets the script read privileged settings such as Secure Boot details, Remote Login state, TCC.db permission holders, and sudoers entries. `--quick` skips privileged checks. `--network` is intentionally shown as a main copy-paste command, but it remains opt-in: the default run is offline.

Flags:

| Flag | Effect |
|---|---|
| `--quick` | Skip checks that require sudo |
| `--json` | Machine-readable JSON output |
| `--network` | Allow live external probes (e.g., NextDNS live-routing check). Default off. |
| `--offline` | Explicit no-external-calls (already the default) |
| `--redact` | Mask hostname, emails, admin usernames, resolver IPs, and `$HOME` paths in output. Use when sharing the report. |
| `--profile NAME` | Severity calibration. One of `normal` (default), `web3`, `paranoid`, `developer`, `founder`. See [Profiles](#profiles). |
| `--diff PATH` | Compare current run against a previously saved `--json` output. Prints one line per id whose status differs. Exits 0 if no diffs, 1 if any. |
| `--version` | Show the script version and exit |
| `--help` | Show usage and exit |

### Profiles

`--profile NAME` escalates specific checks past their default severity based on threat model. The check still runs and its base evaluation is unchanged; only the resulting `status` is rewritten before being counted and printed.

| Profile | Escalates |
|---|---|
| `normal` | nothing — defaults |
| `web3` | wallet-on-main-user → `fail`; npm/yarn/pnpm `ignore-scripts=false` → `fail`; missing supply-chain scanner → `fail`; unencrypted SSH key → `fail`; missing transaction simulator → `fail`; wallet data inside cloud sync → `fail`; remote-access app present → `fail`; wallet-isolation indicators missing → `fail`; IDE workspace trust disabled → `fail`; browser bundle >28d stale → `fail`; VPN killswitch off → `fail` |
| `paranoid` | everything in `web3`, plus Bluetooth-on, AirDrop-discoverable, firewall not in block-all / no stealth, stale or unencrypted Time Machine, missing auto-updates, plaintext Docker auth, pip / uv / pixi `extra-index-url` configured |
| `developer` | npm/yarn/pnpm `ignore-scripts=false` → `fail`; missing supply-chain scanner → `fail`; pip / uv / pixi `extra-index-url` → `fail`; shell-rc credential pattern → `fail` (already `fail` by default in normal) |
| `founder` | explicit union of `developer` + `web3` — for solo founders shipping their own code who also custody crypto |

The full override matrix lives at `PROFILE_OVERRIDES` in [mac-posture-audit.sh](mac-posture-audit.sh) — each entry is `profile|id|from_status|to_status` and only triggers when the check actually emits `from_status`. A profile can never lower a `fail` to a `warn`.

Exit code: `0` if no failures, `1` if any check fails, `2` if the script itself errors.

### JSON output

Each row carries a stable `id`, `status`, `label`, and `hint`. IDs are unique within a single run and stable across runs, so external consumers can diff successive scans by `id`:

```json
{
  "host":"<HOST>","macos":"26.4.1","arch":"arm64",
  "summary":{"pass":47,"warn":6,"fail":0,"skip":10},
  "results":[
    {"id":"system.sip.enabled","status":"pass","label":"SIP (System Integrity Protection) is enabled","hint":""},
    {"id":"system.gatekeeper.enabled","status":"pass","label":"Gatekeeper is enabled","hint":""},
    {"id":"network.firewall.stealth","status":"warn","label":"Firewall stealth mode is off","hint":"Firewall Options → Enable stealth mode"}
  ]
}
```

ID grammar is `<area>.<subject>.<fact>` for fixed checks and `<area>.<subject>.<instance>` for templated checks where `<instance>` is the lower-cased item name (currently only `network.sharing.<service>` and `persist.system.<dir>`). The full canonical list lives at [tests/fixtures/expected_ids.txt](tests/fixtures/expected_ids.txt) and dynamic patterns at [tests/fixtures/expected_id_patterns.txt](tests/fixtures/expected_id_patterns.txt); CI gates on both. Full schema details (field types, status enum, versioning policy) are in [docs/schema.md](docs/schema.md).

### Diffing two runs

```bash
./mac-posture-audit.sh --json --quick --redact > yesterday.json
# … time passes …
./mac-posture-audit.sh --diff yesterday.json
# Prints e.g.
#   ^ ext.wallet            warn -> fail        (escalation)
#   v ssh.keys.unencrypted  warn -> pass        (resolved)
#   + persist.user.launchagents  (new)  warn    (new check or condition appeared)
#   - av.engine.detected   (removed)  pass     (no longer emitted this run)
```

Exit code: `0` if no diffs, `1` if any diff, `2` on file/parse error. Combine with cron + `--profile` to track posture over time.

### AI agent review

The audit is intentionally under-opinionated: it emits raw, stable signals and leaves the synthesis — which findings matter for *this user's* threat model, which combinations of low-signal SKIPs together indicate a real gap — to whoever reads the report. Increasingly that "whoever" is an LLM. [`docs/AGENTS.md`](docs/AGENTS.md) is the user manual for that LLM. Point any AI coding agent at it (or at a saved JSON) and it can produce contextual recommendations rather than a generic checklist. Composite patterns covered there include backup-desert detection, wallet-without-isolation, plaintext-disk-on-theft, SSH risk surface, supply-chain composites for developers, and persistence sprawl.

Sample output (truncated):

```
macOS Posture Audit
Read-only. No changes will be made.
Host: MacBook-Pro.local · macOS 26.4.1 · arch arm64

━━━ 01 · System Integrity (Disk & Boot) ━━━
  ✅ PASS SIP (System Integrity Protection) is enabled
  ✅ PASS Gatekeeper is enabled
  ✅ PASS FileVault is on (full-disk encryption active)
  ✅ PASS Apple Silicon Secure Boot: Full Security
  ✅ PASS Third-party kernel extensions disabled

[…23 sections…]

━━━ Summary ━━━
  ✅ Pass:  47
  ⚠️  Warn:  6
  ❌ Fail:  0
  ⏭  Skip:  10
```

## Safety model

- **Read-only.** Never modifies any file or setting.
- **No external services contacted by default.** `--network` explicitly allows the live NextDNS routing check and `gh auth status` if GitHub CLI is installed.
- **Bash 3.2 compatible** — works on stock macOS without `brew install bash`.
- **No assumptions** about your folder layout, project naming, email, or installed apps.
- **Sudo behavior** — optional. Without sudo, privileged checks use non-interactive sudo and skip cleanly if credentials are unavailable. With sudo, the script still audits the invoking user's home directory rather than `/var/root`.
- **Security policy** — see [SECURITY.md](./SECURITY.md) for the read-only guarantee, verification steps, and vulnerability reporting contact.

## Deeper read-only verification

In addition to the steps in [Inspect before running](#inspect-before-running):

- The tripwire (`scripts/check-read-only.sh`) blocks command-position uses of `rm`, `mv`, `cp`, `chmod`, `chown`, `defaults write`, `plutil -replace`, mutating `launchctl`, package installs (brew/npm/yarn/pnpm/pip/cargo/gem), kill commands, disk tooling (`diskutil`, `hdiutil`), and `curl|bash` / `wget|bash` patterns. It also fails on any new network command outside the explicit `--network` opt-in probe.
- Two narrow allowlists exist: `sqlite3` only with `-readonly` as the first argument (used for `TCC.db` in §22), and `osascript` only with read-only verbs like `to get` (used for the login-items query in §22). Mutating verbs (`set`, `do shell script`) are rejected. Both allowlists have dedicated positive/negative fixtures.
- For a one-line skim, this regex should only return read-only probes, remediation hint text, or the opt-in NextDNS / `gh auth` checks:

```bash
grep -En 'sudo|curl|gh |rm |mv |cp |chmod|chown|defaults|plutil|launchctl|kill|brew |npm |pip |osascript|sqlite3|diskutil|hdiutil' mac-posture-audit.sh
```

## Privacy of the output

The script's output is sensitive — it lists which credential files live in `$HOME`, which TCC services have approved clients, which LaunchAgents are installed, which VPN / AV / wallet apps are running, and so on. Reading the output tells someone what to attack. Use `--redact` before sharing:

```bash
./mac-posture-audit.sh --json --quick --redact > posture.json
```

`--redact` masks hostnames, emails, admin usernames, resolver IPs, `$HOME` paths, VPN brand names, system-extension bundle IDs, AV brands, wallet extension brands, Time Machine destination names, third-party Homebrew taps, sensitive TCC clients, login items, and clipboard manager brands. The credential check itself uses `grep -l` (filenames only) and never prints matched secret values; the redaction smoke tests in [`tests/integration/redaction.bats`](tests/integration/redaction.bats) assert absence of known leak tokens in the JSON output on every CI build.

## Testing

Install the local test tools with Homebrew:

```bash
brew install bats-core shellcheck shfmt
```

Run the same checks CI runs:

```bash
bash -n mac-posture-audit.sh
shellcheck -S warning mac-posture-audit.sh scripts/check-read-only.sh tests/helpers.bash
shfmt -d -i 2 mac-posture-audit.sh scripts/check-read-only.sh tests/helpers.bash
./scripts/check-read-only.sh
bats tests/sections tests/integration
```

The Bats suite sources `mac-posture-audit.sh` as a library and uses fixtures/mocked macOS CLIs for section-level tests. Integration tests run the real script in `--quick` mode and assert JSON validity, redaction, argument handling, and summary counter parity.

## Compatibility

| Platform | Support |
|---|---|
| macOS Tahoe (26) | ✅ primary target, CI runner |
| macOS Sequoia (15) | ✅ primary target |
| macOS Sonoma (14) | ⚠️ should work — CI does not currently run against Sonoma |
| macOS Ventura (13) | ⚠️ should work — some checks may use Sequoia-specific output formats (e.g. `sysadminctl -screenLock`) and degrade to SKIP |
| Earlier macOS | ⚠️ some checks fall back to legacy `defaults read`; not actively supported |
| Apple Silicon | ✅ |
| Intel Mac | ✅ (Apple-Silicon-specific boot security checks become n/a) |

## What this isn't

- Not a remediation tool. It tells you what's wrong; it doesn't fix anything.
- Not a malware scanner. Use Bitdefender, Malwarebytes, or Objective-See tools for that.
- Not a substitute for a real security audit. It's a self-check you can run weekly to track posture.

## Roadmap

v1.0.0 is the public-release cutover. Possible directions from here:

- **More macOS-version fixtures** for login, firewall/sharing, AirDrop, users/sudo, browser extensions, and TCC corner cases.
- **Evidence fields** in JSON rows so consumers can show structured supporting detail without scraping labels.
- **`--deep` mode** for a slower, opt-in scan across project directories with explicit excludes and redaction-safe output.
- **Signed release artifacts** with published checksums for easier pre-run verification.
- **Continuous snapshot mode** that stores JSON locally and alerts on newly-introduced failures.
- **Separate remediation companion** only if it stays clearly outside this audit script and requires explicit confirmation for every mutation.
- **Per-brand killswitch verification** for ProtonVPN / NordVPN (currently advisory-only).
- **Messaging app coverage** for Signal, Discord, WhatsApp — same advisory shape as Telegram in Section 25.

## Contributing

Pull requests welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the four invariants: read-only probes, bash 3.2 compatibility, stable IDs, and hermetic tests via `*_ROOTS` overrides.

## License

MIT — see [LICENSE](./LICENSE).
