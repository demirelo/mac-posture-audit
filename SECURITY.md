# Security Policy

## Read-Only Guarantee

`mac-posture-audit.sh` is an audit script only. It must not create, modify, delete,
install, unload, enable, disable, or reconfigure any file, service, package,
profile, account, keychain, browser, network setting, macOS setting, or security
control.

The script only performs read-style probes such as `defaults read`, `plutil -p`,
`launchctl list`, `profiles -L/list`, `tmutil destinationinfo/latestbackup`,
`git config --global`, `brew tap` with no tap name, process checks, and filesystem
metadata/listing checks.

## Network Behavior

Default mode is offline. The script must not contact external services unless the
user explicitly passes `--network`.

The only allowed `--network` probes are:

- `https://test.nextdns.io` for live NextDNS routing verification.
- `gh auth status` for GitHub CLI authentication status, if `gh` is installed.

Both are read-only. They do not install, write, or change configuration.

## Privileged Checks

Privileged probes use non-interactive `sudo -n` and skip cleanly when sudo is not
already available. The script does not ask for a password itself and does not
change sudoers, users, groups, services, or settings.

Running `sudo ./mac-posture-audit.sh` is optional and provides fuller read-only
visibility. Even under sudo, the script preserves the invoking user's home
directory for user-scope checks instead of auditing `/var/root`.

## Narrow Read-Only Exceptions

Two commands are allowed only in tightly constrained read-only forms:

- `sqlite3` is allowed only when `-readonly` is the first sqlite3 argument. This
  is used to inspect `TCC.db`.
- `osascript` is allowed only for the exact login-items query used by Section 22:
  `tell application "System Events" to get the name of every login item`.

## Enforcement

The guarantee is enforced in CI by `scripts/check-read-only.sh`. The checker
rejects command-position uses of mutating or risky commands such as `rm`,
`chmod`, `defaults write`, `plutil -replace`, mutating `launchctl`, package
installs, kill commands, disk tooling, `curl | bash`, writable `sqlite3`, and
mutating `osascript`.

The tripwire also has positive and negative fixtures under
`tests/check-read-only/`; CI fails if a mutating fixture is accepted or a
read-only fixture is rejected.

## How To Verify Before Running

```bash
less mac-posture-audit.sh
bash -n mac-posture-audit.sh
./scripts/check-read-only.sh
for f in tests/check-read-only/should_fail/*.sh; do
  ./scripts/check-read-only.sh "$f" >/dev/null 2>&1 && echo "MISS: $f"
done
shasum -a 256 mac-posture-audit.sh
```

## Practical Limits

Like any command execution, the user's shell, Terminal, macOS, `sudo`, Homebrew,
or GitHub CLI may create normal logs, history entries, telemetry, or caches
outside this script's control. This repository's guarantee is that
`mac-posture-audit.sh` itself does not intentionally mutate files, settings,
services, packages, accounts, or security controls.

If you find a command that violates this guarantee, treat it as a security bug.

## Reporting A Vulnerability

Email `omer[_]progfi[_]xyz` (replace the first `[_]` with `@` and the second with
`.`). Please do not open public issues for sensitive findings.

Expected acknowledgement: within 7 days.

## Scope

In scope: any command in `mac-posture-audit.sh` or `scripts/check-read-only.sh`
that mutates state, exfiltrates data outside documented opt-in probes, weakens
the read-only tripwire, or misclassifies a security control in a way that gives a
false sense of safety.

Out of scope: false negatives caused by macOS version drift, undocumented private
APIs, tools the script does not yet check, or normal OS/runtime logging outside
the script's control.
