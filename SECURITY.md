# Security Policy

## Read-only probes and explicit report writes

Default scans inspect configuration without changing files, packages, accounts,
services, or security settings. They do not install tools or apply remediation.

There are two explicit report-write operations:

- `--snapshot` creates report storage and saves redacted JSON. It requires a
  normal user, a private directory owned by that user, and a new filename.
  Directory mode is `0700`; file mode is `0600`. User-controlled symlinks,
  writable non-sticky ancestors, and access-granting directory ACLs are rejected.
  It does not fix an existing directory's permissions or overwrite reports.
- The separate Python companion's `--output FILE` creates a new HTML report with
  mode `0600`. It rejects an existing path, including a symlink. On macOS it
  removes inherited ACLs through the newly opened file descriptor before it
  writes report data. A failure to remove the ACL stops the write.

An interrupted or failed write can leave a new, incomplete file. Report-write
errors exit `2`. Invalid snapshots also make trend comparison exit `2`.

## Command execution

Run `./mac-posture-audit.sh` as your normal user. Running the whole audit as root
is rejected. Checks that need more access use non-interactive `sudo -n`; the
audit does not ask for a password. A failed probe must not become a safe result.

Direct execution uses `/bin/bash -p`. This prevents Bash startup files and
exported functions from loading. The audit prioritizes system command paths.
Optional-tool inventory can inspect the caller's PATH without executing those
tools. The script does not execute npm, Yarn, pnpm, Homebrew, or Gitleaks.
Package-policy checks inspect user configuration only. Project configuration,
environment overrides, and package-manager version differences remain outside
that verification.

The installed GitHub CLI remains executable code trusted by the optional
network check. These controls do not protect against a compromised operating
system, a malicious same-user process, or an altered audit script. If you run
`bash script` instead of executing the file directly, the calling interpreter's
startup behavior is outside the script's control.

## Network behavior

Default mode is offline. `--network` permits only:

- The HTTPS `https://test.nextdns.io` routing probe, with a five-second timeout,
  HTTPS-only protocol selection, and curl startup configuration disabled.
- `gh auth status`, if the GitHub CLI is installed.

These probes request status only. System and CLI logs or caches remain outside
the script's control.

## Constrained native probes

- On macOS versions before 27, SQLite uses `-readonly -init /dev/null` to inspect
  TCC tables. Startup files, shell commands, extension loading, and output
  commands are not permitted.
- On macOS 27+, Apple has removed direct TCC database access. The audit skips
  these inventories without running SQLite, `sudo`, or `tccutil` for them.
  Unknown versions also skip this path. Review permissions in System Settings;
  unavailable data does not mean no permissions exist. See
  [Apple's enterprise changes](https://support.apple.com/en-us/148830) and the
  [macOS 27 coverage notes](docs/macOS-27.md).
- AppleScript is limited to the fixed System Events login-item query. macOS may
  require Automation permission. A denied query produces an unverified result.

## Report handling

Reports describe sensitive aspects of a device. Redaction reduces identifying
information; it is not a guarantee of anonymity. Review a report before sharing.
Git helper commands and rewrite URLs are omitted because they can contain
credentials. Do not paste unredacted reports into public issues.

The HTML companion validates structure and counts, escapes displayed values,
and uses a restrictive content security policy without external assets.
Markdown cells escape markup from probe values. Terminal findings escape
control characters. JSON comparison rejects malformed or excessive input,
duplicate keys and IDs, and unsafe check identifiers.

## Enforcement and limits

`scripts/check-read-only.sh` is a static tripwire. It checks known command forms,
exact probe arguments, and local network guards. Positive and negative fixtures
cover accepted forms and known bypasses. It is not a complete shell parser or
a sandbox. Passing it does not prove that arbitrary shell code, redirections,
or embedded programs are safe. Runtime checks, code review, and tests are also
required.

```bash
less mac-posture-audit.sh
/bin/bash -n mac-posture-audit.sh
./scripts/check-read-only.sh
./scripts/test.sh
shasum -a 256 mac-posture-audit.sh
```

The test runner uses a temporary home directory for Bats. Some integration tests
still perform real read-only macOS probes in quick mode.

Release validation uses read-only permissions. Publication uses the tested
commit and verifies the tag still resolves to it. Manual dispatch must select
the same version tag. Existing release assets cannot be replaced by the workflow.
Local tests do not establish that a hosted release workflow has run successfully.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/demirelo/mac-posture-audit/security/advisories/new),
or email `omer[_]progfi[_]xyz` (replace the first `[_]` with `@` and the second
with `.`). Do not open public issues for sensitive findings.

Expected acknowledgement: within 7 days.

In scope: unintended mutation, command execution, data disclosure, report
injection, unsafe report writes, weakened safety checks, and false safe results.
Include the macOS version, check ID, and a minimal fixture when possible. Do not
include private configuration or credentials.
