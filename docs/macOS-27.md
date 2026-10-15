# macOS 27 coverage

Reviewed on 2026-10-15. The audit has been tested on macOS 27.0.1. Some controls
still need manual review. The manual-review rows use `skip` because the state
of those controls is unverified.

## Test evidence

| Item | Evidence |
|---|---|
| Operating system | `/usr/bin/sw_vers`: macOS 27.0.1, build 26A434 |
| Architecture and shell | arm64, stock Bash 3.2.57 |
| Complete local suite | 570 Bats tests, 67 Python tests, and 57 safety-checker fixtures passed on 2026-10-15. Bash syntax, ShellCheck, shfmt, the read-only tripwire, and diff whitespace checks passed. Workflow YAML also parsed successfully. |
| Host smoke test | A real read-only `--quick --json` run with a temporary home directory passed JSON structure, unique-ID, summary-count, TCC, and Background Security Improvements checks. |
| Privileged checks | The automated results do not establish a full privileged audit or a complete inventory of managed-device permissions. |

The complete run used Apple's `/usr/bin/python3`, Python 3.9.6, supplied by
Xcode on this Mac. CI selects the same Apple interpreter path and records the
version supplied by its Xcode image. This does not require a Homebrew Python
installation. Xcode or Command Line Tools must provide the interpreter; the
version can change with those tools. The hosted suite also found and corrected a
test assumption about JSON parser depth limits in Python 3.15; production code
did not need a change for that difference.
Use `./scripts/test.sh` for the complete test set in the current checkout. A
successful smoke test checks execution and report structure; it does not prove
that every reported setting matches a separately verified system state.

Apple supports macOS 27 on Macs with Apple silicon. The project's Intel support
applies to compatible earlier macOS releases. See Apple's
[macOS 27 compatibility guidance](https://support.apple.com/en-au/127455).

Runtime detection accepts only a successful, recognized version string from
`sw_vers`; an empty, malformed, or failed result becomes `unknown`. Version
comparisons include both the major and minor numbers. If a process reports
`x86_64`, the audit also checks the hardware's Apple-silicon flag so that a
translated process does not omit Apple-silicon boot checks.

For development, use arm64 or universal builds of test dependencies. Run
`./scripts/test.sh --check-tools` to check them before the test suite. Apple
states that Rosetta remains available in macOS 27 but is not automatically
restored during the upgrade. An Intel-only tool may therefore fail to run.
See the [enterprise upgrade guidance](https://support.apple.com/en-us/148830).

## Privacy permissions and TCC

Apple states that applications can no longer read the local TCC database
directly on macOS 27. Apple documents `tccutil list` for managed devices, with
capability information from `tccutil --info`. See the
[macOS 27 enterprise changes](https://support.apple.com/en-us/148830).

The audit preserves these check IDs and emits `skip` on macOS 27 or later:

| Check ID | Manual review |
|---|---|
| `tcc.holders` | System Settings → Privacy & Security; review Accessibility, screen recording, Full Disk Access, and Input Monitoring permissions. |
| `tcc.appleevents` | System Settings → Privacy & Security → Automation. |
| `tcc.camera_microphone` | System Settings → Privacy & Security → Camera and Microphone. |

These branches do not query SQLite, request `sudo`, or run `tccutil`. Unknown or
malformed macOS versions also skip database inspection. Valid earlier versions
retain the legacy read-only queries, subject to access and `--quick` limits.
If either legacy database is unreadable, an empty AppleEvents or
Camera/Microphone inventory also remains unverified.

On the macOS 27.0.1 test host, `/usr/bin/tccutil --info` returned exit 64 and
displayed reset-only usage. Therefore, the audit does not assume that the new
managed-device command is available on every Mac. Ask the administrator to
verify the supported interface for a managed device. An unavailable inventory
does not establish that no applications have permissions.

## Background Security Improvements

Apple provides Background Security Improvements from macOS 26.1 onward. Their
automatic installation has a separate setting: System Settings → Privacy &
Security → Background Security Improvements → Automatically Install. Apple also
limits these improvements to Macs started from built-in storage; an external
startup disk receives the fixes in a later software update. See Apple's
[Background Security Improvements guidance](https://support.apple.com/en-us/102657).

`update.background_security` reports this state as unverified on applicable
versions. A pass for automatic update checks or update recency does not verify
this setting or prove that the latest background patch is active. Review the
setting and startup-storage condition manually.

## Apple Intelligence and Siri

Review System Settings → Siri, including App Access, the ChatGPT integration,
and request confirmation. The available options depend on the Siri version and
feature availability. See Apple's
[Siri settings guide](https://support.apple.com/en-ie/guide/mac-help/mchl3fd7fc15/mac).

Screen Time → Content & Privacy → Intelligence & Siri provides restrictions for
Apple Intelligence features. See Apple's
[Intelligence & Siri restrictions](https://support.apple.com/en-ie/guide/mac-help/mchl1885610b/mac).
The audit does not infer these permissions from an undocumented preference key
or treat an unreadable setting as disabled. Select the settings that match the
device's intended use and data-sharing policy.

## Managed updates and remaining limits

Apple states that legacy software-update management no longer works in the
27.0 operating systems and directs administrators to declarative update
management. Enrollment alone does not verify an enforced update policy. See
the [enterprise guidance](https://support.apple.com/en-us/148830).

This change concerns device-management update commands and policy. It does not
establish that the local `softwareupdate --schedule` query has been removed.
The audit accepts only successful, recognized On/Off output from that query;
an explicit Off result cannot become a pass through a preference-file fallback.

Apple's release notes describe default denial of cross-developer app-container
access and further XProtect restrictions on app data. These protections can
limit inventories. Unreadable data does not prove that an app or setting is
absent. See the [macOS 27 release notes](https://developer.apple.com/documentation/macos-release-notes/macos-27-release-notes).
This audit does not establish complete coverage of those access limits.

No change to SIP, FileVault, Gatekeeper, or firewall behavior is claimed solely
because the major version is 27. Their existing probes still require a readable,
recognized result. This page records the tested paths and known coverage limits;
it is not a certification of every macOS 27 security control.
