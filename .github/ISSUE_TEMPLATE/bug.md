---
name: Bug report
about: A check is wrong, the script fails, or output is inconsistent
title: ''
labels: bug
assignees: ''
---

## Summary

<!-- One sentence describing what's wrong. -->

## What I expected vs. what I saw

<!-- State the check ID and expected/observed status. Use synthetic values.
     Do not paste a host report or raw JSON row, even with --redact: findings
     can still reveal installed tools, private paths and security settings.
     For suspected vulnerabilities, use SECURITY.md instead of this issue. -->

## Reproduction

- macOS version: <!-- `sw_vers -productVersion` -->
- Script version: <!-- `./mac-posture-audit.sh --version` -->
- Apple Silicon or Intel:
- Profile flag (if any): `--profile=`
- Sudo or no sudo:
- Other flags (`--quick`, `--network`, `--redact`, `--diff`):

```bash
# The exact command I ran:

# Minimal synthetic output that reproduces the issue:

```

## What I already checked

<!-- e.g. "ran `bash -n mac-posture-audit.sh`", "checked tests/fixtures/expected_ids.txt for the id" -->

## For false-positive reports

<!-- What signal does the system actually carry, and what does the audit see? Which CLI does the check call, and what does its output look like on your machine? -->

## For false-negative reports

<!-- What posture gap does the audit miss, and what did you use to verify the gap exists? Existing row IDs that *should* have caught it: -->
