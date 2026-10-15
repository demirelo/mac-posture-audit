# Human review checklist

Use this checklist for a specific PR head. Record what you inspected and tested;
list any limits. An AI-generated review does not constitute a human approval.
Do not approve your own changes or reuse an approval after a material change.

## Execution and trust

- Trace each new command and argument. Does it only inspect state? Do not rely
  on the safety tripwire alone. Check the narrow snapshot/write exceptions.
- Check hostile configuration and command output as data. No eval, sourcing,
  startup files, executable package-manager configuration or new helper execution.
- Verify no new network path exists unless explicitly opted in and documented.
  Default audit paths must remain offline. Do not upload a host report for review.
- Check unavailable, failed and denied probes. They must not become a safe result.
  A listening socket alone does not establish remote reachability.

## Inputs, output and writes

- Reject malformed, duplicate, oversized or excessive-depth report input.
  Escape terminal controls, HTML and Markdown before display.
- Test redaction using synthetic identifiers and credentials. Keep real reports,
  hostnames, paths, inventories and private configuration out of the PR and CI.
- For report writes, review exclusive creation, ownership, private permissions,
  symlinks, ACLs, races and error handling. Do not broaden the allowed writes.
- Keep fixed IDs stable and instance IDs unique. Review profile escalation and
  composites against warn/fail overrides.

## Compatibility and validation

- Use Bash 3.2 and stock macOS tools. The core audit must not need Python.
  Optional Python tools and tests use Apple `/usr/bin/python3` on macOS.
- Check new OS behavior against Apple documentation. Missing access must produce
  an explicit unverified/skip result. Test both old and new version branches.
- Require a regression fixture for behavior changes and negative cases for trust
  boundaries. Use temporary, synthetic data instead of private configuration.
- Inspect required CI at the reviewed commit. For a release, verify the exact tag,
  artifact checksum, signature and provenance; do not substitute a branch result.

## Record and merge

Record the reviewed commit, findings, fixes, relevant checks and remaining limits
in the GitHub review. Approve only when the identified blockers are resolved.
A new material patch requires another look. Do not grant write access to obtain
an approval; outside reviewers can inspect and discuss public changes first.
