# OpenSSF Scorecard maintenance

## Baseline and current limits

The public report retrieved on 2026-10-15 scored **8.2/10**. It was generated on
2026-08-25 for commit `96f423d5e0211af963f6de44a42d19c8fda1738d`, using Scorecard
5.5.0. It does not assess the pending hardening changes.

The latest scheduled scan failed with HTTP 401 from the saved `SCORECARD_TOKEN`.
The workflow now uses its short-lived GitHub token. Its analysis job has explicit
read access to contents, with write access only for SARIF and OIDC publication.
Public branch rules expose protection settings without a long-lived admin token.
A successful default-branch scan is still required to refresh the public report.

| Check | Published score | Next useful action |
| --- | --- | --- |
| Code Review | 0 | Obtain independent human review before merging changes. AI review does not count as human approval. |
| Branch Protection | 4 | Recruit a second maintainer before requiring approvals. Existing protections remain active, with review-thread resolution added. |
| CII Best Practices | 0 | Complete the OpenSSF Best Practices questionnaire with evidence and honest answers. No badge is claimed. |
| Contributors | 0 | Attract real independent contributors. Do not create artificial contributors or affiliations. |
| SAST | 9 | Keep CodeQL scans successful on PR heads; historical coverage improves only as new reviewed changes accumulate. |
| Packaging | -1 | This check is unscored. Retain the signed tarball distribution; an unrelated package publication is not needed. |

All other scored checks were 10 in that report. Configuration changes do not
establish a higher score until a fresh published scan measures them.

## Controls checked on 2026-10-15

Repository API reads confirmed that vulnerability alerts, Dependabot security
updates, secret scanning, secret push protection, and private vulnerability
reporting were enabled. Active public main rules retain the existing status
check, strict updates, linear history, no force pushes/deletion, and no admin
bypass. Review discussions must be resolved. The classic protection remains in
place while the public ruleset is validated by a refreshed scan.

Dependabot covers GitHub Actions, the fuzzing Docker image, and hashed Python
fuzz dependencies. Action updates stay in one monthly group so CodeQL init,
analyze, and upload-sarif move together. A regression test checks matching pins.

The fuzz harness now instruments input rejection, uses the production strict
JSON loader, and treats unexpected renderer errors as crashes. The old batch
job was green but reported no interesting inputs after more than 515 million
iterations. A green workflow alone does not prove useful coverage.

PR validation on commit `11753a3` built both real fuzz targets and loaded the two
synthetic seeds. The address run exercised 766,229 inputs in 61 seconds; its
coverage counter grew from 131 to 161. The undefined run exercised 4,530,636
inputs and reached 163. Both corpora grew from 2 to 69 inputs with no crashes.
The PR build step also needs its short-lived token and `actions: read` to load
previous coverage artifacts. Scheduled and coverage builds do not need that
token for affected-target selection.

## Best Practices badge evidence

The repository has a license, contribution guide, private security reporting,
release history, automated tests, static analysis, fuzzing configuration,
dependency maintenance, pinned CI dependencies, and signed release assets.
These are inputs to a questionnaire, not proof of every badge criterion.

The maintainer must verify each criterion, including response practices,
review practice, reproducible build instructions, and release evidence. Enroll
through the official site only when those answers can be supported. Do not add
a badge image until the project has an actual registered badge URL.

## Sources

- [Public report](https://scorecard.dev/viewer/?uri=github.com/demirelo/mac-posture-audit)
- [Report API](https://api.securityscorecards.dev/projects/github.com/demirelo/mac-posture-audit)
- [Failed scheduled run](https://github.com/demirelo/mac-posture-audit/actions/runs/38482268394)
- [Observed fuzz run](https://github.com/demirelo/mac-posture-audit/actions/runs/38721414500)
- [Seeded PR fuzz validation](https://github.com/demirelo/mac-posture-audit/actions/runs/38753849356)
- [Scorecard check definitions](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [Scorecard ruleset support](https://github.com/ossf/scorecard/blob/v5.5.0/clients/githubrepo/branches.go)
- [Atheris input instrumentation](https://github.com/google/atheris#why-am-i-getting-no-interesting-inputs-were-found)
- [OpenSSF Best Practices](https://www.bestpractices.dev/en)
