# OpenSSF Scorecard maintenance

## Baseline and current limits

The public report generated on 2026-10-15 at 18:36 UTC scored **8.0/10** for
commit `b8cb1d66f07ce127d1a644df69408f9342d39a23`. The previous published report
scored **8.2/10** for `96f423d5e0211af963f6de44a42d19c8fda1738d` on 2026-08-25.

The latest report gives Maintained 7: nine commits and no issue activity in its
90-day window. The earlier baseline recorded 10 for this check. The core
supply-chain controls remain at 10: pinned dependencies, least-privilege tokens,
fuzzing, signed releases, binary artifacts, vulnerability checks and CI tests.
A rolling activity window can lower the aggregate without a control being removed.

The stale-token scan failure has been repaired. Publication now uses the
short-lived GitHub token. Only public repository metadata and source-analysis
results are published; host audits and private configuration are not inputs.

| Check | Published score | Next useful action |
| --- | --- | --- |
| Code Review | 0 | Obtain independent human review before merging changes. AI review does not count as human approval. |
| Branch Protection | 4 | Recruit a second maintainer before requiring approvals. Existing protections remain active, with review-thread resolution added. |
| CII Best Practices | 0 | Complete the OpenSSF Best Practices questionnaire with evidence and honest answers. No badge is claimed. |
| Contributors | 0 | Attract real independent contributors. Do not create artificial contributors or affiliations. |
| Maintained | 7 | Merge useful, tested changes and maintain the project. Do not create empty commits or artificial issue activity. |
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
