# OpenSSF Best Practices assessment

Assessment date: 2026-10-15. Scope: passing-level criteria for the public
mac-posture-audit repository and v1.7.0 release.

The [registered assessment](https://www.bestpractices.dev/projects/15528) was
saved at **81% complete**, with status **in progress**, on 2026-10-15.
It has not earned a passing badge. The saved answers match
[.bestpractices.json](../.bestpractices.json): 47 Met, 6 N/A, 1 Unmet and 13
unknown. Unknown (`?`) answers are deliberately ignored by import automation.
Keep them unknown until supported; do not advertise passing before it is earned.

The criterion identifiers and requirements come from the
[OpenSSF Best Practices badge contributors](https://www.bestpractices.dev/en/criteria/0).
See the [import format](https://github.com/ossf/best-practices-badge/blob/main/docs/bestpractices-json.md).
Justifications below are project-specific evidence, not copies of the criteria.

## Proposed supported answers

| Criterion | Proposed answer | Evidence and limit |
| --- | --- | --- |
| `build` | N/A | The delivered Bash audit and Python companion run directly from source; no compiler or build is required for use. Creating the release archive uses standard tar and gzip. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md#install) |
| `build_common_tools` | N/A | The delivered Bash audit and Python companion run directly from source; no compiler or build is required for use. Creating the release archive uses standard tar and gzip. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md#install) |
| `build_floss_tools` | N/A | The delivered Bash audit and Python companion run directly from source; no compiler or build is required for use. Creating the release archive uses standard tar and gzip. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md#install) |
| `contribution` | Met | The contribution guide explains issues, pull requests, coding rules, tests and review. English reports are accepted. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/CONTRIBUTING.md) |
| `contribution_requirements` | Met | The contribution guide explains issues, pull requests, coding rules, tests and review. English reports are accepted. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/CONTRIBUTING.md) |
| `crypto_call` | Met | The audit implements no cryptographic primitive. Optional HTTPS uses curl; release integrity uses SHA-256 and established Sigstore tooling. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/SECURITY.md) |
| `crypto_floss` | Met | The audit implements no cryptographic primitive. Optional HTTPS uses curl; release integrity uses SHA-256 and established Sigstore tooling. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/SECURITY.md) |
| `crypto_password_storage` | N/A | The project implements no external-user authentication store and generates no cryptographic keys or nonces. Snapshot uniqueness is not an authentication mechanism. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/SECURITY.md) |
| `crypto_published` | Met | The audit implements no cryptographic primitive. Optional HTTPS uses curl; release integrity uses SHA-256 and established Sigstore tooling. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/SECURITY.md) |
| `crypto_random` | N/A | The project implements no external-user authentication store and generates no cryptographic keys or nonces. Snapshot uniqueness is not an authentication mechanism. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/SECURITY.md) |
| `crypto_weaknesses` | Met | The audit has no default cryptographic protocol or legacy cipher implementation; release hashing uses SHA-256. Optional network operations rely on platform HTTPS. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/.github/workflows/release.yml) |
| `crypto_working` | Met | The audit has no default cryptographic protocol or legacy cipher implementation; release hashing uses SHA-256. Optional network operations rely on platform HTTPS. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/.github/workflows/release.yml) |
| `delivery_mitm` | Met | Source and release assets are delivered over HTTPS. SHA-256 checksums, Sigstore signatures and GitHub provenance are published; no HTTP-only hash verification is documented. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md#inspect-before-running) |
| `delivery_unsigned` | Met | Source and release assets are delivered over HTTPS. SHA-256 checksums, Sigstore signatures and GitHub provenance are published; no HTTP-only hash verification is documented. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md#inspect-before-running) |
| `description_good` | Met | The README describes the offline audit, installation, CLI flags, output and safe use. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md) |
| `discussion` | Met | GitHub issues and PR discussions provide public, searchable, URL-addressable feedback and review. [Source](https://github.com/demirelo/mac-posture-audit/issues) |
| `documentation_basics` | Met | The README describes the offline audit, installation, CLI flags, output and safe use. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md) |
| `documentation_interface` | Met | The README describes the offline audit, installation, CLI flags, output and safe use. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/README.md) |
| `dynamic_analysis` | Met | ClusterFuzzLite runs an Atheris harness against the production strict loader and renderer. Unexpected accepted-document failures crash the harness. Tests contain assertions. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/.clusterfuzzlite/fuzz_render_report.py) |
| `dynamic_analysis_enable_assertions` | Met | ClusterFuzzLite runs an Atheris harness against the production strict loader and renderer. Unexpected accepted-document failures crash the harness. Tests contain assertions. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/.clusterfuzzlite/fuzz_render_report.py) |
| `dynamic_analysis_unsafe` | N/A | The project produces Bash and Python source, not C or C++ software. Its fuzz workflow still uses sanitizer configurations. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/.github/workflows/cflite_pr.yml) |
| `english` | Met | The contribution guide explains issues, pull requests, coding rules, tests and review. English reports are accepted. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/CONTRIBUTING.md) |
| `floss_license` | Met | The public source and tests use the OSI-approved MIT license in the root LICENSE file. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/LICENSE) |
| `floss_license_osi` | Met | The public source and tests use the OSI-approved MIT license in the root LICENSE file. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/LICENSE) |
| `interact` | Met | The contribution guide explains issues, pull requests, coding rules, tests and review. English reports are accepted. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/CONTRIBUTING.md) |
| `license_location` | Met | The public source and tests use the OSI-approved MIT license in the root LICENSE file. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/LICENSE) |
| `maintained` | Met | The project published v1.7.0 and merged tested fixes on 2026-10-15. [Source](https://github.com/demirelo/mac-posture-audit/releases/tag/v1.7.0) |
| `release_notes` | Met | Versioned Git tags and GitHub releases have human-readable change summaries. [Source](https://github.com/demirelo/mac-posture-audit/releases) |
| `repo_distributed` | Met | The public Git repository uses HTTPS and records authors, timestamps, interim commits and pull requests. [Source](https://github.com/demirelo/mac-posture-audit/commits/main/) |
| `repo_interim` | Met | The public Git repository uses HTTPS and records authors, timestamps, interim commits and pull requests. [Source](https://github.com/demirelo/mac-posture-audit/commits/main/) |
| `repo_public` | Met | The public Git repository uses HTTPS and records authors, timestamps, interim commits and pull requests. [Source](https://github.com/demirelo/mac-posture-audit/commits/main/) |
| `repo_track` | Met | The public Git repository uses HTTPS and records authors, timestamps, interim commits and pull requests. [Source](https://github.com/demirelo/mac-posture-audit/commits/main/) |
| `report_archive` | Met | GitHub issues and PR discussions provide public, searchable, URL-addressable feedback and review. [Source](https://github.com/demirelo/mac-posture-audit/issues) |
| `report_process` | Met | GitHub issues and PR discussions provide public, searchable, URL-addressable feedback and review. [Source](https://github.com/demirelo/mac-posture-audit/issues) |
| `report_tracker` | Met | GitHub issues and PR discussions provide public, searchable, URL-addressable feedback and review. [Source](https://github.com/demirelo/mac-posture-audit/issues) |
| `sites_https` | Met | The public Git repository uses HTTPS and records authors, timestamps, interim commits and pull requests. [Source](https://github.com/demirelo/mac-posture-audit/commits/main/) |
| `static_analysis` | Met | Required PR CI runs ShellCheck and Python CodeQL. The tagged release validation also runs the safety suite before publication. [Source](https://github.com/demirelo/mac-posture-audit/actions/workflows/codeql.yml) |
| `static_analysis_common_vulnerabilities` | Met | Required PR CI runs ShellCheck and Python CodeQL. The tagged release validation also runs the safety suite before publication. [Source](https://github.com/demirelo/mac-posture-audit/actions/workflows/codeql.yml) |
| `static_analysis_often` | Met | Required PR CI runs ShellCheck and Python CodeQL. The tagged release validation also runs the safety suite before publication. [Source](https://github.com/demirelo/mac-posture-audit/actions/workflows/codeql.yml) |
| `test` | Met | The documented scripts/test.sh entry point runs Bats, Python tests, ShellCheck, shfmt and safety fixtures in required PR CI. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/scripts/test.sh) |
| `test_continuous_integration` | Met | The documented scripts/test.sh entry point runs Bats, Python tests, ShellCheck, shfmt and safety fixtures in required PR CI. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/scripts/test.sh) |
| `test_invocation` | Met | The documented scripts/test.sh entry point runs Bats, Python tests, ShellCheck, shfmt and safety fixtures in required PR CI. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/scripts/test.sh) |
| `test_most` | Unmet | Broad branch coverage has not been measured. The number of test cases is not a branch-coverage percentage. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/scripts/test.sh) |
| `test_policy` | Met | New checks require automated fixtures, including error, privacy and profile behavior where applicable. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/CONTRIBUTING.md#adding-a-new-check) |
| `tests_are_added` | Met | The recent runtime hardening added regression tests for untrusted reports, unsafe writes, macOS version handling and false positives. [Source](https://github.com/demirelo/mac-posture-audit/pull/51/files) |
| `tests_documented_added` | Met | New checks require automated fixtures, including error, privacy and profile behavior where applicable. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/CONTRIBUTING.md#adding-a-new-check) |
| `version_semver` | Met | Versioned Git tags and GitHub releases have human-readable change summaries. [Source](https://github.com/demirelo/mac-posture-audit/releases) |
| `version_tags` | Met | Versioned Git tags and GitHub releases have human-readable change summaries. [Source](https://github.com/demirelo/mac-posture-audit/releases) |
| `version_unique` | Met | Versioned Git tags and GitHub releases have human-readable change summaries. [Source](https://github.com/demirelo/mac-posture-audit/releases) |
| `vulnerability_report_private` | Met | SECURITY.md documents private GitHub reporting, an alternate contact, scope and acknowledgement target. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/SECURITY.md#reporting-a-vulnerability) |
| `vulnerability_report_process` | Met | SECURITY.md documents private GitHub reporting, an alternate contact, scope and acknowledgement target. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/SECURITY.md#reporting-a-vulnerability) |
| `warnings` | Met | CI treats ShellCheck warning-level findings and shfmt differences as failures; scripts also use Bash strict options. Informational/style-only linter rules are not all enabled. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/scripts/test.sh) |
| `warnings_fixed` | Met | CI treats ShellCheck warning-level findings and shfmt differences as failures; scripts also use Bash strict options. Informational/style-only linter rules are not all enabled. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/scripts/test.sh) |
| `warnings_strict` | Met | CI treats ShellCheck warning-level findings and shfmt differences as failures; scripts also use Bash strict options. Informational/style-only linter rules are not all enabled. [Source](https://github.com/demirelo/mac-posture-audit/blob/main/scripts/test.sh) |

## Answers that remain unknown

No private reports, credentials, or host results are included in this assessment.
The maintainer can confirm process history without publishing report contents.

| Criterion | Evidence still needed |
| --- | --- |
| `crypto_keylength` | The optional HTTPS client delegates negotiation to macOS curl. An application-enforced cryptographic parameter policy has not been established. |
| `crypto_pfs` | The optional HTTPS client delegates negotiation to macOS curl; forward-secrecy behavior has not been verified. |
| `dynamic_analysis_fixed` | Confirm historical severity and fix-time evidence for fuzz findings; a successful run alone is insufficient. |
| `enhancement_responses` | Confirm response history for enhancement requests through all supported channels. |
| `know_common_errors` | A primary human developer must confirm knowledge of relevant vulnerability classes and mitigations. |
| `know_secure_design` | A primary human developer must confirm understanding of all secure-design principles required by this criterion; AI analysis is not that attestation. |
| `no_leaked_credentials` | Current-source and release scans passed, but a complete credential/history attestation remains pending. Do not infer credential validity from pattern matching. |
| `release_notes_vulns` | Confirm the complete public advisory/CVE history before asserting that every applicable release note identifies it. |
| `report_responses` | The public issue archive was empty at the assessment date; confirm reports received through any other channel and the applicable review period. |
| `static_analysis_fixed` | Confirm historical severity and fix-time evidence for exploitable findings; a current green scan alone is insufficient. |
| `vulnerabilities_critical_fixed` | A response policy alone does not establish historical critical-vulnerability fix times. |
| `vulnerabilities_fixed_60_days` | Confirm the complete vulnerability history and whether any medium-or-higher public issue remains unpatched beyond the allowed interval. |
| `vulnerability_report_response` | The seven-day policy is documented, but actual private response times in the last six months require maintainer confirmation. |

## Scorecard effects and review limits

Scorecard gives an enrolled in-progress badge 2/10, passing 5/10, silver 7/10,
and gold 10/10. A local proposal alone receives no credit. The published scan at
2026-10-15 20:39:12 UTC detected this registration and scored Best Practices
**2/10**, up from 0. The rounded overall score remained **8.3/10**.
The unknown mandatory criteria above prevent claiming passing today.

Code-Review requires a second human; AI review does not count. GitHub prevents
an author from approving their own pull request. The only current maintainer is
`demirelo`; CODEOWNERS routes external contributions to that real owner, but
cannot create an independent reviewer for owner-authored changes. CI remains
mandatory, and zero is retained until qualifying review evidence exists.

Contributors measures recent, substantive participation from real organizations.
No contributor identity, affiliation or historical attribution is created or
changed for this assessment. The maintainer's profile remains unchanged.

[Scorecard rules](https://github.com/ossf/scorecard/blob/v5.5.0/docs/checks.md)
explain these distinct requirements.
