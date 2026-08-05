# typed: false
# frozen_string_literal: true

# Homebrew formula for mac-posture-audit.
#
# STATUS: ready to publish, not yet live. `brew install
# demirelo/tap/mac-posture-audit` resolves only once this file lives in a
# Homebrew *tap* repository named `demirelo/homebrew-tap`. See
# packaging/homebrew/README.md in this repo for the exact one-time steps to
# create that tap and copy this formula into it.
#
# It pins the existing signed, SLSA-attested v1.6.0 release tarball by SHA-256.
# The checksum below is the content of the release's published
# `mac-posture-audit-v1.6.0.tar.gz.sha256` asset. When a new version is
# released, bump `url`, `version`, and `sha256` together (the new checksum is
# always attached to the release as `*.tar.gz.sha256`).
class MacPostureAudit < Formula
  desc "Read-only macOS security-posture auditor (single-file bash, 183 checks)"
  homepage "https://github.com/demirelo/mac-posture-audit"
  url "https://github.com/demirelo/mac-posture-audit/releases/download/v1.6.0/mac-posture-audit-v1.6.0.tar.gz"
  version "1.6.0"
  sha256 "d3580a9457bcaaf246d28d40c81c7a76a609d7b7639fe2c620ba69ccf9569c64"
  license "MIT"

  # No runtime dependencies. The auditor is bash 3.2-compatible and uses only
  # tools that ship with macOS. The optional HTML renderer
  # (tools/render_report.py) relies solely on the stdlib python3 from the Xcode
  # Command Line Tools, so it is not declared as a formula dependency either.

  def install
    # The signed tarball extracts to a single top-level directory
    # (mac-posture-audit-vX.Y.Z/) that Homebrew strips, leaving the canonical
    # release layout — script + docs + tools + scripts — in the build root.
    bin.install "mac-posture-audit.sh" => "mac-posture-audit"
    pkgshare.install "tools" if File.directory?("tools")
    pkgshare.install "scripts" if File.directory?("scripts")
    doc.install "README.md", "SECURITY.md", "CHANGELOG.md"
    doc.install "docs" if File.directory?("docs")
  end

  test do
    # Read-only, no-scan invocations only — the formula test never runs a full
    # audit. `--version` and `--help` neither read host state nor touch the
    # network, so they are safe in Homebrew's sandboxed test.
    assert_match "mac-posture-audit #{version}", shell_output("#{bin}/mac-posture-audit --version")
    help = shell_output("#{bin}/mac-posture-audit --help")
    assert_match "--json", help
    assert_match "--quick", help
  end
end
