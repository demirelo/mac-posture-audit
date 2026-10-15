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
# It pins the existing signed, SLSA-attested v1.7.0 release tarball by SHA-256.
# The checksum below is the content of the release's published
# `mac-posture-audit-v1.7.0.tar.gz.sha256` asset. When a new version is
# released, bump `url`, `version`, and `sha256` together (the new checksum is
# always attached to the release as `*.tar.gz.sha256`).
class MacPostureAudit < Formula
  desc "Read-only macOS security-posture auditor (single-file bash)"
  homepage "https://github.com/demirelo/mac-posture-audit"
  url "https://github.com/demirelo/mac-posture-audit/releases/download/v1.7.0/mac-posture-audit-v1.7.0.tar.gz"
  version "1.7.0"
  sha256 "9dd7fc65610c8348ccc4992abe46cc78f2a377eb2ff2431ac2dc5d2fc22ad796"
  license "MIT"

  # No runtime dependencies. The auditor is bash 3.2-compatible and uses only
  # tools that ship with macOS. The optional HTML renderer
  # (tools/render_report.py) relies solely on the Apple /usr/bin/python3 from the Xcode
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
