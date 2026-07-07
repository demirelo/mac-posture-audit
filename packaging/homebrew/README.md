# Homebrew packaging

This directory holds a ready-to-publish Homebrew formula
([`mac-posture-audit.rb`](mac-posture-audit.rb)) pinned to the signed,
SLSA-attested **v1.6.0** release tarball by SHA-256.

The formula is not live yet. Homebrew resolves `brew install
demirelo/tap/mac-posture-audit` only when the formula lives in a **tap**
repository named `demirelo/homebrew-tap`. Creating that repository is a
one-time manual step (it's a new repo, intentionally left for a human to
create). Everything else is done.

## One-time: create the tap and publish

```bash
# 1. Create the tap repo (Homebrew requires the `homebrew-` name prefix; the
#    `tap` shorthand in `demirelo/tap/...` expands to `demirelo/homebrew-tap`).
gh repo create demirelo/homebrew-tap --public \
  --description "Homebrew tap for demirelo's tools"

# 2. Clone it and add the formula under Formula/.
git clone https://github.com/demirelo/homebrew-tap
mkdir -p homebrew-tap/Formula
cp packaging/homebrew/mac-posture-audit.rb homebrew-tap/Formula/mac-posture-audit.rb

# 3. Commit and push.
cd homebrew-tap
git add Formula/mac-posture-audit.rb
git commit -m "Add mac-posture-audit formula (pinned to v1.6.0 signed release)"
git push
```

That's it — users can now run:

```bash
brew install demirelo/tap/mac-posture-audit
mac-posture-audit --quick
```

## Verifying the pin before publishing

The `sha256` in the formula is the content of the release's published
`mac-posture-audit-v1.6.0.tar.gz.sha256` asset. To re-verify it yourself:

```bash
gh release download v1.6.0 --repo demirelo/mac-posture-audit \
  --pattern 'mac-posture-audit-v1.6.0.tar.gz' --dir /tmp/mpa-verify
shasum -a 256 /tmp/mpa-verify/mac-posture-audit-v1.6.0.tar.gz
# Expect: d3580a9457bcaaf246d28d40c81c7a76a609d7b7639fe2c620ba69ccf9569c64
```

For the full supply-chain verification (cosign signature + SLSA provenance),
see [`SECURITY.md`](../../SECURITY.md).

## Updating the formula on a new release

When a new version is tagged and `release.yml` publishes its assets, bump three
lines in `Formula/mac-posture-audit.rb` in the tap repo:

- `url` — point at the new `vX.Y.Z` tarball.
- `version` — the new `X.Y.Z`.
- `sha256` — the content of the new `*.tar.gz.sha256` release asset.

A future improvement is to have `release.yml` open that bump as a PR against the
tap automatically; until then it's a three-line manual edit.
