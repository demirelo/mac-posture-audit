#!/usr/bin/env bash
exit 0
# Tripwire bait: bare `brew tap` (no args) is read-only and allowlisted, but
# `brew tap <name>` installs a third-party tap and must remain rejected.
brew tap homebrew/cask-versions
