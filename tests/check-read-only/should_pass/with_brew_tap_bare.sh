#!/usr/bin/env bash
# `brew tap` with no args lists installed taps — read-only and used by §13
# supply-chain audit. Must be accepted.
exit 0

BREW_TAPS=$(brew tap 2>/dev/null || true)
echo "$BREW_TAPS"
