#!/usr/bin/env bash
# `gh auth status` is read-only, but may contact GitHub. It must therefore be
# guarded by the explicit NETWORK opt-in.
exit 0

if $NETWORK; then
  gh auth status >/dev/null 2>&1 || true
fi
