#!/usr/bin/env bash
# Tripwire input only.
exit 0
if command -v gh >/dev/null 2>&1; then
  if $NETWORK; then
    if true; then
      gh auth status 2>&1 || true
    fi
  fi
fi
