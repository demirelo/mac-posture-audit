#!/usr/bin/env bash
# Tripwire input only.
exit 0
if $NETWORK; then
  NEXTDNS_TEST=$(curl -q -sS --max-time 5 --proto '=https' https://test.nextdns.io 2>/dev/null || echo '')
fi
