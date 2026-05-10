#!/usr/bin/env bats

load '../helpers'

@test "NextDNS profile passes in offline mode" {
  load_script
  mock_cli profiles profiles/nextdns.txt
  mock_cli scutil scutil/dns.txt
  mock_cli_script pgrep '#!/usr/bin/env bash
exit 1'

  section_06_dns_outbound

  assert_recorded pass "NextDNS profile installed (offline mode"
  assert_recorded skip "Active resolver(s):"
  # network.dns.encrypted: NextDNS profile is enough to flip this to PASS.
  assert_recorded pass "Encrypted DNS"
  assert_recorded warn "No outbound network monitor detected"
}

@test "live NextDNS check passes without a profile when network mode is enabled" {
  load_script
  mock_cli profiles profiles/empty.txt
  mock_cli system_profiler profiles/empty.txt
  mock_cli scutil scutil/empty.txt
  mock_cli_script curl '#!/usr/bin/env bash
printf "%s\n" "{\"status\":\"ok\",\"protocol\":\"DOH\"}"'
  mock_cli_script pgrep '#!/usr/bin/env bash
exit 1'
  NETWORK=true

  section_06_dns_outbound

  assert_recorded pass "NextDNS active via live test"
  # No profile + no VPN + plaintext resolvers -> network.dns.encrypted warns.
  assert_recorded warn "Plaintext DNS"
}

@test "no NextDNS, no DoH/DoT profile, no VPN -> network.dns.encrypted WARNs" {
  load_script
  mock_cli profiles profiles/empty.txt
  mock_cli system_profiler profiles/empty.txt
  mock_cli scutil scutil/empty.txt
  mock_cli_script pgrep '#!/usr/bin/env bash
exit 1'

  section_06_dns_outbound

  assert_recorded warn "Plaintext DNS — every query is visible"
}

@test "no encrypted DNS but VPN running -> network.dns.encrypted SKIPs with VPN caveat" {
  load_script
  mock_cli profiles profiles/empty.txt
  mock_cli system_profiler profiles/empty.txt
  mock_cli scutil scutil/empty.txt
  # pgrep matches ProtonVPN
  mock_cli_script pgrep '#!/usr/bin/env bash
case "$*" in
  *ProtonVPN*) exit 0 ;;
  *) exit 1 ;;
esac'

  section_06_dns_outbound

  assert_recorded skip "Plaintext DNS resolvers, but VPN is running"
}
