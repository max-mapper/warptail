#!/bin/sh
# warptail-verify: run inside the container (./warptail verify does). It checks the kernel's own
# answers about where each kind of traffic would go, plus the firewall and Tailscale state.
# Exit status 0 = every check passed.
. /usr/local/lib/warp-tunnel/lib.sh
. /etc/warp-tunnel/hooks.sh
. /run/warp-tunnel/state

fails=0
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; fails=$((fails + 1)); }
# expect_dev <description> <expected-dev> <ip route get args...>
expect_dev() {
  desc="$1" want="$2"; shift 2
  got=$(ip route get "$@" 2>&1 | head -1)
  case "$got" in
    *" dev $want "*|*" dev $want") pass "$desc → $want" ;;
    *) fail "$desc: expected dev $want, got: $got" ;;
  esac
}
expect_unroutable() {
  desc="$1"; shift
  if got=$(ip route get "$@" 2>&1) && ! echo "$got" | grep -q unreachable; then
    fail "$desc: expected unreachable, got: $got"
  else
    pass "$desc → unreachable"
  fi
}

echo "WARP egress (mode $MODE, interface $WARP_IF, endpoint $ENDPOINT:$EP_PORT)"
t=$(curl -4 -s --max-time 8 https://www.cloudflare.com/cdn-cgi/trace)
echo "$t" | grep -Eq '^warp=(on|plus)$' && pass "IPv4 trace: $(echo "$t" | grep -E '^(ip|colo|warp)=' | tr '\n' ' ')" || fail "trace says egress is not WARP"
if [ "$WARP_IPV6" = 1 ]; then
  t6=$(curl -6 -s --max-time 8 https://www.cloudflare.com/cdn-cgi/trace)
  echo "$t6" | grep -Eq '^warp=(on|plus)$' && pass "IPv6 trace: $(echo "$t6" | grep -E '^(ip|warp)=' | tr '\n' ' ')" || fail "IPv6 egress is not WARP"
fi

echo "DNS"
warp_resolv_ok && pass "resolv.conf lists only the tunnel resolvers ($WARP_DNS)" ||
  fail "resolv.conf has drifted from $WARP_DNS: $(awk '$1=="nameserver"{printf "%s ", $2}' /etc/resolv.conf)"

echo "Firewall (nftables table inet warp)"
for c in input forward output; do
  nft list chain inet warp "$c" 2>/dev/null | grep -q "hook $c priority filter; policy drop;" &&
    pass "$c chain: policy drop" || fail "$c chain missing or not policy drop"
done
others=$(nft list tables | grep -v '^table inet warp$' | tr '\n' ' ')
[ -z "$others" ] && pass "no other nftables tables" ||
  echo "  · also loaded: ${others}(Docker's embedded-DNS NAT for 127.0.0.11; our output chain drops 127.0.0.11, and a packet our table drops stays dropped whatever other tables say)"

echo "Routing decisions"
ts_ip=$(ts ip -4 2>/dev/null | head -1)
peer4=100.64.0.7; peer6=fd7a:115c:a1e0::7
if [ -z "$ts_ip" ]; then
  echo "  · exit-node path checks skipped: tailscale0 has no address until this node is logged in"
elif ip link show tailscale0 >/dev/null 2>&1; then
  expect_dev "exit-node traffic (from tailnet, to 9.9.9.9)" "$WARP_IF" 9.9.9.9 from "$peer4" iif tailscale0
  expect_dev "exit-node traffic (from tailnet, to the WARP endpoint IP)" "$UPLINK" "$ENDPOINT" from "$peer4" iif tailscale0
  echo "    (allowed by routing, but the firewall forwards only tailscale0 → $WARP_IF)"
  [ "$WARP_IPV6" = 1 ] && expect_dev "exit-node IPv6 traffic (to 2620:fe::9)" "$WARP_IF" 2620:fe::9 from "$peer6" iif tailscale0
else
  fail "tailscale0 does not exist"
fi
expect_dev "this container's own traffic" "$WARP_IF" 9.9.9.9
expect_dev "tailscaled underlay (marked)" "$UPLINK" 9.9.9.9 mark "$TS_MARK"
for d in $WARP_DNS; do
  case "$d" in *:*) [ "$WARP_IPV6" = 1 ] || continue ;; esac
  expect_dev "exit-node DNS via tailscaled (marked, to $d)" "$WARP_IF" "$d" mark "$TS_MARK"
done
[ "$WARP_IPV6" = 1 ] && expect_unroutable "tailscaled underlay over IPv6" 2620:fe::9 mark "$TS_MARK"

echo "Tailscale"
ip -4 rule show | grep -q "fwmark $TS_MARK/$TS_MASK lookup main" &&
  pass "tailscaled uses bypass mark $TS_MARK/$TS_MASK" || fail "tailscaled's bypass mark differs from $TS_MARK/$TS_MASK"
st=$(ts status --json 2>/dev/null)
state=$(echo "$st" | jq -r .BackendState)
case "$state" in
  Running) pass "logged in as $(echo "$st" | jq -r '.Self.DNSName') ($ts_ip)" ;;
  NeedsLogin) fail "not logged in yet: open the login URL from ./warptail login" ;;
  *) fail "tailscale state: $state" ;;
esac
if [ "$state" = Running ]; then
  echo "$st" | jq -e '.Self.AllowedIPs // [] | index("0.0.0.0/0")' >/dev/null &&
    pass "approved as an exit node" ||
    fail "exit node advertised but not approved yet: approve it in the Tailscale admin console (Machines → $TS_HOSTNAME → Edit route settings → Use as exit node)"
fi

echo "Counters (packets/bytes since start)"
pkts() { nft list counter inet warp "$1" 2>/dev/null | awk '/packets/ {print $2}'; }
for c in fwd_via_warp fwd_blocked out_underlay underlay_blocked out_tunnel out_blocked in_blocked; do
  printf '  %-21s %s\n' "$c" "$(nft list counter inet warp "$c" 2>/dev/null | awk '/packets/ {print $2" pkts, "$4" bytes"}')"
done
echo "  fwd_blocked: forwarded packets that tried to leave by anything other than $WARP_IF."
echo "  underlay_blocked: tailscaled packets outside its UDP port and TCP 80/443 (e.g. router port-mapping probes)."
# Blocked, so nothing leaked, but either one means something tried to resolve outside WARP.
for c in docker_dns_blocked underlay_dns_blocked; do
  n=$(pkts "$c")
  [ "${n:-0}" -eq 0 ] && pass "$c: 0 (no DNS attempted outside WARP)" ||
    fail "$c: $n packets of DNS tried to bypass WARP (blocked; check resolv.conf and TS_EXTRA_ARGS)"
done

[ "$fails" -eq 0 ] && echo "all checks passed" || { echo "$fails check(s) failed"; exit 1; }
