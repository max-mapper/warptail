# warptail hooks for warp-tunnel (sourced by its entrypoint and healthcheck; see
# vendor/warptorrent/tunnel/lib.sh for the hook contract).
#
# Two kinds of traffic leave this namespace, and they're kept apart:
#
#   1. Exit-node traffic: packets your devices send through tailscale0 to the internet. The
#      kernel forwards them like any other packet. They're unmarked, so they use the main table,
#      whose only default route is the WARP interface. The firewall forwards tailscale0 → WARP
#      and nothing else, and masquerades them to the WARP address. If WARP is down they're
#      unreachable, never sent another way.
#
#   2. Tailscale's own underlay: the WireGuard-encrypted tailnet packets between your phone and
#      this node, plus DERP relays and the control plane. tailscaled tags its own sockets with
#      fwmark 0x80000. A policy rule sends marked packets to a separate table whose default
#      route is the Docker uplink, so the phone↔node leg doesn't get hairpinned through
#      Cloudflare, and stays up while WARP reconnects. The firewall lets marked packets out
#      the uplink, but only what the underlay needs: UDP from tailscaled's own port (WireGuard,
#      disco, STUN, peer relays) and TCP 80/443 (control plane, DERP). DNS ports are dropped and
#      counted, and anything else marked is dropped and counted. Setting a socket mark needs
#      CAP_NET_ADMIN, which only this container's own processes have.
#
# One exception to (2): DNS. When a device uses this exit node, tailscaled answers its DNS
# queries by asking the resolvers in /etc/resolv.conf (1.1.1.1 etc.) from its own marked
# sockets. Policy rules ordered before the mark rule send those resolver addresses through
# WARP too, so your DNS also exits via WARP.

TS_PORT="${TS_PORT:-41642}"
TS_HOSTNAME="${TS_HOSTNAME:-warptail}"
TS_STATE_DIR=/var/lib/tailscale
TS_SOCKET=/var/run/tailscale/tailscaled.sock
# tailscaled's bypass mark (tailscale.com/net/tsconst: LinuxBypassMark, LinuxFwmarkMask).
TS_MARK=0x80000
TS_MASK=0xff0000
UNDERLAY_TABLE=200
TS_AUTHKEY_FILE=/run/secrets/ts_authkey   # compose secret; empty unless TS_AUTHKEY is set in .env

ts() { tailscale --socket="$TS_SOCKET" "$@"; }

hook_firewall() {
  NFT_INPUT="iifname \"tailscale0\" accept
    iifname \"$UPLINK\" udp dport $TS_PORT accept"
  NFT_FORWARD="iifname \"tailscale0\" oifname \"$WARP_IF\" counter name fwd_via_warp accept
    iifname \"$WARP_IF\" oifname \"tailscale0\" ct state established,related accept"
  mk="oifname \"$UPLINK\" meta mark and $TS_MASK == $TS_MARK"
  NFT_OUTPUT="oifname \"tailscale0\" accept
    $mk meta l4proto { tcp, udp } th dport { 53, 853 } counter name underlay_dns_blocked drop
    $mk udp sport $TS_PORT counter name out_underlay accept
    $mk tcp dport { 80, 443 } counter name out_underlay accept
    $mk counter name underlay_blocked drop"
  NFT_EXTRA="
  counter fwd_via_warp {}
  counter out_underlay {}
  counter underlay_dns_blocked {}
  counter underlay_blocked {}

  chain mss {
    type filter hook forward priority mangle; policy accept;
    oifname \"$WARP_IF\" tcp flags syn tcp option maxseg size set rt mtu
    iifname \"$WARP_IF\" tcp flags syn tcp option maxseg size set rt mtu
  }

  chain nat {
    type nat hook postrouting priority srcnat; policy accept;
    oifname \"$WARP_IF\" masquerade
  }"
}

hook_routes() {
  # Underlay table: marked (tailscaled's own) packets leave via the Docker uplink. IPv4 only;
  # marked IPv6 is unreachable rather than falling through to the WARP default.
  ip -4 route replace default via "$GW" dev "$UPLINK" table "$UNDERLAY_TABLE"
  # Peers on the same Docker network (e.g. ./warptail e2e) are reached directly, not via the gateway.
  ip -4 route replace "$BRIDGE" dev "$UPLINK" table "$UNDERLAY_TABLE"
  ip -4 route replace unreachable default metric 4000 table "$UNDERLAY_TABLE"
  # IPv6 rules can fail on hosts without IPv6. Every failure still ends in "via WARP" or
  # "unreachable", never the uplink, but say so instead of failing silently.
  ip -6 route replace unreachable default table "$UNDERLAY_TABLE" 2>/dev/null ||
    log "WARNING: no IPv6 underlay table (IPv6 unavailable?)"
  for d in $WARP_DNS; do
    case "$d" in
      *:*) ip -6 rule add to "$d" lookup main priority 5100 2>/dev/null ||
             log "WARNING: could not add IPv6 DNS rule for $d" ;;
      *)   ip -4 rule add to "$d" lookup main priority 5100 ;;
    esac
  done
  # Before tailscaled's own rules (5210+), so they can never send marked traffic to main.
  ip -4 rule add fwmark "$TS_MARK/$TS_MASK" lookup "$UNDERLAY_TABLE" priority 5200
  ip -6 rule add fwmark "$TS_MARK/$TS_MASK" lookup "$UNDERLAY_TABLE" priority 5200 2>/dev/null ||
    log "WARNING: could not add IPv6 underlay rule"
  log "routing: tailscaled underlay (fwmark $TS_MARK) → table $UNDERLAY_TABLE via $GW; DNS ($WARP_DNS) via $WARP_IF"
}

# Flags that would undo what warptail guarantees: routing this node's traffic through another
# exit node, letting the tailnet change its DNS or routes, or letting tailscaled manage netfilter.
check_extra_args() {
  for a in ${TS_EXTRA_ARGS:-}; do
    case "$a" in
      --exit-node*|--accept-dns*|--accept-routes*|--netfilter-mode*|--reset*|--advertise-exit-node*|--auth-key*|--authkey*)
        die "TS_EXTRA_ARGS may not contain $a (warptail sets it; changing it voids the guarantees)" ;;
    esac
  done
}

hook_start() {
  check_extra_args
  mkdir -p "$TS_STATE_DIR" "$(dirname "$TS_SOCKET")"
  tailscaled --state="$TS_STATE_DIR/tailscaled.state" --socket="$TS_SOCKET" \
    --tun=tailscale0 --port="$TS_PORT" &
  WATCH_PIDS="$WATCH_PIDS $!"
  i=0
  until ts status --json 2>/dev/null | jq -e '.BackendState != "NoState"' >/dev/null; do
    i=$((i + 1)); [ "$i" -le 150 ] || die "tailscaled did not start"
    sleep 0.2
  done
  if ! ip -4 rule show | grep -q "fwmark $TS_MARK/$TS_MASK lookup main"; then
    log "WARNING: tailscaled's bypass mark is not $TS_MARK/$TS_MASK; its underlay will go via WARP"
  fi
  # The auth key is only offered when this node isn't logged in yet, and is passed as a file
  # path, never in a command line (visible in ps) or the container environment (docker inspect).
  key=""
  if [ -s "$TS_AUTHKEY_FILE" ] && ts status --json 2>/dev/null | jq -e '.BackendState == "NeedsLogin"' >/dev/null; then
    key="--auth-key=file:$TS_AUTHKEY_FILE"
    log "logging in with the auth key from .env; you can remove TS_AUTHKEY from .env afterwards"
  fi
  # `up` prints a login URL and waits if this node isn't logged in yet, so don't block on it.
  # --netfilter-mode=off: the warp-tunnel firewall is the only one; tailscaled must not add rules.
  # shellcheck disable=SC2086
  ts up --reset --advertise-exit-node --accept-dns=false --accept-routes=false \
    --netfilter-mode=off --hostname="$TS_HOSTNAME" $key ${TS_EXTRA_ARGS:-} &
}

# tailscaled must be running with its kernel interface: in userspace mode it would forward
# exit-node traffic from its own (marked) sockets instead of through tailscale0.
hook_health() {
  pgrep -x tailscaled >/dev/null && ip link show tailscale0 >/dev/null 2>&1
}
