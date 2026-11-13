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
#      the uplink. Setting a socket mark needs CAP_NET_ADMIN, which only this container's own
#      processes have.
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

ts() { tailscale --socket="$TS_SOCKET" "$@"; }

hook_firewall() {
  NFT_INPUT="iifname \"tailscale0\" accept
    iifname \"$UPLINK\" udp dport $TS_PORT accept"
  NFT_FORWARD="iifname \"tailscale0\" oifname \"$WARP_IF\" counter name fwd_via_warp accept
    iifname \"$WARP_IF\" oifname \"tailscale0\" ct state established,related accept"
  NFT_OUTPUT="oifname \"tailscale0\" accept
    oifname \"$UPLINK\" meta mark and $TS_MASK == $TS_MARK counter name out_underlay accept"
  NFT_EXTRA="
  counter fwd_via_warp {}
  counter out_underlay {}

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
  ip -4 route replace unreachable default metric 4000 table "$UNDERLAY_TABLE"
  ip -6 route replace unreachable default table "$UNDERLAY_TABLE" 2>/dev/null || true
  for d in $WARP_DNS; do
    case "$d" in
      *:*) ip -6 rule add to "$d" lookup main priority 5100 2>/dev/null || true ;;
      *)   ip -4 rule add to "$d" lookup main priority 5100 ;;
    esac
  done
  # Before tailscaled's own rules (5210+), so they can never send marked traffic to main.
  ip -4 rule add fwmark "$TS_MARK/$TS_MASK" lookup "$UNDERLAY_TABLE" priority 5200
  ip -6 rule add fwmark "$TS_MARK/$TS_MASK" lookup "$UNDERLAY_TABLE" priority 5200 2>/dev/null || true
  log "routing: tailscaled underlay (fwmark $TS_MARK) → table $UNDERLAY_TABLE via $GW; DNS ($WARP_DNS) via $WARP_IF"
}

hook_start() {
  mkdir -p "$TS_STATE_DIR" "$(dirname "$TS_SOCKET")"
  tailscaled --state="$TS_STATE_DIR/tailscaled.state" --socket="$TS_SOCKET" \
    --tun=tailscale0 --port="$TS_PORT" &
  WATCH_PIDS="$WATCH_PIDS $!"
  i=0
  until ts status --json >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -le 150 ] || die "tailscaled did not start"
    sleep 0.2
  done
  if ! ip -4 rule show | grep -q "fwmark $TS_MARK/$TS_MASK lookup main"; then
    log "WARNING: tailscaled's bypass mark is not $TS_MARK/$TS_MASK; its underlay will go via WARP"
  fi
  # `up` prints a login URL and waits if this node isn't logged in yet, so don't block on it.
  # --netfilter-mode=off: the warp-tunnel firewall is the only one; tailscaled must not add rules.
  # shellcheck disable=SC2086
  ts up --reset --advertise-exit-node --accept-dns=false --accept-routes=false \
    --netfilter-mode=off --hostname="$TS_HOSTNAME" \
    ${TS_AUTHKEY:+--auth-key="$TS_AUTHKEY"} ${TS_EXTRA_ARGS:-} &
}

hook_health() {
  pgrep -x tailscaled >/dev/null
}
