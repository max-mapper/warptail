#!/usr/bin/env bash
# Usage: scripts/e2e.sh <ephemeral-auth-key> [lan|nat]     (normally via ./warptail e2e [nat])
#
# End-to-end proof from a real tailnet client's point of view, standing in for your phone:
# a throwaway Tailscale node (ephemeral, so it disappears from your tailnet afterwards) joins
# with warptail as its exit node, then:
#   1. its internet egress must be WARP (warp=on), and not this host's real IP;
#   2. with WARP cut off inside warptail, its traffic must fail, not go out some other way.
# lan (default): the client joins warptail's Docker network, like a phone on the same Wi-Fi, so
#   the tailnet leg can be direct.
# nat: the client sits on Docker's default bridge, behind the same hard NAT as warptail, like
#   a remote device that can't hole-punch. The tailnet leg then needs DERP or a peer relay.
set -euo pipefail
key="$1" where="${2:-lan}"
C=warptail E=warptail-e2e
SOCK=/var/run/tailscale/tailscaled.sock
TS_IMAGE=tailscale/tailscale:v1.104.7
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; exit 1; }
trace() { docker exec "$E" wget -qO- -T "${1:-10}" https://www.cloudflare.com/cdn-cgi/trace; }

cleanup() {
  # Logging out deletes an ephemeral node from the tailnet right away, instead of leaving it
  # listed as offline until Tailscale garbage-collects it.
  docker exec "$E" tailscale logout >/dev/null 2>&1 || true
  docker rm -f "$E" >/dev/null 2>&1 || true
  if docker exec "$C" nft list chain inet warp output 2>/dev/null | grep e2e >/dev/null; then
    echo "→ restoring: restarting warptail"; docker restart "$C" >/dev/null
  fi
}
trap cleanup EXIT

exit_ip=$(docker exec "$C" tailscale --socket="$SOCK" ip -4)
endpoint=$(docker exec "$C" sh -c '. /run/warp-tunnel/state; echo $ENDPOINT')
real4=$(curl -4 -s --max-time 10 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '$1=="ip"{print $2}' || true)
warp_ip=$(docker exec "$C" curl -s --max-time 10 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '$1=="ip"{print $2}')
echo "warptail tailnet IP $exit_ip, WARP egress $warp_ip, host real IPv4 ${real4:-none}"

# The client joins warptail's Docker network, like a phone on the same Wi-Fi, so the tailnet
# leg can be direct. (From anywhere else in this VM it would sit behind the same hard NAT.)
net=bridge
[[ "$where" == nat ]] || net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$C")
echo "→ starting a throwaway tailnet client on $net that uses warptail as its exit node"
docker rm -f "$E" >/dev/null 2>&1 || true
docker run -d --name "$E" --network "$net" --cap-add NET_ADMIN --device /dev/net/tun \
  -e TS_AUTHKEY="$key" -e TS_USERSPACE=false -e TS_HOSTNAME=warptail-e2e \
  -e TS_EXTRA_ARGS="--exit-node=$exit_ip --accept-dns=true" \
  "$TS_IMAGE" >/dev/null
for i in $(seq 1 60); do
  st=$(docker exec "$E" tailscale status --json 2>/dev/null || true)
  [[ "$(jq -r .BackendState <<<"$st" 2>/dev/null)" == Running && "$(jq -r '.ExitNodeStatus.Online // false' <<<"$st")" == true ]] && break
  ((i < 60)) || fail "client never came up using the exit node: $(docker logs "$E" 2>&1 | tail -5)"
  sleep 2
done
pass "client is on the tailnet with warptail as its exit node"
path=$(docker exec "$E" tailscale ping -c 10 "$exit_ip" 2>&1 | grep -E '^pong' | tail -1 || true)
case "$path" in
  *DERP*) echo "  · tailnet leg relayed by Tailscale DERP: $path" ;;
  *peer-relay*) echo "  · tailnet leg via a peer relay: $path" ;;
  pong*) pass "tailnet leg is direct: $path" ;;
  *) echo "  · could not determine the tailnet path" ;;
esac

echo "1) client egress"
t=$(trace 15) || fail "client could not reach the internet through warptail"
cip=$(awk -F= '$1=="ip"{print $2}' <<<"$t"); cwarp=$(awk -F= '$1=="warp"{print $2}' <<<"$t")
echo "    client sees: ip=$cip warp=$cwarp"
[[ "$cwarp" == on || "$cwarp" == plus ]] || fail "client egress is not WARP"
[[ "$cip" != "$real4" ]] || fail "client egress is this host's real IP"
pass "client traffic exits via WARP, not this host's IP"
docker exec "$E" nslookup -timeout=5 example.com >/dev/null 2>&1 && pass "client DNS works through the exit node" || fail "client DNS failed"

echo "2) WARP cut off inside warptail (drop everything to $endpoint)"
docker exec "$C" nft insert rule inet warp output ip daddr "$endpoint" drop comment '"e2e"'
sleep 3
faulted() { docker exec "$C" nft list chain inet warp output | grep e2e >/dev/null; }
for probe in "HTTPS by hostname:trace 8" \
             "HTTPS to 1.1.1.1:docker exec $E wget -qO- -T 8 https://1.1.1.1/cdn-cgi/trace" \
             "ICMP to 9.9.9.9:docker exec $E ping -c2 -W3 9.9.9.9"; do
  name="${probe%%:*}" cmd="${probe#*:}"
  faulted || fail "fault healed before '$name', inconclusive"
  if eval "$cmd" >/dev/null 2>&1; then fail "$name got through with WARP down"; fi
  pass "$name blocked"
done
pkts=$(docker exec "$C" nft list counter inet warp fwd_blocked | awk '/packets/ {print $2}')
echo "    warptail fwd_blocked counter: $pkts packets"
echo "end-to-end checks passed"
