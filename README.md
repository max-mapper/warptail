# warptail

A Tailscale exit node whose internet egress is only Cloudflare WARP, run as one persistent
container on your Mac or Linux box. Point your phone (or any tailnet device) at it as its exit
node, and its traffic leaves the internet from a WARP IP, carried from this machine over MASQUE
(HTTP/3) or WireGuard. If WARP drops, your devices' traffic stops. It never falls back to this
machine's real IP.

```
phone ══ Tailscale (WireGuard, direct or via DERP) ══> warptail ══ WARP (MASQUE or WireGuard) ══> internet
                                                          └─ kill switch: nothing else gets out
```

```
./warptail up            # build, register WARP, start (comes back on its own after reboots)
./warptail status        # WARP egress, tailnet login, exit-node approval
./warptail verify        # routing/firewall checks + kill-switch leaktest
./warptail e2e           # end-to-end test through a throwaway tailnet client
./warptail --wireguard up   # switch to WARP over WireGuard (--masque switches back)
./warptail logs | down | login
```

The WARP tunnel and kill switch come from
[warptorrent](https://github.com/max-mapper/warptorrent)'s reusable `tunnel/` image, pinned as a
git submodule in `vendor/warptorrent`. warptail adds Tailscale on top through the tunnel's hook
interface (`image/hooks.sh`).

## Setup

Requirements: rootful Docker with `docker compose` (or `docker-compose`), bash and git. Tested on
macOS with Colima. Docker Desktop and OrbStack work the same way, as does Docker Engine on Linux
(e.g. Arch: `pacman -S docker docker-compose docker-buildx && systemctl enable --now docker`).
Images are multi-arch (amd64 and arm64).

```
git clone --recursive https://github.com/max-mapper/warptail.git && cd warptail
./warptail up
```

1. `up` registers an anonymous free WARP device into `config/` (no Cloudflare account needed),
   starts the container, and prints a **login link**. Open it and add the node to your tailnet.
   This happens once. The node identity is kept in the `warptail_tailscale-state` Docker volume.
   For a headless setup, put `TS_AUTHKEY=tskey-auth-…` in `.env` before the first `up` instead.
2. In the [admin console](https://login.tailscale.com/admin/machines), open **warptail** →
   **Edit route settings** → tick **Use as exit node**.
3. On your phone: Tailscale → **Exit node** → **warptail**. Then open
   <https://www.cloudflare.com/cdn-cgi/trace>. It should show `warp=on` and an IP that isn't your
   home IP.

**Staying up:** the container has `restart: unless-stopped`, so it survives crashes and reboots as
long as Docker itself starts at boot:
- Colima: `brew services start colima`
- Docker Desktop: Settings → General → *Start Docker Desktop when you sign in*
- Linux: `sudo systemctl enable docker`

`./warptail up` reminds you if this isn't set.

Settings live in `.env` (gitignored, mode 600):

| Variable | Default | |
|---|---|---|
| `WARP_MODE` | `masque` | `masque` or `wireguard` (`--masque` / `--wireguard` set it) |
| `WARP_IPV6` | `1` | carry IPv6 through WARP too (`0` = drop IPv6) |
| `TS_HOSTNAME` | `warptail` | the node's name in your tailnet |
| `TS_PORT` | `41642` | tailscaled's UDP port, published on the host so peers can connect directly (not 41641, so it can't clash with a Tailscale install on the host) |
| `TS_AUTHKEY` | | optional, for logging in without the link |
| `TS_EXTRA_ARGS` | | extra `tailscale up` flags |
| `TS_TEST_AUTHKEY` | | ephemeral auth key used only by `./warptail e2e` |

## How it works

One container, one network namespace, two kinds of traffic kept apart:

```
                 ┌──────────────── warptail container (own network namespace) ────────────────┐
 your phone ═══> │ tailscale0 ──forward──> warp0 ══ MASQUE/WireGuard ══> Cloudflare WARP ──> internet
 (tailnet)       │      ▲                    nftables: forward ONLY tailscale0 → warp0 (+ NAT)  │
                 │  tailscaled ──underlay (fwmark 0x80000)──> eth0 ──> Docker ──> your router   │
                 └─────────────────────────────────────────────────────────────────────────────┘
```

1. **Exit-node traffic** (what your phone browses) arrives on `tailscale0` and is forwarded by
   the kernel. It's unmarked, so it uses the main routing table. That table has no default route
   except `warp0`, plus an `unreachable` fallback. The nftables forward chain (policy drop)
   accepts only `tailscale0 → warp0` and masquerades it to the WARP address. With WARP down,
   these packets have no route and no firewall rule that lets them out.
2. **Tailscale's own underlay** is the WireGuard-encrypted phone↔node packets, plus DERP and the
   control plane. tailscaled tags all its own sockets with fwmark `0x80000`. A policy rule
   (priority 5200, ahead of tailscaled's own rules) sends marked packets to table 200, whose
   default route is the Docker uplink. The output chain lets marked packets out the uplink.
   Setting a socket mark needs `CAP_NET_ADMIN`, which only this container's processes have.
   Doing it this way keeps the phone↔node leg direct instead of hairpinning it through
   Cloudflare, and keeps the tailnet connected while WARP reconnects.
3. **DNS:** a device using an exit node sends its DNS to the exit node, and tailscaled resolves it
   with the container's resolvers (1.1.1.1 / 1.0.0.1 and the IPv6 equivalents) from marked
   sockets. Rules at priority 5100 send those resolver addresses through `warp0` regardless of
   mark, so DNS exits via WARP too, and is unreachable when WARP is down.

The base kill switch (default-drop nftables on input, forward and output, no default route, only
the WARP endpoint reachable on the uplink) comes from warptorrent's tunnel image. warptail's hooks
can only add rules ahead of its final drops. tailscaled runs with `--netfilter-mode=off`, so it
never touches the firewall.

## Verifying it

- `./warptail verify` runs inside the container and asks the kernel where each kind of traffic
  would go (`ip route get … iif tailscale0`, `… mark 0x80000`). It checks that every chain is
  policy drop, shows the login and approval state, and prints the packet counters, including
  `fwd_blocked` (forwarded packets that tried to leave by anything other than `warp0`). Then it
  runs warptorrent's leaktest. That test simulates a WARP outage and takes `warp0` down, and in
  both cases HTTPS, DNS and ICMP probes must all fail.
- `./warptail e2e` is the closest thing to your phone. It starts a throwaway, ephemeral tailnet
  client in Docker that uses warptail as its exit node. It checks that the client's egress is
  `warp=on` and not this machine's IP, and that DNS works. Then it cuts WARP inside warptail and
  checks that the client's HTTPS and ICMP traffic fail rather than leak. Needs `TS_TEST_AUTHKEY`:
  admin console → Settings → Keys → *Generate auth key*, with **Ephemeral** on and **Reusable** off.
- From the phone: <https://www.cloudflare.com/cdn-cgi/trace> shows `warp=on`, and
  <https://test-ipv6.com> shows Cloudflare addresses for both IPv4 and IPv6.

## Verified (2026-11-13, macOS, Docker via Colima on arm64)

- `./warptail verify`: all checks pass. IPv4 and IPv6 egress are WARP (`warp=on`). Exit-node
  traffic from the tailnet routes to `warp0` and tailscaled's underlay to the uplink. Exit-node
  DNS (marked) routes to `warp0`. The leaktest passes in both MASQUE and WireGuard modes.
- `./warptail e2e`: the throwaway client's egress was the WARP IP (`warp=on`), not the host's,
  and its DNS worked. With WARP cut off inside warptail, its HTTPS (by hostname and to 1.1.1.1)
  and ICMP were all blocked.

## Caveats

- **WARP is a privacy relay, not an anonymity network.** Websites see a Cloudflare IP, but
  Cloudflare sees this machine's real IP. WARP exit IPs also geolocate near you.
- **Tailscale's underlay is not hidden.** Your ISP (and the Wi-Fi your phone is on) can see that
  the phone talks to this machine over Tailscale, though not what's inside. Only the exit-node
  traffic goes through WARP.
- **Direct connections behind Colima / Docker Desktop.** The container sits behind the VM's NAT
  as well as your router's. If a direct path can't be punched, Tailscale relays over DERP, which
  still works but is slower. `docker exec warptail tailscale --socket=/var/run/tailscale/tailscaled.sock netcheck`
  shows what it found. On Linux the published UDP port makes direct connections easy.
- **MASQUE depends on usque**, which describes itself as unstable. If it misbehaves, run
  `./warptail --wireguard up`.
- **`config/` and the `warptail_tailscale-state` volume hold secrets** (WARP keys, tailnet node key).
