# warptail security review

**Date:** 2026-11-13
**Scope:** `~/src/warptail` at `d47d400`, including the vendored tunnel image `vendor/warptorrent` at `b70baff`.
**Method:** static reading of the repo's scripts, compose file and Dockerfiles only. Nothing was run, no network was used, and one reviewer did the whole pass.
**Limit:** tailscaled, usque and Docker are not in the repo. Findings that depend on their internals are marked *unconfirmed* and say what would confirm them.

## What the project promises

From the README:

1. Devices using warptail as their exit node reach the internet only through Cloudflare WARP.
2. If WARP drops, their traffic stops. It never falls back to this machine's real IP.
3. Their DNS also exits through WARP, and is unreachable when WARP is down.
4. The WARP keys and the tailnet node key are kept secret.

## Verdict

I found **no path in the default configuration that sends a client's forwarded packets out with the real IP.** The forward chain accepts exactly one direction (`tailscale0 → warp0`), and the main routing table has no route to the uplink other than the WARP endpoint. That part is sound.

The weak point is everything tailscaled sends from its own sockets. The firewall lets any packet carrying tailscaled's mark out the uplink, to any destination, on any port. Promise 3 (DNS) therefore rests on routing rules alone, with no firewall rule behind it. Two findings (F1, F2) describe ways DNS could leave outside WARP without any counter or test noticing. Neither is confirmed to happen today.

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | Docker's built-in resolver at `127.0.0.11` is reachable and bypasses WARP | Medium | Latent: needs `/etc/resolv.conf` to be regenerated |
| F2 | Marked traffic is allowed out the uplink without limits; DNS relies on a destination list | Medium | Unconfirmed: depends on tailscaled internals |
| F3 | Nothing tests the marked-traffic path, and block counters aren't asserted | Medium | Confirmed (test gap) |
| F4 | Auth keys are exposed in process arguments and container config | Low–Medium | Confirmed |
| F5 | Build inputs aren't pinned to hashes | Low | Confirmed |
| F6 | Container runs with more privilege than it needs | Low | Confirmed |
| F7 | `TS_EXTRA_ARGS` can undo safety flags | Low | Confirmed (footgun) |
| F8 | Smaller items | Info | — |

---

## F1. Docker's built-in resolver bypasses WARP (Medium, latent)

**What:** On a compose network, Docker runs a DNS server inside the container's namespace at `127.0.0.11`. The lookups it makes upstream are sent by the Docker daemon from the *host*, with the host's resolver and real IP. The firewall accepts all loopback traffic (`oif "lo" accept`, `iif "lo" accept` in `vendor/warptorrent/tunnel/lib.sh:99,116`), so a query to `127.0.0.11` never reaches any WARP rule or counter.

**Why it's safe today:** the entrypoint overwrites `/etc/resolv.conf` with the WARP-only resolvers on every start (`lib.sh:141`), so nothing asks `127.0.0.11`.

**How it could break:** `/etc/resolv.conf` is a file Docker owns and can rewrite while the container runs. I believe it does so when a network is connected to or disconnected from a running container, but I could not confirm that without running Docker. If the file reverts to `nameserver 127.0.0.11`, tailscaled would resolve exit-node clients' DNS through the host. Promise 3 would be broken, and `verify`, `leaktest` and `e2e` would all still pass.

**Note on the verify output:** `image/verify.sh:45` says Docker's NAT table is "unused here; a packet our table drops stays dropped". That is true but beside the point: our table *accepts* this traffic.

**Fix:**
- Drop it in the firewall, before the loopback accept: `ip daddr 127.0.0.11 drop` in the output chain.
- In `healthcheck.sh` and `verify.sh`, fail if `/etc/resolv.conf` contains anything other than `$WARP_DNS`.

The same applies to warptorrent's tunnel image, where the fix belongs.

## F2. Marked traffic is unrestricted on the uplink (Medium, unconfirmed)

**What:** `image/hooks.sh:42` accepts every packet with tailscaled's mark out the uplink:

```
oifname "$UPLINK" meta mark and 0xff0000 == 0x80000 accept
```

There is no limit on destination, protocol or port. tailscaled marks all of its own sockets, including the ones it uses to answer DNS for exit-node clients. Those DNS packets are kept inside WARP only by four routing rules that match the resolver *addresses* (`hooks.sh:67-72`).

**Ways this could leak** (each would need a runtime check to confirm or rule out):

- **A resolver address outside the list.** If tailscaled contacts a resolver at an address not in `$WARP_DNS`, the packet goes out the uplink with the real IP. Examples: an upgrade to DNS-over-HTTPS that dials a different address, or a user-set `WARP_DNS` whose provider's DoH address differs from its plain address.
- **tailscaled in userspace mode.** If tailscaled ever carried exit-node traffic from its own sockets instead of through `tailscale0`, *all* client traffic would be marked and leave directly. `hooks.sh:81` passes `--tun=tailscale0`, and I expect tailscaled to exit rather than fall back, but the healthcheck (`hooks.sh:100`) only checks that the process exists, not that `tailscale0` does.
- **Features added through `TS_EXTRA_ARGS`** that make tailscaled dial out on a user's behalf.

**Fix:** narrow the accept rule to what tailscaled's underlay needs.
- UDP: only from tailscaled's own port (`udp sport $TS_PORT`). Its DNS sockets use other source ports, so UDP DNS could no longer leave by the uplink.
- TCP: only ports 443 and 80 (control plane and DERP).
- Drop marked UDP/TCP to ports 53 and 853 explicitly, with a named counter.
- Make `hook_health` require that `tailscale0` exists.

This does not cover DoH on TCP 443, which can't be told apart from control-plane traffic by port. The destination list remains the only guard for that.

## F3. The marked path is untested, and counters aren't asserted (Medium)

The README says the egress is verifiable. The tests cover two of the three traffic classes:

| Traffic class | Covered by |
|---|---|
| Unmarked traffic from inside the namespace | `leaktest.sh` (probes have no capabilities, so they can't set a mark) |
| Forwarded client traffic | `e2e.sh` |
| Marked traffic sent by tailscaled for clients (DNS) | **Nothing.** `verify.sh:61-66` asks the routing table only; no packet is sent. |

Other gaps:
- `e2e.sh:71` checks that client DNS *works*, not where it exits. After WARP is cut, "HTTPS by hostname blocked" (`e2e.sh:77`) passes whether DNS or the connection failed, so a DNS leak would not show.
- `verify.sh:85-88` prints `fwd_blocked` and `out_blocked` but never fails on them. `e2e.sh:85` does the same.

**Fix:**
- Add counters for marked uplink packets to ports 53/853 and assert they are zero in `verify` and `e2e`.
- In `e2e`, after cutting WARP, run a DNS lookup for a fresh name from the client and require it to fail.

## F4. Auth keys exposed in arguments and container config (Low–Medium)

- `warptail:131` runs `e2e.sh "$key" …`, so the key is in that process's arguments for the whole test. `e2e.sh:46` then passes it as `-e TS_AUTHKEY=…` on the `docker run` command line.
- `hooks.sh:97` passes `--auth-key=$TS_AUTHKEY` to `tailscale up`.
- `compose.yaml:34` puts `TS_AUTHKEY` in the container's environment, where `docker inspect` shows it for the life of the container.

On a Linux host, any local user can read other processes' arguments with `ps`. On a single-user Mac the exposure is small. The key in `.env` is re-sent on every start and never removed.

**Fix:**
- Pass keys through a file or environment, not arguments: `--auth-key=file:<path>`, and `docker run --env-file` or `-e TS_AUTHKEY` with the value exported.
- Skip `--auth-key` once `tailscaled.state` exists, and tell the user to delete the key from `.env` after the first login.

Checked and fine: `.env` and `config/*` are mode 600, `config/` is 700, both are gitignored, and the git history contains no keys. The WireGuard private key is written to a 600 file and removed (`lib.sh:186-191`), never passed as an argument.

## F5. Build inputs aren't pinned (Low)

- `usque` and `wgcf` are checked against a `checksums.txt` downloaded from the same release (`tunnel/Dockerfile:18-25`). That catches a corrupted download, not a replaced release.
- Base images use tags, not digests: `alpine:3.22`, `tailscale/tailscale:v1.104.7`. `apk add` is unpinned.
- `leaktest.sh` pulls `curlimages/curl:latest` and `busybox:latest` and joins them to the namespace (without capabilities).

A tampered `usque` would run as root with `NET_ADMIN` and could rewrite the firewall or set the bypass mark.

**Fix:** put the expected SHA-256 of each binary in the Dockerfile, and pin base images by digest.

## F6. More privilege than needed (Low)

`compose.yaml:21` adds `NET_ADMIN` on top of Docker's default capabilities. Everything runs as root with a writable filesystem and no `no-new-privileges`. usque parses data from the network and tailscaled parses packets from tailnet peers; a bug in either gives the attacker the means to remove the kill switch.

**Fix:** `cap_drop: [ALL]` then add back only what's needed (`NET_ADMIN`, and `NET_RAW` if tailscaled requires it), plus `security_opt: ["no-new-privileges:true"]` and `read_only: true` with tmpfs for `/run`, `/tmp` and `/var/run`.

## F7. `TS_EXTRA_ARGS` can undo safety flags (Low)

`hooks.sh:95-97` appends `TS_EXTRA_ARGS` after the fixed flags, so a later `--accept-dns=true`, `--accept-routes`, `--exit-node=…` or `--netfilter-mode=on` wins.

- None of these lets forwarded traffic out the uplink; the forward chain still holds.
- `--exit-node=…` would send the container's own traffic to another exit node instead of WARP.
- `--accept-dns=true` could change which resolvers tailscaled uses, which feeds F2.

**Fix:** reject those flags in `hook_start`, or document that they void the guarantees.

## F8. Smaller items (Info)

- **Invalid-state packets aren't dropped in forward.** `hooks.sh:39` accepts any `tailscale0 → warp0` packet. Packets conntrack marks invalid skip the masquerade and enter WARP with a tailnet source address. They still only go to WARP, so this is not a real-IP leak. Add `ct state invalid drop` first.
- **Silent IPv6 rule failures.** `hooks.sh:66,69,75` ignore errors on the IPv6 rules. By my reading every failure combination ends in "via WARP" or "unreachable", so it fails safe, but a failure is invisible. Log it.
- **Published UDP port.** `compose.yaml:41` binds tailscaled's port on all host interfaces. On Linux, Docker's port publishing bypasses most host firewalls. The port only speaks authenticated WireGuard, so the risk is small.
- **Peer relay grant.** The README example uses `"src": ["*"]`, which lets every device in the tailnet relay through the Mac. The relay sees only encrypted packets. Narrow `src` if the tailnet has shared users.
- **Startup window.** IP forwarding is on (compose sysctl) a moment before the firewall loads. `tailscale0` doesn't exist yet, so no client traffic can be forwarded in that window.
- **Unused variable.** `TS_IMAGE` in `warptail:27`.

## Checked and found sound

- **Forwarding:** only `tailscale0 → warp0` is accepted. Traffic arriving on the uplink from other containers can't be forwarded anywhere. Clients can't reach the Docker subnet or the WARP endpoint address through the node.
- **Kill switch:** firewall and routes are in place before usque or tailscaled start (`entrypoint.sh:21-25`). `set -e` plus an atomic `nft -f` means a setup failure stops the container instead of leaving it half-configured.
- **WARP down:** the main table keeps an `unreachable` default, so forwarded and own traffic fail fast. The resolver rules point at the main table, so DNS is unreachable too.
- **Other firewall tables:** a drop in our table is final whatever other tables accept, so tailscaled or Docker adding rules can't open a path.
- **Mark changes:** if a future tailscaled used a different mark, its traffic would fall to the main table and go via WARP. That fails safe.
- **Marks from outside:** packet marks don't cross network namespaces, and joined containers have no `NET_ADMIN`, so only this container's processes can use the exemption.
- **Stated caveats are accurate:** Cloudflare sees the host's real IP, and Tailscale's own traffic (control plane, DERP, peer-to-peer) uses the real IP by design.

## Suggested order of work

1. F1: drop `127.0.0.11` and check `/etc/resolv.conf` in the healthcheck. Small change, closes a silent bypass.
2. F2: narrow the marked-uplink rule and add the port 53/853 drop with a counter.
3. F3: assert the new counters and add the post-cut DNS probe to `e2e`.
4. F4: move keys out of arguments; revoke the reusable test key.
5. F5–F7 as hardening.

---

## Resolution (2026-11-13)

All findings were fixed in warptail `main` and warptorrent `46fc048`, then re-tested on macOS with
Colima (arm64): `./warptail verify`, the leaktest in both WARP modes, `./warptail e2e`, and
`./warptail e2e nat`.

| # | Fix |
|---|---|
| F1 | The tunnel's output chain drops `127.0.0.11` (counter `docker_dns_blocked`), ahead of the loopback accept. `/etc/resolv.conf` is now a file warptail owns (`config/resolv.conf`), so Docker can't rewrite it. The supervisor restores it if it changes, and the healthcheck and `verify` fail while it differs. The leaktest probes `127.0.0.11`. |
| F2 | Marked uplink traffic is limited to UDP from tailscaled's port and TCP 80/443. Marked DNS (53/853) is dropped (`underlay_dns_blocked`), and anything else marked is dropped (`underlay_blocked`). Tracing showed the only packets blocked this way are router port-mapping probes (UDP 5351/1900), which can't work from a container. `hook_health` requires `tailscale0`. |
| F3 | `verify` and `e2e` fail if `docker_dns_blocked` or `underlay_dns_blocked` is non-zero. `e2e` resolves a name never looked up before (under `sslip.io`), both while WARP is up (must work) and after cutting it (must fail). |
| F4 | `TS_AUTHKEY` reaches the container as a compose secret file and is passed as `--auth-key=file:…`, only while the node needs login. The e2e key travels by environment variable, never on a command line. |
| F5 | usque and wgcf are pinned by SHA-256 in the Dockerfile; the values match GitHub's upload-time asset digests. Alpine, tailscale, curl and busybox images are pinned by digest. |
| F6 | `cap_drop: [ALL]`, plus only `NET_ADMIN`, `NET_RAW` and `DAC_OVERRIDE`; `no-new-privileges`; read-only root with tmpfs for `/run`, `/tmp`, `/var/run` and `/var/cache`. |
| F7 | `TS_EXTRA_ARGS` containing `--exit-node`, `--accept-dns`, `--accept-routes`, `--netfilter-mode`, `--reset`, `--advertise-exit-node` or an auth key is refused at start. |
| F8 | The forward chain drops invalid-state packets. IPv6 rule failures are logged. The published UDP port and the peer-relay grant scope are documented in the README. The unused `TS_IMAGE` variable is gone. |
