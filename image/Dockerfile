# warptail: tailscaled as a Tailscale exit node, inside warptorrent's warp-tunnel namespace.
# `tunnel` is the warp-tunnel image built from vendor/warptorrent/tunnel (see compose.yaml).
# The tunnel image does the kill switch and the WARP connection. hooks.sh adds the
# Tailscale-specific firewall rules, routing and process.
FROM tailscale/tailscale:v1.104.7 AS tailscale

FROM tunnel
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscaled /usr/local/bin/
COPY hooks.sh /etc/warp-tunnel/hooks.sh
COPY verify.sh /usr/local/bin/warptail-verify
RUN chmod +x /usr/local/bin/warptail-verify
