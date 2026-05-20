#!/bin/sh
set -eu

# ip_forward is set by docker-compose sysctls; nothing to do here.

echo "[opnsense] applying nftables rules"
nft -f /etc/nftables.conf

echo "[opnsense] bringing wg0 up"
# wg-quick complains about the chmod on a bind-mounted file; copy it first.
cp /etc/wireguard/wg0.conf.in /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
wg-quick up wg0

echo "[opnsense] ready"
wg show
exec sleep infinity
