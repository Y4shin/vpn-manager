# Test WireGuard keys

These are **deterministic test fixtures** for the e2e suite ([test/e2e/](..)).
They are checked in so the docker-compose stack — VPS, OPNsense, clients — comes
up with matching keys on a fresh clone, with no key-distribution dance.

- `vps-home.key` — VPS's wg-home private key (bind-mounted into the vps container).
- `opnsense.key` — OPNsense-simulator's private key (referenced in [../config/opnsense/wg0.conf](../config/opnsense/wg0.conf)).
- `*.pub` — matching public keys; the public keys are also baked into [../config/vps/config.yaml](../config/vps/config.yaml) and the opnsense wg0.conf.

**These keys do not protect anything real.** They are only ever loaded inside the
isolated `vpn-manager-e2e_internet` Docker network. Do not reuse them anywhere
that matters.

If you want to rotate them:

```sh
cd test/e2e/keys
nix develop --command sh -c 'wg genkey | tee vps-home.key | wg pubkey > vps-home.pub'
nix develop --command sh -c 'wg genkey | tee opnsense.key | wg pubkey > opnsense.pub'
chmod 600 *.key
# Then update the pubkeys in:
#   test/e2e/config/vps/config.yaml     (wireguard.home.peer.public_key)
#   test/e2e/config/opnsense/wg0.conf   ([Peer] PublicKey)
```
