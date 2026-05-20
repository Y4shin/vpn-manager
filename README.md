# vpn-manager

Self-hosted WireGuard portal. A VPS-hosted Go service that lets OIDC-authenticated users mint WireGuard configs to access a home network through a second WireGuard tunnel terminated at OPNsense.

```
user devices ──wg──▶ VPS:51820 (wg-users) ──forward──▶ VPS:51821 (wg-home) ◀──wg── OPNsense ──▶ home LAN
                                                                 (opnsense dials in)
```

OIDC groups map to per-group `/24`s carved out of `10.100.0.0/16`; OPNsense enforces per-group firewall rules.

## Develop

All commands run inside the Nix dev shell. A [Taskfile.yml](Taskfile.yml) provides shortcuts (via [taskfile.dev](https://taskfile.dev)).

```sh
task test        # unit + webflow integration tests (fast, no docker)
task check       # vet + test
task test-e2e    # full docker-compose end-to-end suite (needs WG kmod loaded)
task test-all    # check + test-e2e
task --list      # show every task
```

Or call go directly:

```sh
nix develop --command go test ./...
nix develop --command go test -tags=e2e -v ./test/e2e
```

The e2e suite spins up six containers (vps, mock-idp, opnsense, home-nas, two clients) on isolated docker networks and verifies the full data path: OIDC login → device generation → tunnel up → ping through to a simulated home LAN → source-IP preservation → per-group firewall enforcement → revoke → reconcile after restart. See [test/e2e/](test/e2e/) for the harness.

On WSL2 the WireGuard kernel module must be loaded on the host once per boot:

```sh
sudo modprobe wireguard
```

Run the production binary locally (needs root + WG kmod — easiest inside the container):

```sh
nix develop --command go run ./cmd/vpn-manager --config ./config.yaml
```

## Deploy

See the full step-by-step in [docs/deployment.md](docs/deployment.md). Short version: register an OIDC client, fill in `config.yaml`, `docker compose up -d`, copy the printed `wg-home` pubkey into OPNsense's WireGuard peer, add per-group firewall rules on OPNsense, front `:8080` with Caddy or Traefik for TLS.

## What's intentionally not here (v1)

- Admin UI listing all users/devices.
- Device expiry or auto-rotation on group change.
- Multi-VPS HA.
- Audit log surfaced in UI (everything is on stdout).
