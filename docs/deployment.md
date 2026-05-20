# Deployment guide

A step-by-step walkthrough for taking vpn-manager from "git clone" to "real users have configs" against your own VPS, your own OIDC provider, and your own OPNsense home network. Follow the steps in order — several of them depend on outputs from earlier steps.

If you only want to skim the architecture first, read [the top of the README](../README.md) and the diagram below.

```
user devices ──wg──▶ VPS:51820 (wg-users) ──forward──▶ VPS:51821 (wg-home) ◀──wg── OPNsense ──▶ home LAN
                                                                       (opnsense dials in)
```

---

## 0. Prerequisites

Before you start, you need:

| Thing                            | Notes                                                                                                                             |
|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| A VPS with a static public IPv4  | Ubuntu/Debian/anything-with-systemd; any modern Linux kernel includes the WireGuard module.                                       |
| Docker + Compose v2 on the VPS   | `docker compose version` should print 2.x.                                                                                        |
| A DNS A record                   | e.g. `vpn.example.com` → VPS public IP.                                                                                           |
| TLS via a reverse proxy          | Caddy and Traefik both auto-issue Let's Encrypt certs. This guide uses Caddy.                                                     |
| An OIDC provider                 | Authentik, Keycloak, Dex, Google Workspace, Okta — anything that issues a `groups` claim.                                          |
| OPNsense at home                 | With WireGuard plugin installed (`os-wireguard`). Outbound UDP must work — no port-forward needed.                                 |
| A plan for your IP ranges        | The defaults below are fine; pick CIDRs that don't collide with your home LAN or anything you tunnel to.                          |

Your IP plan — adjust to taste, but write it down before configuring:

| Network              | Example CIDR        | Lives where           |
|----------------------|---------------------|-----------------------|
| User supernet        | `10.100.0.0/16`     | VPS `wg-users`        |
| └ Group `admins`     | `10.100.10.0/24`    | allocated by app      |
| └ Group `family`     | `10.100.20.0/24`    | allocated by app      |
| └ Group `guests`     | `10.100.30.0/24`    | allocated by app      |
| VPS ↔ OPNsense link  | `10.99.0.0/30`      | VPS `wg-home` peering |
| Home LAN             | `192.168.1.0/24`    | behind OPNsense       |

---

## 1. Register an OIDC client at your IdP

Create a new OIDC application. The exact UI varies by provider; the values you need are universal:

| Field                | Value                                                  |
|----------------------|--------------------------------------------------------|
| Redirect URI         | `https://vpn.example.com/auth/callback`                |
| Grant type           | Authorization code (with PKCE)                         |
| Scopes               | `openid`, `profile`, `email`, `groups`                 |
| Groups claim         | Configurable in vpn-manager. Default key: `groups`     |
| Sign-in method       | Confidential client (client secret)                    |

Record three values:
- **Issuer URL** — e.g. `https://auth.example.com` (must serve `/.well-known/openid-configuration`).
- **Client ID** — e.g. `vpn-manager`.
- **Client secret** — kept out of `config.yaml`; passed in via an env var.

Make sure your IdP actually puts the user's group memberships in the configured claim. Test by decoding an issued ID token at [jwt.io](https://jwt.io) — you should see `"groups": ["admins"]` or similar. If you can't get a real `groups` claim, decide which group name your users should fall into by default and set `default_group` later.

---

## 2. Configure OPNsense's WireGuard instance (partial)

You need OPNsense's public key to fill in vpn-manager's config in the next step. The fastest path is to provision the OPNsense side first, save once to generate the keypair, copy out the pubkey, then come back later to finish wiring it.

On OPNsense → **VPN → WireGuard → Instances → +**:

| Field              | Value                                                  |
|--------------------|--------------------------------------------------------|
| Name               | `vps-uplink`                                           |
| Listen port        | (leave blank — this side is purely outbound)           |
| Tunnel address     | `10.99.0.2/30`                                         |
| MTU                | `1420`                                                 |
| Disable routes     | unchecked                                              |

Save. OPNsense generates and shows a public/private keypair. **Copy the public key.** Don't add the peer yet — we'll do that in step 4 once vpn-manager is up.

---

## 3. Prepare `config.yaml` on the VPS

On the VPS:

```sh
mkdir -p /etc/vpn-manager /var/lib/vpn-manager
cd /opt/vpn-manager
git clone https://github.com/<you>/vpn-manager.git .
cp config.example.yaml /etc/vpn-manager/config.yaml
```

Edit `/etc/vpn-manager/config.yaml`. The file is heavily commented in [config.example.yaml](../config.example.yaml). The fields you actually need to change:

```yaml
public_url: "https://vpn.example.com"

oidc:
  issuer: "https://auth.example.com"
  client_id: "vpn-manager"
  client_secret_env: "OIDC_CLIENT_SECRET"  # name of the env var, not the secret itself
  groups_claim: "groups"

wireguard:
  users:
    endpoint: "vpn.example.com:51820"          # what clients dial — must resolve publicly
    allowed_ips: ["192.168.1.0/24"]            # split tunnel: route only the home LAN

  home:
    peer:
      public_key: "<OPNSENSE_PUBLIC_KEY_FROM_STEP_2>"

groups:
  admins: { cidr: "10.100.10.0/24" }
  family: { cidr: "10.100.20.0/24" }
  guests: { cidr: "10.100.30.0/24" }

default_group: guests   # users with no matching group land here; remove to deny them
```

Tunnel addresses (`10.100.0.1/16` for users, `10.99.0.1/30` for the home uplink) and listen ports (`51820`, `51821`) can stay at their defaults unless they collide with something on your VPS.

Put the OIDC client secret in a file the compose stack can read. Either as a real env var on the host:

```sh
echo "OIDC_CLIENT_SECRET=<actual-secret>" > /etc/vpn-manager/secrets.env
chmod 600 /etc/vpn-manager/secrets.env
```

…and then reference it from compose (next step), or export it inline before running `docker compose up`.

---

## 4. Start vpn-manager and read its `wg-home` pubkey

Use the [docker-compose.yml](../docker-compose.yml) at the root of the repo. Tweak it to:
- bind-mount your `/etc/vpn-manager/config.yaml`,
- expose the right ports,
- load `secrets.env`,
- persist `/var/lib/vpn-manager`:

```yaml
services:
  vpn-manager:
    image: ghcr.io/y4shin/vpn-manager:latest   # or pin a tag: :v1.2.3
    restart: unless-stopped
    cap_add: [NET_ADMIN]
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv4.conf.all.src_valid_mark: "1"
    ports:
      - "51820:51820/udp"           # wg-users (clients dial in here)
      - "51821:51821/udp"           # wg-home (OPNsense dials in here)
      - "127.0.0.1:8080:8080/tcp"   # behind the reverse proxy on localhost
    env_file:
      - /etc/vpn-manager/secrets.env
    volumes:
      - /etc/vpn-manager/config.yaml:/etc/vpn-manager/config.yaml:ro
      - /var/lib/vpn-manager:/var/lib/vpn-manager
```

Bring it up:

```sh
docker compose up -d --build
docker compose logs --tail=30 vpn-manager
```

The first start generates `wg-users.key` and `wg-home.key` in `/var/lib/vpn-manager`, and logs both public keys:

```
vpn-manager listening on :8080
wg-users pubkey: 4CMoieClyY+zw7ERMLgQd7pEvSxr4pNT3uMt6LoF5Hk=
wg-home  pubkey: NHPeUHmKiAENFKvTIPHzE+PR65u0FdC8lcZRmfe+NEA=
```

**Copy the `wg-home pubkey`.** That goes into OPNsense next.

> The keys persist in `/var/lib/vpn-manager`. Back up that directory — losing it forces every user to re-issue every device.

---

## 5. Finish the OPNsense side

Back in OPNsense → **VPN → WireGuard → Peers → +**:

| Field                  | Value                                                                  |
|------------------------|------------------------------------------------------------------------|
| Name                   | `vps`                                                                  |
| Public key             | `<VPS wg-home pubkey from step 4 logs>`                                |
| Endpoint               | `vpn.example.com:51821`                                                |
| Endpoint port          | `51821`                                                                |
| Persistent keepalive   | `25`                                                                   |
| Allowed IPs            | `10.99.0.1/32, 10.100.0.0/16`                                          |

On the **Instance** you created in step 2, attach this peer.

Then enable WireGuard on **VPN → WireGuard → General**: tick **Enable WireGuard** and **Apply**.

Verify the tunnel is up from OPNsense → **VPN → WireGuard → Status**: the peer should show a recent handshake and bytes transferred. On the VPS, mirror-check:

```sh
docker compose exec vpn-manager wg show wg-home
```

You should see a non-zero `latest handshake` and a non-empty `endpoint` (the home CPE's public IP, discovered dynamically).

If the production image is distroless and doesn't have `wg`, run a one-off probe container in the same netns:

```sh
docker run --rm --net=container:vpn-manager-vpn-manager-1 \
  alpine sh -c 'apk add -q wireguard-tools && wg show'
```

---

## 6. Configure the per-group firewall on OPNsense

This is the whole point of the design — group membership maps to source CIDR, and OPNsense decides what each group can reach.

On **Firewall → Rules → vps-uplink** (the WG interface from step 2), add rules. Example policy matching the IP plan above:

| Action  | Source              | Destination        | Description                                |
|---------|---------------------|--------------------|--------------------------------------------|
| Pass    | `10.100.10.0/24`    | `LAN net`          | Admins: full home LAN access               |
| Pass    | `10.100.20.0/24`    | `192.168.1.0/24`   | Family: home LAN only, no Internet egress  |
| Pass    | `10.100.30.0/24`    | `192.168.1.10`     | Guests: just the NAS                       |
| Block   | `any`               | `any`              | Default deny (or leave the implicit deny)  |

Reload rules. Test from a real client in step 8.

---

## 7. Reverse proxy + VPS firewall

A minimal Caddy config in front of `:8080`:

```caddy
vpn.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

Open the right ports on the VPS firewall (UFW example):

```sh
ufw allow 22/tcp                    # ssh
ufw allow 80,443/tcp                # reverse proxy
ufw allow 51820/udp                 # wg-users
ufw allow 51821/udp                 # wg-home (OPNsense dial-in)
ufw enable
```

Don't expose `:8080` directly — it's HTTP, no TLS.

---

## 8. End-to-end verification

From a device on the public internet:

1. Browse to `https://vpn.example.com/`. You should be redirected to your IdP, log in, and land on a dashboard.
2. Create a device named e.g. `laptop`. The next page shows the `.conf` and a QR code **exactly once** — save it now.
3. Import it into a real WireGuard client (desktop app, mobile app, or `wg-quick`).
4. Bring the tunnel up. Ping a home-LAN address that your group should be able to reach (e.g. `ping 192.168.1.10` for the NAS).
5. On OPNsense → **Firewall → Log Files**, you should see the connection sourced from `10.100.X.X` (your group's CIDR), **not** from `10.99.0.1` — that confirms no accidental SNAT and that your per-group rules will fire.
6. Try a destination your group should **not** be able to reach. It must time out.
7. Revoke the device via the UI (dashboard → revoke). The tunnel drops within a few seconds; pings fail.
8. Restart the container: `docker compose restart vpn-manager`. Existing client tunnels resume within ~30 s without users having to do anything.

If any step fails, see [Troubleshooting](#troubleshooting).

---

## Operations

### Backups

Everything stateful lives in `/var/lib/vpn-manager`:

- `vpn-manager.sqlite` — users, devices, sessions.
- `wg-users.key`, `wg-home.key` — server private keys. **Cannot be regenerated without breaking every issued config.**

Back it up nightly. A 2 MB tarball is plenty:

```sh
tar czf /backup/vpn-manager-$(date +%F).tgz -C /var/lib/vpn-manager .
```

### Upgrading

If you pinned a version tag in `docker-compose.yml`, bump it and redeploy:

```sh
docker compose pull
docker compose up -d
```

Or stay on `:latest` and just pull. Image tags published from this repo:

| Tag                     | Built from                          | Notes                                            |
|-------------------------|-------------------------------------|--------------------------------------------------|
| `:latest`               | the most recent `vX.Y.Z` git tag    | Stable channel; recommended.                     |
| `:vX.Y.Z`               | the matching git tag                | Pin this in production for reproducible rollouts.|
| `:preview-latest`       | the most recent commit on `main`    | Tracks main; may break.                          |
| `:preview-<shortsha>`   | a specific commit on `main`         | Useful for bisecting.                            |

Schema migrations are applied automatically on start (idempotent `CREATE IF NOT EXISTS`). Server keys persist across rebuilds because they live in the bind-mounted data dir, not the image.

### Logs

```sh
docker compose logs -f --tail=200 vpn-manager
```

Look for the per-startup line `vpn-manager listening on :8080` and the two pubkey lines. Reconciler runs every 30 s and logs only on errors.

### Restart behaviour

On any restart, the reconciler:
1. Re-applies the peer set from sqlite to the kernel WG interface (so revoked peers stay revoked).
2. Re-installs the route `192.168.1.0/24 dev wg-home`.
3. Begins polling `latest_handshake_time` per peer for the dashboard's "last seen" column.

User tunnels typically resume within one persistent-keepalive (25 s) of the VPS being up again.

### Adding a new group

1. Edit `/etc/vpn-manager/config.yaml`, add the group under `groups:`.
2. Add the matching firewall rule on OPNsense for the new CIDR.
3. `docker compose restart vpn-manager`. Existing devices keep their IPs (groups are recorded at creation time as `group_at_creation`).

### Removing a group

Remove the entry from `config.yaml` and restart. Devices already allocated from that CIDR continue to work until revoked. If you also want to evict them, look up `group_at_creation` in sqlite and revoke individually via the UI or `DELETE FROM devices WHERE group_at_creation = '...'`; then restart so the reconciler drops the peers.

---

## Troubleshooting

**`wg show wg-home` shows no handshake.**
Either the OPNsense side never dialled in, or it can't reach `vpn.example.com:51821`. Check OPNsense's WireGuard status; check `tcpdump -ni any udp port 51821` on the VPS. Most often: a typo in the public key on one side, or the home CPE blocking outbound UDP.

**Browser hits `/auth/callback` and gets `400 Bad Request` ("state mismatch").**
The session cookie isn't being kept across redirects. The cookie is set with `Secure` flag iff `public_url` starts with `https://`. If you're testing over plain HTTP, point `public_url` at `http://...`; otherwise make sure the reverse proxy presents real TLS at the address in `public_url`.

**OIDC discovery fails on startup ("oidc discovery: ...").**
The `issuer` URL must serve `/.well-known/openid-configuration` over HTTPS that the VPS trusts. Check `curl -v https://auth.example.com/.well-known/openid-configuration` from inside the VPS.

**Users see the "no matching group" warning.**
The IdP's `groups` claim doesn't include any name listed under `groups:` in `config.yaml`. Either rename the group in `config.yaml` to match the IdP, or set `default_group: <name>` so unmatched users fall into a safe bucket.

**OPNsense firewall blocks everything (or allows everything).**
Confirm OPNsense actually sees the user source IP, not the link IP. On OPNsense → **Firewall → Log Files**, look at allowed/blocked packets; the source must be in `10.100.X.X`. If it's `10.99.0.1`, something is doing SNAT — most likely an OPNsense outbound NAT rule on the WG interface. Remove it.

**Restart loses everything.**
You forgot the volume mount. `/var/lib/vpn-manager` must be persistent. Check `docker compose config` and grep for `vpn-manager` volume.

**The `wg-home` pubkey changed after a restart.**
Same cause: data directory not persistent. Restore from backup, or warn every user and re-issue all device configs (their server-side pubkey is baked into their `.conf`).
