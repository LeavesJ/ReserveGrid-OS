# Runbook: Product services off Fly, onto a tunneled self-managed host

Migrates `rg-auth` (and later `rg-feed-server`) from Fly.io to a self-managed host behind Cloudflare Tunnel. Written 2026-06-11; execute after the Setup B T+7 wrap. The target host is a parameter: first run uses the existing operator node, the follow-on run (Part 8) moves to a dedicated free ARM instance. Total recurring cost of this architecture: zero.

**Why.** The Fly app has been suspended at the platform level since April (only support can lift it, the CLI cannot; see PRODUCTION_BLOCKERS PB-14 and lesson R-176), which stranded a security hotfix off production for two months. This migration makes the platform irrelevant rather than repaired: deploys become rsync plus compose, no inbound firewall port ever opens (the tunnel daemon dials out), and no third party can suspend the app again.

**Architecture after cutover.**

```
client → https://auth.veldra.org
       → Cloudflare edge (TLS, free plan)
       → Cloudflare Tunnel (outbound-only connection from the host)
       → cloudflared (systemd, on the host)
       → 127.0.0.1:8080 rg-auth (Docker Compose, restart: unless-stopped)
       → SQLite on a host volume (WAL mode)
```

The host firewall stays exactly as it was (SSH only). The host IP appears nowhere in DNS.

---

## Part 0. Prerequisites (one-time, free)

1. Cloudflare account, free plan. Add the `veldra.org` zone and switch the domain's nameservers to Cloudflare at the registrar. Re-create the existing DNS records first (GitHub Pages A/AAAA or CNAME records for the apex and any www record) so the site never blips; Pages records can stay DNS-only (grey cloud). Propagation typically minutes, allow up to 24h.
2. Confirm the repo is present on the target host (the operator node already carries it for the Setup B stack).
3. Confirm Docker and Compose on the target host (already present on the node).

## Part 1. Step zero: attempt the Fly data export

The rg-auth SQLite volume lives on the suspended Fly app. R-176 records that the dashboard could still wake the single machine even while every CLI path was blocked.

1. Fly dashboard → the app → Machines → start the machine from the dashboard.
2. If the machine wakes, from the dashboard console (or `fly ssh console -a <app>` if the CLI cooperates once it is running): locate the volume mount from fly.toml, then produce a consistent snapshot: `sqlite3 /path/to/auth.db ".backup /tmp/auth-export.db"`.
3. Pull it: `fly ssh sftp get /tmp/auth-export.db` (or base64 through the console as a last resort).
4. Locally: `sqlite3 auth-export.db "PRAGMA integrity_check;"` must return `ok`.
5. If the wake fails entirely: inventory what is lost before shrugging. Pre-launch contents are test accounts and any issued license rows. The Ed25519 signing key is NOT lost (it lives in the password manager and CI secrets per R-150), so licenses are re-issuable. Record the outcome either way in DEVLOG.

## Part 2. Tunnel setup on the host

1. Install cloudflared (Debian/Ubuntu package or static binary; use the arm64 build on the ARM follow-on host).
2. Authenticate and create the tunnel (one-time):
   ```
   cloudflared tunnel login
   cloudflared tunnel create veldra-prod
   ```
   The credentials JSON lands under `~/.cloudflared/`; `chmod 600` it. It is a secret; it never enters the repo.
3. Config at `/etc/cloudflared/config.yml`:
   ```yaml
   tunnel: veldra-prod
   credentials-file: /home/<user>/.cloudflared/<tunnel-id>.json
   ingress:
     - hostname: auth.veldra.org
       service: http://127.0.0.1:8080
     # - hostname: feed.veldra.org        # enable when rg-feed-server moves
     #   service: http://127.0.0.1:9200
     - service: http_status:404
   ```
4. Route DNS through the tunnel (replaces the old Fly CNAME for auth.veldra.org):
   ```
   cloudflared tunnel route dns veldra-prod auth.veldra.org
   ```
5. Install as a service and start: `cloudflared service install && systemctl enable --now cloudflared`. Verify with `cloudflared tunnel info veldra-prod` (connector registered) and `journalctl -u cloudflared -n 20`.

## Part 3. rg-auth compose unit

New `docker-compose.auth.yml` at the repo root on the host (commit the file; secrets stay in an env file):

```yaml
services:
  rg-auth:
    build:
      context: .
      dockerfile: services/rg-auth/Dockerfile
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      VELDRA_LOG_FORMAT: json
      VELDRA_LOG_FILTER: info
      VELDRA_AUTH_ADDR: "0.0.0.0:8080"        # container-internal; host exposure is loopback-only above
      VELDRA_AUTH_DB_PATH: /data/auth.db
      VELDRA_LICENSE_SIGNING_KEY: "${VELDRA_LICENSE_SIGNING_KEY}"
    volumes:
      - ./data/auth:/data:rw
```

Notes: confirm the exact env var names against `services/rg-auth` clap/env definitions before first boot (R-01); copy the exported `auth-export.db` to `./data/auth/auth.db` before `up`; create `.env.auth` from the password-manager secrets (never committed; the existing `.env.*` gitignore rule covers it). Run with `docker compose -f docker-compose.auth.yml --env-file .env.auth up -d --build`.

Opportunistic P2 from the 2026-06-11 deep scan: add `PRAGMA busy_timeout = 5000` alongside the WAL pragma in `services/rg-auth/src/db.rs` in the same change window.

## Part 4. Cutover verification

1. `curl -s https://auth.veldra.org/health` returns healthy through the tunnel (Cloudflare cert at the edge).
2. Smoke the auth flows per `scripts/test-auth-flow.sh` against the new origin.
3. Confirm the admin URL sanitizer behavior is live (the stranded `20c62a6` ships automatically since the host builds current `main`).
4. Confirm rate limiting still returns 429s under the existing thresholds (the limiter sees Cloudflare connector IPs; if per-IP fidelity matters later, trust `CF-Connecting-IP` explicitly, as a deliberate code change, not a default).
5. Watch `journalctl -u cloudflared` and container logs for one clean hour.

No client-side changes exist anywhere: the hostname `auth.veldra.org` is unchanged, only its route is new. Rollback risk is null in the strict sense: the previous state was a suspended app serving nothing.

## Part 5. Decommission Fly

After seven clean days: remove the auth DNS record pointing at Fly if any remains, `fly apps destroy` both apps from the dashboard (or leave the corpses, they serve nothing), delete `services/rg-auth/fly.toml`, `services/rg-feed-server/fly.toml`, and `scripts/fly-deploy.sh` from the repo, which closes the 2026-06-11 deep-scan P1 by deletion. Flip PB-14 to resolved-by-migration. R-176 remains in lessons as the platform pattern it is.

## Part 6. rg-feed-server (when it ships)

Same pattern: compose service bound `127.0.0.1:9200`, uncomment the feed ingress rule, `cloudflared tunnel route dns veldra-prod feed.veldra.org`. WebSockets pass through Cloudflare Tunnel on the free plan.

## Part 7. Optional hardening (free)

Cloudflare Access policy in front of admin paths (free to 50 users): a Zero Trust application matching `auth.veldra.org/admin*` with an allow rule for the operator email turns admin routes into authenticated-at-edge endpoints without code changes.

## Part 8. Follow-on: dedicated free ARM host (separation restored)

When separation from the operator node matters (target: the December node-term decision, or sooner if traffic warrants):

1. Oracle Cloud Always Free: VM.Standard.A1.Flex up to 4 OCPU / 24 GB at no cost. Signup needs a card for identity; pick a home region with ARM capacity (capacity hunting may take attempts).
2. Reclaim rule: Oracle reclaims Always Free instances idling under 20% CPU (95th percentile over 7 days) and may purge accounts idle 30+ days. Mitigate with a keep-warm cron (or upgrade the account to pay-as-you-go, which stays $0 within free limits and exempts reclaim).
3. Harden per `setup-b-self-host-bitcoind.md` Parts 1-2 (key-only SSH, ufw SSH-only).
4. Build for arm64: native `cargo build --release` on the box, or `docker buildx build --platform linux/arm64` in CI.
5. Re-run Parts 2-4 of this runbook on the new host (move the ingress entries or create a second tunnel), `scp` a fresh `sqlite3 .backup` snapshot across, flip the tunnel route, verify, retire the compose unit on the node.

## Rollback

At any point before Fly decommission: `cloudflared tunnel route dns` entries can be deleted and the old Fly CNAME restored, returning to the prior state (which, to be plain, was an outage). After decommission, rollback means re-running Parts 2-4 on any host with the repo and the data snapshot, which is the resilience property this design buys.
