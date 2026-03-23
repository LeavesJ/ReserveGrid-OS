# ReserveGrid OS — Deployment Runbook

Production deployment guide for pool operators. Covers all three deployment
modes (shadow, observe, inline), security configuration, monitoring, backup,
upgrade procedures, and troubleshooting.

Version: 1.0.0
Last updated: 2026-03-12

---

## Prerequisites

**Hardware (inline mode, mainnet):**

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 100 GB SSD (bitcoind pruned) | 1 TB NVMe (full node) |
| Network | 100 Mbps symmetric | 1 Gbps symmetric |

Shadow and observe modes require approximately half the above resources because
they do not run bitcoind or sv2-gateway locally.

**Software:**

- Docker Engine 24+ with Compose v2
- A Linux host (Ubuntu 22.04 LTS or Debian 12 recommended)
- `curl` and `jq` for health verification
- Git (to clone the repository)

**Network access:**

| Direction | Port | Protocol | Purpose |
|---|---|---|---|
| Inbound | 3333 | TCP (Noise NX) | Miners connect to sv2-gateway |
| Inbound | 8084 | HTTP/HTTPS | Operator dashboard |
| Outbound | 8332/18443 | HTTP | bitcoind JSON-RPC (inline mode) |
| Outbound | 443 | HTTPS | SMTP relay for auth emails |
| Internal | 8080-8082, 9090, 3030 | HTTP/TCP | Inter-service communication |

Firewall rules should expose only ports 3333 and 8084 to the internet. All
other ports are internal only.

---

## Mode Selection

Choose the deployment mode that matches your trust posture. All modes use the
same binaries. The mode is selected by a single config key and the compose file
you start.

**Shadow** (free trial, zero risk). Synthetic template feed from Veldra
infrastructure. No connection to your bitcoind. No miners. Demonstrates the
verification surface with curated edge cases. Use this to evaluate the product
before committing any infrastructure.

```
docker compose -f docker-compose.shadow.yml up --build
```

**Observe** (paid evaluation, read-only). Live mainnet template data from a
Veldra-hosted reference feed. Requires a license key from Veldra. Verdicts are
logged but not enforced. Use this to see how your real template traffic looks
under policy, without any production risk.

```
docker compose -f docker-compose.observe.yml up --build
```

**Inline** (production, full enforcement). Your own bitcoind, your own miners,
active policy enforcement on every template. Templates that fail policy are
rejected before reaching miners. This is the production mode.

```
docker compose up --build
```

The rest of this runbook focuses on inline mode. Shadow and observe mode
follow the same structure with fewer services and no enforcement. Differences
are noted where they apply.

---

## Step 1: Clone and Configure Environment

```bash
git clone https://github.com/veldra/reservegrid-os.git
cd reservegrid-os
cp deploy/env.prod.example .env
```

Open `.env` and fill every `TODO_SET_*` field. The system will fail at startup
if required values are missing.

**Required fields:**

| Variable | Description | Example |
|---|---|---|
| `VELDRA_BITCOIND_RPC_USER` | bitcoind RPC username | `mypool` |
| `VELDRA_BITCOIND_RPC_PASS` | bitcoind RPC password | (generate a strong random string) |
| `VELDRA_API_SECRET` | API authentication key, min 32 hex bytes | (see Step 2) |
| `VELDRA_AUTH_SMTP_HOST` | SMTP server for verification emails | `smtp.mailgun.org` |
| `VELDRA_AUTH_SMTP_USER` | SMTP username | `postmaster@mg.yourpool.com` |
| `VELDRA_AUTH_SMTP_PASS` | SMTP password | (from SMTP provider) |
| `VELDRA_AUTH_ALLOWED_ORIGIN` | Frontend URL for CORS | `https://dashboard.yourpool.com` |
| `VELDRA_AUTH_SITE_URL` | Base URL for email links | `https://dashboard.yourpool.com` |
| `VELDRA_AUTH_URL` | Auth service public URL | `https://auth.yourpool.com` |

**Optional but recommended:**

| Variable | Default | Notes |
|---|---|---|
| `VELDRA_GRAFANA_ADMIN_PASSWORD` | `reservegrid` | Change for production |
| `VELDRA_AUTH_RATE_GLOBAL_CEILING` | (disabled) | Set if DDoS is a concern |
| `VELDRA_AUTH_SESSION_TTL_HOURS` | `168` (7 days) | Reduce for higher security |

---

## Step 2: Generate Cryptographic Material

**API secret:**

```bash
openssl rand -hex 32
```

Paste the output into `VELDRA_API_SECRET` in `.env`.

**Noise keypair (one per gateway instance):**

```bash
# Build the gateway binary first (or use a released image)
docker compose build sv2-gateway

# Generate the keypair
docker compose run --rm sv2-gateway reservegrid keygen --noise > keys/noise.key
```

If you do not have the `reservegrid keygen` command available yet, generate a
32-byte Ed25519 keypair using your preferred tool and place the private key file
at the path referenced by `noise_keypair_path` in your gateway config.

Set file permissions:

```bash
chmod 0400 keys/noise.key
```

Record the derived x-only public key. You will need it in Step 3.

**mTLS certificates (if verifier runs on a separate host):**

Generate a CA, server certificate for pool-verifier, and client certificate for
sv2-gateway. Use your organization's PKI or a tool like `cfssl`:

```bash
# Example with cfssl (adjust for your CA setup)
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem verifier-csr.json | cfssljson -bare verifier
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem gateway-csr.json | cfssljson -bare gateway-client
```

Place the certificates in a `tls/` directory and reference them in the gateway
and verifier configuration. See `deploy/gateway-prod.toml` for the `[verifier]`
TLS fields.

If both services run on the same host (single-machine deployment), mTLS is not
required and the loopback verifier address is accepted without TLS.

---

## Step 3: Configure Services

Copy the production config templates and customize them:

```bash
mkdir -p config/keys
cp deploy/gateway-prod.toml config/gateway.toml
cp deploy/policy-prod.toml config/policy.toml
cp keys/noise.key config/keys/noise.key
```

**Gateway config (`config/gateway.toml`):**

Fill in the TODO fields:

1. `authority_pubkey`: paste the x-only public key from Step 2
2. `gateway_instance_id`: a unique string per gateway instance (e.g., `prod-gw-us-east-01`)
3. `template_url`: your template-manager URL (default `http://template-manager:8082` if same compose stack)
4. Verify `wal_path` points to a persistent volume mount

**Policy config (`config/policy.toml`):**

The production policy enables all enforcement by default. Review each field
and adjust thresholds to match your pool's requirements:

| Field | Default | What it does |
|---|---|---|
| `min_total_fees` | 1000 sats | Minimum total fees to accept a template |
| `max_weight_ratio` | 0.999 | Maximum block weight ratio before rejection |
| `max_template_age_ms` | 5000 | Templates older than 5s are rejected as stale |
| `reject_empty_templates` | true | Reject templates with zero transactions |
| `reject_coinbase_zero` | true | Reject templates with zero coinbase value |

Start with the defaults. Tune after observing verdict patterns in the
dashboard.

---

## Step 4: Prepare Docker Compose for Production

The development `docker-compose.yml` mounts `./dev/` for config. Production
deployments should mount `./config/` (or bake configs into the image).

Create a production override file or modify volume mounts:

```yaml
# docker-compose.prod.yml (override)
services:
  sv2-gateway:
    volumes:
      - ./config:/config:ro
      - ./data:/data:rw
    environment:
      VELDRA_ALLOW_REMOTE_VERIFIER: "0"

  pool-verifier:
    volumes:
      - ./config:/config:ro

  template-manager:
    volumes:
      - ./config:/config:ro

  grafana:
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${VELDRA_GRAFANA_ADMIN_PASSWORD}
      GF_AUTH_ANONYMOUS_ENABLED: "false"
```

Use the override:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

**Persistent volumes:**

Ensure the `./data` directory exists and is writable by the container user. This
directory stores:

- `share_wal.ndjson` (gateway WAL for crash-durable share delivery)
- `auth.db` (rg-auth SQLite database)

Back up `./data` regularly. See the Backup section below.

---

## Step 5: Bootstrap Bitcoin Core

If using inline mode with a fresh bitcoind, you need a wallet for block
template generation.

For **regtest** (testing):

```bash
docker compose exec bitcoind bitcoin-cli -regtest \
  -rpcuser=$VELDRA_BITCOIND_RPC_USER \
  -rpcpassword=$VELDRA_BITCOIND_RPC_PASS \
  createwallet "default"

docker compose exec bitcoind bitcoin-cli -regtest \
  -rpcuser=$VELDRA_BITCOIND_RPC_USER \
  -rpcpassword=$VELDRA_BITCOIND_RPC_PASS \
  -generate 101
```

For **mainnet**: your bitcoind should already be synced and have a wallet loaded.
Template-manager will begin polling `getblocktemplate` immediately on startup.
Verify bitcoind is reachable:

```bash
curl -s --user "$VELDRA_BITCOIND_RPC_USER:$VELDRA_BITCOIND_RPC_PASS" \
  --data-binary '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
  -H 'content-type: text/plain;' \
  http://localhost:8332/ | jq .result.blocks
```

---

## Step 6: Start the Stack

**Important:** Grafana (port 3000) and Prometheus (port 9091) are on the
`monitoring` Docker Compose profile. A plain `docker compose up` will not
start them. You must pass `--profile monitoring` to include the observability
stack.

```bash
# Inline mode with monitoring (production)
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile monitoring up --build -d

# Development (no prod overlay, with monitoring)
docker compose --profile monitoring up --build -d

# Development (core services only, no monitoring)
docker compose up --build -d
```

Watch the logs during first startup:

```bash
docker compose logs -f --tail=50
```

What to look for in a healthy startup sequence:

1. `bitcoind` reports `getblockchaininfo` success in healthcheck
2. `pool-verifier` logs `listening on 0.0.0.0:9090` and `http server on 0.0.0.0:8081`
3. `template-manager` logs first template received from bitcoind
4. `sv2-gateway` logs `listening for miners on 0.0.0.0:3333`
5. `rg-dashboard` logs `serving on 0.0.0.0:8084`
6. `prometheus` begins scraping (check `http://localhost:9091/targets`) — requires `--profile monitoring`
7. `grafana` loads the provisioned dashboard (check `http://localhost:3000`) — requires `--profile monitoring`

---

## Step 7: Verify Health

Run health checks against every service:

```bash
# Core services
curl -sf http://localhost:8081/health | jq .         # pool-verifier
curl -sf http://localhost:8082/health               # template-manager
curl -sf http://localhost:8080/healthz | jq .        # sv2-gateway
curl -sf http://localhost:3030/auth/health           # rg-auth
curl -sf http://localhost:8084/healthz               # rg-dashboard

# Aggregated health (dashboard probes all backends)
curl -sf http://localhost:8084/api/health | jq .

# Verify template flow is active
curl -sf http://localhost:8082/latest | jq .block_height

# Verify policy is loaded
curl -sf http://localhost:8081/policy | jq .

# Verify gateway is accepting connections
curl -sf http://localhost:8080/healthz | jq .status
```

All endpoints should return 200. If any service reports unhealthy, check its
logs with `docker compose logs <service-name>`.

**Monitoring endpoints:**

| URL | What it shows |
|---|---|
| `http://localhost:8084` | Operator dashboard (embedded React SPA) |
| `http://localhost:3000` | Grafana dashboards (12 panels across 3 rows) |
| `http://localhost:9091` | Prometheus UI (raw metrics and targets) |

---

## Step 8: Connect Miners

Miners connect to the sv2-gateway on port 3333 using the Stratum V2 protocol
with Noise NX encryption.

**Miner configuration requirements:**

| Parameter | Value |
|---|---|
| Pool address | `your-server:3333` |
| Protocol | Stratum V2 |
| Authority public key | The x-only pubkey from Step 2 |
| Worker name | Operator-defined (e.g., `farm-rack01-unit05`) |

The gateway performs a Noise NX handshake on connection. Miners that fail
the handshake (wrong authority key, timeout, protocol mismatch) are
disconnected. Successful connections appear in the gateway health endpoint:

```bash
curl -sf http://localhost:8080/healthz | jq .connections
```

Channel activity appears in the dashboard and Grafana "Gateway Overview" row.

---

## Monitoring

### Prometheus Metrics

Three scrape targets are configured by default:

| Target | Port | Key metrics |
|---|---|---|
| sv2-gateway | 8080 | `svtwo_shares_total`, `svtwo_connections_active`, `svtwo_channels_active`, `svtwo_verdicts_total`, `svtwo_share_forward_total` |
| pool-verifier | 8081 | `verifier_verdicts_total`, `verifier_templates_evaluated_total`, `verifier_policy_reloads_total` |
| template-manager | 8082 | (template pipeline health) |

All rejection metrics are keyed by `reason_code` label. This is the canonical
join key across the entire observability stack (see EX-006).

### Grafana Dashboard

The pre-built dashboard (`reservegrid-os.json`) is auto-provisioned on Grafana
startup. It contains 12 panels across 3 collapsible rows:

**Gateway Overview:** Active Connections, Active Channels, Total Connections,
Templates Received.

**Share Traffic:** Share Rate (accepted vs rejected timeseries), Rejections by
Reason Code (stacked bars), Share Forward Rate (upstream relay), Gateway
Verdicts Rate.

**Template Verification:** Verifier Verdict Rate, Verifier Rejections by Reason
Code (stacked bars), Templates Evaluated Rate, Policy Reloads (point markers).

Default credentials: admin / (value of `VELDRA_GRAFANA_ADMIN_PASSWORD`). Change
this immediately in production. Disable anonymous access by setting
`GF_AUTH_ANONYMOUS_ENABLED=false`.

### Alerting

Grafana alerting is not pre-configured. Recommended alert rules to add:

| Condition | Severity | Query |
|---|---|---|
| No templates received in 60s | Critical | `rate(svtwo_templates_received_total[2m]) == 0` |
| Rejection rate > 10% sustained 5m | Warning | `rate(verifier_verdicts_total{verdict="rejected"}[5m]) / rate(verifier_verdicts_total[5m]) > 0.1` |
| Active connections drop to 0 | Critical | `svtwo_connections_active == 0` |
| WAL pending entries > 500 | Warning | (custom metric, if exposed) |
| Gateway health probe stale | Critical | Prometheus target down for > 30s |

---

## Backup and Recovery

### What to Back Up

| Data | Location | Frequency | Method |
|---|---|---|---|
| Auth database | `./data/auth.db` | Continuous or hourly | Litestream to R2/S3, or `sqlite3 .backup` |
| Share WAL | `./data/share_wal.ndjson` | Hourly | File copy (append-only, safe to copy while running) |
| Noise keypair | `./config/keys/noise.key` | On creation and rotation | Secrets manager |
| Policy config | `./config/policy.toml` | On change | Version control |
| Gateway config | `./config/gateway.toml` | On change | Version control |
| Environment file | `./.env` | On change | Secrets manager (never version control) |

### Litestream for Auth Database

rg-auth uses SQLite. For continuous replication to Cloudflare R2:

```yaml
# litestream.yml (mounted into rg-auth container)
dbs:
  - path: /data/auth.db
    replicas:
      - type: s3
        bucket: your-bucket
        path: rg-auth/
        endpoint: https://<account-id>.r2.cloudflarestorage.com
        access-key-id: ${R2_ACCESS_KEY_ID}
        secret-access-key: ${R2_SECRET_ACCESS_KEY}
```

The rg-auth Dockerfile includes Litestream. Configure the replica in the
entrypoint or as an environment variable.

### Recovery from Crash

The gateway WAL provides crash-durable share delivery. On restart:

1. Gateway reads `share_wal.ndjson`
2. Orphaned pending entries (accepted shares without a forward result) receive
   synthetic `share_forward_result` events with `process_crash_recovery`
   reason_code
3. Normal operation resumes

No manual intervention required. The WAL auto-compacts after
`wal_compaction_threshold` completions (default 1000).

---

## Upgrade Procedure

### Minor Version Upgrades (1.0.x to 1.0.y)

1. Pull the latest release tag
2. Review the changelog for breaking config changes (there should be none in patch releases)
3. Rebuild images: `docker compose build`
4. Rolling restart: `docker compose up -d --no-deps <service-name>` one service at a time
5. Verify health after each service restart

**Restart order for zero-downtime upgrades:**

1. `pool-verifier` (stateless, fast restart)
2. `template-manager` (stateless)
3. `rg-auth` (SQLite, brief write pause during restart)
4. `rg-dashboard` (stateless)
5. `sv2-gateway` (last, because miners will reconnect)

Restarting sv2-gateway causes all connected miners to disconnect and
reconnect. Schedule this during a low-activity window. Miners that support
automatic reconnection will recover within seconds.

### Major Version Upgrades (1.x to 2.0)

Major versions may include schema changes, new config keys, or reason code
additions. Follow the release notes precisely. Back up all data and config
before upgrading.

---

## Noise Keypair Rotation

Two rotation methods are supported simultaneously:

**SIGHUP (recommended for bare-metal):**

1. Generate a new keypair and write it to the same `noise_keypair_path`
2. Send SIGHUP to the gateway process: `kill -HUP $(pidof sv2-gateway)` or `docker kill -s HUP <container>`
3. Gateway logs confirmation of reload
4. Existing connections continue uninterrupted
5. New connections use the new keypair

**File poll (recommended for containers):**

1. Set `noise_keypair_poll_interval_secs = 300` in gateway config
2. Overwrite the key file at `noise_keypair_path` with the new keypair
3. Gateway detects the file modification time change within the poll interval
4. Same behavior as SIGHUP: existing connections unaffected, new connections use new key

**After rotation:** update the `authority_pubkey` in your miner configuration
to match the new derived public key. Miners that connect with the old key will
fail the Noise handshake and be rejected.

---

## Troubleshooting

### Templates Not Flowing

**Symptom:** `curl http://localhost:8082/latest` returns 404 or stale data.

**Causes:**
1. bitcoind not synced or wallet not loaded
2. template-manager cannot reach bitcoind RPC
3. bitcoind mempool empty (regtest: generate transactions first)

**Fix:** Check template-manager logs for RPC errors. Verify bitcoind is
responding to `getblocktemplate`.

### All Templates Rejected

**Symptom:** Dashboard shows 100% rejection rate.

**Causes:**
1. Policy too strict for current traffic (e.g., `min_total_fees` set higher than
   actual mempool fee totals)
2. `enforce_template_age = true` with clock skew between gateway and bitcoind
3. Stale `authority_pubkey` in gateway config after key rotation

**Fix:** Check the `reason_code` breakdown in Grafana "Rejections by Reason
Code" panel. The reason code tells you exactly which policy rule is firing.
Adjust the corresponding policy threshold in `config/policy.toml`.

### Miners Cannot Connect

**Symptom:** Miners report connection refused or handshake failure.

**Causes:**
1. Port 3333 not exposed or firewalled
2. Wrong `authority_pubkey` in miner config
3. Noise handshake timeout (default 5s, increase `noise_handshake_timeout_ms` for
   high-latency miners)
4. `max_connections_per_ip` exceeded (default 50 in production)

**Fix:** Check gateway logs for handshake errors. Verify the authority pubkey
matches between gateway config and miner config.

### Gateway WAL Growing Unbounded

**Symptom:** `share_wal.ndjson` file size exceeds expectations.

**Causes:**
1. Share forwarding failing (upstream unreachable), preventing completion events
2. Compaction threshold too high

**Fix:** Check `share_upstream` connectivity. Verify `wal_compaction_threshold`
is set (default 1000). The WAL compacts automatically after the threshold is
reached.

### Auth Emails Not Sending

**Symptom:** Users register but never receive verification emails.

**Causes:**
1. SMTP credentials incorrect or missing in `.env`
2. SMTP provider blocking sends (check spam/bounce logs)
3. `VELDRA_AUTH_SMTP_HOST` empty (dev mode: emails print to stdout)

**Fix:** Check rg-auth logs for SMTP errors. In development, emails are
printed to container stdout when SMTP is not configured.

### Grafana Shows No Data

**Symptom:** Dashboard panels show "No data."

**Causes:**
1. Prometheus not scraping targets (check `http://localhost:9091/targets`)
2. Services not exposing metrics on expected ports
3. Datasource not configured (should auto-provision)

**Fix:** Verify all three Prometheus targets are UP in the targets page.
If a target is down, check that the service is running and its metrics port
is accessible within the Docker network.

---

## Security Checklist

Run through this checklist before exposing any service to the internet.

- [ ] All `TODO_SET_*` fields in `.env` are filled with real values
- [ ] No default credentials remain (`reservegrid`, `admin@localhost`, etc.)
- [ ] `VELDRA_LOG_FORMAT=json` (structured logs for production)
- [ ] `VELDRA_ALLOW_INSECURE_VERIFIER=0` (unless single-host deployment)
- [ ] `VELDRA_ALLOW_DROP_OLD_INLINE=0`
- [ ] `VELDRA_ALLOW_REMOTE_VERIFIER=0` (unless verifier is on a separate host with mTLS)
- [ ] Noise keypair is unique to this gateway instance
- [ ] Noise key file permissions are 0400
- [ ] `dev/keys/noise.key` is NOT used outside regtest
- [ ] Grafana anonymous access is disabled (`GF_AUTH_ANONYMOUS_ENABLED=false`)
- [ ] Grafana admin password is changed from the default
- [ ] Firewall exposes only ports 3333 (miners) and 8084 (dashboard) externally
- [ ] All internal service ports (8080, 8081, 8082, 9090, 3030) are not reachable from the internet
- [ ] `VELDRA_AUTH_ALLOWED_ORIGIN` is set to the actual frontend URL, not `*`
- [ ] SMTP is configured for email verification (not printing to stdout)
- [ ] Persistent volume for `./data` is backed up
- [ ] WAL is enabled (`wal_path` points to a persistent volume)

---

## Port Reference

| Port | Service | Protocol | Exposure |
|---|---|---|---|
| 3333 | sv2-gateway | TCP (Noise NX) | Public (miners) |
| 8084 | rg-dashboard | HTTP | Public (operators), put behind HTTPS reverse proxy |
| 8080 | sv2-gateway health/metrics | HTTP | Internal only |
| 8081 | pool-verifier HTTP API | HTTP | Internal only |
| 8082 | template-manager HTTP API | HTTP | Internal only |
| 9090 | pool-verifier TCP (NDJSON) | TCP | Internal only (mTLS for remote) |
| 3030 | rg-auth | HTTP | Internal only (proxied through dashboard) |
| 3000 | Grafana | HTTP | Internal only (or behind auth proxy) |
| 9091 | Prometheus | HTTP | Internal only |
| 18443 | bitcoind RPC (regtest) | HTTP | Internal only |
| 8332 | bitcoind RPC (mainnet) | HTTP | Internal only |

---

## Support

For deployment assistance, contact support@veldra.org.

For security issues, contact security@veldra.org. Do not open public issues
for security vulnerabilities.
