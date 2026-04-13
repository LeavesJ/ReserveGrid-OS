# Changelog

All notable changes to ReserveGrid OS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-04-13 — Yield

### Added

- Extended mining channels (0x13 `OpenExtendedMiningChannel`, 0x1b `SubmitSharesExtended`) with variable length extranonce negotiation
- Variable difficulty (vardiff) with configurable target share rate, retarget interval, and per-retarget adjustment cap
- Automatic inline to observe degradation when verifier heartbeat is lost, with recovery on `HeartbeatAck`
- Mode transition NDJSON events (timestamp, direction, unenforced job count during degraded window)
- Multi-gateway active/standby deployment documentation
- Graceful shutdown drain for the management/health HTTP server via `shutdown_rx` watch channel
- SIGHUP triggered HMAC secret rotation without restart (`Arc<RwLock<Vec<u8>>>`)
- Per-IP rate limiter extracted from rg-auth into `reservegrid-common` and wired into sv2-gateway and rg-feed-server
- Fly.io deployment scaffolding for rg-feed-server (`fly.toml`)
- Production Ed25519 keypair generated for license signing (S-6)
- Tauri devtools gated behind `cfg(feature = "devtools")`, debug builds only

### Changed

- `observe_free` tier renamed to `shadow` across the entire stack (SQLite migration v4, Rust constants, TypeScript types)
- rg-feed-server WebSocket auth moved to tungstenite handshake callback (reject before first frame)
- `gateway_signature_hex` HMAC now covers `event_id || SHA256(canonical_body)` instead of `event_id` alone (**breaking**)
- Legacy DB-only `validate_key` fallback in rg-auth removed (all keys now require Ed25519 signature verification)
- Static key list in rg-feed-server removed

### Fixed

- `build.rs` devtools gating uses Cargo `PROFILE` env var instead of `cfg!(debug_assertions)` (build scripts always compile in debug)

## [1.0.2] — 2026-04-07 — Stress

### Added

- File descriptor limit check at sv2-gateway startup on Linux (safe `/proc/self/limits` read)
- Fee tier ordering validation at startup (`lo <= mid <= hi`, fails with explicit error)
- `VELDRA_GATEWAY_MODE` env var overlay on TOML mode config (was silently ignored)
- Website i18n completion: 32 new keys in `es.json` and `zh.json`, 30+ elements across 14 pages

### Changed

- Template age timestamp uses bitcoind `curtime` field instead of `SystemTime::now()` (accurate under RPC latency)
- Feed adapter `MAX_BACKOFF_SECS` reduced from 30 to 10 seconds
- Verifier reconnect uses hash-based jitter (0 to 50 percent of base delay) to prevent thundering herd
- Degraded policy mode logging upgraded from WARN to ERROR
- Dashboard policy poll interval reduced from 30s to 5s to match verdict polling

### Fixed

- Stale-diff bug in all four dashboard save handlers (policy, verifier, gateway, template settings) via `baselineRef` pattern
- `libc::getrlimit` replaced with safe `/proc/self/limits` read to satisfy workspace `unsafe_code = "deny"`

## [1.0.1] — 2026-04-04 — Temper

### Added

- Ed25519 signed license key format (`veldra_lic_<base64url_payload>.<base64url_sig>`) replacing the old `veldra_<hex>` keys
- Offline license key verification in rg-feed-server (tier gating for `observe_paid` and `inline_licensed`)
- Offline license key verification in rg-desktop (compile time public key via `VELDRA_LICENSE_PUBKEY`)
- License key persistence in rg-desktop (survives app restart via `~/.config/reservegrid/desktop.toml`)
- Copy-to-clipboard on the website license page with full key value in TOML snippet
- Demo Ed25519 keypair in observe compose stack for out of the box key generation
- `VELDRA_LICENSE_SIGNING_KEY` and `VELDRA_LICENSE_PUBKEY` env vars documented in `.env.example`
- `gateway_instance_id` field in `TemplatePropose` for multi-gateway split-brain prevention
- `PRAGMA integrity_check` on rg-auth SQLite startup
- `VELDRA_VERDICT_LOG_MAX_ENTRIES` env var for configurable in-memory verdict log cap
- `VELDRA_MEMPOOL_TIMEOUT_MS` env var for configurable mempool client timeout
- 7 rg-auth email module tests (template bodies, config parsing, dev mode send)

### Changed

- `rg-auth` `generate_key` now produces signed keys with embedded org, tier, expiry, and features
- `rg-auth` `validate_key` performs 3 step validation: signature, expiry, DB revocation check (falls back to DB only when signing key absent)
- `rg-feed-server` `KeyValidator::new()` accepts pubkey as first argument for offline verification
- `list_keys` API response now includes `key_value` alongside `key_prefix` for authenticated users
- `MAX_TOKEN_LENGTH` in rg-feed-server increased from 256 to 512 for signed key format
- Verifier reconnect delay, heartbeat interval, and channel open timeout are now config fields (previously hardcoded as 2s, 5s, 30s)
- WAL I/O and verdict log handler moved to `spawn_blocking` to avoid blocking the async executor
- Health server bind failure is now non-fatal (warns and continues without health endpoint)
- In-memory verdict log capped at both push sites (previously only one of two enforced the limit)
- Verdict log rotation and WAL open use direct open with ENOENT handling instead of path.exists() to avoid TOCTOU races

### Fixed

- Observe compose stack: key generation returned 503 due to missing signing key env var
- `generate-license-key.py` tier choices corrected from mode names to DB tier constants
- Stale TODO comments removed from rg-desktop license module
- Stale reason code counts corrected across 17 files (websites, i18n JSON, docs, pitchdeck)
- 6 timing parameter cross-validation checks added to gateway config startup
- 9 silent `try_send` channel drops in share handler now log warnings
- 15 silent `let _ =` error drops across 4 crates replaced with logged warnings
- 3 codec decode sites now send error frames before disconnecting (SetupConnection, OpenMiningChannel, SubmitShares)
- Extension type validation added at all 3 SV2 frame dispatch points (rejects non-base-protocol)
- Connection limit added to rg-feed-server accept loop (`VELDRA_FEED_MAX_CONNECTIONS`, default 256)
- `max_connections_per_ip` default changed from 0 (unlimited) to 16
- CloseChannel decode failure now disconnects instead of silently continuing

### Security

- 111 findings across 14 services resolved (full stack security audit)
- rg-auth hardened: 11 additional findings resolved (rate limiting, input validation, session management)
- Production Ed25519 keypair generated for license signing deployment
- Tauri auto-updater signing keypair configured (v1.0.0 shipped with empty pubkey)
- Root Dockerfile renamed to prevent flyctl auto-discovery of wrong build target
- Stale root tauri.conf.json excluded from version control

## [1.0.0] — Unreleased

### Added

- Three deployment modes: shadow (read only), observe (non enforcing), inline (full enforcement)
- `sv2-gateway` with Noise NX encryption, share lifecycle WAL, and per channel rate limiting
- `rg-auth` service with registration, email verification, admin approval, license keys, and per endpoint rate limiting
- `rg-dashboard` with embedded React frontend and unified API proxy
- Feed stack: `rg-demo-feed` (synthetic GBT), `rg-feed-adapter` (WebSocket to JSON RPC bridge), `rg-feed-server` (authenticated feed)
- `rg-load-test` benchmarking tool for template verdict latency
- `test-miner` integration harness with job timeout and share submission
- 15 verdict reason codes and 58 gateway reason codes, all canonical snake_case
- NDJSON WAL for crash durable event delivery
- CSV and Prometheus export of verdict history
- mTLS support for remote verifier channel
- HMAC nonce replay protection on gateway
- TCP accept rate limiting (per IP connection cap)
- Configurable policy via TOML with 51 keys across `[policy]` and `[policy.safety]`
- Full CI matrix: build, test, clippy pedantic, rustfmt, cargo audit, cargo deny, cargo vet, gitleaks
- Integration test suites for all three modes (14 inline, 9 observe, shadow)
- Auth flow integration test (20 endpoints)
- Endpoint contract verification (22 endpoints across 5 services)
- Release build benchmarks: sub 6ms average, sub 35ms p99 at 2000 TPS
- Deployment profiles for dev, staging, and production
- Supply chain auditing via cargo vet

### Changed

- Workspace migrated to Rust 2024 edition
- All crates use workspace level lint policy (unsafe_code = deny, clippy pedantic)

### Security

- Fail closed rate limiting (deny on mutex poison)
- CORS wildcard hard errors at startup
- Constant time API key comparison with redacted logs
- Password length cap (1024 bytes) on register and reset
- Email input validation (local, domain, TLD)
- SQL parameterization enforced (no format! with user input)
- License key masking (key_prefix only in list responses)
- Secure by default production profile (no plaintext verifier, no wildcard CORS)

## [0.3.0] — 2026-02-25

Initial open source release. Pool verifier with shadow mode template
verification, basic gateway, and template manager.

### Added

- `pool-verifier` with configurable policy engine
- `template-manager` for bitcoind RPC integration
- `reservegrid-gateway` (predecessor to sv2-gateway)
- `rg-protocol` shared types and reason codes
- Docker Compose stack for local development
- Basic CI with build and test
