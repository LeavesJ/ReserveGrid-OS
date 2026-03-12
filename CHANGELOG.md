# Changelog

All notable changes to ReserveGrid OS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — Unreleased

### Added

- Three deployment modes: shadow (read only), observe (non enforcing), inline (full enforcement)
- `sv2-gateway` with Noise NX encryption, share lifecycle WAL, and per channel rate limiting
- `rg-auth` service with registration, email verification, admin approval, license keys, and per endpoint rate limiting
- `rg-dashboard` with embedded React frontend and unified API proxy
- Feed stack: `rg-demo-feed` (synthetic GBT), `rg-feed-adapter` (WebSocket to JSON RPC bridge), `rg-feed-server` (authenticated feed)
- `rg-load-test` benchmarking tool for template verdict latency
- `test-miner` integration harness with job timeout and share submission
- 15 verdict reason codes and 19 gateway reason codes, all canonical snake_case
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
