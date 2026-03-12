# Security Policy

## Supported Versions

| Version   | Supported |
|-----------|-----------|
| 1.0.x     | Yes       |
| < 1.0     | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in ReserveGrid OS, please report it
responsibly. Do not open a public GitHub issue.

**Email:** jarrondeng@veldra.org

Include as much of the following as possible:

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected component(s) and version(s)
- Potential impact assessment

## Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix or mitigation:** within 30 days for critical issues

## Scope

The following components are in scope:

- `pool-verifier` (template verification engine)
- `sv2-gateway` (Stratum V2 gateway with Noise encryption)
- `rg-auth` (authentication and license key service)
- `template-manager` (bitcoind RPC integration)
- `rg-feed-server` (authenticated template feed)
- `rg-dashboard` (API proxy and web interface)

The following are out of scope:

- `rg-demo-feed` (synthetic test data generator)
- `rg-load-test` (benchmarking tool)
- `test-miner` (integration test harness)

## Disclosure

We follow coordinated disclosure. We will credit reporters in release notes
unless anonymity is requested.
