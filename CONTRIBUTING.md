# Contributing to ReserveGrid OS

Thank you for your interest in contributing. This document covers the workflow,
conventions, and quality gates that apply to all changes.

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Open a pull request against `main`

## Development Setup

```bash
# Install Rust 2024 edition (1.92+)
rustup install 1.92
rustup default 1.92

# Build the workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Branch Naming

Use descriptive prefixes:

- `feat/` for new features
- `fix/` for bug fixes
- `refactor/` for structural changes with no behavior change
- `test/` for test additions or improvements
- `docs/` for documentation changes
- `ci/` for CI/CD changes

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `style`, `perf`, `chore`

Scope should be the crate name when applicable (e.g., `pool-verifier`,
`sv2-gateway`, `rg-auth`).

Examples:

```
feat(sv2-gateway): add per-channel share rate limiting
fix(pool-verifier): handle empty coinbase transaction in template
test(rg-auth): add rate limiter sliding window edge cases
```

## Pull Request Requirements

Every PR must:

1. Pass CI (build, test, clippy, fmt, audit, deny, vet, secrets scan)
2. Include tests for new behavior
3. Not break existing tests
4. Not introduce new clippy warnings
5. Target `main` via a feature branch

## Code Conventions

- **Edition:** Rust 2024
- **Line width:** 100 characters (enforced by `rustfmt.toml`)
- **Error handling:** fail fast with explicit errors, no silent fallbacks
- **Logging:** use `tracing` with structured fields
- **Env vars:** prefix with `VELDRA_`
- **Reason codes:** canonical `snake_case`, stable across protocol/verifier/exports
- **Dependencies:** justify new additions; prefer the existing stack (tokio, reqwest, serde, clap, tracing)

## Testing

- Unit tests live alongside the code in `#[cfg(test)]` modules
- Integration tests live in `scripts/` and run via Docker Compose
- Load tests use `rg-load-test` against the compose stack

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

Do not introduce `unsafe` code. The workspace denies it via lint config:

```toml
[workspace.lints.rust]
unsafe_code = "deny"
```

## License

By contributing, you agree that your contributions will be licensed under the
same license as the project (see [LICENSE](LICENSE)).
