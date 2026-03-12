# pool-verifier: Template verification service
# Multi-stage build: Rust builder -> debian-slim runtime.

FROM rust:1.92-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY services/ services/

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target,target=/build/target,sharing=locked \
    cargo build --release -p pool-verifier && \
    cp target/release/pool-verifier /tmp/pool-verifier

# ── Runtime stage ──
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r reservegrid && useradd -r -g reservegrid -s /usr/sbin/nologin reservegrid

COPY --from=builder /tmp/pool-verifier /usr/local/bin/pool-verifier

USER reservegrid

ENV VELDRA_LOG_FORMAT=json
ENV VELDRA_LOG_FILTER=info

# NDJSON TCP listener for gateway.
EXPOSE 9090
# Health HTTP port.
EXPOSE 8081

ENTRYPOINT ["pool-verifier"]
