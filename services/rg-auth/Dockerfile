# ── Stage 1: Build ────────────────────────────
FROM rust:1.92-bookworm AS builder

WORKDIR /build

# Copy workspace root files
COPY Cargo.toml Cargo.lock ./

# Copy all workspace members (needed for workspace resolution)
COPY services/rg-auth/ services/rg-auth/
COPY services/pool-verifier/Cargo.toml services/pool-verifier/Cargo.toml
COPY services/template-manager/Cargo.toml services/template-manager/Cargo.toml
COPY services/rg-protocol/Cargo.toml services/rg-protocol/Cargo.toml
COPY services/sv2-bridge/Cargo.toml services/sv2-bridge/Cargo.toml
COPY services/reservegrid-common/Cargo.toml services/reservegrid-common/Cargo.toml
COPY services/reservegrid-gateway/Cargo.toml services/reservegrid-gateway/Cargo.toml
COPY services/sv2-gateway/Cargo.toml services/sv2-gateway/Cargo.toml
COPY services/test-miner/Cargo.toml services/test-miner/Cargo.toml
COPY services/rg-dashboard/Cargo.toml services/rg-dashboard/Cargo.toml
COPY services/rg-feed-adapter/Cargo.toml services/rg-feed-adapter/Cargo.toml
COPY services/rg-demo-feed/Cargo.toml services/rg-demo-feed/Cargo.toml
COPY services/rg-feed-server/Cargo.toml services/rg-feed-server/Cargo.toml
COPY services/rg-load-test/Cargo.toml services/rg-load-test/Cargo.toml

# Create dummy src files for other workspace members so cargo resolves
RUN mkdir -p services/pool-verifier/src && echo "fn main(){}" > services/pool-verifier/src/main.rs \
    && mkdir -p services/template-manager/src && echo "fn main(){}" > services/template-manager/src/main.rs \
    && mkdir -p services/rg-protocol/src && echo "" > services/rg-protocol/src/lib.rs \
    && mkdir -p services/sv2-bridge/src && echo "fn main(){}" > services/sv2-bridge/src/main.rs \
    && mkdir -p services/reservegrid-common/src && echo "" > services/reservegrid-common/src/lib.rs \
    && mkdir -p services/reservegrid-gateway/src && echo "fn main(){}" > services/reservegrid-gateway/src/main.rs \
    && mkdir -p services/sv2-gateway/src && echo "fn main(){}" > services/sv2-gateway/src/main.rs \
    && mkdir -p services/test-miner/src && echo "fn main(){}" > services/test-miner/src/main.rs \
    && mkdir -p services/rg-dashboard/src && echo "fn main(){}" > services/rg-dashboard/src/main.rs \
    && mkdir -p services/rg-feed-adapter/src && echo "fn main(){}" > services/rg-feed-adapter/src/main.rs \
    && mkdir -p services/rg-demo-feed/src && echo "fn main(){}" > services/rg-demo-feed/src/main.rs \
    && mkdir -p services/rg-feed-server/src && echo "fn main(){}" > services/rg-feed-server/src/main.rs \
    && mkdir -p services/rg-load-test/src && echo "fn main(){}" > services/rg-load-test/src/main.rs

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target,target=/build/target,sharing=locked \
    cargo build --release -p rg-auth && \
    cp target/release/rg-auth /tmp/rg-auth

# ── Stage 2: Runtime ──────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Install Litestream for continuous SQLite replication.
# Set LITESTREAM_REPLICA_BUCKET to enable; without it rg-auth runs standalone.
ARG LITESTREAM_VERSION=0.3.13
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL --retry 3 --retry-delay 2 "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-${ARCH}.deb" -o /tmp/litestream.deb \
    && dpkg -i /tmp/litestream.deb \
    && rm /tmp/litestream.deb

COPY --from=builder /tmp/rg-auth /usr/local/bin/rg-auth
COPY services/rg-auth/litestream.yml /etc/litestream.yml
COPY services/rg-auth/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# SQLite data lives on a persistent volume mounted at /data
RUN mkdir -p /data

ENV VELDRA_AUTH_ADDR=0.0.0.0:3030
ENV VELDRA_AUTH_DB=/data/auth.db

EXPOSE 3030

ENTRYPOINT ["/entrypoint.sh"]
