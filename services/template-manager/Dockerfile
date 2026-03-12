# template-manager: Bitcoin block template polling and caching
# Multi-stage build: Rust builder -> debian-slim runtime.

FROM rust:1.92-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY services/ services/

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target,target=/build/target,sharing=locked \
    cargo build --release -p template-manager && \
    cp target/release/template-manager /tmp/template-manager

# ── Runtime stage ──
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r reservegrid && useradd -r -g reservegrid -s /usr/sbin/nologin reservegrid

COPY --from=builder /tmp/template-manager /usr/local/bin/template-manager

USER reservegrid

ENV VELDRA_LOG_FORMAT=json
ENV VELDRA_LOG_FILTER=info

# HTTP API for template polling.
EXPOSE 8082

ENTRYPOINT ["template-manager"]
