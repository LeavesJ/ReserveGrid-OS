# sv2-gateway: SV2 Mining Protocol gateway
# Multi-stage build: Rust builder -> debian-slim runtime.

FROM rust:1.92-bookworm AS builder

WORKDIR /build

# Copy workspace root manifests.
COPY Cargo.toml Cargo.lock ./

# Copy all workspace member manifests and source.
COPY services/ services/

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target,target=/build/target,sharing=locked \
    cargo build --release -p sv2-gateway && \
    cp target/release/sv2-gateway /tmp/sv2-gateway

# ── Runtime stage ──
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r reservegrid && useradd -r -g reservegrid -s /usr/sbin/nologin reservegrid

COPY --from=builder /tmp/sv2-gateway /usr/local/bin/sv2-gateway

RUN mkdir -p /var/lib/reservegrid && chown reservegrid:reservegrid /var/lib/reservegrid

USER reservegrid

ENV VELDRA_LOG_FORMAT=json
ENV VELDRA_LOG_FILTER=info

# SV2 listener port.
EXPOSE 3333
# Health HTTP port.
EXPOSE 8080

ENTRYPOINT ["sv2-gateway"]
CMD ["--config", "/config/gateway.toml"]
