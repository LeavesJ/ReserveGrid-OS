# rg-dashboard: ReserveGrid OS operator dashboard.
# Three-stage build: Node (frontend) -> Rust (backend) -> slim runtime.

# ── Stage 1: Build frontend SPA ──
FROM node:22-bookworm-slim AS frontend

WORKDIR /frontend
COPY services/rg-dashboard/frontend/package.json services/rg-dashboard/frontend/package-lock.json* ./
RUN npm ci
COPY services/rg-dashboard/frontend/ .
RUN npm run build

# ── Stage 2: Build Rust binary with embedded assets ──
FROM rust:1.92-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY services/ services/

# Copy built frontend assets into the embed folder
COPY --from=frontend /frontend/dist services/rg-dashboard/frontend/dist/

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target,target=/build/target,sharing=locked \
    cargo build --release -p rg-dashboard && \
    cp target/release/rg-dashboard /tmp/rg-dashboard

# ── Stage 3: Minimal runtime ──
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r reservegrid && useradd -r -g reservegrid -s /usr/sbin/nologin reservegrid

COPY --from=builder /tmp/rg-dashboard /usr/local/bin/rg-dashboard

# Default config (overridden by volume mount in Docker Compose).
COPY services/rg-dashboard/config/default.toml /etc/reservegrid/dashboard.toml

USER reservegrid

ENV VELDRA_LOG_FORMAT=json
ENV VELDRA_LOG_FILTER=info
ENV VELDRA_DASHBOARD_CONFIG=/etc/reservegrid/dashboard.toml

# Dashboard HTTP port
EXPOSE 8084

ENTRYPOINT ["rg-dashboard"]
