#!/usr/bin/env bash
# Deploy a service to Fly.io from the workspace root.
#
# Usage:
#   scripts/fly-deploy.sh rg-auth
#   scripts/fly-deploy.sh rg-auth --remote-only
#
# The script copies the service Dockerfile to the repo root as Dockerfile,
# deploys, then removes it. This works around flyctl always auto-discovering
# Dockerfile at the build context root and ignoring --dockerfile.
#
# Prerequisites:
#   - Run from the repo root (or the script will cd there)
#   - flyctl authenticated (`fly auth login`)
#   - The root Dockerfile must NOT exist (renamed to Dockerfile.gateway)

set -euo pipefail

SERVICE="${1:?Usage: $0 <service-name> [fly deploy flags...]}"
shift

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SERVICE_DIR="services/${SERVICE}"
SERVICE_DOCKERFILE="${SERVICE_DIR}/Dockerfile"
SERVICE_FLY_TOML="${SERVICE_DIR}/fly.toml"

if [ ! -f "$SERVICE_DOCKERFILE" ]; then
    echo "Error: ${SERVICE_DOCKERFILE} not found" >&2
    exit 1
fi

if [ ! -f "$SERVICE_FLY_TOML" ]; then
    echo "Error: ${SERVICE_FLY_TOML} not found" >&2
    exit 1
fi

if [ -f Dockerfile ]; then
    echo "Error: root Dockerfile exists. Rename it first (e.g. Dockerfile.gateway)." >&2
    echo "The root Dockerfile interferes with Fly's auto-discovery." >&2
    exit 1
fi

APP_NAME=$(grep '^app\s*=' "$SERVICE_FLY_TOML" | head -1 | sed 's/^app\s*=\s*"\(.*\)"/\1/')
if [ -z "$APP_NAME" ]; then
    echo "Error: could not parse app name from ${SERVICE_FLY_TOML}" >&2
    exit 1
fi

cleanup() {
    rm -f "$REPO_ROOT/Dockerfile"
}
trap cleanup EXIT

cp "$SERVICE_DOCKERFILE" Dockerfile
echo "Deploying ${SERVICE} (app: ${APP_NAME}) ..."
DOCKER_HOST="" fly deploy . -a "$APP_NAME" "$@"
