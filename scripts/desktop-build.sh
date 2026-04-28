#!/usr/bin/env bash
# desktop-build.sh — Wrapper for local rg-desktop builds.
#
# Modes:
#   dev      Skip updater bundle + signing. Fast local test builds.
#            No updater secrets required.
#   release  Full bundle including signed updater tarball.
#            Requires TAURI_SIGNING_PRIVATE_KEY and
#            TAURI_SIGNING_PRIVATE_KEY_PASSWORD in env.
#
# The license pubkey list is always required. Read from
# ~/.veldra/license-signing.pub by default, or pass --pubkey-file.
# For multi-pubkey rotation support, set VELDRA_LICENSE_PUBKEY
# directly to a comma-separated list (see ADR-001).
#
# Examples:
#   # Fast local dev build, no signing
#   scripts/desktop-build.sh dev
#
#   # Full signed build for distribution
#   scripts/desktop-build.sh release
#
#   # Multi-pubkey override for rotation testing
#   VELDRA_LICENSE_PUBKEY="$NEW_KEY,$OLD_KEY" scripts/desktop-build.sh dev

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-}"
TARGET="${TARGET:-aarch64-apple-darwin}"
LICENSE_PUBKEY_FILE="${LICENSE_PUBKEY_FILE:-$HOME/.veldra/license-signing.pub}"

usage() {
    cat <<EOF
Usage: $(basename "$0") <dev|release> [--target TARGET]

Modes:
  dev      No updater bundle, no signing required. Fast iteration.
           Automatically enables dev-passkey feature when
           VELDRA_DEV_PASSKEY_HASH is set.
  release  Full signed build for distribution.

Environment overrides:
  TARGET                   Rust target triple (default: aarch64-apple-darwin)
  LICENSE_PUBKEY_FILE      Path to license signing pubkey
                           (default: ~/.veldra/license-signing.pub)
  VELDRA_LICENSE_PUBKEY    Override pubkey value directly.
                           Comma-separated list supported (multi-pubkey).
  VELDRA_DEV_PASSKEY_HASH  Hex SHA-256 of your dev passkey.
                           Enables the dev-passkey feature in dev mode.
                           Generate: printf 'mysecret' | shasum -a 256 | cut -d' ' -f1

Release-mode requirements:
  TAURI_SIGNING_PRIVATE_KEY           Tauri updater private key (base64 blob)
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD  Password for the encrypted key
EOF
    exit 1
}

if [[ -z "$MODE" ]]; then
    usage
fi

case "$MODE" in
    dev|release) ;;
    -h|--help) usage ;;
    *)
        echo "ERROR: unknown mode '$MODE'" >&2
        usage
        ;;
esac

# Auto-load dev passkey hash if not already set.
DEV_PASSKEY_HASH_FILE="${DEV_PASSKEY_HASH_FILE:-$HOME/.veldra/dev-passkey-hash}"
if [[ -z "${VELDRA_DEV_PASSKEY_HASH:-}" && -f "$DEV_PASSKEY_HASH_FILE" ]]; then
    VELDRA_DEV_PASSKEY_HASH="$(tr -d '\n' < "$DEV_PASSKEY_HASH_FILE")"
    export VELDRA_DEV_PASSKEY_HASH
fi

# Resolve license pubkey.
if [[ -z "${VELDRA_LICENSE_PUBKEY:-}" ]]; then
    if [[ ! -f "$LICENSE_PUBKEY_FILE" ]]; then
        echo "ERROR: license pubkey file not found at $LICENSE_PUBKEY_FILE" >&2
        echo "Either create it (see scripts/generate-license-key.py --generate-keys)" >&2
        echo "or set VELDRA_LICENSE_PUBKEY directly." >&2
        exit 1
    fi
    VELDRA_LICENSE_PUBKEY="$(tr -d '\n' < "$LICENSE_PUBKEY_FILE")"
fi
export VELDRA_LICENSE_PUBKEY

echo "==> rg-desktop build"
echo "    mode:    $MODE"
echo "    target:  $TARGET"
echo "    pubkey:  ${VELDRA_LICENSE_PUBKEY:0:12}... ($(echo -n "$VELDRA_LICENSE_PUBKEY" | tr ',' '\n' | wc -l | tr -d ' ') key(s) embedded)"

# Ensure cargo and tauri-cli are available.
if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found on PATH. Source ~/.cargo/env or install Rust." >&2
    exit 1
fi
if ! cargo tauri --version >/dev/null 2>&1; then
    echo "ERROR: cargo-tauri not found. Install with:" >&2
    echo "  cargo install tauri-cli --version '^2' --locked" >&2
    exit 1
fi

if [[ "$MODE" == "release" ]]; then
    if [[ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" || -z "${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" ]]; then
        echo "ERROR: release mode requires TAURI_SIGNING_PRIVATE_KEY and" >&2
        echo "TAURI_SIGNING_PRIVATE_KEY_PASSWORD in the environment." >&2
        echo "For testing without signing, use: $(basename "$0") dev" >&2
        exit 1
    fi
    echo "    bundles: all (dmg + updater tarball, signed)"
    cargo tauri build --target "$TARGET"
else
    # Dev mode: produce only the dmg, skip updater artifacts entirely.
    # No TAURI_SIGNING_* env vars required.
    DEV_FEATURES=""
    if [[ -n "${VELDRA_DEV_PASSKEY_HASH:-}" ]]; then
        DEV_FEATURES="--features dev-passkey"
        echo "    devkey:  enabled (dev-passkey feature compiled in)"
    else
        echo "    devkey:  disabled (set VELDRA_DEV_PASSKEY_HASH to enable)"
    fi
    echo "    bundles: dmg only (no updater, no signing)"
    # shellcheck disable=SC2086
    cargo tauri build --target "$TARGET" --bundles dmg $DEV_FEATURES
fi

# Surface the output path.
DMG_PATH="$(find "$REPO_ROOT/target/$TARGET/release/bundle/dmg" -name '*.dmg' -newer "$REPO_ROOT/Cargo.toml" 2>/dev/null | head -1)"
if [[ -n "$DMG_PATH" ]]; then
    echo ""
    echo "==> Build complete"
    echo "    dmg:  $DMG_PATH"
    echo ""
    echo "Install with: open \"$DMG_PATH\""
fi
