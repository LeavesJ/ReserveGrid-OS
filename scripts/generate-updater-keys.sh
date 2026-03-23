#!/usr/bin/env bash
# generate-updater-keys.sh
#
# One-time setup: generates an Ed25519 keypair for Tauri auto-update
# signature verification. Run this locally, then:
#
#   1. Copy the PUBLIC key into tauri.conf.json → plugins.updater.pubkey
#   2. Add the PRIVATE key as a GitHub Actions secret:
#      - TAURI_SIGNING_PRIVATE_KEY  = the private key string
#      - TAURI_SIGNING_PRIVATE_KEY_PASSWORD = the password you choose
#
# Requires: cargo tauri CLI (cargo install tauri-cli)

set -euo pipefail

if ! command -v cargo-tauri &>/dev/null && ! cargo tauri --version &>/dev/null 2>&1; then
    echo "ERROR: tauri-cli not found. Install with: cargo install tauri-cli --version '^2' --locked"
    exit 1
fi

echo "Generating Tauri updater signing keypair..."
echo "You will be prompted for a password to protect the private key."
echo ""

cargo tauri signer generate -w ~/.tauri/reservegrid-updater.key

echo ""
echo "Keys written to:"
echo "  Private: ~/.tauri/reservegrid-updater.key"
echo "  Public:  ~/.tauri/reservegrid-updater.key.pub"
echo ""
echo "Next steps:"
echo "  1. Copy the contents of ~/.tauri/reservegrid-updater.key.pub"
echo "     into tauri.conf.json → plugins.updater.pubkey"
echo ""
echo "  2. Add GitHub Actions secrets:"
echo "     gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/reservegrid-updater.key"
echo "     gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD"
echo ""
echo "  3. Do NOT commit the private key to the repository."
