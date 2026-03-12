#!/usr/bin/env bash
# Generate a throwaway secp256k1 keypair for regtest/dev use.
# Produces dev/keys/noise.key (32-byte raw secret key).
#
# Requirements: openssl (any version with ec support).
#
# WARNING: This keypair is for development ONLY. Do not use in production.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${SCRIPT_DIR}/keys"

mkdir -p "${KEYS_DIR}"

KEY_FILE="${KEYS_DIR}/noise.key"

if [ -f "${KEY_FILE}" ]; then
    echo "Key file already exists at ${KEY_FILE}; skipping generation."
    echo "Delete it manually if you want to regenerate."
    exit 0
fi

# Generate a 32-byte random secret key (valid for secp256k1 with high probability).
openssl rand 32 > "${KEY_FILE}"

# Derive the x-only public key from the secret key using openssl.
# 1. Convert raw 32 bytes to a DER-encoded EC private key.
# 2. Extract the public key and take the x-coordinate (bytes 1..33 of compressed form).
PUBKEY_HEX=$(openssl ec -inform DER \
  -in <(printf '\x30\x2e\x02\x01\x01\x04\x20' && cat "${KEY_FILE}" && printf '\xa0\x07\x06\x05\x2b\x81\x04\x00\x0a') \
  -pubout -outform DER 2>/dev/null \
  | tail -c 65 | head -c 33 | tail -c 32 | xxd -p -c 32)

# If openssl derivation failed, abort. The gateway requires matching
# authority_pubkey in gateway.toml, so a placeholder is not viable.
if [ -z "${PUBKEY_HEX}" ] || [ "${#PUBKEY_HEX}" -ne 64 ]; then
    echo "ERROR: Could not derive x-only pubkey from ${KEY_FILE}."
    echo "Ensure openssl and xxd are installed."
    exit 1
fi

echo "Generated dev noise keypair at ${KEY_FILE}"
echo "Authority x-only pubkey: ${PUBKEY_HEX}"

# Patch authority_pubkey in dev/gateway.toml and docker-compose.yml so the
# freshly generated key matches. Without this, load_authority_credentials
# fails with PubkeyMismatch and the gateway exits immediately.
GATEWAY_TOML="${SCRIPT_DIR}/gateway.toml"
COMPOSE_FILE="${SCRIPT_DIR}/../docker-compose.yml"

if [ -f "${GATEWAY_TOML}" ]; then
    sed -i "s/^authority_pubkey = \"[0-9a-fA-F]\{64\}\"/authority_pubkey = \"${PUBKEY_HEX}\"/" "${GATEWAY_TOML}"
    echo "Patched authority_pubkey in ${GATEWAY_TOML}"
fi
if [ -f "${COMPOSE_FILE}" ]; then
    # The 64-char hex pubkey appears as a standalone YAML list element
    # right after the "--authority-pubkey" element.
    sed -i "/\"--authority-pubkey\"/{n;s/\"[0-9a-fA-F]\{64\}\"/\"${PUBKEY_HEX}\"/;}" "${COMPOSE_FILE}"
    echo "Patched --authority-pubkey in ${COMPOSE_FILE}"
fi

echo "WARNING: This keypair is for development ONLY. Regenerate for production."
