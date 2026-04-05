#!/usr/bin/env python3
"""
generate-license-key.py

Generates a signed veldra_lic_* license key using Ed25519.

Usage:
    # Generate a new signing keypair (one-time setup):
    python3 generate-license-key.py --generate-keys

    # Issue a license key:
    python3 generate-license-key.py \
        --private-key ~/.veldra/license-signing.key \
        --org-id org_acme \
        --tier inline_licensed \
        --features gateway,exporter,dashboard \
        --days 365

    # Verify a key against the public key:
    python3 generate-license-key.py \
        --verify \
        --public-key ~/.veldra/license-signing.pub \
        --key "veldra_lic_eyJ...sig"

The private key stays on veldra.org (or with the operator for self-hosting).
The public key is compiled into rg-desktop via VELDRA_LICENSE_PUBKEY env var.

Dependencies: pip install PyNaCl (or: pip install ed25519)
Uses the nacl (libsodium) Ed25519 implementation which is compatible with
ed25519-dalek on the Rust side.
"""

import argparse
import base64
import json
import sys
import time
import os


def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def generate_keys(output_dir: str):
    """Generate a new Ed25519 signing keypair."""
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    vk = sk.verify_key

    os.makedirs(output_dir, exist_ok=True)
    key_path = os.path.join(output_dir, "license-signing.key")
    pub_path = os.path.join(output_dir, "license-signing.pub")

    # Private key: 32 bytes, base64url encoded
    with open(key_path, "w") as f:
        f.write(b64url_encode(bytes(sk)) + "\n")
    os.chmod(key_path, 0o600)

    # Public key: 32 bytes, base64url encoded
    pub_b64 = b64url_encode(bytes(vk))
    with open(pub_path, "w") as f:
        f.write(pub_b64 + "\n")

    print(f"Private key: {key_path}")
    print(f"Public key:  {pub_path}")
    print()
    print("Public key (for VELDRA_LICENSE_PUBKEY):")
    print(f"  {pub_b64}")
    print()
    print("Compile rg-desktop with:")
    print(f"  VELDRA_LICENSE_PUBKEY={pub_b64} cargo tauri build")
    print()
    print("IMPORTANT: Keep the private key secret. Do NOT commit it.")


def issue_key(
    private_key_path: str,
    org_id: str,
    tier: str,
    features: list[str],
    days: int,
):
    """Generate a signed license key."""
    from nacl.signing import SigningKey

    with open(private_key_path) as f:
        sk_bytes = b64url_decode(f.read().strip())
    sk = SigningKey(sk_bytes)

    now = int(time.time())
    payload = {
        "org_id": org_id,
        "tier": tier,
        "issued_at": now,
        "expires_at": now + (days * 86400),
        "features": features,
    }

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=False)
    payload_b64 = b64url_encode(payload_json.encode("utf-8"))

    # Sign the base64url-encoded payload (matches rg-desktop verification).
    signed = sk.sign(payload_b64.encode("ascii"))
    sig_b64 = b64url_encode(signed.signature)

    key = f"veldra_lic_{payload_b64}.{sig_b64}"

    print(key)
    print()
    print(f"Org:      {org_id}")
    print(f"Tier:     {tier}")
    print(f"Features: {', '.join(features)}")
    print(f"Issued:   {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now))}")
    print(f"Expires:  {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now + days * 86400))}")

    return key


def verify_key(public_key_path: str, key: str):
    """Verify a license key against a public key."""
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    with open(public_key_path) as f:
        vk_bytes = b64url_decode(f.read().strip())
    vk = VerifyKey(vk_bytes)

    if not key.startswith("veldra_lic_"):
        print("ERROR: Key must start with 'veldra_lic_'", file=sys.stderr)
        sys.exit(1)

    body = key[len("veldra_lic_"):]
    dot_pos = body.rfind(".")
    if dot_pos < 0:
        print("ERROR: Key is missing signature component", file=sys.stderr)
        sys.exit(1)

    payload_b64 = body[:dot_pos]
    sig_b64 = body[dot_pos + 1:]

    sig_bytes = b64url_decode(sig_b64)

    try:
        vk.verify(payload_b64.encode("ascii"), sig_bytes)
    except BadSignatureError:
        print("FAILED: Signature verification failed", file=sys.stderr)
        sys.exit(1)

    payload_json = b64url_decode(payload_b64).decode("utf-8")
    payload = json.loads(payload_json)

    now = int(time.time())
    expired = payload.get("expires_at", 0) < now

    print("VERIFIED: Signature is valid")
    print(f"Org:      {payload.get('org_id')}")
    print(f"Tier:     {payload.get('tier')}")
    print(f"Features: {', '.join(payload.get('features', []))}")
    print(f"Expired:  {'YES' if expired else 'no'}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate and verify Veldra license keys (Ed25519)"
    )
    parser.add_argument(
        "--generate-keys",
        action="store_true",
        help="Generate a new Ed25519 signing keypair",
    )
    parser.add_argument(
        "--private-key",
        help="Path to the Ed25519 private key file",
    )
    parser.add_argument(
        "--public-key",
        help="Path to the Ed25519 public key file (for --verify)",
    )
    parser.add_argument("--org-id", help="Organization ID (e.g., org_acme)")
    parser.add_argument(
        "--tier",
        choices=["observe_free", "observe_paid", "inline_licensed"],
        help="License tier (must match rg-auth/src/db.rs tier constants)",
    )
    parser.add_argument(
        "--features",
        default="gateway,dashboard",
        help="Comma-separated feature list (default: gateway,dashboard)",
    )
    parser.add_argument(
        "--days", type=int, default=365, help="Days until expiry (default: 365)"
    )
    parser.add_argument(
        "--verify", action="store_true", help="Verify a key instead of issuing one"
    )
    parser.add_argument("--key", help="License key string to verify")
    parser.add_argument(
        "--key-dir",
        default=os.path.expanduser("~/.veldra"),
        help="Directory for key storage (default: ~/.veldra)",
    )

    args = parser.parse_args()

    if args.generate_keys:
        generate_keys(args.key_dir)
    elif args.verify:
        if not args.public_key or not args.key:
            parser.error("--verify requires --public-key and --key")
        verify_key(args.public_key, args.key)
    else:
        if not args.private_key or not args.org_id or not args.tier:
            parser.error("Issuing a key requires --private-key, --org-id, and --tier")
        features = [f.strip() for f in args.features.split(",") if f.strip()]
        issue_key(args.private_key, args.org_id, args.tier, features, args.days)


if __name__ == "__main__":
    main()
