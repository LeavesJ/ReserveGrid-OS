#!/bin/sh
set -e

# If Litestream replica bucket is configured, use Litestream to wrap rg-auth.
# Litestream restores the DB from the replica on boot, then starts rg-auth
# as a subprocess and continuously replicates WAL changes to object storage.
#
# Without LITESTREAM_REPLICA_BUCKET, rg-auth runs standalone (local dev).

if [ -n "$LITESTREAM_REPLICA_BUCKET" ]; then
    echo "[entrypoint] Litestream enabled, restoring from replica..."
    litestream restore -if-replica-exists -config /etc/litestream.yml "$VELDRA_AUTH_DB"
    echo "[entrypoint] Starting rg-auth under Litestream..."
    exec litestream replicate -config /etc/litestream.yml -exec "rg-auth"
else
    echo "[entrypoint] Litestream not configured, running rg-auth standalone."
    exec rg-auth
fi
