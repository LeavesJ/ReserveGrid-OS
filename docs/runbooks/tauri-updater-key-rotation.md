# Runbook: Tauri Updater Key Rotation

**Audience:** Veldra operators (currently solo founder, future ops staff).
**Frequency:** Rare. Planned rotation on schedule, or emergency on key loss / compromise.
**Blast radius if botched:** Existing desktop installs lose auto-update ability and must manually reinstall from the veldra.org downloads page.

## When to Run This Runbook

| Trigger | Severity | Rotation allowed window |
|---|---|---|
| Private key lost (no recoverable copy) | Must rotate | Immediately |
| Password forgotten | Must rotate | Immediately |
| Scheduled rotation (annual hygiene) | Should rotate | Any time, coordinate with desktop release |
| Suspected compromise | Must rotate | Within 24 hours |
| Transfer of custody (e.g., co-founder added) | Optional | Plan with stakeholders |

## Prerequisites

- Local machine with `cargo tauri` installed (`cargo install tauri-cli --version '^2' --locked`)
- `gh` CLI authenticated against the Veldra GitHub org
- Access to `~/.veldra/license-signing.pub` (license pubkey, unchanged by this rotation)
- A durable place to store the new password (1Password vault, or Apple Notes until 1Password is set up)
- A second independent backup location for the new private key file

## Procedure

### Step 1. Back up the old key file (if it exists)

```bash
if [ -f ~/.tauri/reservegrid.key ] || [ -f ~/.tauri/reservegrid-updater.key ]; then
    mkdir -p ~/.tauri/archive
    mv ~/.tauri/reservegrid*.key* ~/.tauri/archive/ 2>/dev/null || true
    echo "Old key archived. Safe to proceed."
fi
```

Even a lost-password key is archived, not deleted, in case some future recovery method emerges.

### Step 2. Generate a new keypair

```bash
cargo tauri signer generate -w ~/.tauri/reservegrid-updater.key
```

Tauri will prompt for a password. Use a strong one. Immediately write both the file path and the password to your durable storage.

### Step 3. Record the new secrets

1. Open Apple Notes or 1Password.
2. Create an entry titled "Veldra Tauri updater signing key".
3. Store: the password, the generation date, and the path `~/.tauri/reservegrid-updater.key`.
4. Copy the private key contents to a second location (external drive, encrypted USB, or separate password manager vault).

```bash
# Sanity check that both files exist
ls -la ~/.tauri/reservegrid-updater.key ~/.tauri/reservegrid-updater.key.pub

# Copy pubkey value to clipboard for the next step
cat ~/.tauri/reservegrid-updater.key.pub | pbcopy
echo "Pubkey copied to clipboard."
```

### Step 4. Update tauri.conf.json

```bash
cd ~/Veldra/services/rg-desktop
# Open in editor
code tauri.conf.json
# OR
vim tauri.conf.json
```

Replace the `pubkey` value on the updater line (around line 78) with the new pubkey content from your clipboard. Preserve the surrounding JSON structure.

Verify the JSON is still valid:

```bash
python3 -c "import json; json.load(open('tauri.conf.json'))"
echo "JSON valid."
```

### Step 5. Update GitHub Action secrets

```bash
cd ~/Veldra

# Tauri signing key (the whole encrypted file contents)
gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/reservegrid-updater.key

# The password, entered when prompted (not echoed)
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD
```

Confirm both secrets are present:

```bash
gh secret list | grep TAURI_SIGNING
```

Expected output: two lines naming both secrets with a recent "updated" date.

### Step 6. Local test build

```bash
cd ~/Veldra
export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/reservegrid-updater.key)"
read -rs 'TAURI_PASS?Password: '; echo
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$TAURI_PASS"
unset TAURI_PASS

scripts/desktop-build.sh release
```

If the build completes and produces a dmg + `.app.tar.gz.sig`, the new keypair works end to end.

Unset the secrets from the current shell to avoid accidental leaks:

```bash
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD
```

### Step 7. Commit the pubkey change

```bash
cd ~/Veldra
git add services/rg-desktop/tauri.conf.json
git commit -m "chore: rotate tauri updater signing keypair

Old private key was irrecoverable (password lost). New keypair generated
locally with password stored in password manager. GitHub Action secrets
updated.

Impact: existing v1.0.x desktop installs (zero production users at time of
rotation) will lose auto-update. Users must manually reinstall the next
release from veldra.org. Auto-update works normally for installs from the
first release built against the new pubkey onward."
```

### Step 8. Document in DEVLOG

Append a dated entry to `docs/DEVLOG.md` noting the rotation, why, and the fact that zero production users were affected. Cross-reference ADR-001 (multi-pubkey license) and this runbook.

### Step 9. Release the first desktop build with the new key

Trigger the release workflow normally (tag push or manual dispatch). The CI build uses the updated GitHub secrets and produces signed artifacts that install and auto-update correctly.

### Step 10. Verify the release artifact

```bash
gh release download <tag> -p '*.dmg' -p '*.app.tar.gz.sig'
```

Install the dmg. Confirm the app launches and accepts a license key. Confirm the in-app Settings → Check for Updates flow works.

## Rollback

If anything goes wrong mid-procedure:

1. Old key file is still in `~/.tauri/archive/`. If the password was recovered in the meantime, restore and cancel rotation.
2. Git revert the tauri.conf.json commit.
3. Overwrite GitHub secrets with the original values (from the archived key, if you have the password).

If the new build is broken after commit, revert and re-run from Step 4.

## Key Custody Rules

1. The Tauri updater private key must exist in at least two durable locations at all times. GitHub Actions secrets count as zero because they are write-only.
2. The password must exist in at least one password manager entry plus one offline backup (paper in a safe, or an encrypted USB).
3. When a key is no longer in production use, archive it under `~/.tauri/archive/` rather than deleting it. Encrypted-but-lost keys may become recoverable via future cryptanalysis decades from now, and archives are cheap.
4. Never put a Tauri signing password into shell history, a config file that gets committed, or a chat message. Use `read -rs` when you need it in env vars.
5. Rotate keys on a maximum 24-month cadence even without incident. Forces the custody procedure to be exercised regularly.

## Related

- ADR-001: Multi-pubkey license validation (rg-desktop)
- R-150 in `docs/lessons.md`: signing keys require two independent durable copies
- Script: `scripts/desktop-build.sh`
- Script: `scripts/generate-updater-keys.sh`
