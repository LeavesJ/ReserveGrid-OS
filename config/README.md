# Policy Configuration

ReserveGrid OS uses TOML policy files to control template verification behavior.
The pool verifier reads the policy file specified by the `VELDRA_POLICY_FILE`
environment variable at startup.

## Files in This Directory

| File | Purpose | Tracked |
|---|---|---|
| `policy.toml` | Local development defaults (your working copy) | No (gitignored) |
| `policy-strict.toml` | All enforcement enabled, strict thresholds | Yes |
| `demo-open-policy.toml` | Permissive policy for demo/evaluation | Yes |
| `demo-showcase-policy.toml` | Balanced policy for live demonstrations | Yes |
| `demo-strict-policy.toml` | Aggressive policy for rejection showcase | Yes |

## Production Policy

Production deployment profiles live in `deploy/` with their own policy file
(`deploy/policy-prod.toml`). See `deploy/README.md` for details.

## Creating a Local Policy

Copy any tracked policy file as a starting point:

```bash
cp config/policy-strict.toml config/policy.toml
```

Edit `config/policy.toml` to match your requirements. This file is gitignored
and will not be committed.

## Policy Structure

All keys live under a flat `[policy]` table with an optional `[policy.safety]`
section for enforcement toggles. See `policy-strict.toml` for the full set of
available keys with comments.
