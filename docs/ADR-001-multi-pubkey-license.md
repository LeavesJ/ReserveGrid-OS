# ADR-001: Multi-Pubkey License Validation in rg-desktop

**Status:** Proposed
**Date:** 2026-04-14
**Deciders:** Jarron (Veldra, Inc.)

## Context

The desktop license module validates Ed25519-signed license keys against a single public key embedded at compile time via the `VELDRA_LICENSE_PUBKEY` environment variable. This worked when there was one signing keypair forever. It fails the moment the signing keypair changes for any reason.

The breakage path we hit on 2026-04-14:

The v1.0.2 desktop binary was built before the production license signing keypair (S-6) was generated. The installed app on the operator's machine has the v1.0.2-era pubkey baked in. A license key issued today, signed by the S-6 production key, fails validation against the embedded v1.0.2 pubkey. The error message reads "Validation failed" and there is no way to recover without rebuilding the desktop app.

The product strategy is desktop-heavy. Operators download the desktop app, pay for a tier, paste the license key, and use the app. They will not rebuild from source. They will not understand why the key fails. They will not return.

This problem repeats every time the signing keypair changes for any reason: scheduled rotation, key compromise, organizational handoff, separate signing keys per environment. Every such event would otherwise force a desktop release and a forced upgrade for every customer.

The fix needs to be once-and-done.

## Decision

Replace the single `VELDRA_LICENSE_PUBKEY` with a comma-separated list of public keys. The desktop tries each in order and accepts on first successful verification. The format remains base64url for each individual key.

```
VELDRA_LICENSE_PUBKEY=<current_pubkey>,<previous_pubkey>,<emergency_rotation_pubkey>
```

Single-pubkey deployments continue to work unchanged. The comma-split of a single-element string produces a one-element list.

## Options Considered

### Option A: Multi-pubkey list at compile time (proposed)

| Dimension | Assessment |
|---|---|
| Complexity | Low. ~30 lines of Rust changed. |
| Cost | Zero. No new dependencies, no runtime overhead. |
| Scalability | High. Supports unlimited pubkeys, but practical use is 2 to 4. |
| Team familiarity | Native. Pure Ed25519, same algorithm. |
| Customer impact | Zero. No UX change, no migration. |
| Time to ship | One commit, one build. |

**Pros**
- Backward compatible. Single-key configs work without change.
- Solves key rotation forever. Ship desktop with both old and new pubkey, all customers validate.
- Solves disaster recovery. If a private key is compromised, rotate by issuing a new pubkey and shipping the next desktop release with both.
- Supports multi-environment signing (production, staging, internal demo).
- No customer action ever needed. No rebuild, no reinstall, no support burden.
- Fast. Ed25519 verification is microseconds. Trying 4 keys is still instant.

**Cons**
- A compromised pubkey remains a valid signer until the next desktop release strips it from the list. Mitigated by treating pubkey rotation as a release-cadence event, not a hot rotation.
- Build artifact slightly larger by ~32 bytes per pubkey embedded. Negligible.

### Option B: Runtime pubkey fetch from veldra.org

The desktop fetches the current pubkey list from `https://veldra.org/license/pubkeys` on first run, pins it locally, and re-checks periodically.

| Dimension | Assessment |
|---|---|
| Complexity | High. Network code, retry logic, TLS pinning, offline degradation. |
| Cost | Recurring. Veldra needs to serve and monitor the endpoint. |
| Scalability | Constrained. Single endpoint becomes a critical dependency. |
| Customer impact | Negative. Adds network requirement to a tool sold on offline operation. |
| Time to ship | Weeks. |

**Pros**
- True hot rotation possible.
- Single source of truth.

**Cons**
- Breaks the "offline validation" promise that is part of the product pitch (S-6 deliberately moved to offline validation in v1.0.1).
- Introduces a network dependency that operators will challenge in security review.
- TLS pinning needed or downgrade attacks become viable.
- Endpoint becomes a public DDoS target.
- Out of scope for v1.x.

### Option C: Trust-on-first-use pubkey from license metadata

Embed the pubkey in the license key payload itself, signed by a meta-key that ships with the desktop. First use of a key pins the pubkey for that license.

| Dimension | Assessment |
|---|---|
| Complexity | High. New key-of-keys hierarchy, pin storage, revocation logic. |
| Cost | Engineering time, audit surface. |
| Scalability | Adequate but speculative. |
| Customer impact | Confusing. Adds a layer customers cannot reason about. |
| Time to ship | Weeks. |

**Cons**
- Solves a problem we do not have. We are not running a CA.
- Increases attack surface.
- Hard to explain in a security review.

### Option D: Status quo (single pubkey, rebuild forever)

| Dimension | Assessment |
|---|---|
| Complexity | None. |
| Cost | Per-rotation: rebuild and force every customer to upgrade. |
| Customer impact | Severe at every rotation event. |

**Cons**
- Already failing. The current installed desktop cannot accept the production-signed key.
- Every future rotation creates a forced upgrade event.
- Incompatible with "desktop heavy" product strategy.

## Trade-off Analysis

Option A wins on every dimension except hot rotation, which we do not need. The cost of going from one to many pubkeys is one struct field, one parse loop, and ~30 lines of code. The benefit is that every future key rotation becomes a release-cadence event instead of a customer-facing crisis.

Option B and C solve more elaborate threat models that we do not have. The product is sold on offline operation. The signing key is a Veldra-controlled secret with low rotation frequency. There is no CA hierarchy to manage and no scenario where a single fetched-at-runtime endpoint adds value over a list embedded at build time.

Option D is the current state and it just broke. Any other option is better.

## Consequences

**What becomes easier**

- Issuing a new production keypair without breaking existing customer installations.
- Operating multiple signing environments (staging, internal demo) without separate desktop builds.
- Recovering from a private key compromise. Rotate, ship next release with both old and new pubkey, deprecate old pubkey in the release after.
- Onboarding the first pilot customer. The desktop they install today will accept keys signed by any production key we issue going forward as long as the relevant pubkey is in the embedded list.

**What becomes harder**

- Documentation needs to mention the comma-separated format.
- The release process needs to track which pubkeys are currently embedded so we know when it is safe to retire an old one.
- A compromised pubkey lives in the wild until the next desktop release. This is acceptable because rotation is a planned event, not an incident response one.

**What we will need to revisit**

- If we ever need true hot rotation (e.g., regulator-mandated revocation within 24 hours), revisit Option B.
- If the embedded pubkey list grows past 4 entries, audit which can be retired.

## Action Items

1. [x] Patch `services/rg-desktop/src/license.rs` to parse `VELDRA_LICENSE_PUBKEY` as a comma-separated list and try each pubkey on verification.
2. [x] Update tests to cover multi-pubkey scenarios (one valid, multiple valid, no valid).
3. [ ] Update `services/rg-desktop/src/license.rs` doc comment to describe the new format.
4. [ ] Update the `release-desktop.yml` workflow to set `VELDRA_LICENSE_PUBKEY` from a `secrets.VELDRA_LICENSE_PUBKEYS` GitHub secret (renamed for clarity, value is comma-separated list).
5. [ ] Add to deployment runbook: how to rotate a signing key safely (issue new pubkey, ship desktop release with both, wait one release cycle, deprecate old).
6. [ ] Add R-149 to lessons.md: "Compile-time embedded credentials should always be lists, never scalars, even if you currently have only one. The cost is one parse loop. The benefit is that future-you can rotate without a forced upgrade."
