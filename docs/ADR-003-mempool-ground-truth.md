# ADR-003: v2.0 Invariant Shield Phase 2 — Mempool Ground Truth and Enforcement Policy

**Status:** Proposed
**Date:** 2026-04-29
**Deciders:** Jarron (Veldra, Inc.)
**Supersedes:** None
**Extends:** ADR-002 (v2.0 Invariant Shield Scope and Parser Choice)

## Context

ADR-002 Phase 1 introduced the v2.0 Invariant Shield as a re-derivation
pass inside `pool-verifier` that catches two attacker classes against
block templates: T1 internal `raw_block` tampering where the header,
coinbase, and body bytes are mutually inconsistent, and T2
`TemplatePropose` declared values disagreeing with what re-derivation
of the same `raw_block` bytes shows. Phase 1 #4b shipped on 2026-04-29
with 10 of 18 invariants wired and tested against genesis plus a
regtest segwit fixture, closing T1 and T2 to ~95% practical coverage.
Phase 1.5 will extend coverage with the remaining 8 belt-and-suspenders
checks after a production observation cycle in shadow mode.

Phase 1 cannot close one specific attacker class:

> **T3 consistent template-manager fabrication.** A malicious or
> compromised template-manager produces a `TemplatePropose` whose
> `raw_block_hex` carries a fabricated transaction set. The merkle
> root over the fabricated body matches the header, the witness
> commitment over the fabricated wtxids matches the coinbase
> `OP_RETURN`, the declared `coinbase_value` matches the fabricated
> coinbase outputs, every BIP-141 and BIP-34 check passes, and the
> shield emits `Agreed`. The fabrication is internally consistent
> by construction. The shield has no source of external truth to
> compare against.

T3 is real because template-managers are operational software with
network exposure. A template-manager is the smallest component an
attacker needs to compromise to siphon pool revenue: any operator
running a pool routes 100% of their revenue through template-manager
output. The attacker payload is not exotic, it is "include one of my
own outputs in every coinbase you produce". The shield as currently
shipped has no path to detect this.

Phase 2 closes T3 by introducing a second source of truth that the
verifier can cross-check the template's transaction set against. The
network mempool is the natural reference. A real Bitcoin block at
the time of mining must consist of the coinbase plus a subset of
transactions present in the operator's mempool at that block height.
A template with transactions absent from the mempool has either a
benign explanation (mempool propagation lag) or T3-class fabrication.
The verifier runs a tolerance-window check on the overlap and
rejects on excess divergence.

Phase 2 explicitly leaves two attacker classes open and documents
them as out of scope:

> **T4 compromised operator bitcoind.** If the bitcoind that backs
> the verifier's mempool view is itself the tampered source, no
> internal check can catch it. The operator owns the trust boundary
> at their bitcoind. Future mitigations (network-diverse second
> bitcoind, signed blockheader chain feed) are v3.x territory.

> **T5 selfish-mining or aggressive mempool-policy divergence.**
> Real Bitcoin mempools can legitimately differ across peers under
> selfish mining strategies or operator-side mempool policy
> divergence. The 4% tolerance window covers benign divergence;
> targeted selfish-mining-style attacks against template integrity
> are a different threat model that v2.0 does not address.

## Decision

**Add a Class M (Mempool) check to the v2.0 Invariant Shield that
runs after Class S and Class D checks. The verifier holds its own
bitcoind RPC client, maintains an in-memory mempool view as a
`HashSet<Txid>` refreshed on a configurable poll interval, and
checks every template's transaction set against the view with a
tolerance-window threshold defaulting to 4%. Failure modes use
fail-stale degradation up to 60 seconds, then fail-degraded to
Phase 1 behavior with a counter increment. Phase 2 rejection gates
the template only in inline mode; shadow and observe still emit
the verdict but do not gate template flow.**

This decision flows from six locked design forks documented in
EXECLOG D-18 on 2026-04-29. The full rationale per fork is in the
Options Considered section. Action item sequencing for
implementation lives in the Action Items section.

## Options Considered

### F1: Mempool source

**F1a (chosen): Verifier holds its own bitcoind RPC client.**
Pool-verifier gains a new RPC client. Polls `getrawmempool verbose=false`
every N seconds (configurable, default 10s). Maintains an in-memory
`HashSet<Txid>` plus a `last_refresh_unix_ms` timestamp. Per-template
checks are sub-microsecond hash lookups against the in-memory set.

**F1b (rejected): Template-manager pre-fetches mempool digest, ships
it inside `TemplatePropose`.** Trusting a possibly-tampered
template-manager to ship the ground truth defeats the point of
external cross-check. If template-manager is the attacker, it
controls the digest. Rejected on first principles.

**F1c (rejected): Verifier asks bitcoind on demand per template.**
N RPC calls per template at ~1ms each. For a 2000-tx template this
is ~2 seconds, brushing against `prevhash_verdict_timeout_ms = 2000`.
Latency budget too tight, and chatty RPC traffic adds operational
load on bitcoind.

### F2: Consistency check granularity

**F2a (rejected): Strict every-txid-must-be-in-mempool.** Every
template tx must be in the verifier's mempool view. Rejected on
false-positive risk. Mempool propagation lag between healthy peers
can transiently leave a 2-second gap during which a real tx is in
template-manager's mempool but not yet in verifier's. RBF transitions
and eviction events also produce legitimate divergence.

**F2b (chosen): Tolerance window with configurable threshold,
default 4%.** Templates pass when at most 4% of their transactions
are unknown to the verifier's mempool view. Reject with
`v2_invariant_mempool_tolerance_exceeded` otherwise. Threshold
lives in `policy.toml` as `mempool_tolerance_pct`.

The 4% default is operationally tunable, set per the criteria:

- Mainnet mempool propagation between healthy peers is typically
  under 2 seconds; measured tx-set divergence sits well under 1%
  during normal operation.
- 4% provides headroom for RBF transitions, eviction events, and
  peers-of-our-bitcoind disagreements without opening a meaningful
  tampering window.
- A T3-class fabrication cannot stay reliably under 4% of a
  multi-thousand-tx template without network-side coordination.
- **Tuning trigger:** false positive rate above 0.5% of templates
  in shadow observation raises threshold by 1% increments; if shield
  catches genuine attacks, consider lowering toward 2%.
- **Acceptance metric for default 4%:** zero false positives across
  one week of shadow-mode production observation against a real
  operator bitcoind.

**F2c (rejected): Coinbase-and-fee-only.** Verifier checks only that
the coinbase output sum is consistent with declared mempool fees plus
subsidy. Catches the most-revenue-impactful T3 attack but misses
fabrications that match the fee math but include fake non-coinbase
transactions (which can still alter the block's effective transaction
set and hide value-extraction patterns). Insufficient.

**F2d (rejected): Policy-driven mode selection.** Operator chooses
strict, tolerant, or coinbase-only via policy. Adds operational
complexity for v2.0 launch with no current customer demand for the
flexibility.

### F3: Enforcement policy

**F3a (chosen): Inline-only enforcement.** Phase 2 rejection blocks
the template only in inline mode, matching Phase 1 today. Shadow
and observe emit the verdict but do not gate template flow. Operators
graduate to F3b after production observation shows zero false
positives.

**F3b (rejected for v2.0, candidate for v2.1): Inline plus observe
enforcement.** Observe-mode operators run real miners against real
hashrate; arguably they want T3 protection too. Defer because
inline-only is the conservative default; promotion to F3b should
come from operator data, not a priori reasoning.

**F3c (rejected): Per-mode operator override.** Adds policy keys
and decision surface without obvious customer demand. Revisit in
v2.1 if observed need surfaces.

### D: Failure mode under bitcoind unavailability

**D1 (rejected): Fail-closed.** Bitcoind unreachable, every template
rejects with `v2_invariant_mempool_unavailable`. Creates an
availability cliff during normal bitcoind blips (restart, network
hiccup, restart-on-config-reload). Production hostility outweighs
security benefit.

**D2 (rejected as standalone): Fail-degraded.** Phase 2 check
skipped immediately on RPC unavailability, templates fall through to
Phase 1 with counter increment. Acceptable but loses the recently-fresh
mempool view that is still trustworthy for several seconds.

**D3 (chosen): Fail-stale with bounded staleness then fail-degraded.**
Verifier serves the last known mempool view up to 60 seconds old.
Beyond that, Phase 2 check is skipped, templates fall through to
Phase 1 behavior, and `verifier_phase2_degraded_total` increments.
60-second default lives in `policy.toml` as
`mempool_max_stale_secs`. Bitcoind blips under 60 seconds remain
fully covered; longer outages degrade gracefully with operator
alerting.

### Q6: ADR-003 vs extending ADR-002

**Chosen: ADR-003 dedicated.** ADR-002 is already substantial
(~400 lines covering Phase 1 scope, parser choice, facade design,
check set, and action items). Phase 2's threat model formalization
warrants its own document for reviewers and future-you. ADR-002
gains a short Phase 2 stub section that cross-links to ADR-003.

## Trade-off Analysis

The chosen design optimizes for three properties.

**Trust completeness for the v2.0 launch story.** With Phase 2 wired,
the shield closes T1, T2, and T3. T4 (compromised operator bitcoind)
is operator-side and explicitly named as out of scope. T5 (selfish
mining) is a different threat model. The trio T1+T2+T3 is what the
v2.0 marketing narrative needs and what a paying mainnet customer
needs to trust the inline-mode enforcement decision.

**Operational realism.** F1a verifier-owned RPC client matches how
operators already deploy: pool-verifier already has metrics endpoints
and a config file; adding a bitcoind client follows existing patterns.
D3 fail-stale behavior matches operational reality where bitcoind
blips happen under load and we cannot afford to convert every blip
into a production outage. F2b 4% threshold acknowledges that real
mempools diverge benignly and the shield must distinguish divergence
from attack.

**Forward compatibility with v3.x.** Per-tx detail mode lets dashboards
drill into specific missing transactions, which is the data shape v3.x
will need for selfish-mining detection or operator-side mempool policy
analytics. Adding the mode now keeps the export schema stable when
v3.x ships. The new reason codes follow the existing `v2_invariant_*`
prefix convention so canonical strings stay stable across protocol,
verifier, exports, and docs (R-118 / Tier 1 #3 pattern).

The chosen design accepts three costs.

**One new RPC client surface in pool-verifier.** Adds bitcoind RPC
config keys, error handling, retry policy, and metrics. Estimated
~200-300 lines of new code in pool-verifier across rpc client,
mempool view subscription, fail-stale state machine, and shield
integration.

**Operational complexity at deploy time.** Operators must point
pool-verifier at a bitcoind RPC endpoint. In observe and inline modes
this is the same bitcoind template-manager already consumes via
rg-feed-adapter; the verifier could in principle reuse the same
endpoint. Deployment runbook gains a Phase 2 section explaining the
shared bitcoind credential pattern.

**One additional latency dimension.** Per-template mempool checks are
sub-millisecond by design (HashSet lookup), but the polling loop
maintains the view in the background. Tuning the poll interval is
a trade-off between view freshness and bitcoind load. Default 10s
is a starting point; production observation will inform.

## Consequences

**What becomes easier.**

- The v2.0 marketing story acquires a concrete trust completeness
  claim ("the shield catches three of three template-manager attacker
  classes") tied to specific reason codes, not aspirational language.
- Operators running inline mode get protection against T3 without
  any per-template configuration; the shield runs by default once
  Phase 2 is wired and bitcoind RPC is configured.
- Selfish-mining detection (v3.x) and operator mempool analytics
  ride the same per-tx detail data shape Phase 2 introduces, so
  no schema break later.
- Public veldra-site redesign (task #43) gains a clear "Threat Model"
  page anchor that names T1 through T5 explicitly, which the
  competitive comparison matrix can reference.

**What becomes harder.**

- Pool-verifier deploy now requires bitcoind RPC creds; previously
  pool-verifier was bitcoind-agnostic. Documentation burden grows.
- Operators on observe mode using the Veldra-hosted feed must wire
  their own bitcoind for Phase 2 to work, or accept Phase 2 stays
  in degraded mode (Phase 1 only) on shadow-fed deployments.
- Test harness for Phase 2 needs a regtest bitcoind plus the ability
  to craft a tampered template that includes a fabricated tx. Phase
  2 #3 covers this.

**Trust boundary statement.** ReserveGrid OS v2.0 with Phase 1+2
shipped catches T1, T2, and T3 attacker classes. T4 compromised
operator bitcoind and T5 selfish mining are explicitly out of scope.
This is the canonical sentence that public docs, threat model page,
and customer conversations should converge on.

## Phase 2 Check Set and Reason Code Allocation

Phase 2 wires one Class M (Mempool) check that runs after Class S
and Class D in the existing shield short-circuit chain. The single
check produces four canonical reason codes covering the failure
modes:

| Reason code | When it fires |
| --- | --- |
| `v2_invariant_mempool_tx_unknown` | A specific template tx is not in the verifier's mempool view. Per-tx detail mode emits one record per missing tx; default mode emits one summary record listing first 10 and total count. |
| `v2_invariant_mempool_tolerance_exceeded` | Aggregate count of unknown txs exceeds the configured `mempool_tolerance_pct` (default 4%). Always emitted as one record per template. |
| `v2_invariant_mempool_unavailable` | Bitcoind RPC unreachable beyond the `mempool_max_stale_secs` (default 60s) fail-stale window. Phase 2 check skipped, template falls through to Phase 1 behavior; this code accompanies the verdict to record the degraded path. |
| `v2_invariant_mempool_view_stale` | Mempool view age exceeds the staleness threshold during a refresh attempt that did not yet trigger fail-stale; observability code, fires when a refresh is overdue but not yet over the limit. |

Total V2 invariant codes after Phase 2: 22 (18 Phase 1 + 4 Phase 2).
Total canonical reason codes after Phase 2: 95 (37 verdict + 59
gateway minus 1 shared `internal_error`). Public-surface count
refresh trigger when Phase 2 ships, gated on the website redesign
per task #43 and BIZLOG 2026-04-29.

**Per-tx detail mode** (`mempool_per_tx_detail` in `policy.toml`,
default `false`):

- false (default): one verdict record per template with `reason_code`
  set to the appropriate aggregate code and `reason_detail` listing
  up to 10 example txids plus the total unknown count. Bounded
  export volume.
- true: one verdict record per missing tx with `reason_code =
  v2_invariant_mempool_tx_unknown` and `reason_detail` carrying the
  txid. Plus one aggregate record per template if the threshold is
  also exceeded. Useful for forensic analysis but produces N records
  per template where N is the missing-tx count.

**New policy keys added to `[policy]` table in `policy.toml`:**

```
mempool_enforce              bool, default true   master enable for Phase 2
mempool_tolerance_pct        f64,  default 4.0    tolerance window threshold
mempool_poll_interval_secs   u64,  default 10     getrawmempool poll cadence
mempool_max_stale_secs       u64,  default 60     fail-stale window
mempool_per_tx_detail        bool, default false  forensic detail mode
mempool_rpc_url              str,  default ""     bitcoind RPC endpoint (required when mempool_enforce=true)
mempool_rpc_user             str,  default ""     bitcoind RPC user
mempool_rpc_pass             str,  default ""     bitcoind RPC pass (also via VELDRA_BITCOIND_RPC_PASS)
```

Eight new policy keys take the v1.1.0 `[policy]` count of 61 to
69 once Phase 2 ships. Bumping public docs and i18n entries follows
the Tier 1 #3 / R-167 pattern.

**New metrics:**

```
verifier_phase2_degraded_total       counter      bitcoind unavailable beyond fail-stale
verifier_mempool_view_age_seconds    gauge        seconds since last successful refresh
verifier_mempool_view_size           gauge        current HashSet<Txid> count
verifier_phase2_checks_total{result} counter vec  result in {agreed, rejected, degraded}
```

Four new metrics. Dashboards consume `verifier_mempool_view_age_seconds`
and `verifier_phase2_degraded_total` for operator alerting.

## Action Items

The Phase 2 implementation sequence mirrors Phase 1 #4b's bucketing
discipline. Each bucket lands as one or more commits with explicit
test gates and CI green requirements before the next bucket starts.

1. [ ] **Phase 2 #1 rg-consensus** Add `MempoolDisagreement`,
   `MempoolToleranceExceeded`, `MempoolUnavailable`, and
   `MempoolViewStale` variants to `ConsensusViolation`. Mirror as
   four new `VerdictReason::V2InvariantMempool*` and four new
   `ReasonCode::V2InvariantMempool*` variants. Update `ALL_CODES`
   length assertions (18 → 22 for ConsensusViolation, 33 → 37 for
   VerdictReason, 91 → 95 for ReasonCode). Pure facade additions, no
   wiring or behavior. Tests cover round-trip canonical strings,
   distinct mapping, and `as_reason_code` exhaustiveness.

2. [ ] **Phase 2 #2 pool-verifier** Add `bitcoind_rpc` module
   (HTTP JSON-RPC client over reqwest, basic auth from
   `mempool_rpc_user` and `mempool_rpc_pass`). Add `mempool_view`
   module owning the `HashSet<Txid>` plus `last_refresh_unix_ms`
   plus a tokio task that polls `getrawmempool` every
   `mempool_poll_interval_secs`. Add `MempoolState` enum
   (`Fresh`, `Stale`, `Degraded`) wired to the fail-stale
   state machine per D3. Extend `check_invariant_shield` with
   a Class M section after the existing Class S / Class D
   chain that runs the tolerance check against the current
   view. Wire the four new reason codes plus per-tx detail
   mode behind `mempool_per_tx_detail`. Wire the four new
   metrics. Eight new policy keys parsed from `policy.toml`.
   `cargo build`, `cargo clippy --all-targets -- -D warnings`,
   `cargo test` all green for `pool-verifier`.

3. [ ] **Phase 2 #3 pool-verifier integration tests** Add a
   regtest-backed test harness that spins up bitcoind via the
   existing `lncm/bitcoind:v27.0` container, mines a few blocks,
   and constructs three test scenarios: (a) happy path where the
   template's tx set fully overlaps the verifier's mempool view,
   shield emits Agreed; (b) fabrication path where the template
   includes a tx not in the mempool, shield emits
   `v2_invariant_mempool_tolerance_exceeded` when fabricated
   ratio is above 4%; (c) bitcoind unavailable path where RPC
   times out, shield enters fail-stale then fail-degraded after
   60 seconds, counter increments, template falls through to
   Phase 1 behavior. Plus per-tx detail mode test that flips
   the policy key and verifies one verdict record per missing
   tx. Use `tokio::time::pause` to compress the 60s fail-stale
   window into a fast test.

4. [ ] **Phase 2 #4 documentation** Draft this ADR-003 (done as
   part of this design pass). Add a Phase 2 stub section to
   ADR-002 that cross-links here. Update
   `docs/three-mode-architecture.md` with a Phase 2 paragraph
   under the existing Invariant Shield section explaining the
   Class M check and the fail-stale state machine. Update
   `docs/deployment-runbook.md` with the eight new policy keys
   and the bitcoind RPC credential pattern. Update the
   `verifier_shield_skipped_total` metric description in the
   metrics export to mention the new `verifier_phase2_*`
   metrics. The public veldra-site reason code total 91 → 95
   sweep is gated on the website redesign per task #43.

5. [ ] **Phase 2 #5 lessons closure** Add R-168 (or next free
   number) to `docs/lessons.md` capturing any new patterns
   surfaced during Phase 2 implementation. Likely candidates:
   tokio polling-loop shutdown patterns, fail-stale state
   machine testing patterns, regtest bitcoind harness
   reuse pattern.

6. [ ] **Phase 2 #6 production observation** After Phase 2 #2
   and #3 ship and CI is green on origin, run the verifier in
   shadow mode against an operator bitcoind for one week.
   Acceptance criteria: zero false positives at the 4% default
   threshold across the full week. If the bar is not met,
   tune the default threshold downward toward 2% before any
   v2.0 launch announcement that names Phase 2 as live.
   Document the observation results in DEVLOG and in a new
   TESTLOG CL entry that closes Phase 2 verification.

7. [ ] **Phase 2 #7 v3.x precursor markers** Per-tx detail mode
   and the `verifier_mempool_view_size` metric set up the data
   shape for v3.x selfish-mining detection. No code work in
   v2.0, but document the upgrade path in DEVLOG so the v3.x
   design has the prior art linked.

## Notes

This ADR is the design output of EXECLOG D-18 (2026-04-29).
Implementation begins after this document is reviewed and accepted.
Phase 2 #1 through Phase 2 #4 are the next four engineering
bucket commits, sequenced to ship Phase 2 in 3 to 4 sessions.

R-118 reason code stability commitment: the four new
`v2_invariant_mempool_*` strings are canonical from the moment they
land in `rg-consensus` and propagate through `rg-protocol` and
`reservegrid-common`. No renames after Phase 2 #1 ships.

Cross-references:

- ADR-002 Invariant Shield scope and Phase 1 design.
- EXECLOG D-15 (parser choice), D-16 (Phase 1 #4b criticality
  tiering), D-17 (regtest fixture sourcing), D-18 (Phase 2
  architecture forks, this ADR's source).
- BIZLOG 2026-04-29 (post-Phase-2 website redesign reservation).
- Task #43 (veldra-site redesign trigger).
- PRODUCTION_BLOCKERS PB-9 (Independent Consensus Re-derivation;
  Phase 2 closes the trust maturity gap that PB-9 names).
