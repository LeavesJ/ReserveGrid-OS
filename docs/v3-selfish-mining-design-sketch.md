# v3.x Selfish-Mining Detection: Design Sketch

**Status:** Preliminary design notes, not an ADR. Captured 2026-05-01 while v2.0 Phase 2 context is fresh, ahead of formal v3.x design work that begins after the v2.0 launch announcement and at least one quarter of operator deployment data.
**Audience:** Future engineering on the v3.x design team plus design partners evaluating the upgrade path.
**Cross-references:** ADR-003 T5 selfish-mining out-of-scope statement, BIZLOG 2026-04-16 Behavioral Intelligence Platform concept, BIZLOG 2026-05-01 v1 vs v2 reliability scorecard, DEVLOG 2026-05-01 Phase 2 #7 v3.x precursor markers paragraph.

## Why selfish-mining detection lives in v3.x not v2.x

ADR-003 D-18 explicitly carves T5 (selfish-mining and aggressive mempool-policy divergence) out of v2.0 scope. The reasoning was twofold. First, the verifier layer alone cannot tell a benign mempool divergence (legitimate operator-side policy, propagation latency) from a deliberately selfish strategy; both produce the same "template references txs the verifier mempool has not seen" signal. Second, distinguishing the two requires temporal analysis across many templates plus cross-operator correlation, neither of which the per-template synchronous shield path is built for.

v3.x picks this up because by then the data shape Phase 2 ships (per-tx unknown lists, time-series Phase 2 result counters, mempool view age and size gauges) has been collecting for at least a quarter at design partner deployments. That data set is the substrate for the detector.

## What "selfish mining at the template layer" actually looks like

Selfish mining in the original Eyal-Sirer formulation operates at the block layer: the attacker withholds a private chain branch and releases it strategically. At the template layer, a related but distinct attack pattern matters: the operator's template-manager is fed information about txs the rest of the network has not yet seen (a private mempool segment), and constructs templates that reference those txs ahead of the network's mempool state. From the verifier's perspective, this looks like Phase 2 ToleranceExceeded rejections that:

- Cluster temporally (high frequency in a short window, then quiet)
- Reference txid prefixes that share structural patterns (same fee tier, same sender pattern, same script type, suggesting one source feeding the private mempool segment)
- Resolve quickly (the txs the verifier flagged as unknown appear in the network mempool within seconds to a couple of blocks, confirming they were real txs that the operator just had earlier)

A buggy template-manager produces ToleranceExceeded with random-looking txid distribution and no temporal clustering. A selfish strategy produces clustered, structurally-coherent unknown sets that resolve.

## What v2.0 Phase 2 already provides for the detector

Phase 2 #7 markers paragraph in DEVLOG enumerates the substrate. Restated here for the v3.x design team:

| Substrate | Source | What v3.x reads from it |
|---|---|---|
| `v2_invariant_mempool_tolerance_exceeded` verdict records in NDJSON export | Verifier ingress writer (Phase 2 #2 wired) | Per-template rejection events, timestamp, height, sample of unknown txids |
| `[policy.mempool] per_tx_detail = true` in operator policy | Phase 2 #3.5 wiring | Full unknown-txid list per rejection (no cap), enabling fine-grained pattern matching |
| `verifier_phase2_checks_total{result}` Prometheus counter | Phase 2 #2 metrics | Time-series substrate for ratio-based alerting and clustering detection |
| `verifier_mempool_view_size` Prometheus gauge | Phase 2 #2 metrics | Calibration baseline for expected unknown ratio at evaluation time |
| `verifier_mempool_view_age_seconds` Prometheus gauge | Phase 2 #2 metrics | Lets the detector exclude rejections that fired during a stale view (which produce noisier signal) |

No protocol changes required. The v3.x detector subscribes to the existing NDJSON export and the existing metrics endpoint. v2.0 operators flip `per_tx_detail = true` to upgrade their export shape; everything else flows through the existing wire.

## Detection algorithm sketch (rough, not specified)

A first-cut detector takes three inputs per evaluation window (e.g., per block height range or per rolling 10-minute window):

1. The set of `v2_invariant_mempool_tolerance_exceeded` rejections in the window from the operator under test.
2. The full unknown-txid list per rejection (from per-tx detail mode).
3. The same operator's `verifier_phase2_checks_total{result}` counter slope across the window.

Three signals get computed:

- **Temporal density.** Rejections per minute, normalized by the operator's accepted-template throughput. Selfish patterns spike during the strategy window then drop sharply. Random bugs distribute uniformly.
- **Structural coherence of unknown txids.** Cluster the unknown txids in the window by fee rate, script type, output pattern, prevout topology. A shared cluster signature across many rejections is the smoking gun. Random-bug rejections show flat distributions across these dimensions.
- **Resolution latency.** For each previously-unknown txid, measure the time until it appears in the verifier's mempool view (via subsequent `verifier_phase2_checks_total{result="agreed"}` increments referencing the same txid, or via independent mempool probe). Selfish patterns show low resolution latency (seconds to minutes); random bugs show no resolution at all (the txid is fabricated and never appears).

A rough scoring rubric: any operator scoring above a threshold across two of the three signals in two consecutive evaluation windows triggers a v3.x advisory event. The scoring math is the open design question; the substrate it consumes is already shipped.

## Architecture (where the detector runs)

Two architectural options for v3.x. Both reuse the existing verifier; neither requires a verifier-side rewrite.

**Option A: Verifier-local detector.** A new `services/rg-detector` or extension to `pool-verifier` consumes the same NDJSON export the verifier produces, runs the detection algorithm against the local operator's data, emits its own NDJSON event stream (`v3_advisory_*` reason codes) plus dashboard metrics. Fully on-prem; no cross-operator correlation. Ships first because it requires zero infrastructure beyond the operator's existing Veldra deployment.

**Option B: Federated cross-operator detector.** A separate Veldra-hosted service consumes anonymized signals from N operators and runs cross-correlation. The signals exclude raw txid lists (privacy) but include cluster fingerprints, temporal density, and resolution latency stats. Detects patterns that span pools (the same selfish-mining operator deploying against multiple pools simultaneously) which the local detector cannot see by definition. Ships second because it requires multi-operator network density, the federated aggregation infrastructure BIZLOG 2026-04-13 reserves Loki for, and the privacy-preserving aggregation work BIZLOG 2026-04-16 names as the RISELab tie-in.

The two options compose: Option A ships first, runs locally, feeds Option B once it lands. Option B is the moat compounding asset BIZLOG 2026-04-16 names; Option A is the bridge between v2.0 (catches per-template tampering) and Option B (catches cross-operator selfish strategies).

## What v3.x does NOT do (architectural ceilings)

The honest discipline that worked for the v2.0 BIZLOG scorecard applies here too. v3.x cannot:

- Detect selfish mining where the attacker's private mempool segment fully matches the verifier's mempool view at evaluation time. The signal requires the unknown set to be unknown TO the verifier; an attacker who synchronizes their private segment to the verifier's view defeats this.
- Detect selfish strategies that operate within the 4 percent tolerance window. Same architectural ceiling Phase 2 has; v3.x cannot lower the floor without raising operator FP risk.
- Distinguish a sophisticated selfish operator from a poorly-tuned but benign operator whose bitcoind is just behind the network. Resolution latency partially mitigates this, but a selfish operator who throttles their tx broadcast to mimic propagation latency defeats it.
- Provide cryptographic proof of selfish behavior. v3.x produces statistical evidence, not consensus proofs. The output is "this operator's template stream looks selfish with X percent confidence" plus the supporting data, not "this operator IS selfish".

These limitations get named in the v3.x launch announcement the same way the v2.0 4 percent tolerance and bitcoind trust assumption get named in the v2.0 launch.

## Open design questions for v3.x kickoff

1. **Scoring threshold tuning.** What confidence level triggers an advisory? What false-positive budget is acceptable? Open until at least one quarter of design partner data is available.
2. **Advisory action contract.** Does the advisory only emit dashboards/alerts, or does it propose policy actions (raise tolerance, alert operator's own monitoring, etc.)? Probably alerts-only initially, with operator-tunable automated responses in a later increment.
3. **Privacy boundary for federated mode.** What signals can be shared across operators without leaking their tx flow patterns? RISELab-adjacent privacy-preserving aggregation work is the pre-read; the specific privacy budget is the open question.
4. **Cross-pool identity correlation tie-in.** BIZLOG Behavioral Intelligence Platform Layer 6 (cross-pool identity tracking) provides the operator-identity fabric the federated detector consumes. Sequencing question: does identity correlation ship with v3.x selfish-mining or before it?
5. **Per-tx detail mode default.** v2.0 ships `per_tx_detail = false` so verdict log lines stay predictable. v3.x detection requires `true`. Does v3.x ship a policy default flip, or does the v3.x detector require operators to opt-in via `[policy.mempool] per_tx_detail = true`?
6. **Detection latency budget.** Per-template synchronous detection is impossible (the signals are temporal). What is the acceptable wall-clock window between the selfish behavior occurring and the advisory firing? Hours, days, or real-time-with-warmup?

## Tracked

This sketch is preliminary. The formal v3.x design ADR (ADR-004 placeholder) gets drafted when v3.x kickoff begins. Until then this file is the canonical reading material for any conversation about "what does v3 add beyond Phase 2".

When ADR-004 lands, this sketch gets either folded into ADR-004 verbatim (if the design lands close to this shape) or moved to `docs/archive/` (if v3.x diverges substantially). Update the "Status" line above when that happens.
