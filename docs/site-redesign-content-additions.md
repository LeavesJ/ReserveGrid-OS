# Veldra Site Redesign: Content Additions for v2.0

**Status:** Content scope brief for the post-Phase-2 site redesign. Inputs to the design tool consuming this doc; structure, layout, IA, voice, and visual language are decided downstream.
**Audience:** Site redesign work (Claude Design or other design surface), founder review, future contributors briefing on the v2.0 messaging baseline.
**Source of truth:** `services/rg-consensus`, `services/pool-verifier`, `docs/ADR-002-invariant-shield.md`, `docs/ADR-003-mempool-ground-truth.md`, `docs/three-mode-architecture.md`, `docs/architecture-comparison.md`, `docs/v3-selfish-mining-design-sketch.md`, README.

This doc enumerates the content topics that should appear on veldra.org after v2.0 launch and that are not currently on the site. It does not propose where each topic should live, what voice should be used, or what visual treatment applies. Those are downstream decisions.

---

## Current site baseline (what is already published)

For the reader of this doc not familiar with veldra.org:

- **Homepage:** SV2 mining gateway framing. 59 gateway reason codes. 2000ms verdict timeout. Three deployment modes (shadow free, observe paid, inline enforcement). Fail-closed prevhash with dual buffering and 5s stale hold. Two-event share lifecycle. 91 reason codes total (stale: current canonical total is 95 after Phase 2 #1 added 4 v2_invariant_mempool_* variants). 61 TOML keys (stale: current is 69 after Phase 2 #2 added 8 `[policy.mempool]` keys). Noise NX encryption. Machine-readable rejection reason codes with policy context. Prometheus / Grafana / CSV / NDJSON observability. Internal architecture diagram.
- **Product page:** Per-category reason code breakdown (transport / framing / auth / channel / job / share). Share lifecycle JSON examples. Mode switching is a single TOML key change. Per-channel performance targets (p50<50ms, p95<150ms, p99<300ms for prevhash verdict). TOML configuration example across `[gateway]` / `[timing]` / `[share]` / `[auth]` tabs. Escape hatch env var (`VELDRA_ALLOW_NO_SHARE_UPSTREAM_READY_INLINE`). Security philosophy (encrypted transport, fail-closed logic, auditability).
- **About page:** Mission statement on eliminating template ambiguity. Six design principles (deterministic, fail-closed, observable, zero silent failures, stateless, miner-aligned). Service breakdown (sv2-gateway, pool-verifier, template-manager, rg-protocol).
- **Internationalization:** EN, ES, 中 toggles exist. ES and 中 mirror EN.
- **Footer:** Reason Codes page, Configuration page, Documentation, GitHub, Privacy, Terms, Disclaimer, Contact (jarrondeng@veldra.org).

---

## Content additions

Each numbered item below is a content topic that does not currently appear on the site and that v2.0 makes material to operator evaluation.

### A. v2.0 Invariant Shield (Phase 1 plus Phase 2)

1. **Independent consensus re-derivation as a stated capability.** The verifier does not trust what the template declares; it re-derives consensus quantities from the raw block bytes and rejects on mismatch. Source: ADR-002 plus `services/pool-verifier/src/policy.rs::check_invariant_shield_inner`.
2. **rg-consensus as a separable facade.** Five public re-derivation functions: `re_derive_coinbase_value`, `re_derive_template_weight`, `re_derive_merkle_root`, `re_derive_witness_commitment`, `count_sigops`. Plus class accessors: `template_txids`, `parse_block`, `total_sigops`, `coinbase_sigops`, `bip34_height`. Wraps `rust-bitcoin` behind a narrow facade boundary.
3. **The 22 canonical `v2_invariant_*` reason codes** as a named subset of the 95-code `ReasonCode::ALL` total. The 95 splits into 22 v2_invariant_* codes (across Phase 1 and Phase 2 of the Invariant Shield), 14 non-shield verdict reasons (policy and system), and 59 gateway reasons (with one `internal_error` shared between the verdict and gateway sides). The full list of v2_invariant_* canonical strings lives in `rg-consensus::ConsensusViolation::ALL_CODES`.
4. **Tier 1 / Tier 2 / Tier 3 invariant breakdown.** Tier 1 (5 critical: CoinbaseValue, CoinbaseHeight, MerkleRoot, WitnessCommitmentMismatch, TxCount) plus Tier 2 (5 high: TemplateWeight, Sigops, CoinbaseSigops, WitnessCommitmentMissing, CoinbaseBip34) shipped in Phase 1 #4b. Tier 3 (7 belt-and-suspenders: CoinbaseScriptLength, CoinbaseOutputCount, WeightExceedsMax, SigopsExceedMax, NonCoinbaseNullPrevout, HeaderVersionLow, DuplicateTx) ships in Phase 1.5 after the production observation cycle.
5. **Mempool ground truth (Phase 2 Class M check).** The verifier holds its own bitcoind RPC client, polls `getrawmempool` every `[policy.mempool] poll_interval_secs` (default 10), cross-references the template's non-coinbase txids against the network mempool, and rejects when the unknown-tx ratio exceeds `tolerance_pct` (default 4.0, operator-tunable; the right value depends on the operator's bitcoind propagation latency profile relative to the rest of the network).
6. **Fail-stale state machine for the mempool view.** Three states: Fresh, Stale, Degraded. `max_stale_secs` default 60. Last-known view served up to that window after a refresh failure. Beyond `max_stale_secs * 2` the view is Degraded, the Class M check is skipped, and templates fall through to Phase 1 behavior. `verifier_phase2_degraded_total` increments per template served while Degraded.
7. **Per-tx detail mode** as a forensic option. `[policy.mempool] per_tx_detail = true` flips the rejection detail string from the bounded `SAMPLE_UNKNOWN_CAP = 10` representative txids to every unknown txid in the canonical `sample=[hex,hex,...]` field. Wire format stays 1:1 (one TemplateVerdict per accepted TemplatePropose).
8. **Eight new `[policy.mempool]` configuration keys** that bring the operator-tunable surface from 61 to 69: `enforce`, `tolerance_pct`, `poll_interval_secs`, `max_stale_secs`, `per_tx_detail`, `rpc_url`, `rpc_user`, `rpc_pass`. All optional with defaults so older configs continue to load unchanged.
9. **Four new Phase 2 metrics** beyond the existing exports: `verifier_phase2_checks_total{result}` with result in agreed/rejected/skipped/stale, `verifier_phase2_degraded_total`, `verifier_mempool_view_age_seconds`, `verifier_mempool_view_size`.

### B. Trust-layer architectural model

10. **Two orthogonal trust layers in v2.0**, with a third reserved for v3.x. Layer 1 (v1 policy) trusts what the template declares about itself and enforces operator-tuned thresholds against those declared fields. Layer 2 (v2.0 Invariant Shield) is a single shield with three check classes: Class S structural re-derivation against raw block bytes (Phase 1), Class D declared-versus-derived consistency (Phase 1), and Class M mempool ground truth via the operator's bitcoind (Phase 2). Layer 3 (v3.x, design-sketch only as of v2.0 launch) covers selfish-mining detection and other pattern-based behaviors. Each layer catches a class of failures the prior layer cannot see by construction.
11. **What each layer cannot catch (architectural ceilings).** Layer 1 cannot catch any template whose declared fields pass operator thresholds, even if the underlying bytes are fabricated. Layer 2 (the v2.0 Invariant Shield with Class S + Class D + Class M wired) cannot catch tampering that is internally consistent across declared fields, raw bytes, AND the operator's bitcoind mempool view simultaneously. Layer 2 also cannot catch tampering operating within the configured `tolerance_pct` window or while the operator's bitcoind is itself compromised. Layer 3 (v3.x) is the architectural answer to detection of patterns that span many templates over time, and is not in scope for v2.0.

### C. Threat model

12. **Named attacker classes T1 through T5.** T1 raw_block tampering. T2 declared-versus-bytes mismatch. T3 consistent-template-manager tampering (the class Phase 2 mempool ground truth closes). T4 compromised operator bitcoind (explicitly out of scope). T5 selfish mining or aggressive mempool-policy divergence (v3.x territory). Source: ADR-003 D-18 threat model formalization.
13. **Trust boundary statement.** ReserveGrid OS v2.0 with Phase 1 plus Phase 2 catches T1, T2, and T3. T4 and T5 are explicitly out of scope. Source: ADR-003 trust boundary section.
14. **Architectural caveats named upfront.** The configured `tolerance_pct` window in Phase 2 absorbs benign mempool divergence (legitimate propagation latency between the operator's bitcoind and the network). Tuning the threshold downward narrows the window but cannot reach zero without producing false positives on real templates; the right value depends on the operator's bitcoind propagation latency profile. Phase 2 trusts the operator's bitcoind by definition; if that bitcoind is itself compromised, Class M is blind.

### D. Documented public failure incidents (with citations)

These are public Bitcoin mining incidents with public sources. Each maps to a reason code that the verifier emits.

15. **Foundry 2-block reorg at height 941,881.** AntPool plus ViaBTC blocks orphaned. Source: b10c. Reason code that fires: `weight_ratio_exceeded`. v2.0 angle: `v2_invariant_template_weight_mismatch` catches the declared-versus-derived gap independently.
16. **F2Pool sigops invalid blocks at heights 783,426 and 784,121** (April 2023). Custom sigops patch reduced coinbase-reserved sigops. Source: b10c, BitMEX Research. Reason codes: `sigops_budget_warning`, `coinbase_sigops_abnormal`. v2.0 angle: `v2_invariant_sigops_mismatch` (Tier 2, wired in Phase 1 #4b) catches the declared-versus-derived sigops gap. The companion structural `v2_invariant_sigops_exceed_max` is Tier 3 and does not ship until Phase 1.5.
17. **Antpool plus pool fleet invalid coinbase during forks** at heights 874,037, 873,559, 875,590 (December 2024). 17 seconds of invalid jobs from cached coinbase values. Source: b10c. Reason code: `coinbase_value_zero_rejected`. v2.0 angle: `v2_invariant_coinbase_value_mismatch` catches the declared-versus-derived gap regardless of the cached value path.
18. **Antpool plus proxy pools sharing identical templates.** BTC.com 99%, Poolin 98%, Binance Pool, EMCD, Rawpool. Combined network share 26%+ from one template source. Source: b10c template similarity analysis (September 2024). Argument: independent verification at each pool's boundary stops single-source template defects from propagating to a quarter of network hashrate.
19. **F2Pool half-empty block 878,889** (January 2025). ~50% empty 87 seconds after previous block. Pool's block-maker node restarted without mempool.dat. Source: mempool.space (mononautical), PANews.
20. **Antpool 30-second empty-block-jobs after every new block.** ~2% empty block rate vs <1% industry norm. Source: b10c plus mempool.space empty block report.
21. **F2Pool OFAC censorship November 2023.** 6 blocks missing sanctioned transactions. Source: CoinDesk, TheMinerMag, b10c. Argument: structured policy with reason codes versus opaque patches gives operators an auditable filtering surface.
22. **SPV Mining July 2015 incident.** Half of network hashrate mining without full validation. Multiple large miners lost >$50K combined. Source: bitcoin.org alert. Historical precedent for the cost of skipping template validation.

### E. Performance and benchmarks

23. **Concrete verdict latency under load.** The product page already publishes per-channel performance targets (`p50 < 50ms`, `p95 < 150ms`, `p99 < 300ms` for prevhash verdict). What the site does not publish is the actual measured average verdict latency under load (multi-tenant template throughput, not just per-channel). Source: pool-verifier load test claims CL-01.
24. **Zero-drop load test result.** Templates submitted, templates verdict-returned, drops. The CL-02 claim that load testing at 100 concurrent connections plus 2000 templates per second produced zero drops across the test set.
25. **Cold build benchmark.** Cargo cold-build wall clock at the v2.0 Phase 1 baseline. Useful for engineers evaluating fitness as a build dependency.

### F. Differentiation content

26. **Stratum Reference Implementation comparison.** SRI is the canonical proof that the SV2 protocol is implementable. ReserveGrid is built specifically for pool operators who need verification, not just connectivity. SRI catches the v1 policy class only (and not all of it); ReserveGrid adds the v2.0 Invariant Shield's re-derivation (Phase 1) plus mempool ground truth (Phase 2) checks on top.
27. **DATUM and other miner-side template protocols** as ecosystem context. ReserveGrid's verification layer is independent of which miner-side protocol the pool runs.
28. **Bitcoin Core 30.0 IPC mining interface** as SV2 ecosystem maturity anchor (October 2025). Ocean and DEMAND in production. Braiins ships SV2 firmware at scale.
29. **Why-not-build-it-yourself.** Specialization argument. Pools do not build their own ASICs, firmware, or networking stacks. Template verification is the same kind of specialization. Engineering hours spent on verification infrastructure are hours not spent on payout, uptime, fees.
30. **Escrow continuity clause** in the license. If Veldra ceases operations, full source releases under a permissive license. Pool keeps deployment, configuration, data. No lock-in risk.
31. **Source-available license.** Every line of source is auditable. Commercial deployment requires a license; no opacity.
32. **Dual prevhash buffer** as a unique mechanism. The gateway holds two pending templates simultaneously during block transitions with a 2000ms verdict window per the production-safe `prevhash_verdict_timeout_ms` default (configurable in `[timing]`; the regtest-only 50ms default was bumped to 2000ms in Phase 1 #4b Bucket C per R-154). Miners never wait on the verifier across a block transition because the buffer evaluates the next template concurrently with the current one. Currently mentioned as a feature; not framed as the answer to the prevhash race that no other gateway has.
33. **Native desktop app (rg-desktop).** Tauri-built native macOS / Linux app. Wraps the dashboard, manages licensing, includes signed auto-update. Currently absent from public surfaces.
34. **rg-feed-server reference feed for observe mode.** Veldra-hosted authenticated WebSocket relay that streams identical mainnet template data to operators running observe-mode without their own production bitcoind. Decision rationale in `docs/architecture-comparison.md`.

### G. Operational adoption content

35. **Concrete adoption timeline.** Shadow takes a day. Observe a week (self-hosted Docker stack plus license key). Inline depends on the pool's infrastructure readiness. The site says modes exist; it does not say how operators move through them.
36. **License key flow.** How an operator who wants observe or inline mode gets and uses a license key from their veldra.org account. Mentioned implicitly in the `Sign In` link; not surfaced as a flow.
37. **Mainnet bitcoind prerequisite for observe and inline.** What the operator needs to run their side: bitcoind synced and resourced, RPC reachable, env-var or `[policy.mempool] rpc_*` credentials wired.

### H. Industry context

38. **Post-halving economics.** Block reward 3.125 BTC. Each invalid block, half-empty block, or policy-violating template costs more than 18 months ago. Why this risk class is being priced into pool risk posture now.
39. **Mining concentration.** Foundry plus Antpool 51% (August 2025). Five pools control ~80%. Source: b10c. Fewer independent template validation points raises the cost of any one pool's verification gap.

### I. Honest scoping (what claims need empirical backing before they ship)

40. **Wiring versus validation.** The v2.0 code chain is shipped, on origin, CI green. Independent consensus re-derivation runs. Mempool ground truth runs. The launch claim that the system catches consistent template-manager tampering at the verifier layer in production requires the production observation cycle to complete first. Until then, public messaging should distinguish between "wired and tested in CI" and "validated against real mainnet templates over a multi-week observation window."

### J. Roadmap

41. **v2.0 launch milestone** as the current focus. Invariant Shield Phase 1 plus Phase 2 mempool ground truth.
42. **Phase 1.5** as the next engineering bucket. The seven Tier 3 belt-and-suspenders invariants wire after the v2.0 production observation cycle completes cleanly.
43. **v3.x mild vision: selfish mining detection.** Per-tx detail mode plus the four Phase 2 metrics shipped in v2.0 set up the data shape for time-series detection of templates whose unknown-tx sets cluster temporally with structurally coherent fingerprints. v3.x design begins from the shipped Phase 2 surface; no protocol change required, no migration cost beyond enabling per-tx detail in operator policy. Source: `docs/v3-selfish-mining-design-sketch.md`.

### K. Translation parity (operational note)

44. Every content topic above must land in EN, ES, and 中 to maintain the existing language toggle integrity. ES and 中 currently mirror the EN content. The v2.0 additions need translation parity before public launch.

---

## Out of scope for this doc

This doc does not specify:
- Which topics are hero versus secondary
- Which topics share a page versus get their own page
- Voice or tone
- Visual treatment, palette, typography, component vocabulary
- What existing content should be removed, demoted, or kept
- Comparable sites for design inspiration
- Information architecture

Those decisions belong to the design surface consuming this doc.

## Source of truth pointers

For any content topic above, the canonical source for fact-checking lives in the repo:

- v2.0 wiring and reason codes: `services/rg-consensus/src/lib.rs`, `services/rg-protocol/src/lib.rs`, `services/reservegrid-common/src/reason.rs`
- Phase 2 wiring: `services/pool-verifier/src/mempool_view.rs`, `services/pool-verifier/src/bitcoind_rpc.rs`, `services/pool-verifier/src/policy.rs`
- ADRs: `docs/ADR-002-invariant-shield.md` (Phase 1), `docs/ADR-003-mempool-ground-truth.md` (Phase 2)
- Architecture: `docs/three-mode-architecture.md`, `docs/architecture-comparison.md`
- v3.x: `docs/v3-selfish-mining-design-sketch.md`
- Public incidents: pitch-prep references plus the b10c blog plus mempool.space empty block report

If a content topic in this doc disagrees with the source, the source wins.
