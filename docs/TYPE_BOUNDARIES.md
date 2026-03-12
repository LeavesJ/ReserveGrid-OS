# Type Boundary Tightening (v1.0.1+ Roadmap)

**Priority:** Post-publish quality improvement
**Risk without it:** Subtle misuse by future contributors, not a runtime safety issue

## Current State

The codebase uses `String` for several fields that carry semantic meaning beyond "arbitrary text." These work correctly today because all producers are internal and tested, but offer no compile time protection against invalid values.

## Identified Candidates

### 1. Reason code strings

`reason_code: Option<String>` appears in `LoggedVerdict`, `ShareAcceptedEvent`, `ShareForwardResultEvent`, `VerdictLabels`, and `ShareLabels`. The actual values are always `GatewayReason::as_str()` or `VerdictReason::as_str()` outputs.

**Improvement:** Introduce a `ReasonCode` newtype wrapping `&'static str` that can only be constructed from one of the two enums. Serde serializes as the inner string. This makes it impossible to pass a typo through a `String` field.

### 2. Hex-encoded identifiers

`share_id_hex: String` and `event_id_hex: String` appear in WAL records and share events. These are always 64-character lowercase hex strings derived from 32-byte arrays.

**Improvement:** A `HexId` newtype with `From<[u8; 32]>` and `TryFrom<&str>` (validates length and hex charset). Eliminates the risk of accidentally passing a non-hex string or a truncated value.

### 3. Fee tier strings

`fee_tier: String` in `LoggedVerdict` is always one of `"low"`, `"mid"`, `"high"`. `tier_source: String` is always `"measured"` or `"fallback"`.

**Improvement:** `FeeTier` and `TierSource` enums with `serde(rename_all = "snake_case")`. Parse-time validation catches bad values on deserialization of legacy NDJSON log lines.

### 4. Deploy mode as parsed enum

`DeployMode` is already an enum in `reservegrid-common`, so this is done. No action needed.

### 5. Policy config numeric ranges

Fields like `min_avg_fee_lo`, `max_tx_count`, `low_mempool_tx` are `u64` but have domain constraints (fees cannot be negative, tx count has a consensus maximum of ~15,000). These could use bounded newtypes, though the benefit is marginal since policy is validated at load time.

## Migration Strategy

Each newtype should be introduced as a backward compatible change:

1. Define the newtype in `reservegrid-common`.
2. Implement `Serialize` and `Deserialize` as the inner value (transparent serde).
3. Replace `String` fields one at a time, updating producers and consumers.
4. Existing NDJSON log files will still parse because the serde representation is identical.
5. Add a test that `serde_json::from_str::<NewType>(old_string)` succeeds for every known value.

## Why v1.0.1+ Not v1.0.0

These changes are pure refactors with zero behavioral impact. The current `String` types are tested by schema stability tests (CL-17, CL-18, CL-19) and reason code canonicality tests. The newtypes add defense in depth for contributors who do not have the full context of which strings are valid. Shipping v1.0.0 without them carries no runtime risk.
