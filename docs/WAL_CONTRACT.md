# WAL Durability Contract

**Applies to:** sv2-gateway share event delivery
**File:** `services/sv2-gateway/src/wal.rs`
**Format:** NDJSON (one JSON object per line)

## Purpose

The share lifecycle emits two NDJSON events per accepted share:

1. `ShareAcceptedEvent` (Event 1): share validated, SV2 ACK sent to miner.
2. `ShareForwardResultEvent` (Event 2): upstream relay outcome.

A crash between Event 1 and Event 2 creates orphaned accepted events that permanently violate the 1:1 join invariant. The WAL prevents this by persisting `(share_id_hex, event_id_hex)` pairs as pending before enqueuing for forward, and marking them completed after the relay result arrives.

## Record Format

Each line is a JSON object with exactly four fields:

```json
{"status":"pending","share_id_hex":"<64 hex chars>","event_id_hex":"<64 hex chars>","timestamp_ms":1710000000000}
{"status":"completed","share_id_hex":"<64 hex chars>","event_id_hex":"<64 hex chars>","timestamp_ms":1710000000100}
```

The `status` field is either `"pending"` or `"completed"`. Both map to the `WalStatus` enum (serde `snake_case`).

## Write Guarantees

Each record is serialized to JSON with a trailing newline appended in a single buffer before `write_all`, followed by `flush`. This prevents partial (newline-less) lines on crash. The gateway does not call `fsync`; durability depends on the OS buffer flush behavior. On Linux ext4 with default mount options, a process crash (not a power loss) will preserve flushed data.

**Guarantee level:** process crash safe. Not power loss safe without `O_SYNC` or explicit `fsync`. This is an acceptable tradeoff for a share relay because shares can be re-submitted by miners after a full host crash, and the WAL exists to preserve the accounting join invariant, not to guarantee share delivery.

## Lifecycle

1. **`mark_pending(share_id, event_id)`**: append a `"pending"` record, insert into in-memory HashMap.
2. **Forward the share to upstream.**
3. **`mark_completed(share_id, event_id)`**: append a `"completed"` record, remove from in-memory HashMap.
4. Completed records tolerate out-of-order arrival (completion before pending) to handle `select!` scheduling races.

## Recovery

On startup, `open()` replays the file to rebuild the in-memory pending index. Each `"pending"` record inserts, each `"completed"` record removes. Malformed lines and I/O errors are logged and skipped (never fatal).

`recover()` then emits a synthetic `ShareForwardResultEvent` with `reason_code = "process_crash_recovery"` for each orphaned entry. This restores the 1:1 join invariant for downstream consumers. After recovery the pending set is empty and the WAL is compacted.

## Compaction

When `completed_since_compaction` exceeds the configurable threshold, the WAL rewrites only pending entries to a `.wal.tmp` file and atomically renames it over the original. This bounds file growth. Compaction threshold of 0 disables auto-compaction.

The atomic rename means readers that `open()` mid-compaction will see either the old or new file, never a partial write.

## Optionality

The WAL is optional. When `wal_path` is empty, the gateway operates without persistence. This is suitable for regtest and development where crash recovery is not needed.

## Backpressure

The WAL does not implement backpressure. If the forward channel is full, shares are dropped with `share_dropped_queue_full` reason code. The WAL entry is never written for dropped shares because `mark_pending` is called only for shares that successfully enter the forward queue.

## Rotation

The WAL does not implement time or size based rotation. Compaction is the sole mechanism for bounding file size. In practice the file stays small because completed records neutralize pending records and compaction removes both.

## Flush Semantics

Each `append_record` call ends with `BufWriter::flush()`. This pushes data from userspace buffers to the kernel page cache. The kernel will write to disk asynchronously. For process crash safety this is sufficient because the kernel page cache survives process death.

## Test Coverage

8 tests in `wal.rs` covering: open and append, recovery of orphaned entries, compaction, malformed line tolerance, concurrent pending and completed ordering, empty WAL, and threshold-based auto-compaction.
