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

Each record is serialized to JSON with a trailing newline appended in a single buffer before `write_all`, followed by `flush`. This prevents partial (newline-less) lines on crash. **As of PB-39 the flush is followed by `sync_data` (fdatasync)**, so a returned `Ok` means the record reached stable storage, not merely the kernel page cache. Before PB-39 this section read "The gateway does not call `fsync`", which was true of the code and contradicted `wal.rs`'s own module doc and two of its function docs, which promised an fsync that was never performed.

**Guarantee level (PB-39):** power loss safe for appends and for compaction. Appends `sync_data`; compaction `sync_all`s the replacement before the rename and syncs the parent directory after it, so the rename is durable too.

**The tradeoff this section used to record, and why it changed.** It previously read: "process crash safe. Not power loss safe... This is an acceptable tradeoff for a share relay because shares can be re-submitted by miners after a full host crash, and the WAL exists to preserve the accounting join invariant, not to guarantee share delivery." That reasoning was coherent, and it lost to two facts. First, `wal.rs` itself claimed the stronger guarantee in three places, so an operator reading the module got a promise the code did not keep, and the two documents disagreed with each other as well as with the code. Second, the compaction path could lose EVERY pending record at once on power loss, not just recent ones, which the resubmit argument does not cover: a miner cannot resubmit a share whose accounting record vanished after the ACK.

**What it costs, measured rather than assumed.** On the node's ext4 root, 2000 appends of a 221-byte record: 174,361/s with flush alone, 2,340/s with fdatasync. One accepted share costs TWO syncs (`mark_pending` then `mark_completed`) serialized on the same main select loop, so the practical ceiling is roughly 1,170 accepted shares/s. Past it, `share_event_tx` (bounded 4096) drops accounting events with only a warn, which re-opens the join hole this WAL exists to close. **PB-44 tracks moving the syncs off the select loop or batching them, which is the fix that removes the ceiling rather than documenting it.**

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

Each `append_record` call flushes the `BufWriter` and then calls `sync_data` on the underlying file (PB-39). The flush pushes data from userspace to the kernel page cache, which alone survives process death but not power loss; `sync_data` is the fdatasync that pushes it to stable storage, including the file length an append needs to be retrievable. Compaction additionally `sync_all`s the replacement file before `rename(2)` and syncs the parent directory afterwards, because a rename is directory metadata and is not durable until the directory is.

## Test Coverage

8 tests in `wal.rs` covering: open and append, recovery of orphaned entries, compaction, malformed line tolerance, concurrent pending and completed ordering, empty WAL, and threshold-based auto-compaction.
