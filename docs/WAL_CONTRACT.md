# WAL Durability Contract

**Applies to:** sv2-gateway share event delivery
**File:** `services/sv2-gateway/src/wal.rs`
**Format:** NDJSON (one JSON object per line)

## Purpose

The share lifecycle emits two NDJSON events per accepted share:

1. `ShareAcceptedEvent` (Event 1): share validated, SV2 ACK sent to miner.
2. `ShareForwardResultEvent` (Event 2): upstream relay outcome.

A crash between Event 1 and Event 2 creates orphaned accepted events that permanently violate the 1:1 join invariant. The WAL prevents this by persisting `(share_id_hex, event_id_hex)` pairs as pending when the gateway's main loop receives the share's accepted event, and marking them completed after the relay result arrives. The handler queues the share for forward before it emits that event, and ACKs the miner without waiting for the pending write. An earlier revision of this sentence said the pending record was written before the forward enqueue, which the code has not done.

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

**What it costs, measured rather than assumed.** On the node's ext4 root, 2000 appends of a 221-byte record: 174,361/s with flush alone, 2,340/s with fdatasync. Before PB-44 one accepted share cost TWO syncs (`mark_pending` then `mark_completed`), serialized on the same main select loop, which put the practical ceiling near 1,170 accepted shares/s; past it `share_event_tx` (bounded 4096) dropped accounting events, which re-opens the join hole this WAL exists to close. **PB-44 batches the syncs.** Each select arm takes every record already queued behind the one that woke it, up to `WAL_BATCH_MAX` (1024), and pays one sync for all of them. Nothing waits to fill a batch, so no record's sync is delayed; under load the batch grows and the sync cost per share falls instead of capping throughput. Measured on the same ext4 root, 2000 records of 221 bytes: 2,234/s at one sync per record, 100,819/s at 64 per sync, 885,650/s at 1024 per sync. Under load on a developer Mac (APFS, about 6.5ms a sync), a producer offering 3,000 events/s for 4s into an mpsc(4096) with `try_send`, as the handler does: a consumer paying one sync per event drained 399 and dropped 7,507; the batched consumer drained 11,958 and dropped 0. That harness is `offered_load_drops_with_and_without_batching` in `wal.rs`, ignored by default because it measures a filesystem; it models the select arm with the real channel, WAL and `take_queued`, and does not run `main.rs`.

## Lifecycle

1. **`mark_pending(&[(share_id, event_id), ...])`**: append one `"pending"` record per share in a single write and a single sync, then insert them into the in-memory HashMap. The main loop passes every accepted event already queued, up to `WAL_BATCH_MAX` (PB-44).
2. **Forward the share to upstream.** This runs concurrently with step 1: the handler queued the share for forward before emitting the event that leads to it.
3. **`mark_completed(&[(share_id, event_id), ...])`**: append one `"completed"` record per share in a single write and a single sync, then remove them from the in-memory HashMap.
4. A completion can reach the WAL before its pending record, because the two arrive on different arms of one unbiased `select!`. Since PB-47 the WAL remembers such a completion for `EARLY_COMPLETION_TTL_MS` (60s), and the late pending record is then neither written nor indexed, so it cannot survive compaction and come back on restart as a crash orphan with a second forward result. Past 60s an early completion is forgotten: by then its pending record can only belong to an accounting event that was dropped at the queue, which never arrives.

## Recovery

On startup, `open()` replays the file to rebuild the in-memory pending index. Replay is order-independent (PB-47): a share with a `"completed"` record anywhere in the file is not pending, whether that record comes before or after its `"pending"` record. A WAL written before PB-47 therefore heals on its first replay, except where compaction had already dropped the completed record and kept a stale pending one, which recovery still reports as an orphan once. Malformed lines and I/O errors are logged and skipped (never fatal).

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

Each `append_records` call, one per batch since PB-44, flushes the `BufWriter` once and then calls `sync_data` once on the underlying file (PB-39). The flush pushes data from userspace to the kernel page cache, which alone survives process death but not power loss; `sync_data` is the fdatasync that pushes it to stable storage, including the file length an append needs to be retrievable. Compaction additionally `sync_all`s the replacement file before `rename(2)` and syncs the parent directory afterwards, because a rename is directory metadata and is not durable until the directory is.

## Test Coverage

20 tests in `wal.rs`, 2 of them ignored measurements and 1 Linux-only, covering: open and append, recovery of orphaned entries, compaction, malformed line tolerance, empty WAL, threshold-based auto-compaction, that `mark_pending` and compaction are on disk before they return (PB-39), that a batch costs one sync and is fully on disk before it returns, and that `take_queued` stops at its bound (PB-44). The earlier count of 8 had drifted. PB-47 adds four: a completion that arrives before its pending record leaves nothing pending in memory, stays neutralised across compaction, is honoured on replay of a pre-PB-47 file, and is forgotten after its TTL.
