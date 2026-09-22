# WAL Durability Contract

**Applies to:** sv2-gateway share event delivery
**File:** `services/sv2-gateway/src/wal.rs`
**Format:** NDJSON (one JSON object per line)

## Purpose

The share lifecycle emits two NDJSON events per accepted share:

1. `ShareAcceptedEvent` (Event 1): share validated, SV2 ACK sent to miner.
2. `ShareForwardResultEvent` (Event 2): upstream relay outcome.

A crash between Event 1 and Event 2 creates orphaned accepted events that permanently violate the 1:1 join invariant. The WAL prevents this by persisting `(share_id_hex, event_id_hex)` pairs as pending when the gateway's main loop receives the share's accepted event, and marking them completed after the relay result arrives. The handler queues the share for forward before it emits that event, and ACKs the miner without waiting for the pending write. An earlier revision of this sentence said the pending record was written before the forward enqueue, which the code has not done.

**Delivery semantics (PB-44 T2).** With the WAL enabled (`wal_path` set, as `deploy/gateway-prod.toml` does; the built-in default is off) and with `VELDRA_LOG_FILTER` admitting the `share_events` target, Event 2 is delivered **at least once, never zero times**. The gateway emits an Event 2 line before the WAL marks that share complete, and makes an Event 1 line's pending record durable before emitting the line (`services/sv2-gateway/src/accounting.rs`). A crash between the two therefore leaves either an extra synthetic Event 2 for a share whose Event 1 never appeared, or a synthetic Event 2 beside the real one. Either way the synthetic event carries `reason_code = "process_crash_recovery"`, so a consumer that keeps the real Event 2 when both exist, and ignores an Event 2 with no Event 1, recovers an exact 1:1 join. Before this, the forward-result arm marked shares complete and only then logged them, so a crash or a failed compaction in between lost those Event 2 lines for good, a whole batch at a time once PB-44 batched the writes. A line counts as emitted once the process has written it to stdout: the tracing writer is synchronous and flushes each line, which survives the process dying but not the host losing power. The same order holds at startup, where recovery emits the synthetic lines before the WAL lets the orphans go (see Recovery), and at a requested stop (SIGTERM or SIGINT), which drains both accounting queues through the same path before the process exits (PB-49). A WAL failure ends the process with a failure status instead, without draining, since the WAL is what failed.

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

**What it costs, measured rather than assumed.** On the node's ext4 root, 2000 appends of a 221-byte record: 174,361/s with flush alone, 2,340/s with fdatasync. Before PB-44 one accepted share cost TWO syncs (`mark_pending` then `mark_completed`), serialized on the same main select loop, which put the practical ceiling near 1,170 accepted shares/s; past it `share_event_tx` (bounded 4096) dropped accounting events, which re-opens the join hole this WAL exists to close. **PB-44 batches the syncs.** Each select arm takes every record already queued behind the one that woke it, up to `WAL_BATCH_MAX` (1024), and pays one write and one sync for all of them. No timer holds a record back to fill a batch; at low load a batch is one record, exactly as before. Under load a record can wait behind the rest of its batch's per-share bookkeeping (metrics and a channel-registry update per share), which is loop time rather than a sync. Measured, fdatasync throughput for 2000 records of 221 bytes: on the node's ext4 root, with a python equivalent of the append path, 2,234/s at one per sync, 100,819/s at 64, 885,650/s at 1024; on a developer Mac (APFS, about 8ms a sync) through the real code, `bench_append_cost_on_this_filesystem`, 124/s, 8,054/s and 56,511/s. Measured, the whole loop: `two_arm_load_on_one_select_loop` in `accounting.rs` drives BOTH arms on one select loop with the real channels (accounting mpsc(4096) fed by `try_send`, as the handler does), the real WAL with compaction on at the production threshold of 1000, and a relay answering after 1 or 10ms, then drains both channels to empty. On APFS, 1,000/s and 3,000/s offered for 4s dropped 0 accounting events in every run. At 10,000/s the result depends on the machine and its load: the first run dropped 115, and the PB-47 T2 re-reviewer's repeated runs dropped 0, 0, 0, 5,822 and, on a loaded machine, 26,085. So a ceiling remains, set by the disk's sync cost, and on the node's ext4 it sits far higher than on APFS. At 20,000/s for 12s, far past the ceiling here, both the reviewed PB-47 code and the current code drop about 69%, but the reviewed code took 127.9s to drain because compaction rewrote every completion still waiting for its pending record. The current code, which caps that set and prunes it inside compaction, drained in 37.7s and left 2 pending records, the cap's stated cost (see Lifecycle, item 4). The harness is ignored by default because it measures a filesystem, and it runs the arms' real functions but not `main.rs` itself.

## Lifecycle

1. **`mark_pending(&[(share_id, event_id), ...])`, then emit the Event 1 lines**: append one `"pending"` record per accepted share in a single write and a single sync, then insert them into the in-memory HashMap, and only then emit their accepted lines. Rejected events owe no Event 2 and are emitted at once. The main loop passes every accounting event already queued, up to `WAL_BATCH_MAX` (PB-44). If the write fails, the batch's accepted lines are not emitted and the gateway shuts down.
2. **Forward the share to upstream.** This runs concurrently with step 1: the handler queued the share for forward before emitting the event that leads to it.
3. **Emit the Event 2 lines, then `mark_completed(&[(share_id, event_id), ...])`**: remove the shares from the in-memory HashMap, then append one `"completed"` record per share in a single write and a single sync, then compact if the threshold is reached. A failure anywhere in this step is fatal to the gateway, and costs at most a duplicate Event 2 on restart, because the lines went out first.
4. A completion can reach the WAL before its pending record, because the two arrive on different arms of one unbiased `select!`. Since PB-47 the rule is that **a completed record neutralises exactly one pending record for its share, whichever comes first**. A completion that finds nothing pending is remembered; the next pending record for that share is written but not indexed, and consumes it. The record is written so that replay sees the same consumption memory did; without it, replay would spend the completion on the share's NEXT pending record, a genuine re-accept. Compaction keeps a completion that is still waiting, so a late pending record is never left alone in the file. The waiting set is bounded twice over: at most `EARLY_COMPLETION_CAP` (4096) entries, and entries older than `EARLY_COMPLETION_TTL` (10s, on a monotonic clock) are pruned when compaction runs, which is also when the file drops them, so memory and file forget together. Under overload the set fills with completions whose accounting event was dropped at the queue, which never get a pending record; a completion turned away by the cap, or pruned before a late pending record arrives, means the pre-PB-47 behaviour for that share: at worst a duplicate `process_crash_recovery` Event 2 on restart, never a missing one.

## Recovery

On startup, `open()` replays the file to rebuild the in-memory pending index. Replay follows the same rule as the in-memory index (PB-47): a `"completed"` record neutralises exactly one `"pending"` record for its share, whichever comes first in the file. Replay and memory agree on every order of pending and completed records, which a test checks exhaustively, and replay holds only the completions still waiting for their pending record, not every completion in the file. A WAL written before PB-47 heals on its first replay, except where compaction had already dropped the completed record and kept a stale pending one, which recovery still reports as an orphan once. Malformed lines and I/O errors are logged and skipped (never fatal).

`recover()` then returns a synthetic `ShareForwardResultEvent` with `reason_code = "process_crash_recovery"` for each orphaned entry and clears the in-memory pending set, WITHOUT touching the file. The gateway emits those lines, and only then calls `finish_recovery()`, which compacts. A crash between the two replays the orphans again at the next start: a duplicate, never a loss. Until the PB-47 T2 re-review, `recover()` compacted first, and a crash in that window gave the orphans no Event 2 at all. `finish_recovery()` compacts even with no orphans, so completions still waiting for their pending record when the last process stopped leave the file as they left memory: no pending record from before a restart can still arrive, because the queues it would have come through died with that process.

## Compaction

When `completed_since_compaction` reaches the configurable threshold, the WAL prunes waiting completions past their TTL, then rewrites the pending entries plus the waiting completions that remain (at most 4096, PB-47) to a `.wal.tmp` file and atomically renames it over the original. This bounds file growth. Compaction threshold of 0 disables auto-compaction.

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

28 tests in `wal.rs`, 1 of them an ignored measurement and 1 Linux-only, covering: open and append, recovery of orphaned entries, compaction, malformed line tolerance, empty WAL, threshold-based auto-compaction, that `mark_pending` and compaction are on disk before they return (PB-39), that a batch costs one sync and is fully on disk before it returns, that `take_queued` stops at its bound, that a batch jumping past the compaction threshold still compacts, and that a failed pending batch indexes nothing (PB-44); ten for a completion that arrives before its pending record (PB-47), including an exhaustive check that replay and memory agree on every order of up to four records under three compaction thresholds, and checks that the waiting set is capped, that pruning removes a completion from the file as it does from memory, and that a restart forgets waiting completions in both; and one that orphans stay on disk until their recovery lines are out. 9 tests in `accounting.rs`, 1 of them an ignored measurement, covering the write order the delivery semantics depend on: an Event 2 line is out before its completion is on disk, an accepted line waits for its pending record on disk, a failed pending write emits no accepted line, a compaction failure after durable completions loses no Event 2 line, only accepted shares get a pending record, a queued burst costs one sync per arm, every line is still emitted with the WAL disabled, and a requested stop drains both queues. Not covered by any test: `sync_data` being called at all, since fsync is not observable in-process (see the comment above it in `wal.rs`), and the `break` in `main.rs` that shuts the gateway down on a WAL failure, which is read, not run.
