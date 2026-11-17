# 0004. Retry, then buffer failed uploads on disk

Status: Accepted

Date: 2026-11-17 (backfilled)

## Context

The sensor uploads over customer networks to a Cloud Run backend that can be unreachable or slow.
Captures keep arriving every window, so a worker stuck retrying would fill the PCAP (packet
capture) queue and drop captures. Records from a short outage should still arrive once the
backend is back.

## Decision

- `LogUploader` in `internal/api/client.go` sends each batch with a 4m30s deadline
  (`defaultUploadTimeout`, under Cloud Run's 300 s timeout) and keepalive pings while an RPC
  (remote procedure call) is in flight.
- A batch is tried 3 times, waiting half to all of `retryDelay` (5 s), doubled per retry. After
  that it is written to `buffering.dir` (default `logs/buffer`) as `buf_<time>_<nanos>.rec`,
  without its API (application programming interface) key, under a `.tmp` name and then renamed. Once one batch exhausts its retries,
  the rest of the window is buffered without trying.
- Before each upload, `flushBuffer` sends buffered files oldest first, guarded by `flushMu` so one
  worker flushes at a time, stopping at the first failure. Files older than
  `buffering.max_age_hours` (default 2, set in `config/config.go`) are deleted.
- A `410` response (`ErrAPIGone`) is never retried or buffered and stops the sensor with exit 0.
  A `400` (`errUploadRefused`) is never retried or buffered, and a buffered file that gets one is
  deleted.
- `ErrNotBuffered` tells callers (for example `internal/flowlogs/`) that records were neither sent
  nor buffered, so they must not advance their own state.

## Consequences

- Delivery is at least once: the backend must tolerate duplicates.
- An outage longer than `buffering.max_age_hours` loses the oldest data by design. The buffer is
  bounded by age only, not by size, so a long outage at high volume uses disk.
- Buffered files never hold the API key; keep it that way when changing the request.
- Check `ErrAPIGone` and `ErrNotBuffered` with `errors.Is`, never `==`: they are always wrapped.
- New response codes need an explicit decision on retry and buffering in `statusError`.
