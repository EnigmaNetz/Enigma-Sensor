# 0005. Subnet exclusion fails closed

Status: Accepted

Date: 2026-11-17 (backfilled)

## Context

Customers can list CIDR (Classless Inter-Domain Routing) blocks in `zeek.excluded_subnets` whose
traffic must never leave the host. That promise only holds if no code path can upload a record from
an excluded subnet, including when filtering itself goes wrong or a Zeek writes an unexpected
format.

## Decision

- `types.FilterExcludedSubnets` (`internal/processor/common/subnet_filter.go`) rewrites every log
  in `types.ZeekLogFiles` in place before it is renamed and uploaded. It drops any record with an
  excluded address in an address field (`id.orig_h`, `id.resp_h`, DHCP (Dynamic Host Configuration
  Protocol) address fields) or in a list such as DNS (Domain Name System) `answers`.
- An error from the filter fails the whole capture: `internal/processor/linux/processor.go` and
  `internal/processor/windows/processor.go` return it, and nothing from that capture is uploaded.
  A line that is not a JSON (JavaScript Object Notation) record is an error too.
- The Azure flow log path (`internal/flowlogs/poller.go`) runs the same filter on its `conn.log`.
- The logs are filtered on disk, not only in the upload, because support bundles
  (`internal/collect_logs/`) archive the capture directories.

## Consequences

- A filter bug costs a window of data rather than leaking excluded traffic.
- Because the filter has already run, `internal/records` can skip a record it cannot decode
  without risk of leaking excluded data.
- A new uploaded log must be added to `ZeekLogFiles`, which brings it under the filter; a new
  address field must be added to `addressFields` or `addressSetFields`.
- Do not change the filter to log and continue on error, or upload logs before it runs.
