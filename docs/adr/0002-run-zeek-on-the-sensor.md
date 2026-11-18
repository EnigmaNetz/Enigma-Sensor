# 0002. Run Zeek on the sensor; packets never leave the host

Status: Accepted

Date: 2026-11-17 (backfilled)

## Context

The Enigma AI platform analyses connection metadata, not packet payloads, and the README promises
that packets never leave the host. Raw captures are also far larger than the logs derived from
them. Zeek turns a PCAP (packet capture) into structured logs for connections, DNS (Domain Name
System), DHCP (Dynamic Host Configuration Protocol) and TLS (Transport Layer Security)
fingerprints.

## Decision

- Each capture window is processed on the host by Zeek through a `Processor`
  (`internal/processor/common/processor.go`): `internal/processor/linux/processor.go` runs
  `/opt/zeek/bin/zeek`, and `internal/processor/windows/processor.go` runs the bundled
  `zeek-windows/zeek-runtime-win64/bin/zeek.exe`.
- Zeek writes JSON (JavaScript Object Notation) logs (`types.ZeekJSONLogsArg`, `LogAscii::use_json=T`), set on the command line
  so neither platform needs a custom Zeek build.
- `types.ZeekLogFiles` is the one list of uploaded logs: `conn`, `dns`, `dhcp`, `ja3_ja4` and
  `ja4s`. Sampling, DHCP and JA3/JA4 scripts are embedded in
  `internal/processor/common/zeekscripts/`; Windows loads its JA3/JA4 script from
  `installer/windows/zeek-runtime-win64.zip`.
- After processing, the sensor deletes the PCAP (`deletePCAPFile` in `internal/sensor/sensor.go`)
  and uploads only the logs. Zeek output folders are kept for `capture.retention_hours`.
- Captures are processed by a pool of `capture.max_processing_workers` with a queue of the same
  size; when the queue is full, a new capture is dropped with a warning rather than held.

## Consequences

- Only metadata leaves the host, and uploads are much smaller than the traffic captured.
- The host pays the processing cost in CPU (central processing unit) and memory, so changes that
  raise memory use or need a new Zeek build are expensive: sensors reach customers only by
  reinstall (`CLAUDE.md`, Code Standards).
- Anything not in a Zeek log is unavailable upstream; new data means a Zeek script or log change.
- Zeek paths are hardcoded (`zeek.path` is never read), and the Windows Zeek runtime is built by
  the Enigma-Zeek repository, so a script change for Windows needs a new Enigma-Zeek release.
- A new log goes into `ZeekLogFiles` first, which also brings it under subnet filtering (ADR 0005).
